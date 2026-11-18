package flow

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Tests of what a failure is remembered as, and for how long: the marks of names that are down, and the network
// they are marks on.

// A failure that costs nothing to find out again is not remembered: a refusal, no route, the network being down
// (what a dial says in the first seconds after a wake-up). Remembered, it would turn the next five minutes of every
// connection to the name into an error, with the network already back.
func TestRefusedConnectionIsNotRemembered(t *testing.T) {
	l := newLab(t, only(1, 0, tlsAnswer), Timing{TMin: 50 * time.Millisecond, TMax: 100 * time.Millisecond, Budget: time.Second})
	l.s.setFail(errRefused)
	if _, err, _ := l.open(ctx, "docs.example.net"); !errors.Is(err, ErrUnreachable) {
		t.Fatal(err)
	}
	l.s.setFail(nil)
	var allowed time.Duration
	res, err, _ := l.openWith(ctx, "docs.example.net", func(c context.Context) (*net.TCPConn, error) {
		dl, _ := c.Deadline()
		allowed = time.Until(dl)
		return l.s.dial(c)
	})
	if err != nil || res.Strategy != 1 || allowed < 800*time.Millisecond {
		t.Errorf("the network is back: strategy %d, %v, the dial was given %v", res.Strategy, err, allowed)
	}
}

// A connection that timed out is remembered, so that the next ones do not wait a whole budget for an address that is
// still down: they are tried for TMax. A change of network, even one that gives the same key, is the moment what
// made the address silent may be over: the mark goes, and the next connection has the whole budget again.
func TestTimedOutAddressIsTriedBrieflyUntilTheNetworkChanges(t *testing.T) {
	l := newLab(t, only(1, 0, tlsAnswer), Timing{TMin: 50 * time.Millisecond, TMax: 100 * time.Millisecond, Budget: 600 * time.Millisecond})
	var allowed time.Duration
	silent := func(c context.Context) (*net.TCPConn, error) { // a SYN nobody answers
		dl, _ := c.Deadline()
		allowed = time.Until(dl)
		<-c.Done()
		return nil, c.Err()
	}
	try := func() (time.Duration, error) {
		_, err, took := l.openWith(ctx, "docs.example.net", silent)
		return took, err
	}
	if took, err := try(); !errors.Is(err, ErrUnreachable) || took < 500*time.Millisecond {
		t.Fatalf("the first time: %v after %v", err, took)
	}
	if took, err := try(); !errors.Is(err, ErrUnreachable) || took > 300*time.Millisecond || allowed > 150*time.Millisecond {
		t.Errorf("the second time: %v after %v, allowed %v", err, took, allowed)
	}
	l.mem.SetNetwork("lab") // the same network, signalled again
	if took, err := try(); !errors.Is(err, ErrUnreachable) || took < 500*time.Millisecond || allowed < 500*time.Millisecond {
		t.Errorf("after the signal: %v after %v, allowed %v", err, took, allowed)
	}
}

// A connection that is open, and answers late, is not closed because another flow to the same name timed out: what
// one flow saw says nothing about the connection of another.
func TestMarkOfAnotherFlowDoesNotCloseALiveConnection(t *testing.T) {
	l := newLab(t, only(1, 250*time.Millisecond, tlsAnswer), Timing{})
	done := make(chan error, 1)
	go func() {
		res, err, _ := l.open(ctx, "slow.example.org")
		if err == nil && res.Strategy != 1 {
			err = errors.New("not the ordinary connection")
		}
		done <- err
	}()
	time.Sleep(30 * time.Millisecond)
	timedOut := func(c context.Context) (*net.TCPConn, error) { return nil, context.DeadlineExceeded }
	if _, err, _ := l.openWith(ctx, "slow.example.org", timedOut); !errors.Is(err, ErrUnreachable) {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Errorf("the flow that had connected: %v", err)
	}
}

// The name of many sites (the outer name of an encrypted ClientHello) is not cut off because one address was silent:
// a connection to another address of it is made and answered, and ends the mark.
func TestSharedNameIsNotCutOffByOneAddress(t *testing.T) {
	l := newLab(t, only(1, 0, tlsAnswer), Timing{TMin: 50 * time.Millisecond, TMax: 100 * time.Millisecond, Budget: 600 * time.Millisecond})
	dead := func(c context.Context) (*net.TCPConn, error) { <-c.Done(); return nil, c.Err() }
	if _, err, _ := l.openWith(ctx, "front.example.net", dead); !errors.Is(err, ErrUnreachable) {
		t.Fatal(err)
	}
	res, err, _ := l.open(ctx, "front.example.net")
	if err != nil || res.Strategy != 1 {
		t.Fatalf("another address of the name: strategy %d, %v", res.Strategy, err)
	}
	if _, h := l.mem.plan(target{name: "front.example.net"}); h.unreachable {
		t.Error("the mark outlived an answer")
	}
}

// A ladder that found the name silent found one address silent. A connection to another address of the name is not
// held to T: it runs a ladder of its own.
func TestNameFoundDownAtOneAddressIsNotDownAtAnother(t *testing.T) {
	l := newLab(t, exceptPlain(0, tlsAnswer), Timing{})
	tg := target{name: "front.example.net"}
	nm, _ := l.mem.plan(tg)
	l.mem.record(nm, verdict{t: tg, first: 1, pause: time.Hour, addr: netip.MustParseAddr("192.0.2.7")})
	res, err, _ := l.open(ctx, tg.name) // the server is on 127.0.0.1
	if err != nil || res.Strategy == 1 {
		t.Errorf("strategy %d, %v: the name was taken for down at an address it was not found down at", res.Strategy, err)
	}
	// At the address it was found down at, the mark holds: the ladder does not run.
	l.s.setAnswer(func(int) (time.Duration, []byte) { return 0, nil })
	l.mem.record(nm, verdict{t: tg, first: 1, pause: time.Hour, addr: netip.MustParseAddr("127.0.0.1")})
	l.s.reset()
	if _, err, _ := l.open(ctx, tg.name); !errors.Is(err, ErrNoWay) || len(l.s.started()) != 1 {
		t.Errorf("%v, started %v", err, l.s.started())
	}
}

// A change of network, signalled with the key it had before, is the end of the marks: the names found down, the
// addresses that timed out. Records that held only a mark are dropped with them.
func TestSetNetworkForgetsTheMarks(t *testing.T) {
	m := OpenMemory("", newClock().Now)
	m.SetNetwork("n")
	down, gone := target{name: "a.example.org"}, target{name: "b.example.org"}
	nm, _ := m.plan(down)
	m.record(nm, verdict{t: down, first: 1, pause: time.Hour})
	m.record(nm, verdict{t: gone, fail: failUnreachable, pause: time.Hour})
	keeps := target{name: "mine.example.org", own: true}
	win(m, keeps, 1, 3, srcNone)
	m.record(nm, verdict{t: keeps, first: 1, pause: time.Hour})
	if _, h := m.plan(down); !h.dead {
		t.Fatal("not marked")
	}
	if known := m.SetNetwork("n"); !known {
		t.Error("the same network is not known")
	}
	for _, tg := range []target{down, gone, keeps} {
		if _, h := m.plan(tg); h.dead || h.unreachable {
			t.Errorf("%s: %+v", tg.name, h)
		}
	}
	if _, h := m.plan(keeps); h.first != 3 {
		t.Errorf("a result went with the marks: %+v", h)
	}
	if len(m.cur.names) != 1 {
		t.Errorf("%d records left", len(m.cur.names))
	}
}

// Until the fingerprint of a network is ready the caller says "not known yet", and what the connections of those
// seconds find out is learnt nowhere: not for the old network, not for the new one, not in the file.
func TestNothingIsLearntWhileTheNetworkIsNotKnown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bypass.json")
	m := OpenMemory(path, newClock().Now)
	tg := target{name: "a.googlevideo.com", part: partVideo}
	win(m, tg, 1, 6, srcNone) // before the first SetNetwork
	m.SetNetwork("a")
	m.SetNetwork("") // the network is changing
	if known := m.SetNetwork(""); known {
		t.Error("an unknown network is known")
	}
	win(m, tg, 1, 7, srcNone)
	if len(m.Parts()) != 0 || len(m.cur.wins) != 0 {
		t.Errorf("the gap learnt something: %+v %v", m.Parts(), m.cur.wins)
	}
	m.SetNetwork("b")
	if len(m.Parts()) != 0 || len(m.cur.wins) != 0 {
		t.Errorf("the new network was taught by connections of the gap: %+v %v", m.Parts(), m.cur.wins)
	}
	m.SetNetwork("a")
	if len(m.Parts()) != 0 {
		t.Errorf("the old network was taught by connections of the gap: %+v", m.Parts())
	}
	m.SetNetwork("")
	win(m, tg, 1, 6, srcNone)
	m.mu.Lock()
	m.dirty = true
	m.mu.Unlock()
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(path); err != nil || bytes.Contains(data, []byte(`"":`)) {
		t.Errorf("the unknown network is in the file (%v): %s", err, data)
	}
}
