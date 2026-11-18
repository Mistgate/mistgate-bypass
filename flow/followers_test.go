package flow

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Tests of the flows that come to a name while a ladder for it is running, or find no room for a ladder.

// Over MaxLadders a flow keeps its own connection, and looks for room again every T: a ladder that has just ended
// gives it room long before its own budget is gone.
func TestFlowWithNoRoomJoinsWhenRoomIsFree(t *testing.T) {
	l := newLab(t, exceptPlain(0, tlsAnswer), Timing{Budget: 1200 * time.Millisecond, MaxLadders: 1})
	var wg sync.WaitGroup
	for _, name := range []string{"a.example.org", "b.example.org"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err, took := l.open(ctx, name)
			if err != nil || res.Strategy == 1 || took > 700*time.Millisecond {
				t.Errorf("%s: strategy %d, %v after %v", name, res.Strategy, err, took)
			}
		}()
	}
	wg.Wait()
}

// A follower whose leader found nothing is not sent away with it: its own connection is its own, and is waited for
// to the end of its own budget. Here the leader's ladder is over at 300 ms, and the follower's ordinary connection
// answers at 400 ms.
func TestFollowerKeepsItsConnectionWhenTheLadderFindsNothing(t *testing.T) {
	var plains atomic.Int32
	l := newLab(t, func(n int) (time.Duration, []byte) {
		if n == 1 && plains.Add(1) == 2 { // the follower's
			return 250 * time.Millisecond, tlsAnswer
		}
		return 0, nil
	}, Timing{Budget: 300 * time.Millisecond, MaxAttempts: 2})
	leader := make(chan error, 1)
	go func() {
		_, err, _ := l.open(ctx, "rr1.googlevideo.com")
		leader <- err
	}()
	time.Sleep(150 * time.Millisecond)
	res, err, took := l.open(ctx, "rr2.googlevideo.com")
	if err != nil || res.Strategy != 1 {
		t.Errorf("follower: strategy %d, %v after %v", res.Strategy, err, took)
	}
	if err := <-leader; !errors.Is(err, ErrNoWay) {
		t.Errorf("leader: %v", err)
	}
}

// The leader's context ends in the middle of its ladder: a follower, which has a context of its own, does not wait
// out its budget for a ladder that is not there any more. It leads one.
func TestFollowerLeadsWhenTheLeaderIsCancelled(t *testing.T) {
	l := newLab(t, exceptPlain(150*time.Millisecond, tlsAnswer), Timing{Budget: 1200 * time.Millisecond})
	lctx, cancel := context.WithCancel(ctx)
	time.AfterFunc(200*time.Millisecond, cancel)
	leader := make(chan error, 1)
	go func() {
		_, err, _ := l.open(lctx, "rr1.googlevideo.com")
		leader <- err
	}()
	time.Sleep(20 * time.Millisecond)
	res, err, took := l.open(ctx, "rr2.googlevideo.com")
	if err != nil || res.Strategy != 6 || took > 900*time.Millisecond {
		t.Errorf("follower: strategy %d, %v after %v", res.Strategy, err, took)
	}
	if err := <-leader; !errors.Is(err, context.Canceled) {
		t.Errorf("leader: %v", err)
	}
}

// Connections to one name that all find the strategy of its part worse than the ordinary connection are one
// observation, the leader's, and not as many as there are connections: three of them do not make the part forgotten.
func TestFollowersDoNotCountAgainstAStrategy(t *testing.T) {
	m := OpenMemory("", newClock().Now)
	m.SetNetwork("t")
	win(m, target{name: "a.googlevideo.com", part: partVideo}, 1, 6, srcNone)
	for _, name := range []string{"b", "c", "d"} {
		tg := target{name: name + ".googlevideo.com", part: partVideo}
		nm, _ := m.plan(tg)
		ch := m.record(nm, verdict{t: tg, first: 6, src: srcPart, winner: 1, ladder: true, follower: true})
		if ch.broken != 0 {
			t.Fatalf("%+v", ch)
		}
		if _, h := m.plan(tg); h.first != 1 { // the name itself is remembered as it is
			t.Errorf("%s: %+v", name, h)
		}
	}
	if p := m.Parts(); len(p) != 1 || p[0].Strategy != 6 || m.cur.harms[6] != 0 {
		t.Errorf("parts %+v, harms %v", p, m.cur.harms)
	}
}
