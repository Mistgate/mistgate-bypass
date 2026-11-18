package flow

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mistgate/mistgate-bypass/dpitest"
)

var ctx = context.Background()

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// 1. A name nothing filters opens on the first connection: no second connection, nothing remembered but what the
// window shows (a service part that opens as it is), and nothing at all on the next time.
func TestUnfilteredNameOpensWithOneConnection(t *testing.T) {
	e := newEnv(t, dpitest.Never, dpitest.Silence, "ru")
	s, err := e.fetch(ctx, "docs.example.net")
	check(t, err)
	if s != 1 || !slices.Equal(e.started(), []int{1}) || e.flt.Accepted() != 1 {
		t.Errorf("strategy %d, started %v, %d connections", s, e.started(), e.flt.Accepted())
	}
	if len(e.heard()) != 0 || len(e.mem.Parts()) != 0 || len(e.mem.cur.wins) != 0 {
		t.Errorf("a name of no service left a trace: %v %v", e.heard(), e.mem.Parts())
	}

	s, err = e.fetch(ctx, "www.youtube.com")
	check(t, err)
	if s != 1 || !slices.Equal(e.started(), []int{1, 1}) {
		t.Errorf("strategy %d, started %v", s, e.started())
	}
	ev := e.heard()
	if len(ev) != 1 || ev[0].Kind != EventOpened || ev[0].Service != "yt" || ev[0].Part != "site" || ev[0].Strategy != 1 || ev[0].Ladder || ev[0].Name != "" {
		t.Errorf("events %+v", ev)
	}
	if p := e.mem.Parts(); len(p) != 1 || p[0].Service != "yt" || p[0].Part != "site" || p[0].Strategy != 1 {
		t.Errorf("parts %+v", p)
	}
	e.reset()
	if _, err := e.fetch(ctx, "www.youtube.com"); err != nil || len(e.heard()) != 0 {
		t.Errorf("the second time: %v, events %+v", err, e.heard())
	}
}

// 2. A filter that reads each TLS record alone: the first strategy of the list for the country gets by, memory
// keeps it, and the next connection uses it at once, with no ordinary one before. Only the ladder counts a win. The
// ClientHello is the default of crypto/tls, longer than a segment.
func TestFilterOfOneKindOpensWithTheFirstOfTheList(t *testing.T) {
	e := newEnv(t, dpitest.NameInOneRecord(dpitest.OutOfBand, "example.org"), dpitest.Silence, "ru")
	s, err := e.fetch(ctx, "video.example.org")
	check(t, err)
	if s != 6 || !slices.Equal(e.started(), []int{1, 6}) {
		t.Fatalf("strategy %d, started %v", s, e.started())
	}
	e.reset()
	before := e.flt.Accepted()
	s, err = e.fetch(ctx, "video.example.org")
	check(t, err)
	if s != 6 || !slices.Equal(e.started(), []int{6}) || e.flt.Accepted() != before+1 {
		t.Errorf("the second time: strategy %d, started %v, %d new connections", s, e.started(), e.flt.Accepted()-before)
	}
	if w := e.mem.cur.wins[6]; w != 1 { // only the ladder counts
		t.Errorf("wins of 6: %d", w)
	}
}

// A name of a service shares its part's result: the other names of the part go straight to the strategy.
func TestPartResultIsSharedByItsNames(t *testing.T) {
	e := newEnv(t, dpitest.NameInOneRecord(dpitest.OutOfBand, "googlevideo.com"), dpitest.Silence, "ru")
	s, err := e.fetch(ctx, "rr1---sn-aaaa.googlevideo.com")
	check(t, err)
	ev := e.heard()
	if s != 6 || len(ev) != 1 || ev[0].Kind != EventOpened || ev[0].Service != "yt" || ev[0].Part != "video" || ev[0].Strategy != 6 || !ev[0].Ladder {
		t.Fatalf("strategy %d, events %+v", s, ev)
	}
	e.reset()
	s, err = e.fetch(ctx, "rr2---sn-bbbb.googlevideo.com")
	check(t, err)
	if s != 6 || !slices.Equal(e.started(), []int{6}) {
		t.Errorf("another name of the part: strategy %d, started %v", s, e.started())
	}
	if p := e.mem.Parts(); len(p) != 1 || p[0].Part != "video" || p[0].Strategy != 6 {
		t.Errorf("parts %+v", p)
	}
}

// 3. A filter that reads the first two segments, in another country: the first strategy of that country's list is
// not enough, another opens it, and it is another that is remembered.
func TestAnotherFilterAnotherWinner(t *testing.T) {
	e := newEnv(t, dpitest.NameInFirstSegments(2, dpitest.OutOfBand, "example.org"), dpitest.Silence, "tr")
	s, err := e.fetch(ctx, "video.example.org")
	check(t, err)
	if s != 7 || !slices.Equal(e.started(), []int{1, 6, 7}) {
		t.Fatalf("strategy %d, started %v", s, e.started())
	}
	e.reset()
	s, err = e.fetch(ctx, "video.example.org")
	check(t, err)
	if s != 7 || !slices.Equal(e.started(), []int{7}) {
		t.Errorf("the second time: strategy %d, started %v", s, e.started())
	}
}

// 4. A name that cannot be reached at all is not run through the ladder: no connection, no strategy, the error says
// which kind of failure it is, and for as long as the address is left alone it is tried for TMax only.
func TestUnreachableAddressStopsTheLadder(t *testing.T) {
	e := newEnv(t, dpitest.Never, dpitest.Silence, "ru")
	var dials atomic.Int32
	e.dial = func(ctx context.Context) (*net.TCPConn, error) { // a SYN nobody answers
		dials.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	t0 := time.Now()
	_, err := e.fetch(ctx, "video.example.org")
	if !errors.Is(err, ErrUnreachable) || time.Since(t0) < tBudget/2 || time.Since(t0) > 4*tBudget {
		t.Fatalf("%v after %v", err, time.Since(t0))
	}
	if ev := e.heard(); len(ev) != 1 || ev[0].Kind != EventFailed || ev[0].Reason != ReasonUnreachable {
		t.Errorf("events %+v", ev)
	}
	t0 = time.Now()
	_, err = e.fetch(ctx, "video.example.org")
	if !errors.Is(err, ErrUnreachable) || time.Since(t0) > tBudget/2 || dials.Load() != 2 {
		t.Errorf("the second time: %v after %v, %d dials", err, time.Since(t0), dials.Load())
	}
	e.clk.Advance(5*time.Minute + time.Second)
	t0 = time.Now()
	if _, err = e.fetch(ctx, "video.example.org"); !errors.Is(err, ErrUnreachable) || time.Since(t0) < tBudget/2 || dials.Load() != 3 {
		t.Errorf("after the pause: %v after %v, %d dials", err, time.Since(t0), dials.Load())
	}
	if len(e.started()) != 0 || e.flt.Accepted() != 0 {
		t.Errorf("connections were made: %v", e.started())
	}

	// A refusal is as quick as silence, and as unreachable; it is not remembered, being as quick the second time.
	e.dial = func(context.Context) (*net.TCPConn, error) {
		return nil, errors.New("connection refused to 192.0.2.1:443")
	}
	t0 = time.Now()
	_, err = e.fetch(ctx, "other.example.org")
	if !errors.Is(err, ErrUnreachable) || time.Since(t0) > tBudget/4 || errors.Unwrap(err) != nil || strings.Contains(err.Error(), "192.0.2.1") {
		t.Errorf("refused: %v after %v", err, time.Since(t0))
	}
}

// 4b. A block that holds the connection whatever the strategy: the whole ladder is tried once, ends as "no way"
// within the budget, and the next connection is not run through it again, but ends as soon as T has passed.
func TestEverythingSilentMakesTheNameDead(t *testing.T) {
	e := newEnv(t, dpitest.NameByAddress("example.org"), dpitest.Silence, "ru")
	t0 := time.Now()
	_, err := e.fetch(ctx, "video.example.org")
	if !errors.Is(err, ErrNoWay) || time.Since(t0) < tBudget*3/4 {
		t.Fatalf("%v after %v", err, time.Since(t0))
	}
	if want := []int{1, 6, 16, 8, 15}; !slices.Equal(e.started(), want) {
		t.Errorf("started %v, want %v", e.started(), want)
	}
	if ev := e.heard(); len(ev) != 1 || ev[0].Kind != EventFailed || ev[0].Reason != ReasonNoWay {
		t.Errorf("events %+v", ev)
	}
	e.reset()
	t0 = time.Now()
	_, err = e.fetch(ctx, "video.example.org")
	if !errors.Is(err, ErrNoWay) || time.Since(t0) > tBudget*3/4 || !slices.Equal(e.started(), []int{1}) {
		t.Errorf("the second time: %v after %v, started %v", err, time.Since(t0), e.started())
	}
	if len(e.heard()) != 0 {
		t.Errorf("a name that is down said it again: %+v", e.heard())
	}
}

// 5. Ten flows to a blocked name at once: one of them runs the ladder, the rest wait for it and try the strategy it
// found. Each strategy that failed was started once, in all.
func TestParallelFlowsShareOneLadder(t *testing.T) {
	e := newEnv(t, dpitest.NameInFirstSegments(2, dpitest.OutOfBand, "example.org"), dpitest.Silence, "tr")
	const n = 10
	var wg sync.WaitGroup
	got := make([]int, n)
	errs := make([]error, n)
	gate := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			got[i], errs[i] = e.fetch(ctx, "video.example.org")
		}()
	}
	close(gate)
	wg.Wait()
	for i := range n {
		if errs[i] != nil || got[i] != 7 {
			t.Errorf("flow %d: strategy %d, %v", i, got[i], errs[i])
		}
	}
	if e.count(6) != 1 || e.count(7) != n || e.count(1) > n {
		t.Errorf("started %v", e.started())
	}
}

// 6. A site that is slow and not blocked: the ordinary connection is still waited for after T, and it answers.
// The strategies that were started beside it, which the filter holds, are no reason to think the site is blocked:
// nothing is remembered but that it opens as it is.
func TestSlowSiteIsNotTakenForBlocked(t *testing.T) {
	// Only an uncut ClientHello gets through, so that no strategy can win by being faster.
	cutBreaksIt := func(f dpitest.Flight) bool { return len(f.Segments) > 1 }
	e := newEnv(t, cutBreaksIt, dpitest.Silence, "ru")
	e.small = true
	e.flt.SetDelay(3 * tStep)
	t0 := time.Now()
	s, err := e.fetch(ctx, "www.youtube.com")
	check(t, err)
	if s != 1 || time.Since(t0) < 3*tStep {
		t.Errorf("strategy %d after %v", s, time.Since(t0))
	}
	if len(e.started()) < 2 {
		t.Errorf("no strategy was started beside the ordinary connection: %v", e.started())
	}
	ev := e.heard()
	if len(ev) != 1 || ev[0].Kind != EventOpened || ev[0].Strategy != 1 || !ev[0].Ladder {
		t.Errorf("events %+v", ev)
	}
	if p := e.mem.Parts(); len(p) != 1 || p[0].Strategy != 1 || len(e.mem.cur.wins) != 0 {
		t.Errorf("parts %+v, wins %v", p, e.mem.cur.wins)
	}
}

// 7. A strategy that breaks a site that works: memory asks for it, the ordinary connection answers when it starts
// beside it, the name is remembered as it is and the strategy is blamed. The part that asked for it is forgotten
// after three such; then the ladder runs again as for a name never seen, and finds what the filter wants.
func TestStrategyThatBreaksASiteIsForgotten(t *testing.T) {
	var onlyPlain atomic.Bool
	pred := func(f dpitest.Flight) bool {
		if onlyPlain.Load() {
			return len(f.Segments) > 1 // anything cut is held
		}
		return dpitest.NameInFirstSegment("googlevideo.com")(f) // plain is held, anything cut gets by
	}
	e := newEnv(t, pred, dpitest.Silence, "ru")
	e.small = true
	if s, err := e.fetch(ctx, "rr1.googlevideo.com"); err != nil || s != 6 {
		t.Fatalf("strategy %d, %v", s, err)
	}

	onlyPlain.Store(true)
	for i, name := range []string{"rr2.googlevideo.com", "rr3.googlevideo.com", "rr4.googlevideo.com"} {
		e.reset()
		s, err := e.fetch(ctx, name)
		check(t, err)
		if s != 1 || !slices.Equal(e.started(), []int{6, 1}) {
			t.Errorf("%s: strategy %d, started %v", name, s, e.started())
		}
		broken := slices.ContainsFunc(e.heard(), func(ev Event) bool { return ev.Kind == EventBroken && ev.Strategy == 6 })
		if broken != (i == 2) {
			t.Errorf("%s: broken %v, events %+v", name, broken, e.heard())
		}
	}
	// The name that was broken is remembered as it is: one connection, no strategy.
	e.reset()
	if s, err := e.fetch(ctx, "rr2.googlevideo.com"); err != nil || s != 1 || !slices.Equal(e.started(), []int{1}) {
		t.Errorf("a name that works as it is: strategy %d, started %v, %v", s, e.started(), err)
	}
	if e.mem.cur.harms[6] != 3 {
		t.Errorf("harms %v", e.mem.cur.harms)
	}
	if p := e.mem.Parts(); len(p) != 0 {
		t.Fatalf("the part is still remembered: %+v", p)
	}

	// Nothing is remembered for the part now: a name of it starts as a stranger does, and works as it is.
	e.reset()
	if s, err := e.fetch(ctx, "rr5.googlevideo.com"); err != nil || s != 1 || !slices.Equal(e.started(), []int{1}) {
		t.Errorf("after the reset: strategy %d, started %v, %v", s, e.started(), err)
	}
	if p := e.mem.Parts(); len(p) != 1 || p[0].Strategy != 1 {
		t.Errorf("parts %+v", p)
	}

	// The filter changes its mind again: the ladder starts over and finds a strategy, 6 having lost to plain three
	// times before.
	onlyPlain.Store(false)
	e.reset()
	s, err := e.fetch(ctx, "rr6.googlevideo.com")
	check(t, err)
	if s != 16 || !slices.Equal(e.started(), []int{1, 16}) {
		t.Errorf("strategy %d, started %v", s, e.started())
	}
	if p := e.mem.Parts(); len(p) != 1 || p[0].Strategy != s {
		t.Errorf("parts %+v", p)
	}
}

// 7b. The strategy that worked stops working and another still does: the ladder finds it, and it replaces the old
// one.
func TestWinnerThatStopsWorkingIsReplaced(t *testing.T) {
	var second atomic.Bool
	oneRecord := dpitest.NameInOneRecord(dpitest.OutOfBand, "example.org")
	twoSegments := dpitest.NameInFirstSegments(2, dpitest.OutOfBand, "example.org")
	e := newEnv(t, func(f dpitest.Flight) bool {
		if second.Load() {
			return twoSegments(f)
		}
		return oneRecord(f)
	}, dpitest.Silence, "ru")
	if s, err := e.fetch(ctx, "video.example.org"); err != nil || s != 6 {
		t.Fatalf("strategy %d, %v", s, err)
	}
	second.Store(true)
	e.reset()
	s, err := e.fetch(ctx, "video.example.org")
	check(t, err)
	if s != 16 || !slices.Equal(e.started(), []int{6, 1, 16}) {
		t.Fatalf("strategy %d, started %v", s, e.started())
	}
	e.reset()
	if s, err := e.fetch(ctx, "video.example.org"); err != nil || s != 16 || !slices.Equal(e.started(), []int{16}) {
		t.Errorf("the next time: strategy %d, started %v, %v", s, e.started(), err)
	}
}

// A network that resets instead of holding the connection: the ordinary connection fails at once and the ladder
// goes on at once, not after T (made long here, so that waiting for it would show).
func TestResetIsNotWaitedFor(t *testing.T) {
	e := newEnv(t, dpitest.NameInFirstSegment("example.org"), dpitest.Reset, "ru", func(c *Config) {
		c.Timing.TMin, c.Timing.TMax, c.Timing.Budget = 3*time.Second, 3*time.Second, 6*time.Second
	})
	t0 := time.Now()
	s, err := e.fetch(ctx, "video.example.org")
	check(t, err)
	if s != 6 || time.Since(t0) > time.Second {
		t.Errorf("strategy %d after %v", s, time.Since(t0))
	}
}

// What is not a TLS ClientHello, or has no name, gets one ordinary connection with the bytes written: no wait for
// an answer, no ladder, nothing remembered.
func TestNotTLSIsPassedThrough(t *testing.T) {
	leakCheck(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	check(t, err)
	t.Cleanup(func() { ln.Close() })
	got := make(chan []byte, 2)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b := make([]byte, 64)
				c.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, _ := c.Read(b)
				got <- b[:n]
				c.Read(b) // held open until the client is done
			}()
		}
	}()
	var dials atomic.Int32
	dial := func(ctx context.Context) (*net.TCPConn, error) {
		dials.Add(1)
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", ln.Addr().String())
		if err != nil {
			return nil, err
		}
		return c.(*net.TCPConn), nil
	}
	f := New(Config{Timing: Timing{TMin: tStep, TMax: tStep, Budget: tBudget}})
	for _, c := range []struct {
		name  string
		hello []byte
	}{
		{"example.org", []byte("GET / HTTP/1.1\r\n\r\n")},
		{"", []byte{0x16, 3, 1, 0, 4, 1, 0, 0, 0}},
	} {
		t0 := time.Now()
		res, err := f.Open(ctx, c.name, c.hello, dial)
		check(t, err)
		if res.Strategy != 1 || len(res.First) != 0 || time.Since(t0) > tStep/2 {
			t.Errorf("%q: strategy %d, first %x, after %v", c.name, res.Strategy, res.First, time.Since(t0))
		}
		if b := <-got; string(b) != string(c.hello) {
			t.Errorf("%q: the server got %q", c.name, b)
		}
		res.Conn.Close()
	}
	if dials.Load() != 2 || len(f.mem.Parts()) != 0 {
		t.Errorf("%d dials, parts %v", dials.Load(), f.mem.Parts())
	}
}

// Cancelling the context in the middle of the race returns at once and leaves no goroutine and no connection: the
// filter, which sees every connection, has none open afterwards, and leakCheck finds no goroutine.
func TestCancelInTheMiddleOfTheRaceLeavesNothing(t *testing.T) {
	e := newEnv(t, dpitest.NameByAddress("example.org"), dpitest.Silence, "ru")
	c, cancel := context.WithCancel(ctx)
	defer cancel()
	time.AfterFunc(2*tStep+tStep/2, cancel) // three connections are open
	t0 := time.Now()
	_, err := e.fetch(c, "video.example.org")
	if !errors.Is(err, context.Canceled) || time.Since(t0) > 2*tStep+tBudget/2 {
		t.Errorf("%v after %v", err, time.Since(t0))
	}
	if n := len(e.started()); n < 3 {
		t.Errorf("started %v", e.started())
	}
	waitFor(t, "connections to close", func() bool { return e.flt.Active() == 0 })
	if len(e.heard()) != 0 || len(e.mem.Parts()) != 0 {
		t.Errorf("a cancelled flow left a result: %+v", e.heard())
	}
}

// Cancelling while the first connection is still being waited for ends the Open at T at the latest.
func TestCancelWhileWaitingForTheFirstConnection(t *testing.T) {
	e := newEnv(t, dpitest.NameByAddress("example.org"), dpitest.Silence, "ru")
	c, cancel := context.WithCancel(ctx)
	time.AfterFunc(tStep/3, cancel)
	t0 := time.Now()
	_, err := e.fetch(c, "video.example.org")
	if !errors.Is(err, context.Canceled) || time.Since(t0) > 3*tStep {
		t.Errorf("%v after %v", err, time.Since(t0))
	}
	waitFor(t, "connections to close", func() bool { return e.flt.Active() == 0 })
}

// With the ladders at their limit a flow starts none of its own: it waits for the connection it has.
func TestNoMoreLaddersThanTheLimit(t *testing.T) {
	e := newEnv(t, dpitest.NameByAddress("example.org"), dpitest.Silence, "ru", func(c *Config) { c.Timing.MaxLadders = 1 })
	var wg sync.WaitGroup
	for _, name := range []string{"a.example.org", "b.example.org", "c.example.org"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.fetch(ctx, name); !errors.Is(err, ErrNoWay) {
				t.Errorf("%v", err)
			}
		}()
	}
	wg.Wait()
	// One ladder of five connections, and two flows that kept the one they had.
	if n := len(e.started()); n != 5+2 {
		t.Errorf("started %v", e.started())
	}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	end := time.Now().Add(3 * time.Second)
	for !ok() {
		if time.Now().After(end) {
			t.Fatalf("waited for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
