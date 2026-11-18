package flow

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

// Tests of the time a ladder has, and of how far down the list of a country it gets.

// On a network where a round trip is long, T is long, and the strategies start one T apart: the budget is the time
// the whole ladder takes there, not a fixed number. Here T is 200 ms, so the fourth strategy starts at 800 ms and
// needs 2 round trips (160 ms) and the slack to be answered: a budget of 800 ms would end before it had started.
func TestBudgetFollowsTheRoundTrip(t *testing.T) {
	list := ladderOf("ru")
	fourth := list[3]
	const rtt = 80 * time.Millisecond
	l := newLab(t, only(fourth, rtt, tlsAnswer), Timing{TMin: 70 * time.Millisecond, TMax: 250 * time.Millisecond, TSlack: 40 * time.Millisecond, Budget: 800 * time.Millisecond})
	l.s.rtt.Store(int64(rtt))
	res, err, took := l.open(ctx, "blocked.example.org")
	if err != nil || res.Strategy != fourth {
		t.Errorf("strategy %d, %v after %v, started %v", res.Strategy, err, took, l.s.started())
	}
}

// A strategy that has no time left to be answered is not started: it would be one more open connection that cannot
// help.
func TestStrategyThatCannotBeAnsweredInTimeIsNotStarted(t *testing.T) {
	f := New(Config{})
	q := &request{ctx: ctx, end: time.Now().Add(80 * time.Millisecond), need: 200 * time.Millisecond, step: 20 * time.Millisecond}
	r := &run{f: f, q: q, results: make(chan outcome, 4)}
	r.actx, r.cancel = context.WithCancel(ctx)
	defer r.finish()
	pending := f.set().Site("ru")[:1]
	if _, err := r.race(pending, nil, false); !errors.Is(err, ErrNoWay) || r.launched != 0 || len(r.atts) != 0 {
		t.Errorf("%v, launched %d, attempts %d", err, r.launched, len(r.atts))
	}
}

// A list longer than a ladder is gone through, ladder after ladder: the strategies the first ones left out are tried
// by the next, once the name is allowed another ladder. Here only the fifth of the list works.
func TestNextLadderStartsWhereTheLastOneStopped(t *testing.T) {
	list := ladderOf("ru")
	fifth := list[4]
	l := newLab(t, only(fifth, 0, tlsAnswer), Timing{Budget: 500 * time.Millisecond})
	if _, err, _ := l.open(ctx, "blocked.example.org"); !errors.Is(err, ErrNoWay) {
		t.Fatal(err)
	}
	if want := append([]int{1}, list[:4]...); !slices.Equal(l.s.started(), want) {
		t.Fatalf("the first ladder started %v, want %v", l.s.started(), want)
	}
	l.clk.Advance(10*time.Minute + time.Second) // the name may have another ladder
	l.s.reset()
	res, err, _ := l.open(ctx, "blocked.example.org")
	if err != nil || res.Strategy != fifth {
		t.Errorf("the second ladder: strategy %d, %v, started %v", res.Strategy, err, l.s.started())
	}
}

// A site that answers late, and is not blocked, does not start a ladder on every connection: the next connections
// to it wait for it as long as it took (and a little more), and open nothing else. The same for the part of a
// service, whose other names share what is known of it.
func TestSlowSiteDoesNotRunALadderEveryTime(t *testing.T) {
	l := newLab(t, only(1, 300*time.Millisecond, tlsAnswer), Timing{})
	for _, name := range []string{"slow.example.org", "www.youtube.com"} {
		l.s.reset()
		if res, err, _ := l.open(ctx, name); err != nil || res.Strategy != 1 || len(l.s.started()) < 2 {
			t.Fatalf("%s, the first time: strategy %d, %v, started %v", name, res.Strategy, err, l.s.started())
		}
		for i := range 2 {
			l.s.reset()
			res, err, took := l.open(ctx, name)
			if err != nil || res.Strategy != 1 || !slices.Equal(l.s.started(), []int{1}) || took < 250*time.Millisecond {
				t.Errorf("%s, open %d: strategy %d, %v after %v, started %v", name, i+2, res.Strategy, err, took, l.s.started())
			}
		}
	}
	// What a network was like does not outlive it: after a signal the first connection waits T again.
	l.mem.SetNetwork("lab")
	l.s.reset()
	if _, err, _ := l.open(ctx, "slow.example.org"); err != nil || len(l.s.started()) < 2 {
		t.Errorf("after the signal: %v, started %v", err, l.s.started())
	}
}
