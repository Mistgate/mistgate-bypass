package flow

import (
	"errors"
	"testing"
	"time"
)

// A TLS alert on the connection of a strategy is not an answer: it is what a server or a box on the path says to a
// ClientHello that the strategy has damaged. Counted as one, it would pin the strategy to the whole part for as
// long as the part is used, and the browser would show a protocol error on every name of it.
func TestAlertOnAStrategyIsNotAnAnswer(t *testing.T) {
	l := newLab(t, exceptPlain(0, alertAnswer), Timing{Budget: 600 * time.Millisecond})
	for _, name := range []string{"rr1.googlevideo.com", "rr2.googlevideo.com"} {
		if res, err, _ := l.open(ctx, name); !errors.Is(err, ErrNoWay) {
			t.Fatalf("%s: strategy %d, %v", name, res.Strategy, err)
		}
	}
	if p := l.mem.Parts(); len(p) != 0 || len(l.mem.cur.wins) != 0 {
		t.Errorf("an alert was remembered as a win: %+v %v", p, l.mem.cur.wins)
	}

	// The alert ends that attempt at once and the ladder goes on to the next strategy, which gets through.
	l = newLab(t, func(n int) (time.Duration, []byte) {
		switch n {
		case 6:
			return 0, alertAnswer
		case 16:
			return 0, tlsAnswer
		}
		return 0, nil
	}, Timing{})
	res, err, _ := l.open(ctx, "rr1.googlevideo.com")
	if err != nil || res.Strategy != 16 || res.First[0] != 0x16 {
		t.Fatalf("strategy %d, first %x, %v", res.Strategy, res.First, err)
	}
	if p := l.mem.Parts(); len(p) != 1 || p[0].Strategy != 16 {
		t.Errorf("parts %+v", p)
	}
}

// An alert on the ordinary connection is the server's answer, and the application must hear it.
func TestAlertOnTheOrdinaryConnectionIsAnAnswer(t *testing.T) {
	l := newLab(t, func(int) (time.Duration, []byte) { return 0, alertAnswer }, Timing{})
	res, err, _ := l.open(ctx, "docs.example.net")
	if err != nil || res.Strategy != 1 || len(res.First) == 0 || res.First[0] != 0x15 {
		t.Errorf("strategy %d, first %x, %v", res.Strategy, res.First, err)
	}
}
