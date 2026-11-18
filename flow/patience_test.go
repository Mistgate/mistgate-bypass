package flow

import (
	"errors"
	"testing"
	"time"
)

// A site that answers later than the budget, once, and then in 2T. With a fallback (the VPN) the flow is given up
// at the end of the budget and the name is left to T for a while: the caller goes elsewhere at once. With none
// (bypass without a VPN) that would break what opens without the ladder: the connection that is open is handed
// over to the application, which waits for the server as long as it would without us, and a name found down is
// waited for to the end of the budget.
func TestWithoutAFallbackASlowSiteIsWaitedFor(t *testing.T) {
	tm := Timing{Budget: 600 * time.Millisecond}
	t.Run("no fallback", func(t *testing.T) {
		l := newLab(t, only(1, 800*time.Millisecond, tlsAnswer), tm, func(c *Config) { c.NoFallback = func() bool { return true } })
		res, err, took := l.open(ctx, "slow.example.org")
		if err != nil || !res.Silent || res.Strategy != 1 || len(res.First) != 0 || took < 500*time.Millisecond || took > 900*time.Millisecond {
			t.Fatalf("strategy %d, silent %v, %v after %v", res.Strategy, res.Silent, err, took)
		}
		// The connection is the live one: the answer comes on it.
		b := make([]byte, 1)
		res.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, err := res.Conn.Read(b); n != 1 || err != nil || b[0] != 0x16 {
			t.Errorf("the answer on the connection: %d bytes %x, %v", n, b, err)
		}
		// The name is down for a while, and it answers now in 2T: it is waited for, not cut at T.
		l.s.setAnswer(only(1, 200*time.Millisecond, tlsAnswer))
		l.clk.Advance(time.Minute)
		res, err, took = l.open(ctx, "slow.example.org")
		if err != nil || res.Silent || len(res.First) == 0 || res.Strategy != 1 {
			t.Errorf("the second time: strategy %d, silent %v, %v after %v", res.Strategy, res.Silent, err, took)
		}
	})
	t.Run("with a fallback", func(t *testing.T) {
		l := newLab(t, only(1, 800*time.Millisecond, tlsAnswer), tm)
		if _, err, took := l.open(ctx, "slow.example.org"); !errors.Is(err, ErrNoWay) || took > 900*time.Millisecond {
			t.Fatalf("%v after %v", err, took)
		}
		l.s.setAnswer(only(1, 200*time.Millisecond, tlsAnswer))
		l.clk.Advance(time.Minute)
		if _, err, took := l.open(ctx, "slow.example.org"); !errors.Is(err, ErrNoWay) || took > 180*time.Millisecond {
			t.Errorf("the second time: %v after %v", err, took)
		}
	})
}
