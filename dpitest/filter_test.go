package dpitest

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/mistgate/mistgate-bypass/dpi"
)

const (
	blocked = "video.example.org"
	allowed = "docs.example.net"
)

func server(t *testing.T) string {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "pong") }))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

// hello gives the client's TLS config for a name and a size of ClientHello: with the post-quantum key share it
// is longer than a segment (the default of crypto/tls), without it a few hundred bytes.
func hello(name string, big bool) *tls.Config {
	cfg := &tls.Config{ServerName: name}
	if !big {
		cfg.CurvePreferences = []tls.CurveID{tls.X25519}
	}
	return cfg
}

// try runs every strategy of the ladder through the filter at once and returns the numbers of those that opened;
// the others must have got what the action of the filter gives.
func try(t *testing.T, f *Filter, cfg *tls.Config, otherwise Outcome) []int {
	t.Helper()
	ladder := dpi.Ladder()
	got := make([]Outcome, len(ladder))
	errs := make([]error, len(ladder))
	var wg sync.WaitGroup
	for i, s := range ladder {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i], errs[i] = f.Try(s, cfg)
		}()
	}
	wg.Wait()
	var opened []int
	for i, s := range ladder {
		switch {
		case errs[i] != nil:
			t.Errorf("%d %s: %v", s.Num, s.Name, errs[i])
		case got[i] == Opened:
			opened = append(opened, s.Num)
		case got[i] != otherwise:
			t.Errorf("%d %s: %s, want %s or opened", s.Num, s.Name, got[i], otherwise)
		}
	}
	return opened
}

func all() []int {
	var n []int
	for i := 1; i <= 20; i++ {
		n = append(n, i)
	}
	return n
}

// Which strategies get through each filter. The sets are what the strategies do to the first flight, seen through
// what the filter looks at; where a measured network differs from the model, the comment says how.
func TestPredicates(t *testing.T) {
	upstream := server(t)
	names := []string{blocked}
	for _, c := range []struct {
		name string
		pred Predicate
		act  Action
		want []int // numbers of the strategies that open the connection
	}{
		{"nothing filtered", Never, Silence, all()},
		// A filter that reads one packet: everything that keeps the name from being whole in the first segment gets
		// by. Only plain, and rec-multi-nodelay, which sends all its records in one write, are caught.
		{"name in the first segment", NameInFirstSegment(names...), Silence, slices.DeleteFunc(all(), func(n int) bool { return n == 1 || n == 9 })},
		{"name in the first segment, answered with a reset", NameInFirstSegment(names...), Reset, slices.DeleteFunc(all(), func(n int) bool { return n == 1 || n == 9 })},
		// Reassembles TCP, reads each TLS record alone. Measured on one network: 6, 8, 15 and 16 open the blocked
		// hosts (and 2, 9 and 14 too, but only with the large ClientHello). Here the urgent byte is not in the
		// stream, as on loopback, so 8 and 16 do not open: see the next case.
		{"name in one record", NameInOneRecord(OutOfBand, names...), Silence, []int{2, 6, 15, 18, 20}},
		// The same filter, taking the urgent byte for payload: 8, 15 and 16 get by, because the byte lands inside the
		// name or in the record header. That is what the measurement suggests; loopback cannot show it.
		{"name in one record, urgent byte as payload", NameInOneRecord(Inline, names...), Silence, []int{2, 6, 8, 15, 16, 18, 20}},
		// Looks at two segments and reads the handshake from them. Measured on another network: 7, 9-14, 16-20 open
		// the blocked hosts, 1-3, 5, 8 and 15 do not. Not reproduced: 6 (opens there, a filter that glues two
		// segments restores its ClientHello), 17 and 18 (they lose a piece on the way there, which loopback does not).
		{"name in the first two segments", NameInFirstSegments(2, OutOfBand, names...), Silence, []int{7, 9, 10, 11, 12, 13, 14, 16, 19, 20}},
		// With the urgent byte as payload 8 and 15 would open too, which the measurement does not show.
		{"name in the first two segments, urgent byte as payload", NameInFirstSegments(2, Inline, names...), Silence, []int{7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 19, 20}},
		// A block on the address: the way the flight is cut does not matter.
		{"blocked by address", NameByAddress(names...), Silence, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := New(t, upstream, c.pred, c.act)
			otherwise := Silenced
			if c.act == Reset {
				otherwise = Resetted
			}
			for _, big := range []bool{false, true} {
				if got := try(t, f, hello(blocked, big), otherwise); !slices.Equal(got, c.want) {
					t.Errorf("big hello %v: opened %v, want %v", big, got, c.want)
				}
			}
			// Another name is none of its business.
			if got := try(t, f, hello(allowed, false), otherwise); !slices.Equal(got, all()) {
				t.Errorf("another name: opened %v", got)
			}
		})
	}
}

// A client that does not announce its plan gets its first TLS record read as one segment: the filter still passes
// what it does not match, holds what it does and resets when told to.
func TestUnannouncedClient(t *testing.T) {
	upstream := server(t)
	dial := func(f *Filter, d time.Duration) error {
		c, err := net.Dial("tcp", f.Addr())
		if err != nil {
			return err
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(d))
		return tls.Client(c, &tls.Config{ServerName: blocked, InsecureSkipVerify: true}).Handshake()
	}
	if err := dial(New(t, upstream, Never, Silence), 5*time.Second); err != nil {
		t.Errorf("nothing filtered: %v", err)
	}
	if err := dial(New(t, upstream, NameInFirstSegment(blocked), Silence), 300*time.Millisecond); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("silence: %v", err)
	}
	if err := dial(New(t, upstream, NameInFirstSegment(blocked), Reset), 5*time.Second); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("reset: %v", err)
	}
}
