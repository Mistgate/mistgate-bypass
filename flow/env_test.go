package flow

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/mistgate/mistgate-bypass/dpi"
	"github.com/mistgate/mistgate-bypass/dpitest"
)

// The ladder is tested against dpitest: a filter on loopback in front of a TLS server. The "application" is a
// crypto/tls client on one end of a pipe, and the "bridge" on the other end does what the client's bridge does:
// reads the ClientHello, calls Open, writes what Open read back to the application and copies the rest. So a test
// that opens means a whole handshake and a request went through, with the first bytes of the server passed on once.

const (
	tStep   = 200 * time.Millisecond  // T in the tests: fixed, the connect time on loopback is nothing; a quick answer takes ~10 ms, with outliers to ~100 ms
	tBudget = 1200 * time.Millisecond // enough for the first connection and four strategies, one per T
)

// fakeClock is the clock of the memory: it tells when names that are down may be tried again, and when a result
// has grown old, without waiting for either.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Unix(1_800_000_000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// leakCheck fails the test if goroutines are left when it is over. It is registered first, so it runs last, after
// the filter and the server have stopped.
func leakCheck(t *testing.T) {
	base := runtime.NumGoroutine()
	t.Cleanup(func() {
		end := time.Now().Add(3 * time.Second)
		for runtime.NumGoroutine() > base && time.Now().Before(end) {
			time.Sleep(10 * time.Millisecond)
		}
		if n := runtime.NumGoroutine(); n > base {
			buf := make([]byte, 1<<16)
			t.Errorf("goroutines: %d before, %d after\n%s", base, n, buf[:runtime.Stack(buf, true)])
		}
	})
}

type env struct {
	t     *testing.T
	flt   *dpitest.Filter
	clk   *fakeClock
	mem   *Memory
	f     *Flows
	small bool // the application's ClientHello is short enough for one segment
	dial  DialFunc

	mu     sync.Mutex
	starts []int // strategies started, in order
	events []Event
	dials  int
}

func newEnv(t *testing.T, pred dpitest.Predicate, act dpitest.Action, country string, mod ...func(*Config)) *env {
	t.Helper()
	leakCheck(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "pong") }))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the strategies that lose leave handshakes half done
	srv.StartTLS()
	t.Cleanup(srv.Close)
	e := &env{t: t, clk: newClock()}
	e.flt = dpitest.New(t, srv.Listener.Addr().String(), pred, act)
	e.mem = OpenMemory("", e.clk.Now)
	cfg := Config{
		Memory:  e.mem,
		Country: func() string { return country },
		Timing:  Timing{TMin: tStep, TMax: tStep, TSlack: tStep, Budget: tBudget},
		Events:  func(ev Event) { e.mu.Lock(); e.events = append(e.events, ev); e.mu.Unlock() },
		OnSend: func(c *net.TCPConn, num int, p dpi.Plan) {
			e.flt.Announce(c.LocalAddr(), p)
			e.mu.Lock()
			e.starts = append(e.starts, num)
			e.mu.Unlock()
		},
	}
	for _, m := range mod {
		m(&cfg)
	}
	e.f = New(cfg)
	e.dial = func(ctx context.Context) (*net.TCPConn, error) {
		e.mu.Lock()
		e.dials++
		e.mu.Unlock()
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", e.flt.Addr())
		if err != nil {
			return nil, err
		}
		return c.(*net.TCPConn), nil
	}
	return e
}

// reset forgets what has been counted, not what has been learnt.
func (e *env) reset() {
	e.mu.Lock()
	e.starts, e.events = nil, nil
	e.mu.Unlock()
}

func (e *env) started() []int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.starts)
}

func (e *env) count(num int) int {
	n := 0
	for _, s := range e.started() {
		if s == num {
			n++
		}
	}
	return n
}

func (e *env) heard() []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.events)
}

// fetch is one connection of the application to name through the ladder: it returns the strategy that opened it,
// or the error of Open, or the error of the application if Open succeeded and the handshake or the request failed.
func (e *env) fetch(ctx context.Context, name string) (int, error) {
	app, side := net.Pipe()
	app.SetDeadline(time.Now().Add(15 * time.Second))
	cfg := &tls.Config{ServerName: name, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}
	if e.small {
		cfg.CurvePreferences = []tls.CurveID{tls.X25519}
	}
	var (
		wg      sync.WaitGroup
		opened  int
		openErr error
	)
	wg.Add(1)
	go func() { // the bridge
		defer wg.Done()
		defer side.Close()
		hello, err := readRecord(side)
		if err != nil {
			openErr = err
			return
		}
		res, err := e.f.Open(ctx, name, hello, e.dial)
		if err != nil {
			openErr = err
			return
		}
		opened = res.Strategy
		defer res.Conn.Close()
		if len(res.First) == 0 || (res.First[0] != 0x16 && res.First[0] != 0x15) {
			openErr = fmt.Errorf("first bytes %x", res.First)
			return
		}
		if _, err := side.Write(res.First); err != nil {
			return
		}
		var cp sync.WaitGroup
		cp.Add(1)
		go func() {
			defer cp.Done()
			io.Copy(res.Conn, side)
			res.Conn.Close()
		}()
		io.Copy(side, res.Conn)
		side.Close()
		res.Conn.Close()
		cp.Wait()
	}()
	appErr := doRequest(tls.Client(app, cfg))
	app.Close()
	wg.Wait()
	if openErr != nil {
		return 0, openErr
	}
	return opened, appErr
}

// readRecord reads one TLS record from the application: the ClientHello.
func readRecord(c net.Conn) ([]byte, error) {
	var h [5]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return nil, err
	}
	b := make([]byte, 5+(int(h[3])<<8|int(h[4])))
	copy(b, h[:])
	_, err := io.ReadFull(c, b[5:])
	return b, err
}

func doRequest(tc *tls.Conn) error {
	if err := tc.Handshake(); err != nil {
		return err
	}
	if _, err := io.WriteString(tc, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); err != nil {
		return err
	}
	body, _ := io.ReadAll(tc)
	if !bytes.HasSuffix(body, []byte("pong")) {
		return fmt.Errorf("response %q", body)
	}
	return nil
}
