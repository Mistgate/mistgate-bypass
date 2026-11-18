package flow

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mistgate/mistgate-bypass/dpi"
	"github.com/mistgate/mistgate-bypass/sets"
)

// A server that answers each connection by the strategy the client sent it with, which is what a test of the
// ladder's decisions needs: dpitest filters by the shape of the flight, this one by the number, and with any delay
// or bytes. The strategies are not really cut; Config.OnSend tells the server which one is on the connection.

var (
	tlsAnswer   = []byte{0x16, 3, 3, 0, 4, 2, 0, 0, 0} // the start of a ServerHello
	alertAnswer = []byte{0x15, 3, 3, 0, 2, 2, 40}      // a fatal alert
)

type answerFunc func(num int) (after time.Duration, data []byte) // nil data: the connection stays silent

type stratServer struct {
	ln     net.Listener
	mu     sync.Mutex
	nums   map[string]int
	conns  []net.Conn
	seen   []int
	answer atomic.Pointer[answerFunc]
	dials  atomic.Int32
	rtt    atomic.Int64          // nanoseconds a dial takes
	fail   atomic.Pointer[error] // when set, the dials fail with it at once
}

func newStratServer(t *testing.T, answer answerFunc) *stratServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &stratServer{ln: ln, nums: map[string]int{}}
	s.answer.Store(&answer)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns = append(s.conns, c)
			s.mu.Unlock()
			go s.handle(c)
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		s.mu.Lock()
		for _, c := range s.conns {
			c.Close()
		}
		s.mu.Unlock()
	})
	return s
}

func (s *stratServer) setAnswer(a answerFunc) { s.answer.Store(&a) }

func (s *stratServer) handle(c net.Conn) {
	b := make([]byte, 1)
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if n, _ := c.Read(b); n == 0 {
		return
	}
	s.mu.Lock()
	num := s.nums[c.RemoteAddr().String()]
	s.mu.Unlock()
	if d, data := (*s.answer.Load())(num); data != nil {
		time.Sleep(d)
		c.Write(data)
	}
	buf := make([]byte, 4096)
	for {
		if _, err := c.Read(buf); err != nil {
			return
		}
	}
}

func (s *stratServer) onSend(c *net.TCPConn, num int, _ dpi.Plan) {
	s.mu.Lock()
	s.nums[c.LocalAddr().String()] = num
	s.seen = append(s.seen, num)
	s.mu.Unlock()
}

// started is the strategies that were put on a connection since the last reset, in order.
func (s *stratServer) started() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int(nil), s.seen...)
}

func (s *stratServer) reset() { s.mu.Lock(); s.seen = nil; s.mu.Unlock() }

func (s *stratServer) dial(ctx context.Context) (*net.TCPConn, error) {
	s.dials.Add(1)
	if p := s.fail.Load(); p != nil {
		return nil, *p
	}
	if d := time.Duration(s.rtt.Load()); d > 0 {
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", s.ln.Addr().String())
	if err != nil {
		return nil, err
	}
	return c.(*net.TCPConn), nil
}

func (s *stratServer) setFail(err error) {
	if err == nil {
		s.fail.Store(nil)
		return
	}
	s.fail.Store(&err)
}

// probeHello is the ClientHello that crypto/tls writes for name, with one key share (one segment).
func probeHello(t testing.TB, name string) []byte {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go tls.Client(a, &tls.Config{ServerName: name, InsecureSkipVerify: true, CurvePreferences: []tls.CurveID{tls.X25519}}).Handshake()
	h, err := readRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// lab is a Flows in front of a stratServer, on a clock the test moves.
type lab struct {
	t   *testing.T
	s   *stratServer
	clk *fakeClock
	f   *Flows
	mem *Memory

	mu     sync.Mutex
	events []Event
}

// newLab makes a lab. Timing fields that are zero take the small defaults of the lab, in which the whole ladder is a
// second or so; tests that depend on a number set it.
func newLab(t *testing.T, answer answerFunc, tm Timing, mod ...func(*Config)) *lab {
	t.Helper()
	leakCheck(t)
	l := &lab{t: t, s: newStratServer(t, answer), clk: newClock()}
	if tm.TMin == 0 {
		tm.TMin, tm.TMax = 100*time.Millisecond, 100*time.Millisecond
	}
	if tm.TSlack == 0 {
		tm.TSlack = 10 * time.Millisecond
	}
	if tm.Budget == 0 {
		tm.Budget = time.Second
	}
	l.mem = OpenMemory("", l.clk.Now)
	l.mem.SetNetwork("lab")
	cfg := Config{
		Memory:  l.mem,
		Country: func() string { return "ru" },
		Timing:  tm,
		OnSend:  l.s.onSend,
		Events:  func(e Event) { l.mu.Lock(); l.events = append(l.events, e); l.mu.Unlock() },
	}
	for _, m := range mod {
		m(&cfg)
	}
	l.f = New(cfg)
	return l
}

func (l *lab) heard() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Event(nil), l.events...)
}

// open is one Open to name through the server; the connection, if any, is closed with the test.
func (l *lab) open(c context.Context, name string) (Result, error, time.Duration) {
	return l.openWith(c, name, l.s.dial)
}

func (l *lab) openWith(c context.Context, name string, dial DialFunc) (Result, error, time.Duration) {
	hello := probeHello(l.t, name)
	t0 := time.Now()
	res, err := l.f.Open(c, name, hello, dial)
	if err == nil {
		l.t.Cleanup(func() { res.Conn.Close() })
	}
	return res, err, time.Since(t0)
}

// only answers connections of the strategy num, after d.
func only(num int, d time.Duration, data []byte) answerFunc {
	return func(n int) (time.Duration, []byte) {
		if n == num {
			return d, data
		}
		return 0, nil
	}
}

// exceptPlain answers every strategy but the ordinary connection.
func exceptPlain(d time.Duration, data []byte) answerFunc {
	return func(n int) (time.Duration, []byte) {
		if n != 1 {
			return d, data
		}
		return 0, nil
	}
}

// ladderOf is the numbers of the list the set gives a stranger in a country, so that tests follow the data of the
// set and do not copy it.
func ladderOf(country string) []int {
	var out []int
	for _, s := range sets.Embedded().Site(country) {
		out = append(out, s.Num)
	}
	return out
}

var errRefused = errors.New("connection refused")
