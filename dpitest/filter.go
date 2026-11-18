// Package dpitest is a stand-in for the filter of a network, for tests: a TCP proxy on loopback between a client and
// a server that, like a filter on the path, looks at the first bytes of a connection and either lets it through or
// drops it. What it looks at is a predicate, and each predicate models one behaviour that was measured on a real
// network or is known for a type of filter, so that a test can ask which strategies of package dpi get through.
//
// Loopback hides what a path shows: the reader of a socket gets bytes, not the TCP segments they came in. So the
// filter is told how the client's first flight was cut: Try announces the plan of the strategy (cut points, urgent
// bytes), and the predicates work on that, as a path with a 1500-byte MTU would carry it. The filter reads the bytes
// from the socket too, the urgent byte inline as on the wire, and fails the test if they are not the ones announced.
// Pauses between pieces are not modelled (a filter that reassembles waits for them), and pieces sent with a low TTL
// arrive, in order, like any other: loopback drops nothing.
package dpitest

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mistgate/mistgate-bypass/dpi"
)

// mss is the payload of one segment on a 1500-byte MTU: a longer piece reaches the filter as several segments.
const mss = 1460

// Segment is one TCP segment of the first flight.
type Segment struct {
	Data   []byte
	Urgent bool // sent with the URG flag; Data is the one urgent byte
}

// Flight is the first flight of a connection as a path carries it: its segments, in the order they were sent.
type Flight struct{ Segments []Segment }

// Urgent says what a filter makes of an urgent byte.
type Urgent int

const (
	// OutOfBand: not in the stream, as at the end of a connection: what the server's TCP hands up, and what a
	// reader of a loopback socket gets unless it asks for the byte inline.
	OutOfBand Urgent = iota
	// Inline: ordinary payload, as for a filter that does not look at the flag. On the wire it is: the byte takes its
	// place in the sequence between the pieces around it.
	Inline
)

// pieces returns the payload of each segment as the filter reads them: urgent segments are left out or kept.
func (f Flight) pieces(u Urgent) [][]byte {
	var out [][]byte
	for _, s := range f.Segments {
		if !s.Urgent || u == Inline {
			out = append(out, s.Data)
		}
	}
	return out
}

func (f Flight) stream(u Urgent) []byte { return bytes.Join(f.pieces(u), nil) }

// A Predicate says whether the filter takes the connection for one to drop.
type Predicate func(Flight) bool

// An Action is what the filter does to a connection its predicate matched.
type Action int

const (
	// Silence holds the connection open and passes nothing on: the client waits for a reply that never comes.
	Silence Action = iota
	// Reset answers with a TCP reset.
	Reset
)

// Never matches nothing: a path that filters nothing.
var Never Predicate = func(Flight) bool { return false }

// NameInFirstSegment matches when a name is wholly inside the first TCP segment: a filter that looks at one packet.
func NameInFirstSegment(names ...string) Predicate {
	return func(f Flight) bool {
		return len(f.Segments) > 0 && !f.Segments[0].Urgent && containsName(f.Segments[0].Data, names)
	}
}

// NameInOneRecord matches when a name is wholly inside one TLS record of the reassembled stream: a filter that
// puts the TCP segments back together however many there are, but reads each TLS record on its own.
func NameInOneRecord(u Urgent, names ...string) Predicate {
	return func(f Flight) bool {
		s := f.stream(u)
		for len(s) >= 5 && s[0] == 0x16 && s[1] == 3 {
			n := int(s[3])<<8 | int(s[4])
			rec := s[5:]
			if len(rec) > n {
				rec = rec[:n]
			}
			if containsName(rec, names) {
				return true
			}
			if len(s) < 5+n {
				break
			}
			s = s[5+n:]
		}
		return false
	}
}

// minFirstRecord is the least a first record can hold for the next predicate to take it for a ClientHello: the
// handshake header, the version, the random and the length of the session id.
// ponytail: one guess for the whole class of filters that give up on a short first record; an exact bound only
// matters to a strategy that cuts the first record into pieces of 40 bytes or so.
const minFirstRecord = 4 + 2 + 32 + 1

// NameInFirstSegments matches when a name is in the handshake that the first n segments make together, TLS records
// put back together as well, and nothing past them is read: a filter that gives up after n packets. A first record
// too short to start a ClientHello ends the look at once.
func NameInFirstSegments(n int, u Urgent, names ...string) Predicate {
	return func(f Flight) bool {
		p := f.pieces(u)
		if len(p) > n {
			p = p[:n]
		}
		w := bytes.Join(p, nil)
		if len(w) < 5 || int(w[3])<<8|int(w[4]) < minFirstRecord {
			return false
		}
		return containsName(handshake(w), names)
	}
}

// NameByAddress matches every connection to a name, however its first flight is cut: a block on the address, which
// the filter knows the name stands for.
func NameByAddress(names ...string) Predicate {
	return func(f Flight) bool { return containsName(handshake(f.stream(OutOfBand)), names) }
}

// handshake puts the payloads of the TLS records at the start of s together.
func handshake(s []byte) []byte {
	var out []byte
	for len(s) >= 5 && s[0] == 0x16 && s[1] == 3 {
		n := int(s[3])<<8 | int(s[4])
		if len(s) < 5+n {
			return append(out, s[5:]...)
		}
		out = append(out, s[5:5+n]...)
		s = s[5+n:]
	}
	return out
}

func containsName(b []byte, names []string) bool {
	b = bytes.ToLower(b)
	for _, n := range names {
		if bytes.Contains(b, []byte(strings.ToLower(n))) {
			return true
		}
	}
	return false
}

// announced is what the client tells the filter about the connection it is about to open.
type announced struct {
	flight  Flight
	verdict chan Action // gets the action when the filter drops the connection
}

// Filter is the proxy. It listens on loopback and forwards what its predicate lets through to the server.
type Filter struct {
	ln       net.Listener
	upstream string
	pred     Predicate
	act      Action

	mu      sync.Mutex
	flights map[string]*announced // by the client's address
	conns   map[net.Conn]struct{}
	errs    []string
	wg      sync.WaitGroup
}

// New starts a filter in front of the server at upstream. It stops with the test.
func New(t testing.TB, upstream string, pred Predicate, act Action) *Filter {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &Filter{ln: ln, upstream: upstream, pred: pred, act: act, flights: map[string]*announced{}, conns: map[net.Conn]struct{}{}}
	f.wg.Add(1)
	go f.accept()
	t.Cleanup(func() {
		ln.Close()
		f.mu.Lock()
		for c := range f.conns {
			c.Close()
		}
		f.mu.Unlock()
		f.wg.Wait()
		for _, e := range f.errs {
			t.Error(e)
		}
	})
	return f
}

// Addr is where clients connect.
func (f *Filter) Addr() string { return f.ln.Addr().String() }

func (f *Filter) fail(format string, a ...any) {
	f.mu.Lock()
	f.errs = append(f.errs, "dpitest: "+fmt.Sprintf(format, a...))
	f.mu.Unlock()
}

func (f *Filter) accept() {
	defer f.wg.Done()
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		f.mu.Lock()
		f.conns[c] = struct{}{}
		f.mu.Unlock()
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			defer c.Close()
			f.handle(c)
		}()
	}
}

func (f *Filter) handle(c net.Conn) {
	c.SetDeadline(time.Now().Add(30 * time.Second))
	// The urgent byte is read as the payload it is on the wire, so that what arrives can be checked against the plan.
	if err := urgentInline(c.(*net.TCPConn)); err != nil {
		f.fail("urgent data: %v", err)
		return
	}
	flight, e, err := f.readFlight(c)
	if err != nil {
		return // the client went away before it said anything
	}
	if !f.pred(flight) {
		up, err := net.Dial("tcp", f.upstream)
		if err != nil {
			f.fail("upstream: %v", err)
			return
		}
		defer up.Close()
		// The server gets what its TCP would hand up: the urgent byte does not reach it.
		if _, err := up.Write(flight.stream(OutOfBand)); err != nil {
			return
		}
		go func() { io.Copy(up, c); up.Close() }()
		io.Copy(c, up)
		return
	}
	if e != nil {
		e.verdict <- f.act // before the reset, so that a client that sees it can tell why
	}
	if f.act == Reset {
		c.(*net.TCPConn).SetLinger(0)
		return
	}
	io.Copy(io.Discard, c)
}

// readFlight reads the client's first flight. With an announcement it reads as many bytes as the plan sends,
// urgent ones included, and checks them against it; without one the first TLS record is taken as one segment.
func (f *Filter) readFlight(c net.Conn) (Flight, *announced, error) {
	first := make([]byte, 1)
	if err := readFull(c, first); err != nil {
		return Flight{}, nil, err
	}
	f.mu.Lock()
	e := f.flights[c.RemoteAddr().String()]
	f.mu.Unlock()
	if e != nil {
		want := e.flight.stream(Inline)
		got := make([]byte, len(want))
		got[0] = first[0]
		if err := readFull(c, got[1:]); err != nil {
			return Flight{}, nil, err
		}
		if !bytes.Equal(got, want) {
			f.fail("the socket delivered %d bytes that are not the %d the plan sends", len(got), len(want))
		}
		return e.flight, e, nil
	}
	got := first
	if first[0] == 0x16 {
		hdr := make([]byte, 4)
		if err := readFull(c, hdr); err != nil {
			return Flight{}, nil, err
		}
		body := make([]byte, int(hdr[2])<<8|int(hdr[3]))
		if err := readFull(c, body); err != nil {
			return Flight{}, nil, err
		}
		got = append(append(got, hdr...), body...)
	}
	return Flight{[]Segment{{Data: got}}}, nil, nil
}

// readFull is io.ReadFull for a socket that has had urgent data. A reader that sleeps on such a socket on Linux
// can miss the wake-up for bytes that are already queued (seen under load, in both modes of urgent data); one that
// looks again every 20 ms finds them. It gives up after 30 s, as the connection does.
func readFull(c net.Conn, b []byte) error {
	end := time.Now().Add(30 * time.Second)
	defer c.SetReadDeadline(end)
	for len(b) > 0 {
		c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		n, err := c.Read(b)
		b = b[n:]
		var ne net.Error
		if err != nil && !(errors.As(err, &ne) && ne.Timeout()) {
			return err
		}
		if time.Now().After(end) {
			return os.ErrDeadlineExceeded
		}
	}
	return nil
}

// Outcome is what a client saw of a connection through the filter.
type Outcome string

const (
	Opened   Outcome = "opened"   // the handshake and a request went through
	Silenced Outcome = "silenced" // the filter held the connection and the client got nothing
	Resetted Outcome = "reset"    // the filter reset the connection
)

// Try makes a TLS connection through the filter, sending its first flight as strategy s says, and does a request.
// cfg gives the server name and the size of the ClientHello; the server's certificate is not checked. The error is
// for what neither the filter nor the server explains.
func (f *Filter) Try(s dpi.Strategy, cfg *tls.Config) (Outcome, error) {
	raw, err := net.DialTimeout("tcp", f.Addr(), 5*time.Second)
	if err != nil {
		return "", err
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(15 * time.Second))
	e := &announced{verdict: make(chan Action, 1)}
	key := raw.LocalAddr().String()
	defer func() {
		f.mu.Lock()
		delete(f.flights, key)
		f.mu.Unlock()
	}()
	c := cfg.Clone()
	c.InsecureSkipVerify = true
	c.NextProtos = []string{"http/1.1"}
	tc := tls.Client(&announcer{Conn: dpi.FirstWrite(raw.(*net.TCPConn), s), f: f, s: s, key: key, e: e}, c)
	done := make(chan error, 1)
	go func() { done <- request(tc) }()

	select {
	case err := <-done:
		select { // a reset can reach the client before the goroutine that sent it is scheduled again
		case a := <-e.verdict:
			if a == Reset && err != nil {
				return Resetted, nil
			}
		default:
		}
		if err != nil {
			return "", err
		}
		return Opened, nil
	case a := <-e.verdict:
		if a == Reset {
			if err := <-done; err == nil {
				return "", errors.New("the filter reset the connection and the request still went through")
			}
			return Resetted, nil
		}
		select {
		case err := <-done:
			return "", fmt.Errorf("the filter went silent and the client still got an answer (%v)", err)
		case <-time.After(100 * time.Millisecond): // the client has had its chance to hear something
		}
		raw.Close()
		<-done
		return Silenced, nil
	}
}

func request(tc *tls.Conn) error {
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

// announcer tells the filter how the first write is about to be cut, then lets the strategy's wrapper do it.
type announcer struct {
	net.Conn // dpi.FirstWrite of the connection
	f        *Filter
	s        dpi.Strategy
	key      string
	e        *announced
	done     bool
}

func (a *announcer) Write(b []byte) (int, error) {
	if !a.done {
		a.done = true
		for _, c := range a.s.Plan(b) {
			data := bytes.Clone(c.Data) // crypto/tls reuses its buffer once the write returns
			if c.OOB {
				a.e.flight.Segments = append(a.e.flight.Segments, Segment{Data: data, Urgent: true})
				continue
			}
			for d := data; len(d) > 0; {
				n := min(len(d), mss)
				a.e.flight.Segments = append(a.e.flight.Segments, Segment{Data: d[:n]})
				d = d[n:]
			}
		}
		a.f.mu.Lock()
		a.f.flights[a.key] = a.e
		a.f.mu.Unlock()
	}
	return a.Conn.Write(b)
}
