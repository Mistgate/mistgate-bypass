package flow

import (
	"context"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/mistgate/mistgate-bypass/dpitest"
)

// The hot path is a connection to a name that works as it is: the ordinary connection is answered at once. The
// ladder must cost it nothing that the connection does not cost anyway: no goroutine, and no allocation but the
// deadline of the dial and the five bytes handed to the caller.

// echoTLS is a server that answers every connection with the start of a TLS record, and reads nothing: enough for
// the ladder, and it starts no goroutine per connection, so that a count of goroutines or allocations is not
// disturbed by it.
func echoTLS(tb testing.TB) (dial DialFunc, hello []byte) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	var (
		mu    sync.Mutex
		conns []net.Conn
		wg    sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte{0x16, 3, 3, 0, 4, 2, 0, 0, 0})
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	tb.Cleanup(func() {
		ln.Close()
		wg.Wait()
		for _, c := range conns {
			c.Close()
		}
	})
	dial = func(ctx context.Context) (*net.TCPConn, error) {
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", ln.Addr().String())
		if err != nil {
			return nil, err
		}
		return c.(*net.TCPConn), nil
	}
	return dial, []byte{0x16, 3, 1, 0, 4, 1, 0, 0, 0}
}

func TestHotPathStartsNoGoroutine(t *testing.T) {
	dial, hello := echoTLS(t)
	f := New(Config{})
	// A name that is a part of a service, whose result is known: the one lookup, no write.
	if res, err := f.Open(ctx, "www.youtube.com", hello, dial); err != nil {
		t.Fatal(err)
	} else {
		res.Conn.Close()
	}
	before := runtime.NumGoroutine()
	var during int
	counting := func(ctx context.Context) (*net.TCPConn, error) {
		c, err := dial(ctx)
		during = runtime.NumGoroutine()
		return c, err
	}
	res, err := f.Open(ctx, "www.youtube.com", hello, counting)
	if err != nil {
		t.Fatal(err)
	}
	after := runtime.NumGoroutine()
	res.Conn.Close()
	if res.Strategy != 1 || during != before || after != before {
		t.Errorf("goroutines: %d before, %d in the dial, %d after the open", before, during, after)
	}
}

// The ladder's own cost, as the difference of allocations between opening through Open and doing the same by hand:
// dial, write the ClientHello, read the first bytes. What it is made of: the context with a deadline that bounds
// the dial (the timer and the context), and the five bytes that are handed back.
func TestHotPathAllocations(t *testing.T) {
	dial, hello := echoTLS(t)
	f := New(Config{})
	open := func(name string) func() {
		return func() {
			res, err := f.Open(ctx, name, hello, dial)
			if err != nil {
				t.Fatal(err)
			}
			res.Conn.Close()
		}
	}
	byHand := func() {
		dctx, cancel := context.WithDeadline(ctx, time.Now().Add(8*time.Second))
		c, err := dial(dctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		c.Write(hello)
		c.SetReadDeadline(time.Now().Add(time.Second))
		c.Read(make([]byte, 5))
		c.Close()
	}
	base := testing.AllocsPerRun(200, byHand)
	stranger := testing.AllocsPerRun(200, open("docs.example.net"))
	service := testing.AllocsPerRun(200, open("www.youtube.com"))
	t.Logf("allocations per connection: by hand, with the deadline %.1f; Open for a stranger %.1f; Open for a service part %.1f", base, stranger, service)
	if stranger > base+2 || service > base+2 {
		t.Errorf("the ladder costs %.1f and %.1f allocations over the %.1f of the connection", stranger-base, service-base, base)
	}
}

func BenchmarkOpenHotPath(b *testing.B) {
	dial, hello := echoTLS(b)
	f := New(Config{})
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		res, err := f.Open(ctx, "docs.example.net", hello, dial)
		if err != nil {
			b.Fatal(err)
		}
		res.Conn.Close()
	}
}

// The same connection by hand, for the comparison.
func BenchmarkConnectByHand(b *testing.B) {
	dial, hello := echoTLS(b)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		dctx, cancel := context.WithDeadline(ctx, time.Now().Add(8*time.Second))
		c, err := dial(dctx)
		cancel()
		if err != nil {
			b.Fatal(err)
		}
		c.Write(hello)
		c.SetReadDeadline(time.Now().Add(time.Second))
		c.Read(make([]byte, 5))
		c.Close()
	}
}

// A ladder that is not needed is not started either: on a filtered network the remembered strategy goes first, and
// the connections that open at once make a strategy and a connection each, nothing more.
func TestRememberedStrategyOpensWithOneConnection(t *testing.T) {
	e := newEnv(t, dpitest.NameInOneRecord(dpitest.OutOfBand, "example.org"), dpitest.Silence, "ru")
	if _, err := e.fetch(ctx, "video.example.org"); err != nil {
		t.Fatal(err)
	}
	e.reset()
	for range 5 {
		if s, err := e.fetch(ctx, "video.example.org"); err != nil || s != 6 {
			t.Fatalf("%d %v", s, err)
		}
	}
	if n := e.count(6); n != 5 || len(e.started()) != 5 {
		t.Errorf("started %v", e.started())
	}
}

// What Open adds to the connection, without the connection: the match of the name to the set and the one look
// in memory, for a name of a service whose result is known and for a stranger.
func BenchmarkBookkeeping(b *testing.B) {
	f := New(Config{})
	set := f.set()
	for _, name := range []string{"rr3---sn-abcd.googlevideo.com", "docs.example.net"} {
		b.Run(name[:2], func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				t := target{name: name}
				if m, ok := set.Match(name); ok {
					t.part = partKey{m.Service.ID, m.Part.ID}
					set.Candidates("ru", m)
				} else {
					set.Site("ru")
				}
				f.mem.plan(t)
			}
		})
	}
}
