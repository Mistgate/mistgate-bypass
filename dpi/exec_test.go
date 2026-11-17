package dpi

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Every strategy must leave a working TLS stream: a local TLS server completes the handshake through FirstWrite
// and answers a request. Strategies that need a socket option this system lacks are skipped, not failed.
func TestFirstWriteHandshake(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "pong") }))
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	for _, s := range Ladder() {
		t.Run(s.Name, func(t *testing.T) {
			raw, err := net.DialTimeout("tcp", srv.Listener.Addr().String(), 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			raw.SetDeadline(time.Now().Add(10 * time.Second))
			tc := tls.Client(FirstWrite(raw.(*net.TCPConn), s), &tls.Config{ServerName: "example.com", RootCAs: roots, NextProtos: []string{"http/1.1"}})
			start := time.Now()
			if err := tc.Handshake(); err != nil {
				if errors.Is(err, errors.ErrUnsupported) {
					t.Skip("not supported on this system")
				}
				t.Fatalf("handshake: %v", err)
			}
			t.Logf("handshake in %v", time.Since(start).Round(time.Millisecond))
			io.WriteString(tc, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
			body, _ := io.ReadAll(tc)
			if !bytes.HasSuffix(body, []byte("pong")) {
				t.Fatalf("response %q", body)
			}
		})
	}
}

// A raw listener sees what the strategy puts on the stream: for every cut the pieces glue back into the original,
// and tlsrec arrives as two records. Where the cut lands in TCP segments is not observable on loopback (the
// reader may get both pieces in one read), so it is not asserted.
func TestPlansOnTheWire(t *testing.T) {
	hello := helloFor(t, "www.youtube.com", true)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	for _, s := range Ladder() {
		t.Run(s.Name, func(t *testing.T) {
			plan := s.Plan(hello)
			want, _ := join(plan)
			got := make(chan []byte, 1)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					got <- nil
					return
				}
				defer c.Close()
				c.SetReadDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, len(want))
				n, _ := io.ReadFull(c, buf)
				got <- buf[:n]
			}()
			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			start := time.Now()
			if err := Execute(c.(*net.TCPConn), plan); err != nil {
				if errors.Is(err, errors.ErrUnsupported) {
					t.Skip("not supported on this system")
				}
				t.Fatal(err)
			}
			if b := <-got; !bytes.Equal(b, want) {
				t.Fatalf("received %d bytes, want %d (equal=%v)", len(b), len(want), bytes.Equal(b, want))
			}
			// Delivery time: a low-TTL piece that loopback does not drop arrives at once; on a real path it would
			// come only after a retransmission timeout (hundreds of milliseconds).
			t.Logf("delivered in %v", time.Since(start).Round(time.Millisecond))
		})
	}
}

func TestFirstWriteOnlyFirst(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, _ := ln.Accept()
		defer c.Close()
		b, _ := io.ReadAll(c)
		got <- b
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s, _ := ByName("tlsrec")
	c := FirstWrite(raw.(*net.TCPConn), s)
	hello := helloFor(t, "ya.ru", false)
	for _, w := range [][]byte{hello, hello} {
		if n, err := c.Write(w); err != nil || n != len(w) {
			t.Fatalf("write: %d %v", n, err)
		}
	}
	c.Close()
	// The first write grew by one record header; the second is untouched.
	if b := <-got; len(b) != 2*len(hello)+5 || !bytes.Equal(b[len(b)-len(hello):], hello) {
		t.Fatalf("got %d bytes", len(b))
	}
}
