package dpi

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"math/rand"
	"net"
	"testing"
	"time"
)

// helloFor returns the first TLS record that crypto/tls writes when it starts a handshake for host.
func helloFor(t testing.TB, host string, pq bool) []byte {
	t.Helper()
	cfg := &tls.Config{ServerName: host, NextProtos: []string{"h2", "http/1.1"}}
	if pq {
		cfg.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}
	}
	cl, sv := net.Pipe()
	defer sv.Close()
	go func() {
		defer cl.Close()
		_ = tls.Client(cl, cfg).Handshake() // blocks on the pipe until the test has read the hello
	}()
	_ = sv.SetReadDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(sv, hdr); err != nil {
		t.Fatal(err)
	}
	b := append(hdr, make([]byte, int(hdr[3])<<8|int(hdr[4]))...)
	if _, err := io.ReadFull(sv, b[5:]); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseClientHello(t *testing.T) {
	for _, tc := range []struct {
		host string
		mid  int // offset of the cut inside the name
	}{
		{"www.youtube.com", 7},
		{"ya.ru", 1},
		{"discord.com", 3},
		{"cdn.discordapp.com", 9},
		{"bbc.co.uk", 1},
		{"localhost", 4},
	} {
		for _, pq := range []bool{false, true} {
			b := helloFor(t, tc.host, pq)
			if pq && len(b) < 1200 {
				t.Fatalf("%s: post-quantum hello is only %d bytes, the key share is missing", tc.host, len(b))
			}
			h, err := ParseClientHello(b)
			if err != nil {
				t.Fatalf("%s pq=%v: %v", tc.host, pq, err)
			}
			if h.ServerName != tc.host || string(b[h.HostStart:h.HostEnd]) != tc.host {
				t.Errorf("%s: name %q, bytes %q", tc.host, h.ServerName, b[h.HostStart:h.HostEnd])
			}
			if h.MidSLD-h.HostStart != tc.mid {
				t.Errorf("%s: midsld at %d, want %d", tc.host, h.MidSLD-h.HostStart, tc.mid)
			}
			if b[h.SNIExt] != 0 || b[h.SNIExt+1] != 0 || h.SNIExt >= h.HostStart || h.Rec0End != len(b) {
				t.Errorf("%s: sni ext at %d, record end %d of %d", tc.host, h.SNIExt, h.Rec0End, len(b))
			}
		}
	}
}

// reframe cuts the handshake of a one-record hello into records with at most n payload bytes each.
func reframe(b []byte, n int) []byte {
	var out []byte
	for p := b[5:]; len(p) > 0; {
		k := min(n, len(p))
		out = append(out, b[0], b[1], b[2], byte(k>>8), byte(k))
		out = append(out, p[:k]...)
		p = p[k:]
	}
	return out
}

func TestParseSeveralRecords(t *testing.T) {
	const host = "www.youtube.com"
	b := helloFor(t, host, true)
	found := 0
	for n := 16; n < 400; n += 7 {
		r := reframe(b, n)
		h, err := ParseClientHello(r)
		if errors.Is(err, ErrNotClientHello) {
			continue // the name straddles a record header in this framing: refused on purpose
		}
		if err != nil || string(r[h.HostStart:h.HostEnd]) != host || h.Rec0End != 5+n {
			t.Fatalf("records of %d: %+v %v", n, h, err)
		}
		found++
	}
	if found < 10 {
		t.Fatalf("only %d framings parsed", found)
	}
}

func TestParseGarbage(t *testing.T) {
	good := helloFor(t, "www.youtube.com", true)
	// every prefix, also with the handshake spread over several records
	for _, b := range [][]byte{good, reframe(good, 50)} {
		for i := 0; i <= len(b); i++ {
			if h, err := ParseClientHello(b[:i]); err == nil && string(b[h.HostStart:h.HostEnd]) != h.ServerName {
				t.Fatalf("prefix %d: bad offsets %+v", i, h)
			}
		}
	}
	rnd := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		b := append([]byte(nil), good...)
		for j := rnd.Intn(6) + 1; j > 0; j-- {
			b[rnd.Intn(len(b))] = byte(rnd.Intn(256))
		}
		if h, err := ParseClientHello(b); err == nil && (h.HostStart < 0 || h.HostEnd > len(b) || h.HostStart >= h.HostEnd || h.MidSLD < h.HostStart || h.MidSLD > h.HostEnd) {
			t.Fatalf("bad offsets %+v", h)
		}
	}
	for _, b := range [][]byte{nil, {0x16}, {0x16, 3, 1, 0, 0}, bytes.Repeat([]byte{0x16, 3, 3, 0xff, 0xff}, 4), bytes.Repeat([]byte{0xff}, 100)} {
		if _, err := ParseClientHello(b); err == nil {
			t.Errorf("%x parsed", b)
		}
	}
}
