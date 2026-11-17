package dpi

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

func fakeUDPRun(t *testing.T, count, ttl int) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cl, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	fake := bytes.Repeat([]byte{0}, 1200)
	f := NewFakeUDP(cl, count, ttl, fake)
	real1, real2 := []byte("real one"), []byte("real two")
	for _, p := range [][]byte{real1, real2} {
		if _, err := f.WriteTo(p, srv.LocalAddr()); err != nil {
			if errors.Is(err, errors.ErrUnsupported) {
				t.Skip("not supported on this system")
			}
			t.Fatal(err)
		}
	}
	srv.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2000)
	for i := 0; i < count+2; i++ {
		n, _, err := srv.ReadFrom(buf)
		if err != nil {
			t.Fatalf("datagram %d: %v", i, err)
		}
		want := fake
		switch i {
		case count:
			want = real1
		case count + 1:
			want = real2
		}
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("datagram %d: %d bytes", i, n)
		}
	}
	// The decoys are sent once, before the first datagram only.
	srv.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err := srv.ReadFrom(buf); err == nil {
		t.Fatal("an extra datagram")
	}
	if ttl != 0 {
		if got, err := getTTL(cl, false); err != nil || got == ttl {
			t.Fatalf("TTL after the decoys: %d %v", got, err)
		}
	}
}

func TestFakeUDP(t *testing.T) { fakeUDPRun(t, 4, 0) }

// Loopback has no router to expire a packet, so the decoys with TTL 3 are delivered here like the rest; that the
// TTL really drops them on a real path cannot be shown on this interface. What is checked: the option is set and
// put back.
func TestFakeUDPWithTTL(t *testing.T) { fakeUDPRun(t, 3, 3) }
