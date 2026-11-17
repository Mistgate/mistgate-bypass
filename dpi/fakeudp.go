package dpi

import (
	"net"
	"sync"
)

// FakeUDP wraps a UDP socket so that, before the first datagram, it sends Count decoys with a low TTL: they
// reach an inspecting device on the path and expire before the server. Then the TTL goes back and the real
// datagram follows.
type FakeUDP struct {
	net.PacketConn // not the *UDPConn itself: its ReadMsgUDP/WriteMsgUDP would bypass WriteTo

	udp   *net.UDPConn
	count int
	ttl   int
	fake  []byte

	mu   sync.Mutex
	done bool
}

// NewFakeUDP wraps c. A TTL of 0 leaves the TTL alone (the decoys then do reach the server). Use a socket of one
// family ("udp4" or "udp6"), since the TTL option is chosen from the local address.
func NewFakeUDP(c *net.UDPConn, count, ttl int, fake []byte) *FakeUDP {
	return &FakeUDP{PacketConn: c, udp: c, count: count, ttl: ttl, fake: fake}
}

func (f *FakeUDP) WriteTo(p []byte, addr net.Addr) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.done {
		f.done = true
		if err := f.sendFakes(addr); err != nil {
			return 0, err
		}
	}
	return f.PacketConn.WriteTo(p, addr)
}

func (f *FakeUDP) sendFakes(addr net.Addr) (err error) {
	if f.count <= 0 || len(f.fake) == 0 {
		return nil
	}
	if f.ttl != 0 {
		v6 := isV6(f.udp.LocalAddr())
		saved, err := getTTL(f.udp, v6)
		if err != nil {
			return err
		}
		if err := setTTL(f.udp, v6, f.ttl); err != nil {
			return err
		}
		defer func() {
			if e := setTTL(f.udp, v6, saved); err == nil {
				err = e
			}
		}()
	}
	for i := 0; i < f.count; i++ {
		if _, err = f.PacketConn.WriteTo(f.fake, addr); err != nil {
			return err
		}
	}
	return nil
}
