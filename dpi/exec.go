package dpi

import (
	"net"
	"time"
)

// Execute sends a plan on a connected TCP socket: one write per chunk, no coalescing, with the pauses, TTL and
// urgent-data flags the plan asks for. The connection's own TTL is put back before it returns.
func Execute(c *net.TCPConn, p Plan) (err error) {
	// Without this the stack may glue small pieces together and the cut would never reach the wire.
	if err := c.SetNoDelay(true); err != nil {
		return err
	}
	v6 := isV6(c.RemoteAddr())
	var saved int
	lowered := false
	defer func() {
		if lowered {
			if e := setTTL(c, v6, saved); err == nil {
				err = e
			}
		}
	}()
	for _, ch := range p {
		if ch.Delay > 0 {
			time.Sleep(ch.Delay)
		}
		switch {
		case ch.TTL != 0:
			if !lowered {
				if saved, err = getTTL(c, v6); err != nil {
					return err
				}
				lowered = true
			}
			if err = setTTL(c, v6, ch.TTL); err != nil {
				return err
			}
		case lowered:
			if err = setTTL(c, v6, saved); err != nil {
				return err
			}
			lowered = false
		}
		if ch.OOB {
			err = sendOOB(c, ch.Data)
		} else {
			_, err = c.Write(ch.Data)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func isV6(a net.Addr) bool {
	t, ok := a.(*net.TCPAddr)
	if !ok {
		u, ok := a.(*net.UDPAddr)
		return ok && u.IP.To4() == nil
	}
	return t.IP.To4() == nil
}

// FirstWrite wraps a TCP connection so that its first Write, which for crypto/tls is the ClientHello, goes out as
// the strategy's plan. Everything after it is written as it is, so a tls.Client over the wrapper completes an
// ordinary handshake. Only the first Write is planned: a ClientHello larger than one TLS record comes from
// crypto/tls as several writes, and only the first record is cut.
func FirstWrite(c *net.TCPConn, s Strategy) net.Conn {
	return &firstWrite{Conn: c, tcp: c, s: s}
}

type firstWrite struct {
	net.Conn // not the *TCPConn itself: its ReadFrom would bypass Write
	tcp      *net.TCPConn
	s        Strategy
	done     bool
}

func (f *firstWrite) Write(b []byte) (int, error) {
	if f.done {
		return f.Conn.Write(b)
	}
	f.done = true
	if err := Execute(f.tcp, f.s.Plan(b)); err != nil {
		return 0, err
	}
	return len(b), nil
}
