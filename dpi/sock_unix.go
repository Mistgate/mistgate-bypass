//go:build unix

package dpi

import (
	"net"
	"syscall"
)

func ttlOpt(v6 bool) (level, opt int) {
	if v6 {
		return syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS
	}
	return syscall.IPPROTO_IP, syscall.IP_TTL
}

func setTTL(sc syscall.Conn, v6 bool, ttl int) error {
	rc, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	level, opt := ttlOpt(v6)
	var ferr error
	if err := rc.Control(func(fd uintptr) { ferr = syscall.SetsockoptInt(int(fd), level, opt, ttl) }); err != nil {
		return err
	}
	return ferr
}

func getTTL(sc syscall.Conn, v6 bool) (ttl int, err error) {
	rc, err := sc.SyscallConn()
	if err != nil {
		return 0, err
	}
	level, opt := ttlOpt(v6)
	var ferr error
	if err := rc.Control(func(fd uintptr) { ttl, ferr = syscall.GetsockoptInt(int(fd), level, opt) }); err != nil {
		return 0, err
	}
	return ttl, ferr
}

// sendOOB sends urgent data. The net package cannot pass MSG_OOB; the socket is non-blocking, so the send goes
// through the runtime's poller and is tried again when the socket is writable.
func sendOOB(c *net.TCPConn, b []byte) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var ferr error
	if err := rc.Write(func(fd uintptr) bool {
		ferr = syscall.Sendto(int(fd), b, syscall.MSG_OOB, nil)
		return ferr != syscall.EAGAIN
	}); err != nil {
		return err
	}
	return ferr
}
