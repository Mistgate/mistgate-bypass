//go:build windows

package dpi

import (
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

func control(sc syscall.Conn, f func(windows.Handle) error) error {
	rc, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	var ferr error
	if err := rc.Control(func(fd uintptr) { ferr = f(windows.Handle(fd)) }); err != nil {
		return err
	}
	return ferr
}

func ttlOpt(v6 bool) (level, opt int) {
	if v6 {
		return windows.IPPROTO_IPV6, windows.IPV6_UNICAST_HOPS
	}
	return windows.IPPROTO_IP, windows.IP_TTL
}

func setTTL(sc syscall.Conn, v6 bool, ttl int) error {
	level, opt := ttlOpt(v6)
	return control(sc, func(h windows.Handle) error { return windows.SetsockoptInt(h, level, opt, ttl) })
}

func getTTL(sc syscall.Conn, v6 bool) (ttl int, err error) {
	level, opt := ttlOpt(v6)
	err = control(sc, func(h windows.Handle) (e error) { ttl, e = windows.GetsockoptInt(h, level, opt); return })
	return
}

// sendOOB sends urgent data. Go's net package has no way to pass MSG_OOB, and WSASend takes it in its flags
// (windows.MSG_OOB); with no OVERLAPPED it behaves as a plain blocking send, which for one byte returns at once.
func sendOOB(c *net.TCPConn, b []byte) error {
	return control(c, func(h windows.Handle) error {
		buf := windows.WSABuf{Len: uint32(len(b)), Buf: &b[0]}
		var sent uint32
		return windows.WSASend(h, &buf, 1, &sent, windows.MSG_OOB, nil, nil)
	})
}
