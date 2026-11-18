//go:build unix

package dpitest

import (
	"net"
	"syscall"
)

// urgentInline makes the socket deliver urgent data in the stream, where it sits on the wire.
func urgentInline(c *net.TCPConn) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var ferr error
	if err := rc.Control(func(fd uintptr) { ferr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_OOBINLINE, 1) }); err != nil {
		return err
	}
	return ferr
}
