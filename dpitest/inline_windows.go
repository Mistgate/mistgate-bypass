package dpitest

import (
	"net"
	"syscall"
)

// soOOBInline is SO_OOBINLINE of Winsock, which package syscall does not name.
const soOOBInline = 0x100

// urgentInline makes the socket deliver urgent data in the stream, where it sits on the wire.
func urgentInline(c *net.TCPConn) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var ferr error
	if err := rc.Control(func(fd uintptr) {
		ferr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, soOOBInline, 1)
	}); err != nil {
		return err
	}
	return ferr
}
