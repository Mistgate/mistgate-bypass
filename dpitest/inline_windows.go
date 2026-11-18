package dpitest

import (
	"syscall"
)

// soOOBInline is SO_OOBINLINE of Winsock, which package syscall does not name.
const soOOBInline = 0x100

// urgentInline makes a socket deliver urgent data in the stream, where it sits on the wire. It is for the listening
// socket, before it is bound: accepted sockets inherit it. Setting it on an accepted socket is too late, because the
// client may have written its first flight already, and Winsock refuses (WSAEINVAL) to switch a socket to inline
// once urgent data is queued on it.
func urgentInline(_, _ string, c syscall.RawConn) error {
	var ferr error
	if err := c.Control(func(fd uintptr) {
		ferr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, soOOBInline, 1)
	}); err != nil {
		return err
	}
	return ferr
}
