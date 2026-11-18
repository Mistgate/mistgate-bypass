//go:build unix

package dpitest

import "syscall"

// urgentInline makes a socket deliver urgent data in the stream, where it sits on the wire. It is for the listening
// socket, before it is bound: accepted sockets inherit it, so no connection is ever without it, however soon its
// client writes.
func urgentInline(_, _ string, c syscall.RawConn) error {
	var ferr error
	if err := c.Control(func(fd uintptr) { ferr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_OOBINLINE, 1) }); err != nil {
		return err
	}
	return ferr
}
