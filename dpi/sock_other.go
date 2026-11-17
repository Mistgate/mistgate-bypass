//go:build !windows && !unix

package dpi

import (
	"errors"
	"net"
	"syscall"
)

// Socket options are implemented for Windows and Unix systems; elsewhere plans that need them fail early.
func setTTL(syscall.Conn, bool, int) error   { return errors.ErrUnsupported }
func getTTL(syscall.Conn, bool) (int, error) { return 0, errors.ErrUnsupported }
func sendOOB(*net.TCPConn, []byte) error     { return errors.ErrUnsupported }
