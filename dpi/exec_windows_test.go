//go:build windows

package dpi

import (
	"io"
	"net"
	"testing"
)

// disorder-ttl lowers the TTL for one piece; the connection must get its own value back afterwards.
func TestExecuteRestoresTTL(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, _ := ln.Accept()
		io.Copy(io.Discard, c)
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tc := c.(*net.TCPConn)
	before, err := getTTL(tc, false)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := ByName("disorder-ttl")
	if err := Execute(tc, s.Plan(helloFor(t, "www.youtube.com", false))); err != nil {
		t.Fatal(err)
	}
	if after, err := getTTL(tc, false); err != nil || after != before {
		t.Fatalf("TTL %d before, %d after (%v)", before, after, err)
	}
}
