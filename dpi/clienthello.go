// Package dpi holds connection strategies for networks that inspect the first packet of a TLS or QUIC
// connection: how to find the server name in a ClientHello, how to cut the first write into pieces, and the thin
// socket layer that sends those pieces. The parsing and planning are plain byte work and build everywhere; only
// the socket options (TTL, urgent data) are platform code.
package dpi

import (
	"errors"
	"strings"
)

// ErrNotClientHello is returned for anything that is not a TLS ClientHello carrying a server name.
var ErrNotClientHello = errors.New("dpi: not a TLS ClientHello with a server name")

// Hello says where the server name sits inside the bytes given to ParseClientHello. All offsets count from the
// first byte of the input, record headers included, so they can be used to cut the input directly.
type Hello struct {
	ServerName string
	HostStart  int // first byte of the host name
	HostEnd    int // one past its last byte
	MidSLD     int // the middle of the second-level label ("youtube" in www.youtube.com)
	SNIExt     int // first byte of the server_name extension header
	Rec0End    int // one past the end of the first TLS record (may exceed the input when it is cut short)
}

// ParseClientHello reads a ClientHello from the start of b. The handshake message may span several TLS records
// and b may end early; the server name only has to be inside the bytes present. It never panics on garbage.
func ParseClientHello(b []byte) (Hello, error) {
	var h Hello
	// Glue the record payloads together, remembering where each piece came from.
	type seg struct{ hs, orig, n int }
	var segs []seg
	var hs []byte
	for pos := 0; pos+5 <= len(b) && b[pos] == 0x16 && b[pos+1] == 3; {
		n := int(b[pos+3])<<8 | int(b[pos+4])
		if pos == 0 {
			h.Rec0End = 5 + n
		}
		frag := b[pos+5:]
		if len(frag) > n {
			frag = frag[:n]
		}
		segs = append(segs, seg{len(hs), pos + 5, len(frag)})
		hs = append(hs, frag...)
		if len(frag) < n || (len(hs) >= 4 && len(hs) >= 4+int(hs[1])<<16+int(hs[2])<<8+int(hs[3])) {
			break
		}
		pos += 5 + n
	}
	if len(hs) < 4 || hs[0] != 1 {
		return h, ErrNotClientHello
	}
	// orig maps an offset in the glued handshake back to the input.
	orig := func(off int) int {
		for _, s := range segs {
			if off >= s.hs && off < s.hs+s.n {
				return s.orig + off - s.hs
			}
		}
		return -1
	}
	// A cursor over hs that fails softly: every read is bounds-checked.
	p := 4 + 2 + 32
	skip := func(lenBytes int) bool { // skip a vector with a 1- or 2-byte length prefix
		if p+lenBytes > len(hs) {
			return false
		}
		n := int(hs[p])
		if lenBytes == 2 {
			n = n<<8 | int(hs[p+1])
		}
		p += lenBytes + n
		return p <= len(hs)
	}
	if !skip(1) || !skip(2) || !skip(1) || p+2 > len(hs) { // session id, cipher suites, compression
		return h, ErrNotClientHello
	}
	extEnd := p + 2 + (int(hs[p])<<8 | int(hs[p+1]))
	p += 2
	if extEnd > len(hs) {
		extEnd = len(hs) // truncated input: look at what is there
	}
	for p+4 <= extEnd {
		typ, n := int(hs[p])<<8|int(hs[p+1]), int(hs[p+2])<<8|int(hs[p+3])
		if typ != 0 {
			p += 4 + n
			continue
		}
		// server_name: list length(2), then name_type(1) name_len(2) name
		d := p + 4
		if d+5 > len(hs) || hs[d+2] != 0 {
			return h, ErrNotClientHello
		}
		nl := int(hs[d+3])<<8 | int(hs[d+4])
		start, end := d+5, d+5+nl
		if nl == 0 || end > len(hs) {
			return h, ErrNotClientHello
		}
		hostStart, last, ext := orig(start), orig(end-1), orig(p)
		if hostStart < 0 || last < 0 || ext < 0 || last-hostStart != nl-1 {
			return h, ErrNotClientHello // the name straddles a record header: nothing sensible to cut
		}
		h.ServerName = string(hs[start:end])
		h.HostStart, h.HostEnd, h.SNIExt = hostStart, last+1, ext
		h.MidSLD = hostStart + midSLD(h.ServerName)
		return h, nil
	}
	return h, ErrNotClientHello
}

// midSLD returns the offset inside host of the middle of its second-level label.
// ponytail: second-level suffixes are guessed from a short list (co.uk, com.tr, ...), not the public suffix list;
// a miss only moves the cut to another spot inside the name, which is still a cut inside the name.
func midSLD(host string) int {
	labels := strings.Split(host, ".")
	i := len(labels) - 2
	if i > 0 {
		switch labels[i] {
		case "co", "com", "net", "org", "gov", "edu", "ac":
			i--
		}
	}
	if i < 0 { // a single label: cut in the middle of the whole string
		return len(host) / 2
	}
	off := 0
	for _, l := range labels[:i] {
		off += len(l) + 1
	}
	return off + len(labels[i])/2
}
