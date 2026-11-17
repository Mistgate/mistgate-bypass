package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/mistgate/mistgate-bypass/dpi"
)

// The messenger's data centres are checked with the first step of its key exchange: an unencrypted req_pq_multi
// that any server answers with resPQ. Receiving a well-formed resPQ for our nonce proves that the transport
// works end to end, without any account or key. Transport is "abridged"; the obfuscated variants wrap it in the
// 64-byte random header and AES-256-CTR streams of the "obfuscated2" transport.

var mtVariants = []string{"abridged", "obfs", "obfs-split1", "obfs-split1-delay"}

// MTResult is one attempt at one data centre.
type MTResult struct {
	DC      string `json:"dc"`
	Variant string `json:"variant"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail,omitempty"`
	Ms      int64  `json:"ms,omitempty"`
}

const (
	reqPQMulti = 0xbe7e8ef1
	resPQ      = 0x05162463
)

// reqPQ builds the unencrypted message: auth_key_id 0, message id, length, constructor, nonce.
func reqPQ(nonce [16]byte) []byte {
	m := make([]byte, 40)
	binary.LittleEndian.PutUint64(m[8:], uint64(time.Now().Unix())<<32) // client ids are multiples of 4
	binary.LittleEndian.PutUint32(m[16:], 20)
	binary.LittleEndian.PutUint32(m[20:], reqPQMulti)
	copy(m[24:], nonce[:])
	return m
}

// abridged frames a message: its length in 4-byte words, then the message.
func abridged(m []byte) []byte {
	return append([]byte{byte(len(m) / 4)}, m...)
}

// obfs is the obfuscated2 state of one connection.
type obfs struct {
	enc, dec cipher.Stream
}

// newObfs returns the 64-byte first packet to send and the streams for everything after it.
func newObfs(dc int) (init []byte, o *obfs, err error) {
	var h [64]byte
	for {
		if _, err = rand.Read(h[:]); err != nil {
			return
		}
		first, second := binary.LittleEndian.Uint32(h[0:]), binary.LittleEndian.Uint32(h[4:])
		// A header must not look like another protocol's first bytes.
		switch first {
		case 0x44414548, 0x54534f50, 0x20544547, 0x4954504f, 0xdddddddd, 0xeeeeeeee, 0x02010316:
			continue
		}
		if h[0] != 0xef && second != 0 {
			break
		}
	}
	binary.LittleEndian.PutUint32(h[56:], 0xefefefef) // abridged inside
	binary.LittleEndian.PutUint16(h[60:], uint16(dc))
	rev := make([]byte, 48)
	for i := range rev {
		rev[i] = h[8+47-i]
	}
	if o, err = newObfsStreams(h[8:40], h[40:56], rev[:32], rev[32:48]); err != nil {
		return
	}
	// Only the last 8 bytes of the header go out encrypted; the first 56 are the key material in the clear.
	var e [64]byte
	o.enc.XORKeyStream(e[:], h[:])
	copy(h[56:], e[56:])
	return h[:], o, nil
}

func newObfsStreams(encKey, encIV, decKey, decIV []byte) (*obfs, error) {
	ec, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	dc, err := aes.NewCipher(decKey)
	if err != nil {
		return nil, err
	}
	return &obfs{cipher.NewCTR(ec, encIV), cipher.NewCTR(dc, decIV)}, nil
}

// mtOnce runs one variant against one address.
func (p *prober) mtOnce(ctx context.Context, dcName, addr, variant string, dcNum int) MTResult {
	r := MTResult{DC: dcName, Variant: variant}
	start := time.Now()
	defer func() { r.Ms = time.Since(start).Milliseconds() }()
	conn, err := (&net.Dialer{Timeout: p.dial}).DialContext(ctx, "tcp4", addr)
	if err != nil {
		r.Outcome, r.Detail = classify(err)
		if r.Outcome == outSilence {
			r.Outcome = outConnTimeout
		}
		return r
	}
	defer conn.Close()
	tc := conn.(*net.TCPConn)
	_ = tc.SetDeadline(time.Now().Add(p.mt))

	var nonce [16]byte
	rand.Read(nonce[:])
	msg := abridged(reqPQ(nonce))
	var plan dpi.Plan
	var o *obfs
	if variant == "abridged" {
		plan = dpi.Plan{{Data: append([]byte{0xef}, msg...)}}
	} else {
		var first []byte
		if first, o, err = newObfs(dcNum); err != nil {
			r.Outcome, r.Detail = outOther, err.Error()
			return r
		}
		ct := make([]byte, len(msg))
		o.enc.XORKeyStream(ct, msg)
		all := append(first, ct...)
		switch variant {
		case "obfs":
			plan = dpi.Plan{{Data: all}}
		default:
			plan = dpi.Plan{{Data: all[:1]}, {Data: all[1:]}}
			if variant == "obfs-split1-delay" {
				plan[1].Delay = 100 * time.Millisecond
			}
		}
	}
	if err := dpi.Execute(tc, plan); err != nil {
		r.Outcome, r.Detail = classify(err)
		return r
	}

	// The answer is one abridged packet: a length byte (in 4-byte words; 0x7f announces a 3-byte length), then
	// for resPQ auth_key_id, message id, length, constructor and our nonce. A 4-byte payload is a transport
	// error code instead.
	buf := make([]byte, 0, 256)
	for {
		if n, hdr := packetSize(buf); n > 0 && len(buf) >= hdr+n {
			break
		}
		var b [256]byte
		n, err := tc.Read(b[:])
		if n > 0 {
			if o != nil {
				o.dec.XORKeyStream(b[:n], b[:n])
			}
			buf = append(buf, b[:n]...)
		}
		if err != nil {
			if len(buf) == 0 {
				r.Outcome, r.Detail = classify(err)
			} else {
				r.Outcome, r.Detail = outOther, fmt.Sprintf("%d bytes, then %s", len(buf), scrub(err.Error()))
			}
			return r
		}
	}
	size, hdr := packetSize(buf)
	m := buf[hdr : hdr+size]
	switch {
	case size == 4:
		r.Outcome, r.Detail = outOther, fmt.Sprintf("transport error %d", int32(binary.LittleEndian.Uint32(m)))
	case size < 40 || binary.LittleEndian.Uint32(m[20:]) != resPQ || string(m[24:40]) != string(nonce[:]):
		r.Outcome, r.Detail = outOther, fmt.Sprintf("%d bytes, not resPQ", size)
	default:
		r.Outcome = outOK
	}
	return r
}

// packetSize reads the abridged length prefix: the payload size in bytes and the prefix size, or 0 when buf is
// too short to tell.
func packetSize(buf []byte) (size, hdr int) {
	switch {
	case len(buf) == 0:
		return 0, 0
	case buf[0] != 0x7f:
		return int(buf[0]) * 4, 1
	case len(buf) < 4:
		return 0, 0
	}
	return (int(buf[1]) | int(buf[2])<<8 | int(buf[3])<<16) * 4, 4
}

// mtDC runs the variants for one data centre in turn.
func (p *prober) mtDC(ctx context.Context, dcName, addr string, dcNum int) []MTResult {
	var res []MTResult
	for _, v := range mtVariants {
		r := p.mtOnce(ctx, dcName, net.JoinHostPort(addr, fmt.Sprint(p.port)), v, dcNum)
		res = append(res, r)
		p.logf("  %-4s %-18s %s", dcName, v, r.Outcome)
	}
	return res
}
