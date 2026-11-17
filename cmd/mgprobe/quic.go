package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/mistgate/mistgate-bypass/dpi"
)

// quicVariant is one way of starting the QUIC handshake: bare, or behind decoy datagrams.
type quicVariant struct {
	Content string // "", "zeros" or "blob"
	Count   int
	TTL     int
}

func (v quicVariant) name() string {
	if v.Content == "" {
		return "bare"
	}
	return fmt.Sprintf("%s-n%d-ttl%d", v.Content, v.Count, v.TTL)
}

// quicVariants: bare first, then decoys of two contents, two counts and three TTLs.
func quicVariants() []quicVariant {
	vs := []quicVariant{{}}
	for _, c := range []string{"zeros", "blob"} {
		for _, n := range []int{2, 6} {
			for _, ttl := range []int{3, 5, 8} {
				vs = append(vs, quicVariant{c, n, ttl})
			}
		}
	}
	return vs
}

// QUICResult is one HTTP/3 request attempt.
type QUICResult struct {
	Host    string `json:"host"`
	Variant string `json:"variant"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail,omitempty"`
	Addr    string `json:"addr,omitempty"`
	Status  int    `json:"http_status,omitempty"`
	Ms      int64  `json:"ms,omitempty"`
}

// quicOnce makes an HTTP/3 GET to ip. The socket is handed to quic-go through quic.Transport, so a wrapper that
// sends decoys first can sit between the library and the network; http3.Transport.Dial points the library at it.
func (p *prober) quicOnce(ctx context.Context, host string, ip netip.Addr, v quicVariant) QUICResult {
	r := QUICResult{Host: host, Variant: v.name(), Addr: ip.String()}
	udp, err := net.ListenUDP("udp4", nil)
	if err != nil {
		r.Outcome, r.Detail = classify(err)
		return r
	}
	var pc net.PacketConn = udp
	switch v.Content {
	case "zeros":
		pc = dpi.NewFakeUDP(udp, v.Count, v.TTL, make([]byte, 1200))
	case "blob":
		pc = dpi.NewFakeUDP(udp, v.Count, v.TTL, bytes.Clone(quicFakeBlob))
	}
	tr := &quic.Transport{Conn: pc}
	defer func() { tr.Close(); pc.Close() }() // a Transport does not close a socket it was given

	h3 := &http3.Transport{
		TLSClientConfig: &tls.Config{RootCAs: p.roots},
		QUICConfig:      &quic.Config{HandshakeIdleTimeout: quicTime},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return tr.Dial(ctx, &net.UDPAddr{IP: ip.AsSlice(), Port: p.port}, tlsCfg, cfg)
		},
	}
	defer h3.Close()

	ctx, cancel := context.WithTimeout(ctx, quicTime)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+host+"/", nil)
	start := time.Now()
	resp, err := h3.RoundTrip(req)
	r.Ms = time.Since(start).Milliseconds()
	if err != nil {
		r.Outcome, r.Detail = classify(err) // quic-go's idle and handshake timeouts are net.Errors with Timeout() set
		return r
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	r.Outcome, r.Status = outOK, resp.StatusCode
	return r
}

// quicHost runs all variants against one host, one after another.
func (p *prober) quicHost(ctx context.Context, host string, ips []netip.Addr) []QUICResult {
	var res []QUICResult
	for _, v := range quicVariants() {
		var r QUICResult
		switch {
		case len(ips) == 0:
			r = QUICResult{Host: host, Variant: v.name(), Outcome: outNoAddr}
		case ctx.Err() != nil:
			r = QUICResult{Host: host, Variant: v.name(), Outcome: outSkipped, Detail: "out of time"}
		default:
			r = p.quicOnce(ctx, host, ips[0], v)
		}
		res = append(res, r)
		p.logf("  %-18s %-16s %s", host, r.Variant, r.Outcome)
	}
	return res
}
