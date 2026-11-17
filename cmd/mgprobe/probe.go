package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/mistgate/mistgate-bypass/dpi"
	"golang.org/x/net/http2"
)

// prober holds what differs between a real run and a test against loopback.
type prober struct {
	port      int
	roots     *x509.CertPool // nil: the system's
	doh       []dohEndpoint
	alive     []dohEndpoint // the endpoints that answered the reachability probe
	dohClient *http.Client
	ladder    []dpi.Strategy
	dial      time.Duration
	handshake time.Duration
	response  time.Duration
	mt        time.Duration // wait for the messenger answer
	freeze    time.Duration // silence that ends a download

	mu  sync.Mutex
	out io.Writer // progress lines
}

func newProber(out io.Writer) *prober {
	return &prober{
		port: 443, doh: dohEndpoints, out: out, ladder: dpi.LadderSeed(probeSeed),
		dial: dialTimeout, handshake: handshakeTime, response: responseTime, mt: mtprotoTime, freeze: freezeIdle,
		dohClient: &http.Client{
			Transport: &http.Transport{ // no proxy: the probe must show the network, not a configured detour
				Proxy:               nil,
				DialContext:         (&net.Dialer{Timeout: dohTime}).DialContext,
				TLSHandshakeTimeout: dohTime,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (p *prober) logf(format string, a ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(p.out, format+"\n", a...)
}

// TLSResult is one connection to one host with one face and one strategy.
type TLSResult struct {
	Host     string   `json:"host"`
	Face     string   `json:"face,omitempty"`
	Strategy string   `json:"strategy"`
	Outcome  string   `json:"outcome"`
	Detail   string   `json:"detail,omitempty"`
	Attempts []string `json:"attempts,omitempty"` // outcomes of every attempt, when there was more than one
	Addr     string   `json:"addr,omitempty"`
	TLS      string   `json:"tls,omitempty"`  // negotiated version
	ALPN     string   `json:"alpn,omitempty"` // h2 or http/1.1
	Status   int      `json:"http_status,omitempty"`
	TTFBMs   int64    `json:"ttfb_ms,omitempty"` // request written to response headers
	Bytes    int64    `json:"bytes,omitempty"`   // body bytes read
	ReadMs   int64    `json:"read_ms,omitempty"` // headers to the end of reading
	Kbps     int64    `json:"kbit_per_s,omitempty"`
	End      string   `json:"end,omitempty"` // why reading stopped: eof, limit, timeout or an outcome
}

// fetchReq describes one attempt.
type fetchReq struct {
	Host, Path string
	IPs        []netip.Addr
	Face       face
	Strat      dpi.Strategy
	Limit      int64         // body bytes to read at most
	Total      time.Duration // body reading time at most
	Idle       time.Duration // no data for this long ends the reading; at least Total means no separate limit
}

// fetch does one full attempt: connect, handshake with the strategy and face, GET, read the body.
func (p *prober) fetch(ctx context.Context, q fetchReq) TLSResult {
	r := TLSResult{Host: q.Host, Face: q.Face.Name, Strategy: q.Strat.Name}
	conn, ip, err := p.connect(ctx, q.IPs)
	if err != nil {
		r.Outcome, r.Detail = classify(err)
		if r.Outcome == outSilence {
			r.Outcome = outConnTimeout
		}
		return r
	}
	defer conn.Close()
	r.Addr = ip.String()

	_ = conn.SetDeadline(time.Now().Add(p.handshake))
	uc, err := q.Face.handshake(ctx, dpi.FirstWrite(conn, q.Strat), q.Host, p.roots)
	if err != nil {
		r.Outcome, r.Detail = classify(err)
		return r
	}
	st := uc.ConnectionState()
	r.TLS, r.ALPN = tlsName(st.Version), st.NegotiatedProtocol

	_ = conn.SetDeadline(time.Now().Add(p.response))
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+q.Host+q.Path, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "identity")
	sent := time.Now()
	var resp *http.Response
	if st.NegotiatedProtocol == "h2" {
		var cc *http2.ClientConn
		if cc, err = (&http2.Transport{DisableCompression: true}).NewClientConn(uc); err == nil {
			resp, err = cc.RoundTrip(req)
		}
	} else {
		req.Close = true
		if err = req.Write(uc); err == nil {
			resp, err = http.ReadResponse(bufio.NewReader(uc), req)
		}
	}
	if err != nil {
		r.Outcome, r.Detail = classify(err)
		if r.Outcome == outOther && time.Since(sent) >= p.response*9/10 { // http2 hides the deadline error inside its own
			r.Outcome = outSilence
		}
		r.Detail = "after handshake: " + r.Detail
		return r
	}
	defer resp.Body.Close()
	got := time.Now()
	r.Outcome, r.Status, r.TTFBMs = outOK, resp.StatusCode, got.Sub(sent).Milliseconds()

	// Read with a deadline that moves: Idle after every chunk, but never past Total from the headers.
	end := got.Add(q.Total)
	buf := make([]byte, 32<<10)
	var n int64
	for n < q.Limit {
		d := time.Now().Add(q.Idle)
		if d.After(end) {
			d = end
		}
		_ = conn.SetDeadline(d)
		k, err := resp.Body.Read(buf[:min(int64(len(buf)), q.Limit-n)])
		n += int64(k)
		if err == io.EOF {
			r.End = "eof"
			break
		}
		if err != nil {
			r.End, _ = classify(err)
			if r.End == outSilence {
				r.End = "timeout"
				if time.Now().Before(end.Add(-time.Millisecond)) {
					r.End = "idle-timeout" // the Idle limit ran out before the Total one
				}
			}
			break
		}
	}
	if n >= q.Limit {
		r.End = "limit"
	}
	done := time.Now()
	r.Bytes, r.ReadMs = n, done.Sub(got).Milliseconds()
	if ms := done.Sub(sent).Milliseconds(); ms > 0 {
		r.Kbps = n * 8 / ms
	}
	return r
}

func tlsName(v uint16) string {
	switch v {
	case 0x0304:
		return "1.3"
	case 0x0303:
		return "1.2"
	}
	return fmt.Sprintf("0x%04x", v)
}

// connect dials the first two addresses in turn.
func (p *prober) connect(ctx context.Context, ips []netip.Addr) (*net.TCPConn, netip.Addr, error) {
	last := error(net.UnknownNetworkError("no address"))
	for _, ip := range ips[:min(2, len(ips))] {
		c, err := (&net.Dialer{Timeout: p.dial}).DialContext(ctx, "tcp4", netip.AddrPortFrom(ip, uint16(p.port)).String())
		if err == nil {
			return c.(*net.TCPConn), ip, nil
		}
		last = err
	}
	return nil, netip.Addr{}, last
}

// page fetches the front page of host for the matrix: a little of the body is enough.
func (p *prober) page(ctx context.Context, host string, ips []netip.Addr, f face, s dpi.Strategy) TLSResult {
	return p.fetch(ctx, fetchReq{Host: host, Path: "/", IPs: ips, Face: f, Strat: s, Limit: bodyLimit, Total: bodyTime, Idle: bodyTime})
}

// hostMatrix runs the strategies of the ladder against one host, on each face. The plain strategy goes first, on
// the browser-like face and twice, so one lost packet does not pass for a block. When it works both times, every
// other strategy runs once on that face only: the question is then whether it breaks a working site. Otherwise
// every strategy runs once on every face. A host that does not accept connections at all is not tried further:
// no cut of the first packet changes what happens to the SYN.
func (p *prober) hostMatrix(ctx context.Context, host string, ips []netip.Addr) []TLSResult {
	var res []TLSResult
	add := func(r TLSResult) {
		res = append(res, r)
		p.logf("  %-28s %-12s %-20s %s", host, r.Face, r.Strategy, short(r))
	}
	skipped := func(f face, s dpi.Strategy, why string) TLSResult {
		return TLSResult{Host: host, Face: f.Name, Strategy: s.Name, Outcome: outSkipped, Detail: why}
	}
	first := faces[0]
	if len(ips) == 0 {
		for _, f := range faces {
			for _, s := range p.ladder {
				res = append(res, TLSResult{Host: host, Face: f.Name, Strategy: s.Name, Outcome: outNoAddr, Detail: noRealAddr})
			}
		}
		p.logf("  %-28s %s", host, noRealAddr)
		return res
	}

	var seq []string
	var plain TLSResult
	for i := 0; i < 2 && ctx.Err() == nil; i++ {
		a := p.page(ctx, host, ips, first, p.ladder[0])
		seq = append(seq, a.Outcome)
		if plain.Outcome != outOK {
			plain = a
		}
	}
	if len(seq) == 0 {
		plain = skipped(first, p.ladder[0], "out of time")
	}
	plain.Attempts = seq
	add(plain)
	plainWorks := len(seq) == 2 && seq[0] == outOK && seq[1] == outOK
	unreachable := len(seq) == 2 && connectFail(seq[0]) && connectFail(seq[1])

	for i, s := range p.ladder {
		for _, f := range faces {
			if i == 0 && f.Name == first.Name {
				continue // done above
			}
			switch {
			case plainWorks && f.Name != first.Name:
				continue // nothing to learn from other faces of a host that opens as it is
			case unreachable:
				add(skipped(f, s, "the address does not accept connections"))
			case ctx.Err() != nil:
				add(skipped(f, s, "out of time"))
			default:
				add(p.page(ctx, host, ips, f, s))
			}
		}
	}
	return res
}

func connectFail(o string) bool { return o == outConnTimeout || o == outRefused }

// short is the console form of a result.
func short(r TLSResult) string {
	if r.Outcome == outOK {
		return fmt.Sprintf("ok (%d ms, %d B)", r.TTFBMs, r.Bytes)
	}
	return r.Outcome
}

// best is the cheapest (strategy, face) of the ladder that worked for host.
func (p *prober) best(res []TLSResult, host string) (dpi.Strategy, face, bool) {
	for _, s := range p.ladder {
		for _, f := range faces {
			for _, r := range res {
				if r.Host == host && r.Strategy == s.Name && r.Face == f.Name && r.Outcome == outOK {
					return s, f, true
				}
			}
		}
	}
	return dpi.Strategy{}, face{}, false
}

// SpeedResult is a download on the best strategy found for the host.
type SpeedResult struct {
	Control bool `json:"control"`
	TLSResult
}

func (p *prober) speed(ctx context.Context, t speedTarget, ips []netip.Addr, matrix []TLSResult) SpeedResult {
	s, f, ok := p.best(matrix, t.Host)
	if t.Control {
		s, f, ok = p.ladder[0], faces[0], true // the control host is not in the matrix: plain is the honest baseline
	}
	if !ok {
		return SpeedResult{t.Control, TLSResult{Host: t.Host, Outcome: outSkipped, Detail: "no strategy opened this host"}}
	}
	if len(ips) == 0 {
		return SpeedResult{t.Control, TLSResult{Host: t.Host, Strategy: s.Name, Face: f.Name, Outcome: outNoAddr}}
	}
	r := p.fetch(ctx, fetchReq{Host: t.Host, Path: t.Path, IPs: ips, Face: f, Strat: s, Limit: speedLimit, Total: speedTime, Idle: speedTime})
	p.logf("  %-28s %-12s %-18s %s, %d kbit/s", t.Host, f.Name, s.Name, short(r), r.Kbps)
	return SpeedResult{t.Control, r}
}
