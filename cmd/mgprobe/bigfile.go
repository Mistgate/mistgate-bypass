package main

import (
	"context"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
)

// BigResult is one download of up to 256 KB from a foreign hosting provider, on one TLS version, without any
// strategy. Some paths let a connection to such hosts carry about 16 KB and then stop answering.
type BigResult struct {
	Provider string `json:"provider"`
	URL      string `json:"url"` // the address that was used: the first, or the spare when the first gave nothing
	TLS      string `json:"tls"` // requested: 1.3 or 1.2
	Outcome  string `json:"outcome"`
	Detail   string `json:"detail,omitempty"`
	Bytes    int64  `json:"bytes"`
	End      string `json:"end,omitempty"` // limit, eof, idle-timeout, timeout, reset, closed or other
	Ms       int64  `json:"ms,omitempty"`
	Freeze   bool   `json:"freeze_16k,omitempty"`
}

// bigHosts lists the host names of bigFiles, for the DNS stage.
func bigHosts() (hosts []string) {
	seen := map[string]bool{}
	for _, b := range bigFiles {
		for _, u := range b.URLs {
			if pu, err := url.Parse(u); err == nil && !seen[pu.Hostname()] {
				seen[pu.Hostname()] = true
				hosts = append(hosts, pu.Hostname())
			}
		}
	}
	return
}

// isFreeze says a transfer stopped for good inside the window where the stall shows. A finished download, or one
// that was cut by the size limit, is not a stall.
func isFreeze(end string, n int64) bool {
	return end != "limit" && end != "eof" && n >= freezeFrom && n <= freezeTo
}

// bigFile downloads one provider's file on both TLS versions. TLS 1.3 uses the small browser-like face, TLS 1.2
// the one with a 1.2 maximum.
func (p *prober) bigFile(ctx context.Context, b bigFile, addrs map[string][]netip.Addr) []BigResult {
	var out []BigResult
	for _, f := range []struct{ tls, face string }{{"1.3", "chrome-small"}, {"1.2", "tls12"}} {
		var r BigResult
		for _, raw := range b.URLs {
			u, err := url.Parse(raw)
			if err != nil {
				continue
			}
			r = BigResult{Provider: b.Name, URL: raw, TLS: f.tls}
			ips := addrs[u.Hostname()]
			if len(ips) == 0 {
				r.Outcome, r.Detail = outNoAddr, noRealAddr
				continue
			}
			t := p.fetch(ctx, fetchReq{Host: u.Hostname(), Path: u.RequestURI(), IPs: ips, Face: faceByName(f.face), Strat: p.ladder[0],
				Limit: freezeLimit, Total: freezeTotal, Idle: p.freeze})
			r.Outcome, r.Detail, r.Bytes, r.End, r.Ms = t.Outcome, t.Detail, t.Bytes, t.End, t.ReadMs
			if t.Outcome == outOK && t.Status != 200 {
				r.Outcome, r.Detail = outOther, "http status "+strconv.Itoa(t.Status) // a missing file is not a test result
			}
			if r.Outcome == outOK {
				r.Freeze = isFreeze(r.End, r.Bytes)
				break
			}
		}
		p.logf("  %-14s TLS %s %-18s %d B, %s", b.Name, f.tls, r.Outcome, r.Bytes, r.End)
		out = append(out, r)
	}
	return out
}

// runBig runs all providers side by side.
func (p *prober) runBig(ctx context.Context, addrs map[string][]netip.Addr) []BigResult {
	var mu sync.Mutex
	var wg sync.WaitGroup
	var res []BigResult
	for _, b := range bigFiles {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := p.bigFile(ctx, b, addrs)
			mu.Lock()
			res = append(res, r...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return res
}
