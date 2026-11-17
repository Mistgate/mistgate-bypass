package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// DNSResult compares what the system resolver says about a name with what DNS-over-HTTPS says.
type DNSResult struct {
	Name      string   `json:"name"`
	System    []string `json:"system"`
	SystemErr string   `json:"system_err,omitempty"`
	DoH       []string `json:"doh"`
	DoHFrom   string   `json:"doh_from,omitempty"`
	// Verdict: same, overlap, differ (both answered); system-empty or system-suspicious (DoH answered);
	// doh-unavailable (the system answer stands alone); unresolved (no real address could be obtained).
	Verdict string   `json:"verdict"`
	Suspect []string `json:"suspect,omitempty"` // system addresses that look like a stub or a spoof
	Used    string   `json:"used"`              // system, doh or none: where the addresses for the connections came from
	addrs   []netip.Addr
}

// DoHStatus is the result of asking one DoH endpoint for a neutral name.
type DoHStatus struct {
	Name   string `json:"name"`
	ByAddr bool   `json:"by_addr"`
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
}

var bogusNets = func() (n []netip.Prefix) {
	for _, s := range []string{"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4"} {
		n = append(n, netip.MustParsePrefix(s))
	}
	return
}()

// suspicious says an address cannot belong to a public service: it is private, loopback, unspecified, shared or
// reserved space. Resolvers that block a name, and programs that answer for the whole machine with made-up
// addresses, use such addresses.
func suspicious(a netip.Addr) bool { return stubKind(a) != "" }

// stubKind names why an address is not a real public one, or returns "".
func stubKind(a netip.Addr) string {
	switch {
	case a.IsUnspecified():
		return "0.0.0.0"
	case a.IsLoopback():
		return "loopback"
	case a.IsPrivate():
		return "private"
	case !a.IsGlobalUnicast():
		return "reserved"
	}
	for _, p := range bogusNets {
		if p.Contains(a) {
			return p.String()
		}
	}
	return ""
}

// probeDoH asks every endpoint for a neutral name, all at once, and keeps the ones that answer.
func (p *prober) probeDoH(ctx context.Context) []DoHStatus {
	st := make([]DoHStatus, len(p.doh))
	var wg sync.WaitGroup
	for i, ep := range p.doh {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st[i] = DoHStatus{Name: ep.Name, ByAddr: ep.ByAddr}
			if _, err := p.dohQuery(ctx, ep.URL, "example.com"); err != nil {
				_, st[i].Error = classify(err)
				return
			}
			st[i].OK = true
		}()
	}
	wg.Wait()
	p.alive = nil
	for i, ep := range p.doh {
		if st[i].OK {
			p.alive = append(p.alive, ep)
		}
	}
	return st
}

func (p *prober) resolve(ctx context.Context, name string) DNSResult {
	r := DNSResult{Name: name, System: []string{}, DoH: []string{}}
	sctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	sys, err := net.DefaultResolver.LookupNetIP(sctx, "ip4", name)
	cancel()
	if err != nil {
		_, r.SystemErr = classify(err)
	}
	for _, a := range sys {
		a = a.Unmap()
		r.System = append(r.System, a.String())
		if suspicious(a) {
			r.Suspect = append(r.Suspect, a.String())
		}
	}
	doh := []netip.Addr{}
	for _, ep := range p.alive {
		addrs, err := p.dohQuery(ctx, ep.URL, name)
		if err != nil {
			continue
		}
		doh, r.DoHFrom = addrs, ep.Name
		break
	}
	if len(doh) == 0 {
		doh, r.DoHFrom = publicLookup(ctx, name)
	}
	for _, a := range doh {
		r.DoH = append(r.DoH, a.String())
	}
	sort.Strings(r.System)
	sort.Strings(r.DoH)

	sysOK := len(r.System) > 0 && len(r.Suspect) == 0
	switch {
	case r.DoHFrom == "" && sysOK:
		r.Verdict = "doh-unavailable"
	case r.DoHFrom == "":
		r.Verdict = "unresolved" // the system answer is empty or looks forged, and there is nothing to check it against
	case len(r.System) == 0:
		r.Verdict = "system-empty"
	case len(r.Suspect) > 0:
		r.Verdict = "system-suspicious"
	default:
		r.Verdict = compareSets(r.System, r.DoH)
	}
	switch {
	case sysOK:
		r.Used, r.addrs = "system", parseAddrs(r.System)
	case len(doh) > 0:
		r.Used, r.addrs = "doh", doh
	default:
		r.Used = "none" // no conclusions are drawn from a forged or missing address
	}
	return r
}

// publicLookup asks the public resolvers over plain UDP, in turn, and returns the first answer made of real public
// addresses, with "udp <resolver>" as its source.
func publicLookup(ctx context.Context, name string) ([]netip.Addr, string) {
	for _, server := range publicDNS {
		resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "udp4", net.JoinHostPort(server, "53"))
		}}
		c, cancel := context.WithTimeout(ctx, 3*time.Second)
		addrs, err := resolver.LookupNetIP(c, "ip4", name)
		cancel()
		if err != nil || len(addrs) == 0 {
			continue
		}
		clean := addrs[:0]
		for _, a := range addrs {
			if a = a.Unmap(); !suspicious(a) {
				clean = append(clean, a)
			}
		}
		if len(clean) > 0 {
			return clean, "udp " + server
		}
	}
	return nil, ""
}

func parseAddrs(s []string) (out []netip.Addr) {
	for _, x := range s {
		if a, err := netip.ParseAddr(x); err == nil {
			out = append(out, a)
		}
	}
	return
}

func compareSets(a, b []string) string {
	in := map[string]bool{}
	for _, x := range a {
		in[x] = true
	}
	common := 0
	for _, x := range b {
		if in[x] {
			common++
		}
	}
	switch {
	case common == len(a) && common == len(b):
		return "same"
	case common > 0:
		return "overlap" // normal for a service that answers differently from different places
	}
	return "differ"
}

// dohQuery asks one RFC 8484 endpoint for the A records of name (GET with the query in the URL).
func (p *prober) dohQuery(ctx context.Context, endpoint, name string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, dohTime)
	defer cancel()
	n, err := dnsmessage.NewName(name + ".")
	if err != nil {
		return nil, err
	}
	q, err := (&dnsmessage.Message{
		Header:    dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}).Pack()
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", endpoint+"?dns="+base64.RawURLEncoding.EncodeToString(q), nil)
	req.Header.Set("Accept", "application/dns-message")
	resp, err := p.dohClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	var m dnsmessage.Message
	if err := m.Unpack(body); err != nil {
		return nil, fmt.Errorf("bad answer: %w", err)
	}
	if m.RCode != dnsmessage.RCodeSuccess && m.RCode != dnsmessage.RCodeNameError {
		return nil, fmt.Errorf("dns error %d", m.RCode)
	}
	var out []netip.Addr
	for _, an := range m.Answers {
		if a, ok := an.Body.(*dnsmessage.AResource); ok {
			out = append(out, netip.AddrFrom4(a.A))
		}
	}
	return out, nil // an empty list is an answer too
}
