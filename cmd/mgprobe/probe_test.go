package main

import (
	"context"
	"crypto/cipher"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/user"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/apernet/quic-go/http3"
	"github.com/mistgate/mistgate-bypass/dpi"
	"golang.org/x/net/dns/dnsmessage"
)

const testHost = "example.com" // a name in the certificate of httptest's TLS server

var loopback = []netip.Addr{netip.MustParseAddr("127.0.0.1")}

func testProber(port int, roots *x509.CertPool) *prober {
	p := newProber(io.Discard)
	p.port, p.roots = port, roots
	p.handshake, p.response, p.mt, p.freeze = 400*time.Millisecond, 400*time.Millisecond, 600*time.Millisecond, 500*time.Millisecond
	return p
}

func tlsServer(t *testing.T, h2 bool) (*httptest.Server, *x509.CertPool) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.Write(make([]byte, 300<<10))
		case "/stall": // 16 KB, then nothing: the shape of the stall the probe looks for
			w.Write(make([]byte, 16<<10))
			w.(http.Flusher).Flush()
			time.Sleep(3 * time.Second)
		case "/missing":
			http.NotFound(w, r)
		default:
			io.WriteString(w, "pong")
		}
	}))
	srv.EnableHTTP2 = h2
	srv.StartTLS()
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	return srv, roots
}

func portOf(a net.Addr) int { return a.(*net.TCPAddr).Port }

// rawServer runs handle on every accepted connection and returns the port.
func rawServer(t *testing.T, handle func(net.Conn)) int {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(c)
		}
	}()
	return portOf(ln.Addr())
}

// readHello reads one whole TLS record. A close with bytes still unread makes the stack send RST instead of FIN.
func readHello(c net.Conn) {
	var h [5]byte
	if _, err := io.ReadFull(c, h[:]); err == nil {
		io.ReadFull(c, make([]byte, int(h[3])<<8|int(h[4])))
	}
}

func plainStrategy(p *prober) dpi.Strategy { return p.ladder[0] }

func TestFetchOutcomes(t *testing.T) {
	srv, roots := tlsServer(t, false)
	closedPort := func() int {
		ln, _ := net.Listen("tcp4", "127.0.0.1:0")
		defer ln.Close()
		return portOf(ln.Addr())
	}()
	for _, tc := range []struct {
		name  string
		port  int
		roots *x509.CertPool
		want  string
	}{
		{"ok", portOf(srv.Listener.Addr()), roots, outOK},
		{"cert", portOf(srv.Listener.Addr()), nil, outCert},
		{"refused", closedPort, nil, outRefused},
		{"closed", rawServer(t, func(c net.Conn) { readHello(c); c.Close() }), nil, outClosed},
		{"reset", rawServer(t, func(c net.Conn) {
			readHello(c)
			c.(*net.TCPConn).SetLinger(0)
			c.Close()
		}), nil, outReset},
		{"silence", rawServer(t, func(c net.Conn) { c.Read(make([]byte, 100)); time.Sleep(2 * time.Second); c.Close() }), nil, outSilence},
		{"alert", rawServer(t, func(c net.Conn) { tls.Server(c, &tls.Config{}).Handshake(); c.Close() }), nil, outAlert}, // no certificate: an alert answers
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := testProber(tc.port, tc.roots)
			r := p.page(context.Background(), testHost, loopback, faces[0], plainStrategy(p))
			if r.Outcome != tc.want {
				t.Fatalf("outcome %s (%s), want %s", r.Outcome, r.Detail, tc.want)
			}
			if tc.want == outOK && (r.Status != 200 || r.Bytes != 4 || r.ALPN != "http/1.1" || r.TLS != "1.3") {
				t.Errorf("status %d, %d bytes, %s over TLS %s", r.Status, r.Bytes, r.ALPN, r.TLS)
			}
			if strings.Contains(r.Detail, "127.0.0.1") {
				t.Errorf("an address in the detail: %s", r.Detail)
			}
		})
	}
}

// With HTTP/2 offered by the server the request goes over h2, on every face.
func TestFetchHTTP2(t *testing.T) {
	srv, roots := tlsServer(t, true)
	p := testProber(portOf(srv.Listener.Addr()), roots)
	for _, f := range faces {
		r := p.page(context.Background(), testHost, loopback, f, plainStrategy(p))
		want := "1.3"
		if f.Name == "tls12" {
			want = "1.2"
		}
		if r.Outcome != outOK || r.ALPN != "h2" || r.Status != 200 || r.Bytes != 4 || r.TLS != want {
			t.Errorf("%s: %+v", f.Name, r)
		}
	}
}

// faceHello captures the first record a face writes.
func faceHello(t *testing.T, f face) []byte {
	cl, sv := net.Pipe()
	defer sv.Close()
	go func() {
		defer cl.Close()
		f.handshake(context.Background(), cl, "www.youtube.com", nil)
	}()
	sv.SetReadDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(sv, hdr); err != nil {
		t.Fatal(err)
	}
	b := append(hdr, make([]byte, int(hdr[3])<<8|int(hdr[4]))...)
	if _, err := io.ReadFull(sv, b[5:]); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFaces(t *testing.T) {
	size := map[string]int{}
	for _, f := range faces {
		b := faceHello(t, f)
		h, err := dpi.ParseClientHello(b)
		if err != nil || h.ServerName != "www.youtube.com" {
			t.Fatalf("%s: %v %+v", f.Name, err, h)
		}
		size[f.Name] = len(b)
		t.Logf("%s: ClientHello of %d bytes", f.Name, len(b))
	}
	// the small faces fit in one segment, the browser-like one does not
	if size["chrome-small"] >= 1200 || size["tls12"] >= 1200 {
		t.Errorf("small faces: %v", size)
	}
	if size["chrome"] <= 1200 {
		t.Errorf("chrome face is %d bytes: no post-quantum key share?", size["chrome"])
	}
	// tls12 offers nothing newer than 1.2, and a 1.3-capable server settles on 1.2 with it
	srv, roots := tlsServer(t, false)
	p := testProber(portOf(srv.Listener.Addr()), roots)
	if r := p.page(context.Background(), testHost, loopback, faceByName("tls12"), plainStrategy(p)); r.TLS != "1.2" || r.Outcome != outOK {
		t.Errorf("tls12 face: %+v", r)
	}
	b := faceHello(t, faceByName("tls12"))
	if strings.Contains(string(b), "\x00\x2b") && vers13(b) {
		t.Error("tls12 face still lists TLS 1.3")
	}
}

// vers13 looks for a supported_versions extension (type 0x002b) that lists 0x0304 by walking the extensions.
func vers13(b []byte) bool {
	p := 5 + 4 + 2 + 32
	p += 1 + int(b[p])
	p += 2 + int(b[p])<<8 + int(b[p+1])
	p += 1 + int(b[p])
	end := p + 2 + int(b[p])<<8 + int(b[p+1])
	p += 2
	for p+4 <= end {
		typ, n := int(b[p])<<8|int(b[p+1]), int(b[p+2])<<8|int(b[p+3])
		if typ == 0x2b {
			return true
		}
		p += 4 + n
	}
	return false
}

func TestHostMatrix(t *testing.T) {
	srv, roots := tlsServer(t, true)
	p := testProber(portOf(srv.Listener.Addr()), roots)
	res := p.hostMatrix(context.Background(), testHost, loopback)
	// plain twice on chrome, then every other strategy once on chrome only
	if len(res) != len(p.ladder) {
		t.Fatalf("%d results", len(res))
	}
	for i, r := range res {
		if r.Outcome != outOK || r.Face != "chrome" {
			t.Errorf("%s/%s: %s %s", r.Face, r.Strategy, r.Outcome, r.Detail)
		}
		if (i == 0) != (len(r.Attempts) == 2) {
			t.Errorf("%s: attempts %v", r.Strategy, r.Attempts)
		}
	}
	if s, f, ok := p.best(res, testHost); !ok || s.Name != "plain" || f.Name != "chrome" {
		t.Errorf("best %v %v", s.Name, f.Name)
	}
}

// A host that never lets a handshake through is tried with every strategy on every face.
func TestHostMatrixBlocked(t *testing.T) {
	port := rawServer(t, func(c net.Conn) {
		readHello(c)
		c.(*net.TCPConn).SetLinger(0)
		c.Close()
	})
	p := testProber(port, nil)
	res := p.hostMatrix(context.Background(), testHost, loopback)
	if want := len(p.ladder) * len(faces); len(res) != want {
		t.Fatalf("%d results, want %d", len(res), want)
	}
	for _, r := range res {
		if r.Outcome != outReset {
			t.Errorf("%s/%s: %s", r.Face, r.Strategy, r.Outcome)
		}
	}
	rep := &Report{TLS: res, Environment: Environment{}}
	f := collect(rep, testHost)
	if !strings.Contains(f.describe(), "соединение есть, но дальше режут") {
		t.Errorf("verdict: %s", f.describe())
	}
}

func TestHostMatrixUnreachable(t *testing.T) {
	ln, _ := net.Listen("tcp4", "127.0.0.1:0")
	port := portOf(ln.Addr())
	ln.Close()
	p := testProber(port, nil)
	res := p.hostMatrix(context.Background(), testHost, loopback)
	if res[0].Outcome != outRefused || len(res[0].Attempts) != 2 || len(res) != len(p.ladder)*len(faces) {
		t.Fatalf("plain: %+v, %d results", res[0], len(res))
	}
	for _, r := range res[1:] {
		if r.Outcome != outSkipped {
			t.Errorf("%s/%s: %s", r.Face, r.Strategy, r.Outcome)
		}
	}
	if f := collect(&Report{TLS: res}, testHost); !strings.Contains(f.describe(), "адрес недоступен") {
		t.Errorf("verdict: %s", f.describe())
	}
	nores := testProber(1, nil).hostMatrix(context.Background(), testHost, nil)
	if nores[0].Outcome != outNoAddr || !strings.Contains(collect(&Report{TLS: nores}, testHost).describe(), "выводов нет") {
		t.Errorf("no address: %+v", nores[0])
	}
}

// Downloads of a big file: a complete one, one that stops after 16 KB, and a first address that is wrong.
func TestBigFile(t *testing.T) {
	srv, roots := tlsServer(t, false)
	p := testProber(portOf(srv.Listener.Addr()), roots)
	addrs := map[string][]netip.Addr{testHost: loopback}
	for _, tc := range []struct {
		name   string
		urls   []string
		end    string
		freeze bool
	}{
		{"complete", []string{"https://example.com/ok"}, "limit", false},
		{"stall", []string{"https://example.com/stall"}, "idle-timeout", true},
		{"spare", []string{"https://example.com/missing", "https://example.com/ok"}, "limit", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, r := range p.bigFile(context.Background(), bigFile{tc.name, tc.urls}, addrs) {
				if r.Outcome != outOK || r.End != tc.end || r.Freeze != tc.freeze {
					t.Errorf("TLS %s: %+v", r.TLS, r)
				}
				if tc.freeze && r.Bytes != 16<<10 || !tc.freeze && r.Bytes != freezeLimit {
					t.Errorf("TLS %s: %d bytes", r.TLS, r.Bytes)
				}
			}
		})
	}
	if isFreeze("limit", 20<<10) || isFreeze("idle-timeout", 4<<10) || isFreeze("reset", 100<<10) || !isFreeze("reset", 17<<10) || isFreeze("eof", 20<<10) {
		t.Error("isFreeze")
	}
	if hs := bigHosts(); len(hs) < 8 {
		t.Errorf("hosts: %v", hs)
	}
}

// fakeDC answers req_pq_multi like a data centre would, over the abridged transport with or without obfuscation.
// It is written from the other side of the same description, so it proves the probe is self-consistent and
// frames the way the description says; it cannot prove the real servers agree.
func fakeDC(c net.Conn) {
	defer c.Close()
	var first [1]byte
	if _, err := io.ReadFull(c, first[:]); err != nil {
		return
	}
	var enc, dec cipher.Stream
	if first[0] != 0xef {
		var h [64]byte
		h[0] = first[0]
		if _, err := io.ReadFull(c, h[1:]); err != nil {
			return
		}
		rev := make([]byte, 48)
		for i := range rev {
			rev[i] = h[8+47-i]
		}
		o, _ := newObfsStreams(rev[:32], rev[32:48], h[8:40], h[40:56]) // swapped: our encrypt is the client's decrypt
		var tmp [64]byte
		o.dec.XORKeyStream(tmp[:], h[:]) // advance past the header
		if binary.LittleEndian.Uint32(tmp[56:]) != 0xefefefef {
			return
		}
		enc, dec = o.enc, o.dec
	}
	var lb [1]byte
	if _, err := io.ReadFull(c, lb[:]); err != nil {
		return
	}
	if dec != nil {
		dec.XORKeyStream(lb[:], lb[:])
	}
	body := make([]byte, int(lb[0])*4)
	if _, err := io.ReadFull(c, body); err != nil {
		return
	}
	if dec != nil {
		dec.XORKeyStream(body, body)
	}
	if binary.LittleEndian.Uint32(body[20:]) != reqPQMulti {
		return
	}
	resp := make([]byte, 56)
	binary.LittleEndian.PutUint64(resp[8:], uint64(time.Now().Unix())<<32|1)
	binary.LittleEndian.PutUint32(resp[16:], 36)
	binary.LittleEndian.PutUint32(resp[20:], resPQ)
	copy(resp[24:40], body[24:40])
	out := abridged(resp)
	if enc != nil {
		enc.XORKeyStream(out, out)
	}
	c.Write(out)
}

func TestMTProto(t *testing.T) {
	port := rawServer(t, fakeDC)
	p := testProber(port, nil)
	for _, r := range p.mtDC(context.Background(), "DC1", "127.0.0.1", 1) {
		if r.Outcome != outOK {
			t.Errorf("%s: %s %s", r.Variant, r.Outcome, r.Detail)
		}
	}
	// a server that never answers
	silent := rawServer(t, func(c net.Conn) { io.Copy(io.Discard, c) })
	if r := testProber(silent, nil).mtOnce(context.Background(), "DC1", fmt.Sprintf("127.0.0.1:%d", silent), "obfs", 1); r.Outcome != outSilence {
		t.Errorf("silent server: %+v", r)
	}
	// a server that answers with a transport error
	bad := rawServer(t, func(c net.Conn) {
		c.Read(make([]byte, 200))
		c.Write([]byte{1, 0x6c, 0xfe, 0xff, 0xff}) // abridged, error -404
	})
	if r := testProber(bad, nil).mtOnce(context.Background(), "DC1", fmt.Sprintf("127.0.0.1:%d", bad), "abridged", 1); r.Outcome != outOther || !strings.Contains(r.Detail, "-404") {
		t.Errorf("transport error: %+v", r)
	}
}

func TestMTProtoFraming(t *testing.T) {
	m := reqPQ([16]byte{1, 2, 3})
	if len(m) != 40 || binary.LittleEndian.Uint32(m[16:]) != 20 || binary.LittleEndian.Uint32(m[20:]) != reqPQMulti || binary.LittleEndian.Uint64(m[8:])&3 != 0 {
		t.Fatalf("req_pq_multi: %x", m)
	}
	if a := abridged(m); a[0] != 10 || len(a) != 41 {
		t.Fatalf("abridged: %x", a[:2])
	}
	for i := 0; i < 200; i++ { // the header never looks like another protocol
		init, _, err := newObfs(2)
		if err != nil || len(init) != 64 || init[0] == 0xef {
			t.Fatal("bad header")
		}
		switch binary.LittleEndian.Uint32(init) {
		case 0x44414548, 0x54534f50, 0x20544547, 0x4954504f, 0xdddddddd, 0xeeeeeeee, 0x02010316:
			t.Fatal("header looks like HTTP or TLS")
		}
	}
}

// dohServer answers RFC 8484 GET queries for "localhost" with one address and for the rest with nothing.
func dohServer(t *testing.T) *httptest.Server {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		var q dnsmessage.Message
		if err != nil || r.Header.Get("Accept") != "application/dns-message" || q.Unpack(raw) != nil || len(q.Questions) != 1 {
			http.Error(w, "bad", 400)
			return
		}
		m := dnsmessage.Message{Header: dnsmessage.Header{Response: true, ID: q.ID}, Questions: q.Questions}
		if q.Questions[0].Name.String() == "localhost." {
			m.Answers = []dnsmessage.Resource{
				{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}}},
			}
		}
		out, _ := m.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(out)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDoH(t *testing.T) {
	doh := dohServer(t)
	p := testProber(443, nil)
	p.dohClient = doh.Client()
	// the first endpoint is dead (by address), the second answers (by name)
	p.doh = []dohEndpoint{{"dead", "https://127.0.0.1:1/dns-query", true}, {"live", doh.URL + "/dns-query", false}}
	st := p.probeDoH(context.Background())
	if len(st) != 2 || st[0].OK || !st[1].OK || strings.Contains(st[0].Error, "127.0.0.1") || len(p.alive) != 1 {
		t.Fatalf("status %+v", st)
	}
	if l := dohLine(st); !strings.Contains(l, "закрыт по адресам") {
		t.Errorf("line: %s", l)
	}
	r := p.resolve(context.Background(), "localhost")
	// the system answers 127.0.0.1 for localhost: a stub-like address, so the connections use DoH
	if r.DoHFrom != "live" || r.Verdict != "system-suspicious" || r.Used != "doh" || len(r.addrs) != 1 || r.addrs[0].String() != "93.184.216.34" {
		t.Fatalf("resolve: %+v", r)
	}
	// nothing alive: a forged answer stays unresolved and no address is used
	p.alive = nil
	if r := p.resolve(context.Background(), "localhost"); r.Verdict != "unresolved" || r.Used != "none" || len(r.addrs) != 0 {
		t.Fatalf("doh down: %+v", r)
	}
	if l := dohLine([]DoHStatus{{Name: "a", ByAddr: true, Error: outSilence}, {Name: "b", Error: outSilence}}); !strings.Contains(l, "закрыт совсем") {
		t.Errorf("line: %s", l)
	}
}

func TestSuspicious(t *testing.T) {
	for s, want := range map[string]string{"10.1.2.3": "private", "127.0.0.1": "loopback", "0.0.0.0": "0.0.0.0", "100.64.0.1": "100.64.0.0/10", "169.254.1.1": "reserved",
		"192.168.0.1": "private", "198.18.0.5": "198.18.0.0/15", "198.19.255.1": "198.18.0.0/15", "8.8.8.8": "", "142.250.74.14": "", "93.184.216.34": ""} {
		if got := stubKind(netip.MustParseAddr(s)); got != want {
			t.Errorf("%s: %q, want %q", s, got, want)
		}
	}
	if compareSets([]string{"1.1.1.1"}, []string{"1.1.1.1"}) != "same" || compareSets([]string{"1.1.1.1", "2.2.2.2"}, []string{"1.1.1.1"}) != "overlap" || compareSets([]string{"1.1.1.1"}, []string{"3.3.3.3"}) != "differ" {
		t.Error("compareSets")
	}
}

func TestEnvironment(t *testing.T) {
	got := matchTools([]string{"explorer.exe", "WinWS.EXE", "chrome.exe", "Tailscaled.exe", "winws.exe", "svchost.exe", "mistgate-clientd.exe", "sing-box"})
	if strings.Join(got, ",") != "mistgate-clientd,sing-box,tailscaled,winws" {
		t.Errorf("tools: %v", got)
	}
	for i, n := range bypassTools { // matchTools compares lower-case names
		if n != strings.ToLower(n) || slices.Index(bypassTools, n) != i {
			t.Errorf("bad or repeated name in the list: %q", n)
		}
	}
	// An environment with a finding says so loudly; a clean one says nothing is wrong.
	e := Environment{Distorted: true, Reasons: []string{"запущены программы обхода или VPN: winws"}, WinDivert: "unknown"}
	if l := strings.Join(e.lines(), "\n"); !strings.Contains(l, "Результаты искажены") || !strings.Contains(l, "winws") {
		t.Errorf("lines: %s", l)
	}
	if l := strings.Join((Environment{WinDivert: "not-loaded", Routes: []IfType{newIfType(6)}}).lines(), "\n"); strings.Contains(l, "искажены") || !strings.Contains(l, "6 (Ethernet)") {
		t.Errorf("clean: %s", l)
	}
	for ty, normal := range map[int]bool{6: true, 71: true, 243: true, 244: true, 53: false, 131: false, 23: false} {
		if newIfType(ty).Normal != normal {
			t.Errorf("type %d", ty)
		}
	}
	// The real checks read local state only (process snapshot, routing table, service list); no traffic.
	procs, err := listProcesses()
	if err != nil {
		t.Skipf("not available here: %v", err)
	}
	if len(procs) == 0 {
		t.Error("no processes listed")
	}
	if types, err := defaultRouteTypes(); err != nil {
		t.Logf("default route: %v", err) // a machine with no network at all
	} else {
		t.Logf("default route interface types: %v", types)
	}
	if loaded, err := windivertLoaded(); err != nil {
		t.Errorf("service list without rights: %v", err)
	} else {
		t.Logf("WinDivert loaded: %v", loaded)
	}
}

// QUIC against a local HTTP/3 server: the bare handshake and the ones behind decoys, with TTL 3, which loopback
// does not expire (so the decoys do reach the server, which has to ignore them).
func TestQUIC(t *testing.T) {
	srv, roots := tlsServer(t, false)
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	h3 := &http3.Server{
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "pong") }),
		TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: srv.TLS.Certificates}),
	}
	go h3.Serve(udp)
	t.Cleanup(func() { h3.Close(); udp.Close() })
	p := testProber(udp.LocalAddr().(*net.UDPAddr).Port, roots)
	for _, v := range []quicVariant{{}, {"zeros", 2, 3}, {"blob", 6, 8}} {
		r := p.quicOnce(context.Background(), testHost, loopback[0], v)
		if r.Outcome != outOK || r.Status != 200 {
			t.Errorf("%s: %s %s", v.name(), r.Outcome, r.Detail)
		}
	}
	// nobody listens: the attempt ends with silence or a refusal inside the time limit
	dead, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	port := dead.LocalAddr().(*net.UDPAddr).Port
	dead.Close()
	start := time.Now()
	if r := testProber(port, roots).quicOnce(context.Background(), testHost, loopback[0], quicVariant{}); r.Outcome == outOK || time.Since(start) > quicTime+2*time.Second {
		t.Errorf("dead server: %+v after %v", r, time.Since(start))
	}
}

func syntheticReport() *Report {
	rep := &Report{Tool: "mgprobe", Version: version, Time: "2026-01-01T00:00:00Z", OS: "10.0 (build 1)", ElapsedSec: 1, Seed: probeSeed,
		Environment: Environment{Distorted: true, Reasons: []string{"запущены программы обхода или VPN: warp-svc"}, Tools: []string{"warp-svc"}, WinDivert: "not-loaded"}}
	for _, s := range services {
		for _, h := range s.Hosts {
			for _, st := range dpi.Ladder() {
				for _, f := range faces {
					o := outOK
					switch {
					case s.Name == "YouTube" && (st.Name == "plain" || st.Name == "tlsrec"):
						o = outSilence
					case s.Name == "YouTube" && f.Name != "chrome-small" && st.Name != "split1":
						o = outSilence
					case s.Name == "Discord" && h == "discord.com":
						o = outConnTimeout
					case s.Name == "Telegram (веб)" && h == "t.me":
						o = outReset
					case st.Name == "oob" && h == "ya.ru":
						o = outAlert
					}
					if s.Name == "Контроль" && (f.Name != "chrome" || st.Name == "plain" && false) {
						continue // the control opens as it is: only chrome was measured
					}
					rep.TLS = append(rep.TLS, TLSResult{Host: h, Face: f.Name, Strategy: st.Name, Outcome: o})
				}
			}
		}
	}
	rep.DoH = []DoHStatus{{Name: "1.1.1.1", ByAddr: true, Error: outSilence}, {Name: "cloudflare-dns.com", OK: true}}
	rep.DNS = []DNSResult{{Name: "ya.ru", System: []string{"198.18.0.7"}, Verdict: "system-suspicious", Used: "doh"}}
	rep.Big = []BigResult{
		{Provider: "Hetzner", TLS: "1.3", Outcome: outOK, Bytes: 16 << 10, End: "idle-timeout", Freeze: true},
		{Provider: "Hetzner", TLS: "1.2", Outcome: outOK, Bytes: 16 << 10, End: "idle-timeout", Freeze: true},
		{Provider: "OVH", TLS: "1.3", Outcome: outOK, Bytes: freezeLimit, End: "limit"},
		{Provider: "OVH", TLS: "1.2", Outcome: outNoAddr, Detail: noRealAddr},
	}
	rep.Speed = []SpeedResult{{TLSResult: TLSResult{Host: "www.youtube.com", Face: "chrome-small", Strategy: "split1", Outcome: outOK, Bytes: 100, Kbps: 12, End: "eof"}}}
	rep.QUIC = []QUICResult{{Host: "www.youtube.com", Variant: "bare", Outcome: outSilence}, {Host: "www.youtube.com", Variant: "blob-n2-ttl3", Outcome: outOK}}
	rep.MTProto = []MTResult{{DC: "DC1", Variant: "obfs", Outcome: outOK}}
	return rep
}

func TestSummary(t *testing.T) {
	text := render(syntheticReport())
	for _, want := range []string{
		"Провайдер: ____", "Город: ____", "Домашний или мобильный: ____",
		"=== Среда ===", "ВНИМАНИЕ. Результаты искажены", "warp-svc",
		"Контроль: без обхода открывается 3 из 3 хостов",
		"YouTube: без обхода открывается 0 из 4 хостов, только способами 4",
		"www.youtube.com: открывается способами: split1 [все лица]",
		"discord.com: не открывается ничем: адрес недоступен, соединения нет",
		"t.me: не открывается ничем: соединение есть, но дальше режут",
		"Discord: без обхода открывается 3 из 4 хостов, не открывается ничем 1",
		"Лучшие способы",
		"oob (ya.ru)",
		"DoH закрыт по адресам (1.1.1.1, 8.8.8.8), но доступен по именам",
		"Зарубежные датацентры: обрыв после ~16 КБ у 1 из 2 (Hetzner)",
		"QUIC www.youtube.com: без подделок не работает (sil), с подделками работают: blob-n2-ttl3",
		"Лицо chrome-small", "Зерно случайных разрезов",
		"Голос Discord", "--- JSON ---",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the report lacks %q", want)
		}
	}
	// the environment section comes first, before the summary
	if strings.Index(text, "=== Среда ===") > strings.Index(text, "=== Сводка ===") {
		t.Error("the environment is not at the top")
	}
	// the JSON block parses and carries the environment
	var back Report
	if err := json.Unmarshal([]byte(text[strings.Index(text, "--- JSON ---")+len("--- JSON ---"):]), &back); err != nil || len(back.TLS) != len(syntheticReport().TLS) || !back.Environment.Distorted {
		t.Errorf("json: %v", err)
	}
}

// Nothing that identifies the machine or its network may end up in a report that is built from real results.
func TestReportHasNoLocalIdentity(t *testing.T) {
	srv, roots := tlsServer(t, true)
	p := testProber(portOf(srv.Listener.Addr()), roots)
	rep := syntheticReport()
	rep.TLS = p.hostMatrix(context.Background(), testHost, loopback)
	dead, _ := net.Listen("tcp4", "127.0.0.1:0")
	port := portOf(dead.Addr())
	dead.Close()
	rep.TLS = append(rep.TLS, testProber(port, nil).hostMatrix(context.Background(), "gone.example", loopback)...)
	rep.MTProto = append(rep.MTProto, testProber(port, nil).mtDC(context.Background(), "DC1", "127.0.0.1", 1)...)
	rep.Big = append(rep.Big, testProber(port, nil).bigFile(context.Background(), bigFile{"Gone", []string{"https://gone.example/x"}}, map[string][]netip.Addr{"gone.example": loopback})...)
	// the real local checks, whose output goes into the report as numbers and words from fixed lists
	rep.Environment.Tools = matchTools(func() []string { l, _ := listProcesses(); return l }())
	if types, err := defaultRouteTypes(); err == nil {
		for _, ty := range types {
			rep.Environment.Routes = append(rep.Environment.Routes, newIfType(ty))
		}
	}
	text := render(rep)

	var secrets []string
	if h, err := os.Hostname(); err == nil {
		secrets = append(secrets, h)
	}
	if u, err := user.Current(); err == nil {
		secrets = append(secrets, u.Username, u.Name)
		if i := strings.LastIndex(u.Username, `\`); i >= 0 {
			secrets = append(secrets, u.Username[i+1:])
		}
	}
	if ifs, err := net.Interfaces(); err == nil {
		for _, ifc := range ifs {
			secrets = append(secrets, ifc.Name)
			if len(ifc.HardwareAddr) > 0 {
				secrets = append(secrets, ifc.HardwareAddr.String())
			}
			addrs, _ := ifc.Addrs()
			for _, a := range addrs {
				if ip, _, err := net.ParseCIDR(a.String()); err == nil && !ip.IsLoopback() {
					secrets = append(secrets, ip.String())
				}
			}
		}
	}
	// A name that is only a piece of the fixed vocabulary (a tool from the list, an interface type word) may appear.
	vocabulary := strings.ToLower(strings.Join(bypassTools, " "))
	for _, w := range ifTypeWords {
		vocabulary += " " + strings.ToLower(w)
	}
	low := strings.ToLower(text)
	for _, s := range secrets {
		if len(s) >= 3 && !strings.Contains(vocabulary, strings.ToLower(s)) && strings.Contains(low, strings.ToLower(s)) {
			t.Errorf("the report contains %q", s)
		}
	}
	if strings.Contains(text, "127.0.0.1:") {
		t.Error("a socket address in the report")
	}
}
