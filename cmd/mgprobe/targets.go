package main

import (
	_ "embed"
	"time"
)

const (
	version    = "3"
	reportName = "mgprobe-report.txt"

	// probeSeed fixes the random cut points of the strategies, so a run can be repeated; the report states it.
	probeSeed = 20261117

	noRealAddr = "настоящий адрес получить не удалось"
)

// service groups the hosts that must all work for the service to be usable.
type service struct {
	Name  string
	Hosts []string
}

// services is the one list of TLS hosts the probe walks. The first group is the control: sites that are not
// expected to be affected by anything, so a strategy that breaks them is a bad strategy.
var services = []service{
	{"Контроль", []string{"www.wikipedia.org", "www.microsoft.com", "ya.ru"}},
	{"YouTube", []string{"www.youtube.com", "i.ytimg.com", "redirector.googlevideo.com", "youtubei.googleapis.com"}},
	{"Discord", []string{"discord.com", "gateway.discord.gg", "cdn.discordapp.com", "media.discordapp.net"}},
	{"Telegram (веб)", []string{"web.telegram.org", "t.me", "api.telegram.org"}},
}

// speedTarget is a download measured on the best working strategy of its host (plain for the control).
type speedTarget struct {
	Host, Path string
	Control    bool
}

var speedTargets = []speedTarget{
	{"www.youtube.com", "/", false},
	{"i.ytimg.com", "/vi/dQw4w9WgXcQ/maxresdefault.jpg", false},
	{"en.wikipedia.org", "/wiki/Earth", true},
}

// quicHosts are probed over HTTP/3; the first one is the service under test, the rest only show whether UDP 443
// works at all.
var quicHosts = []string{"www.youtube.com", "www.google.com", "cloudflare.com"}

// telegramDCs are the public data-centre addresses that client libraries ship with. They are written down from
// those public lists and can go stale; a dead one shows as a failure for that DC only.
var telegramDCs = []struct {
	Name, Addr string
}{
	{"DC1", "149.154.175.53"},
	{"DC2", "149.154.167.51"},
	{"DC3", "149.154.175.100"},
	{"DC4", "149.154.167.91"},
	{"DC5", "91.108.56.130"},
}

// dohEndpoint is a DNS-over-HTTPS server (RFC 8484, wire format). Some are reached by address and some by name, to tell
// a server blocked by its address from one that cannot be reached at all.
type dohEndpoint struct {
	Name, URL string
	ByAddr    bool
}

// publicDNS are well-known resolvers asked over plain UDP when no DNS-over-HTTPS server answers. A network may
// intercept port 53, so their answer is a second opinion, not the truth; a stub address from them is not used.
var publicDNS = []string{"8.8.8.8", "1.1.1.1", "9.9.9.9", "77.88.8.8"}

// dohEndpoints are probed once; the ones that answer serve the name lookups, in this order.
var dohEndpoints = []dohEndpoint{
	{"1.1.1.1", "https://1.1.1.1/dns-query", true},
	{"8.8.8.8", "https://8.8.8.8/dns-query", true},
	{"cloudflare-dns.com", "https://cloudflare-dns.com/dns-query", false},
	{"dns.google", "https://dns.google/dns-query", false},
	{"dns.quad9.net", "https://dns.quad9.net/dns-query", false},
	{"dns.adguard-dns.com", "https://dns.adguard-dns.com/dns-query", false},
}

// Strict timeouts keep the whole run under six minutes.
const (
	dialTimeout   = 3 * time.Second
	handshakeTime = 4 * time.Second // from connect to the end of the TLS handshake
	responseTime  = 5 * time.Second // from the request to the response headers
	bodyTime      = 6 * time.Second
	bodyLimit     = 64 << 10
	speedTime     = 8 * time.Second
	speedLimit    = 1 << 20
	quicTime      = 5 * time.Second
	mtprotoTime   = 5 * time.Second
	dohTime       = 3 * time.Second
)

// quicFakeBlob is a captured QUIC Initial datagram (1200 bytes) used as decoy content.
// Source: zapret2 by bol-van, files/fake/quic_initial_www_google_com.bin, MIT License (see fake/LICENSE.zapret2.txt).
//
//go:embed fake/quic_initial_www_google_com.bin
var quicFakeBlob []byte

// bigFile is a test file at a foreign hosting provider, with a spare address tried when the first gives nothing.
// The addresses are the providers' published test files, checked to answer on 2026-11-17: a dead one shows as "not
// tested" for that provider.
type bigFile struct {
	Name string
	URLs []string
}

var bigFiles = []bigFile{
	{"Hetzner", []string{"https://fsn1-speed.hetzner.com/100MB.bin", "https://hel1-speed.hetzner.com/100MB.bin"}},
	{"OVH", []string{"https://proof.ovh.net/files/100Mb.dat", "https://proof.ovh.ca/files/100Mb.dat"}},
	{"Vultr", []string{"https://fra-de-ping.vultr.com/vultr.com.100MB.bin", "https://ams-nl-ping.vultr.com/vultr.com.100MB.bin"}},
	{"DataPacket", []string{"https://fra.download.datapacket.com/100mb.bin"}},
	{"Scaleway", []string{"https://scaleway.testdebit.info/100M.iso"}},
	{"Google Cloud", []string{"https://storage.googleapis.com/gcp-public-data-landsat/index.csv.gz"}},
	{"Cloudflare", []string{"https://speed.cloudflare.com/__down?bytes=1000000", "https://speed.cloudflare.com/__down?during=download&bytes=1000000"}},
}

const (
	freezeLimit = 256 << 10
	freezeIdle  = 8 * time.Second
	freezeTotal = 20 * time.Second
	// A transfer that stops for good between these sizes shows the stall that sets in after about 16 KB.
	freezeFrom = 8 << 10
	freezeTo   = 40 << 10
)

// bypassTools are the program names (without .exe, lower case) of known bypass tools, proxies and VPN clients.
// A running one changes what the probe measures, so only the matching names go into the report.
var bypassTools = []string{"winws", "winws2", "goodbyedpi", "ciadpi", "byedpi", "spoofdpi", "zapret", "warp-svc", "tailscaled",
	"wireguard", "openvpn", "amneziavpn", "amneziawg", "mistgate-clientd", "sing-box", "xray", "v2ray", "v2rayn", "nekoray",
	"nekobox", "hiddify", "clash", "mihomo", "clash-verge", "outline", "psiphon", "lantern", "tor", "proxifier", "happ",
	"throne", "karing",
	// as the programs are named on macOS and Linux
	"cloudflarewarp", "cloudflare warp", "wireguard-go", "tailscale", "ipnextension", "tunnelblick", "viscosity", "clashx",
	"clashx pro", "clashx meta", "clash verge", "clash-verge-service", "v2rayu", "v2box", "v2raya", "shadowrocket", "surge",
	"foxray", "streisand", "tpws", "nfqws", "nfqws2", "dvtws", "dvtws2", "openvpn connect", "protonvpn", "nordvpn",
	"mullvad vpn", "expressvpn", "adguard vpn", "outline client"}
