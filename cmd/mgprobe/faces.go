package main

import (
	"context"
	"crypto/x509"
	"net"

	utls "github.com/refraction-networking/utls"
)

// A face is the ClientHello the probe presents. The network may treat a browser-like hello, a small one and a
// TLS 1.2 one differently: a large hello (post-quantum key share) does not fit in one TCP segment, and some
// paths only let TLS 1.2 through.
type face struct {
	Name string
	make func() (utls.ClientHelloID, *utls.ClientHelloSpec) // spec is nil for a stock id
}

var (
	// smallID is the newest Chrome id of uTLS without a post-quantum key share: its hello is about 500 bytes.
	smallID = utls.HelloChrome_120

	faces = []face{
		{"chrome", func() (utls.ClientHelloID, *utls.ClientHelloSpec) { return utls.HelloChrome_Auto, nil }},
		{"chrome-small", func() (utls.ClientHelloID, *utls.ClientHelloSpec) { return smallID, nil }},
		{"tls12", tls12Spec},
	}
)

// tls12Spec is the small hello with everything that only exists in TLS 1.3 taken out and the maximum set to 1.2.
func tls12Spec() (utls.ClientHelloID, *utls.ClientHelloSpec) {
	spec, err := utls.UTLSIdToSpec(smallID)
	if err != nil {
		panic(err) // the id is a constant of the library
	}
	exts := spec.Extensions[:0:0]
	for _, e := range spec.Extensions {
		switch e.(type) {
		case *utls.SupportedVersionsExtension, *utls.KeyShareExtension, *utls.PSKKeyExchangeModesExtension,
			*utls.GREASEEncryptedClientHelloExtension, *utls.ApplicationSettingsExtension:
			continue
		}
		exts = append(exts, e)
	}
	spec.Extensions = exts
	var suites []uint16
	for _, c := range spec.CipherSuites {
		if c < 0x1301 || c > 0x1303 {
			suites = append(suites, c)
		}
	}
	spec.CipherSuites = suites
	spec.TLSVersMin, spec.TLSVersMax = utls.VersionTLS12, utls.VersionTLS12
	return utls.HelloCustom, &spec
}

func faceByName(name string) face {
	for _, f := range faces {
		if f.Name == name {
			return f
		}
	}
	return faces[0]
}

// client wraps conn in a uTLS client that presents this face; the caller runs the handshake.
func (f face) client(conn net.Conn, host string, roots *x509.CertPool) (*utls.UConn, error) {
	id, spec := f.make()
	uc := utls.UClient(conn, &utls.Config{ServerName: host, RootCAs: roots}, id)
	if spec != nil {
		if err := uc.ApplyPreset(spec); err != nil {
			return nil, err
		}
	}
	return uc, nil
}

// handshake is client followed by the handshake itself.
func (f face) handshake(ctx context.Context, conn net.Conn, host string, roots *x509.CertPool) (*utls.UConn, error) {
	uc, err := f.client(conn, host, roots)
	if err != nil {
		return nil, err
	}
	return uc, uc.HandshakeContext(ctx)
}
