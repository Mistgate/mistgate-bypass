package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"regexp"
)

// Outcomes of one connection attempt. The names are what the report prints and what the JSON holds.
const (
	outOK          = "ok"
	outConnTimeout = "connect-timeout" // no answer to the SYN: looks like a block by address
	outRefused     = "connect-refused"
	outReset       = "reset"         // RST after the first bytes went out
	outClosed      = "closed"        // clean FIN where an answer was due
	outSilence     = "silence"       // connected, then nothing until the timeout
	outAlert       = "tls-alert"     // the peer answered with a TLS alert
	outCert        = "cert-mismatch" // a certificate that does not belong to the host: an answer from someone else
	outOther       = "other"
	outSkipped     = "skipped"
	outNoAddr      = "no-address"
)

// classify turns a network or TLS error into an outcome and a short text that is safe to put in the report.
func classify(err error) (outcome, detail string) {
	detail = scrub(err.Error())
	var (
		cv *tls.CertificateVerificationError
		hn x509.HostnameError
		ua x509.UnknownAuthorityError
		ci x509.CertificateInvalidError
		oe *net.OpError
		ne net.Error
	)
	switch {
	case errors.As(err, &cv), errors.As(err, &hn), errors.As(err, &ua), errors.As(err, &ci):
		return outCert, detail
	case errors.As(err, &oe) && oe.Op == "remote error": // an alert received from the peer
		return outAlert, detail
	case isRefused(err):
		return outRefused, detail
	case isReset(err):
		return outReset, detail
	case errors.As(err, &ne) && ne.Timeout():
		return outSilence, detail
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return outClosed, detail
	}
	return outOther, detail
}

var addrRE = regexp.MustCompile(`\[?(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4}\]?(?::\d+)?|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?`)

// scrub removes network addresses from an error text: Go puts the local address and the resolver in them, and
// the report must not carry either.
func scrub(s string) string { return addrRE.ReplaceAllString(s, "<addr>") }
