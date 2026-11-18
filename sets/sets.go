// Package sets is the data side of the bypass: one signed file that says which strategies of package dpi to try,
// in what order, on which network (by country), and which host names belong to which service. A service is the
// unit a person sees in a window (a video site, a messenger); its parts are the groups of names that need
// different answers (the site, the video servers, QUIC).
//
// The file, bypass.json, is JSON of at most MaxFileSize bytes, with a detached ed25519 signature (bypass.json.sig,
// base64 of the signature over the exact bytes of the file):
//
//	{
//	  "v": 1, "seq": 7, "date_unix": 1794960000,
//	  "strategies": { "21": "rec:s+2; cut:s+1; oob:0" },     // new strategies; 1-20 are the permanent ones of dpi
//	  "countries": {                                          // two lower-case letters, or "*" for the rest
//	    "ru": { "quick": [6, 16, 8], "quic_off": ["yt"] },    // quick: strategies to try, in order; quic_off: services
//	    "*":  { "quick": [6, 16] }                            //   whose QUIC is refused so that the app falls to TCP
//	  },
//	  "categories": ["popular"],
//	  "services": [
//	    { "id": "yt", "name": "YouTube", "icon": "media-video", "categories": ["popular"],
//	      "parts": [
//	        { "id": "site", "kind": "tls", "domains": ["youtube.com"], "checks": ["https://www.youtube.com/"] },
//	        { "id": "api",  "kind": "tls", "hidden": true, "domains": ["youtubei.googleapis.com"],
//	          "quick": { "ru": [16, 18, 20] } },              // this part's own order, for one country or "*"
//	        { "id": "quic", "kind": "quic-off", "domains": ["youtube.com"] } ] } ],
//	  "controls": { "*": ["https://www.wikipedia.org/"] }     // sites that are open without a bypass, for checks
//	}
//
// A domain matches itself and every name under it. An empty "quick" list of a part (for "*" or one country) says
// that the service has no way: it stays in the catalog, and the window hides it. A part kind the library does not
// know is carried and reported as not supported, so that services and parts can be added by data alone.
// Fields the library does not know are skipped, so that a later file stays readable by this code; an unknown
// "v" is refused.
package sets

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/mistgate/mistgate-bypass/dpi"
)

// ProjectKey is the ed25519 public key (64 hex digits) that downloaded sets must be signed with.
// It is replaced with the key of the project before release. While it is empty Open refuses every file,
// and only the embedded set is in use.
const ProjectKey = ""

// Format version and limits. A file that goes beyond any of them is refused whole.
const (
	Version = 1

	MaxFileSize   = 256 << 10
	MaxServices   = 128
	MaxParts      = 8  // per service
	MaxDomains    = 64 // per part
	MaxChecks     = 8  // per part and per country in "controls"
	MaxCandidates = 32 // per list
	MaxCountries  = 64
	MaxCategories = 32
	MaxCustom     = 64 // strategies written in the file

	// Numbers below FirstCustom are the permanent ladder of dpi (a test keeps this in step with it); numbers
	// from 1000 are what a search on the device finds. A file defines the ones in between.
	FirstCustom = 21
	LastCustom  = 999

	maxName = 48
	maxID   = 32
	maxHost = 253
	maxURL  = 256
)

// Part kinds the library acts on.
const (
	KindTLS     = "tls"      // ordinary TLS over TCP: the strategies apply
	KindQUICOff = "quic-off" // QUIC to these names is refused, so that the app falls back to TCP
)

// Error codes, for the caller to switch on and for logs: they carry no names or addresses.
const (
	CodeNoKey      = "no_key"        // ProjectKey is not set
	CodeBadSig     = "bad_signature" // the signature is missing, malformed or does not match
	CodeTooLarge   = "too_large"
	CodeBadJSON    = "bad_json"
	CodeBadVersion = "bad_version"
	CodeRollback   = "rollback" // seq is below the one already accepted
	CodeBadField   = "bad_field"
	CodeBadSpec    = "bad_spec" // a strategy outside the grammar of dpi
	CodeUnknownRef = "unknown_ref"
	CodeDuplicate  = "duplicate"
	CodeLimit      = "limit"
	CodeNoDefault  = "no_default" // no "*" section
)

// Error is what every function of the package returns on bad input.
type Error struct {
	Code   string
	Detail string
	Err    error // the cause, when there is one (dpi.ErrBadSpec for CodeBadSpec)
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return "sets: " + e.Code
	}
	return "sets: " + e.Code + ": " + e.Detail
}

func (e *Error) Unwrap() error { return e.Err }

// Code is the code of err, or "" when err is not an *Error.
func Code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func fail(code, format string, a ...any) *Error {
	return &Error{Code: code, Detail: fmt.Sprintf(format, a...)}
}

// A Set is a parsed file. It does not change after it is built, so any number of goroutines may use it;
// the slices and maps it hands out are shared and must not be modified.
type Set struct {
	Seq      uint64
	Date     time.Time
	Services []Service
	Controls map[string][]string // sites open without a bypass: a country's own and "*" for the rest

	categories []string
	sections   map[string]section // by country, "*" always present
	index      map[string]entry   // domain -> where it belongs
}

// A Service is a thing a person asks for by name.
type Service struct {
	ID         string
	Name       string // a trade name; not translated
	Icon       string // a hint for the window, which has its own pictures
	Categories []string
	Parts      []Part
}

// A Part is a group of names of a service that get one answer.
type Part struct {
	ID      string
	Kind    string
	Hidden  bool // the engine uses it, the window does not show it
	Domains []string
	Checks  []string // addresses that tell whether the part opens

	quick map[string][]dpi.Strategy // own order by country or "*"; absent means the order of the country
}

// Supported says whether the library acts on the part; a part that is not shows as "soon" in the window.
func (p *Part) Supported() bool { return p.Kind == KindTLS || p.Kind == KindQUICOff }

type section struct {
	quick   []dpi.Strategy
	quicOff map[string]bool // service ids
}

// entry is where a domain belongs: the service and its ordinary part, and its quic-off part when it has one.
// part is the quic-off part when that is all the domain has.
type entry struct{ svc, part, quic int }

// Open checks the signature of a downloaded file with ProjectKey and reads it. cur is the seq of the set
// already in use, at least that of Embedded(): a file with a lower one is refused, so that an old file that was
// signed once cannot be put back.
func Open(data, sig []byte, cur uint64) (*Set, error) {
	key, err := hex.DecodeString(ProjectKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, fail(CodeNoKey, "the project key is not set")
	}
	return OpenWith(key, data, sig, cur)
}

// OpenWith is Open with another key; the tests and any tool that checks a file before it is published use it.
func OpenWith(key ed25519.PublicKey, data, sig []byte, cur uint64) (*Set, error) {
	if len(data) > MaxFileSize {
		return nil, fail(CodeTooLarge, "over %d bytes", MaxFileSize)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if len(key) != ed25519.PublicKeySize || err != nil || len(raw) != ed25519.SignatureSize || !ed25519.Verify(key, data, raw) {
		// The signature is checked before the file is looked at: nothing that is not the project's is parsed.
		return nil, fail(CodeBadSig, "")
	}
	s, err := parse(data)
	if err != nil {
		return nil, err
	}
	if s.Seq < cur {
		return nil, fail(CodeRollback, "seq %d is below %d", s.Seq, cur)
	}
	return s, nil
}

type fileJSON struct {
	Seq        uint64                 `json:"seq"`
	Date       int64                  `json:"date_unix"`
	Strategies map[string]string      `json:"strategies"`
	Countries  map[string]sectionJSON `json:"countries"`
	Categories []string               `json:"categories"`
	Services   []serviceJSON          `json:"services"`
	Controls   map[string][]string    `json:"controls"`
}

type sectionJSON struct {
	Quick   []int    `json:"quick"`
	QUICOff []string `json:"quic_off"`
}

type serviceJSON struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Icon       string     `json:"icon"`
	Categories []string   `json:"categories"`
	Parts      []partJSON `json:"parts"`
}

type partJSON struct {
	ID      string           `json:"id"`
	Kind    string           `json:"kind"`
	Hidden  bool             `json:"hidden"`
	Domains []string         `json:"domains"`
	Checks  []string         `json:"checks"`
	Quick   map[string][]int `json:"quick"`
}

// parse reads a file whose origin has been settled by the caller: Open has checked the signature, and the
// embedded file is part of the program itself.
func parse(data []byte) (*Set, error) {
	if len(data) > MaxFileSize {
		return nil, fail(CodeTooLarge, "over %d bytes", MaxFileSize)
	}
	// The version first and alone: a later format may not fit the types below, and that is not "bad JSON".
	var head struct {
		V int `json:"v"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return nil, &Error{Code: CodeBadJSON, Err: err}
	}
	if head.V != Version {
		return nil, fail(CodeBadVersion, "version %d", head.V)
	}
	var f fileJSON
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, &Error{Code: CodeBadJSON, Err: err}
	}
	if f.Seq == 0 || f.Date < 0 {
		return nil, fail(CodeBadField, "seq and date")
	}
	s := &Set{Seq: f.Seq, Date: time.Unix(f.Date, 0).UTC(), Controls: map[string][]string{}, index: map[string]entry{}}

	if len(f.Categories) > MaxCategories {
		return nil, fail(CodeLimit, "%d categories", len(f.Categories))
	}
	for _, c := range f.Categories {
		if !validID(c) || slices.Contains(s.categories, c) {
			return nil, fail(CodeBadField, "category %q", c)
		}
		s.categories = append(s.categories, c)
	}
	strats, err := buildStrategies(f.Strategies)
	if err != nil {
		return nil, err
	}
	if err := s.addServices(f.Services, strats); err != nil {
		return nil, err
	}
	if err := s.addSections(f.Countries, strats); err != nil {
		return nil, err
	}
	if len(f.Controls) > MaxCountries {
		return nil, fail(CodeLimit, "%d controls", len(f.Controls))
	}
	for c, urls := range f.Controls {
		if !validCountry(c) || len(urls) > MaxChecks {
			return nil, fail(CodeBadField, "controls %q", c)
		}
		for _, u := range urls {
			if !validURL(u) {
				return nil, fail(CodeBadField, "control address %q", u)
			}
		}
		s.Controls[c] = urls
	}
	return s, nil
}

// buildStrategies gives every number a file may use: the permanent ones of dpi and the ones the file defines.
func buildStrategies(custom map[string]string) (map[int]dpi.Strategy, error) {
	if len(custom) > MaxCustom {
		return nil, fail(CodeLimit, "%d strategies", len(custom))
	}
	all := map[int]dpi.Strategy{}
	for _, st := range dpi.Ladder() {
		all[st.Num] = st
	}
	for k, spec := range custom {
		n, err := strconv.Atoi(k)
		if err != nil || n < FirstCustom || n > LastCustom || strconv.Itoa(n) != k {
			return nil, fail(CodeBadField, "strategy number %q (%d to %d are free)", k, FirstCustom, LastCustom)
		}
		if strings.TrimSpace(spec) == "" {
			return nil, fail(CodeBadSpec, "strategy %d is empty", n)
		}
		st, err := dpi.NewStrategy(n, "set"+k, spec, dpi.DefaultSeed)
		if err != nil {
			return nil, &Error{Code: CodeBadSpec, Detail: fmt.Sprintf("strategy %d", n), Err: err}
		}
		all[n] = st
	}
	return all, nil
}

// list turns numbers into strategies. Plain (1) is not a candidate: the engine always tries it first.
func list(nums []int, strats map[int]dpi.Strategy) ([]dpi.Strategy, error) {
	if len(nums) > MaxCandidates {
		return nil, fail(CodeLimit, "%d candidates in a list", len(nums))
	}
	out := make([]dpi.Strategy, 0, len(nums))
	for i, n := range nums {
		st, ok := strats[n]
		switch {
		case !ok:
			return nil, fail(CodeUnknownRef, "strategy %d", n)
		case n == 1:
			return nil, fail(CodeBadField, "plain is not a candidate")
		case slices.Contains(nums[:i], n):
			return nil, fail(CodeDuplicate, "strategy %d twice in a list", n)
		}
		out = append(out, st)
	}
	return out, nil
}

func (s *Set) addServices(in []serviceJSON, strats map[int]dpi.Strategy) error {
	if len(in) > MaxServices {
		return fail(CodeLimit, "%d services", len(in))
	}
	for si, sv := range in {
		if !validID(sv.ID) || !validName(sv.Name) || (sv.Icon != "" && !validID(sv.Icon)) {
			return fail(CodeBadField, "service %d", si)
		}
		if slices.ContainsFunc(s.Services, func(o Service) bool { return o.ID == sv.ID }) {
			return fail(CodeDuplicate, "service %q", sv.ID)
		}
		if len(sv.Parts) == 0 || len(sv.Parts) > MaxParts {
			return fail(CodeLimit, "service %q has %d parts", sv.ID, len(sv.Parts))
		}
		out := Service{ID: sv.ID, Name: sv.Name, Icon: sv.Icon, Categories: sv.Categories}
		for i, c := range sv.Categories {
			if !slices.Contains(s.categories, c) || slices.Contains(sv.Categories[:i], c) {
				return fail(CodeUnknownRef, "service %q: category %q", sv.ID, c)
			}
		}
		for pi, pt := range sv.Parts {
			if !validID(pt.ID) || !validID(pt.Kind) || slices.ContainsFunc(out.Parts, func(o Part) bool { return o.ID == pt.ID }) {
				return fail(CodeBadField, "service %q: part %d", sv.ID, pi)
			}
			if len(pt.Domains) > MaxDomains || len(pt.Checks) > MaxChecks || len(pt.Quick) > MaxCountries {
				return fail(CodeLimit, "service %q: part %q", sv.ID, pt.ID)
			}
			for _, u := range pt.Checks {
				if !validURL(u) {
					return fail(CodeBadField, "service %q: check address of part %q", sv.ID, pt.ID)
				}
			}
			p := Part{ID: pt.ID, Kind: pt.Kind, Hidden: pt.Hidden, Domains: pt.Domains, Checks: pt.Checks}
			if len(pt.Quick) > 0 {
				p.quick = map[string][]dpi.Strategy{}
				for c, nums := range pt.Quick {
					if !validCountry(c) {
						return fail(CodeBadField, "service %q: part %q: country %q", sv.ID, pt.ID, c)
					}
					l, err := list(nums, strats)
					if err != nil {
						return fmt.Errorf("service %q: part %q: %w", sv.ID, pt.ID, err)
					}
					p.quick[c] = l
				}
			}
			for _, d := range pt.Domains {
				if err := s.addDomain(d, si, pi, &p); err != nil {
					return err
				}
			}
			out.Parts = append(out.Parts, p)
		}
		s.Services = append(s.Services, out)
	}
	return nil
}

// addDomain files d under service si, part pi. A name belongs to one service; inside it to one ordinary part
// and one quic-off part, which is how the same name is a site and a QUIC target at once.
func (s *Set) addDomain(d string, si, pi int, p *Part) error {
	if !validDomain(d) {
		return fail(CodeBadField, "domain %q", d)
	}
	e, seen := s.index[d]
	if !seen {
		e = entry{svc: si, part: -1, quic: -1}
	}
	if e.svc != si {
		return fail(CodeDuplicate, "domain %q in two services", d)
	}
	slot := &e.part
	if p.Kind == KindQUICOff {
		slot = &e.quic
	}
	if *slot >= 0 {
		return fail(CodeDuplicate, "domain %q in two parts", d)
	}
	*slot = pi
	s.index[d] = e
	return nil
}

func (s *Set) addSections(in map[string]sectionJSON, strats map[int]dpi.Strategy) error {
	if len(in) > MaxCountries {
		return fail(CodeLimit, "%d countries", len(in))
	}
	if _, ok := in["*"]; !ok {
		return fail(CodeNoDefault, "")
	}
	s.sections = map[string]section{}
	for c, sc := range in {
		if !validCountry(c) {
			return fail(CodeBadField, "country %q", c)
		}
		l, err := list(sc.Quick, strats)
		if err != nil {
			return fmt.Errorf("country %q: %w", c, err)
		}
		sec := section{quick: l, quicOff: map[string]bool{}}
		for _, id := range sc.QUICOff {
			if !slices.ContainsFunc(s.Services, func(o Service) bool { return o.ID == id }) {
				return fail(CodeUnknownRef, "country %q: quic_off names service %q", c, id)
			}
			sec.quicOff[id] = true
		}
		s.sections[c] = sec
	}
	return nil
}

func validCountry(c string) bool {
	return c == "*" || (len(c) == 2 && c[0] >= 'a' && c[0] <= 'z' && c[1] >= 'a' && c[1] <= 'z')
}

// validID: lower-case letters, digits, "-" and "_"; the ids are keys the window translates.
func validID(s string) bool {
	if s == "" || len(s) > maxID {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func validName(s string) bool {
	return s != "" && len(s) <= maxName && utf8.ValidString(s) && !strings.ContainsFunc(s, unicode.IsControl)
}

// validDomain: a lower-case name in ASCII form (xn-- for IDN) of at least two labels, so that no entry can take
// a whole top-level domain, and not an address.
func validDomain(d string) bool {
	if len(d) > maxHost || strings.Count(d, ".") < 1 {
		return false
	}
	labels := strings.Split(d, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	last := labels[len(labels)-1]
	return strings.IndexFunc(last, func(r rune) bool { return r < '0' || r > '9' }) >= 0
}

func validURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && len(s) <= maxURL && u.Scheme == "https" && u.Hostname() != "" && u.User == nil
}
