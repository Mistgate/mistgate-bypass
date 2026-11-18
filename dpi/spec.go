package dpi

import (
	"errors"
	"fmt"
	"math/rand"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// A Spec is a strategy written as data, so that sets of strategies can arrive in a file instead of in code:
//
//	spec = item *( ";" item )
//	item = "rec:" pos *("," pos)     cut the first TLS record into records at these places
//	     | "cut:" pos *("," pos)     TCP piece boundaries
//	     | "eq:" n                   n equal pieces over the name and two bytes around it
//	     | "labels:" ms              one cut inside every label of the name, ms of pause between the pieces
//	     | "recmulti:" ("0"|"pause") the first record cut at random into 3-6 records; "0" sends them in one write,
//	                                 "pause" one write per record with a short random pause
//	     | "oob:" i *("," i)         one urgent byte after piece i
//	     | "delay:" ms               pause before every piece but the first
//	     | "ttl1:" i *("," i)        pieces sent with TTL 1
//	pos  = base [("+"|"-") int]      base = "s" | "se" | "m" | "sni" | int
//
// s is the first byte of the host name, se the byte after its last one, m the middle of its second-level label,
// sni the first byte of the server_name extension. Every position counts in the ClientHello as the application
// wrote it: the 5 bytes of each record header that "rec" adds are accounted for by the code, not by the author, so
// a cut keeps its place in the text however many records are added before it. Piece numbers count the pieces
// of the stream only, urgent bytes not included. Places outside the packet are dropped, as they always were.
// The empty spec sends the first write as it is.
type Spec []item

type item struct {
	kind string
	pos  []pos // rec, cut
	n    []int // everything else; recmulti: 0 or 1 for "0" or "pause"
}

type pos struct {
	base string // "" for a plain number, else s, se, m or sni
	off  int
}

// kinds in the order they are printed and applied.
var kinds = []string{"rec", "recmulti", "cut", "eq", "labels", "oob", "delay", "ttl1"}

const (
	maxNum   = 1 << 20 // bounds every number, so that sums of them cannot overflow
	maxList  = 64
	maxPause = 10_000 // ms; a set must not be able to hold a connection for long
	maxSpec  = 1024
)

// ErrBadSpec is wrapped by every error ParseSpec returns.
var ErrBadSpec = errors.New("dpi: bad strategy spec")

// ParseSpec reads the text form. It never panics; anything that is not in the grammar is an error.
func ParseSpec(s string) (Spec, error) {
	if len(s) > maxSpec {
		return nil, fmt.Errorf("%w: longer than %d bytes", ErrBadSpec, maxSpec)
	}
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var sp Spec
	for _, raw := range strings.Split(s, ";") {
		it, err := parseItem(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %v", ErrBadSpec, strings.TrimSpace(raw), err)
		}
		if slices.ContainsFunc(sp, func(o item) bool { return o.kind == it.kind }) {
			return nil, fmt.Errorf("%w: %q twice", ErrBadSpec, it.kind)
		}
		sp = append(sp, it)
	}
	// One order for the same strategy however it was written, so that printing is a canonical form.
	sort.SliceStable(sp, func(i, j int) bool { return slices.Index(kinds, sp[i].kind) < slices.Index(kinds, sp[j].kind) })
	if len(sp) > 1 && slices.ContainsFunc(sp, func(it item) bool { return it.kind == "recmulti" }) {
		return nil, fmt.Errorf("%w: recmulti cannot be combined with other items", ErrBadSpec)
	}
	return sp, nil
}

func parseItem(s string) (item, error) {
	kind, arg, ok := strings.Cut(s, ":")
	kind = strings.TrimSpace(kind)
	if !ok || !slices.Contains(kinds, kind) {
		return item{}, errors.New("unknown item")
	}
	args := strings.Split(arg, ",")
	if len(args) > maxList {
		return item{}, errors.New("too many values")
	}
	for i := range args {
		args[i] = strings.TrimSpace(args[i])
	}
	it := item{kind: kind}
	switch kind {
	case "rec", "cut":
		for _, a := range args {
			p, err := parsePos(a)
			if err != nil {
				return item{}, err
			}
			it.pos = append(it.pos, p)
		}
	case "recmulti":
		if len(args) != 1 || (args[0] != "0" && args[0] != "pause") {
			return item{}, errors.New(`want "0" or "pause"`)
		}
		it.n = []int{map[string]int{"0": 0, "pause": 1}[args[0]]}
	default: // eq, labels, delay, oob, ttl1: numbers
		for _, a := range args {
			v, err := parseNum(a)
			if err != nil {
				return item{}, err
			}
			it.n = append(it.n, v)
		}
		switch kind {
		case "eq", "labels", "delay":
			if len(it.n) != 1 {
				return item{}, errors.New("want one number")
			}
		default: // piece numbers: ascending, each once, so that printing is canonical
			sort.Ints(it.n)
			it.n = slices.Compact(it.n)
		}
		if kind == "eq" && (it.n[0] < 1 || it.n[0] > maxList) {
			return item{}, fmt.Errorf("want 1 to %d pieces", maxList)
		}
		if (kind == "labels" || kind == "delay") && it.n[0] > maxPause {
			return item{}, fmt.Errorf("pause over %d ms", maxPause)
		}
	}
	return it, nil
}

func parseNum(s string) (int, error) {
	if s == "" || s[0] < '0' || s[0] > '9' {
		return 0, fmt.Errorf("%q is not a number", s)
	}
	v, err := strconv.Atoi(s)
	if err != nil || v > maxNum {
		return 0, fmt.Errorf("%q is not a number in range", s)
	}
	return v, nil
}

func parsePos(s string) (pos, error) {
	base, rest := s, ""
	if i := strings.IndexAny(s, "+-"); i >= 0 {
		base, rest = s[:i], s[i:]
	}
	var p pos
	switch base {
	case "s", "se", "m", "sni":
		p.base = base
	default:
		v, err := parseNum(base)
		if err != nil {
			return pos{}, err
		}
		p.off = v
	}
	if rest != "" {
		v, err := parseNum(rest[1:])
		if err != nil {
			return pos{}, err
		}
		if rest[0] == '-' {
			v = -v
		}
		p.off += v
	}
	if p.base == "" && p.off < 0 {
		return pos{}, errors.New("negative place")
	}
	return p, nil
}

// String is the canonical text: ParseSpec(sp.String()) gives sp back.
func (sp Spec) String() string {
	parts := make([]string, len(sp))
	for i, it := range sp {
		var vals []string
		for _, p := range it.pos {
			vals = append(vals, p.String())
		}
		for _, v := range it.n {
			vals = append(vals, strconv.Itoa(v))
		}
		if it.kind == "recmulti" {
			vals = []string{[]string{"0", "pause"}[it.n[0]]}
		}
		parts[i] = it.kind + ":" + strings.Join(vals, ",")
	}
	return strings.Join(parts, "; ")
}

func (p pos) String() string {
	switch {
	case p.base == "":
		return strconv.Itoa(p.off)
	case p.off == 0:
		return p.base
	case p.off > 0:
		return p.base + "+" + strconv.Itoa(p.off)
	}
	return p.base + strconv.Itoa(p.off)
}

func (p pos) at(h Hello) int {
	switch p.base {
	case "s":
		return h.HostStart + p.off
	case "se":
		return h.HostEnd + p.off
	case "m":
		return h.MidSLD + p.off
	case "sni":
		return h.SNIExt + p.off
	}
	return p.off
}

// Experimental says whether the strategy depends on how the path treats a segment with a low TTL.
func (sp Spec) Experimental() bool {
	return slices.ContainsFunc(sp, func(it item) bool { return it.kind == "ttl1" })
}

// plan applies the spec to a ClientHello that has been parsed as h.
func (sp Spec) plan(b []byte, h Hello, r *rand.Rand) Plan {
	if len(sp) == 1 && sp[0].kind == "recmulti" {
		p := recMulti(b, h, r, sp[0].n[0] == 1)
		if sp[0].n[0] == 0 {
			var all []byte
			for _, c := range p {
				all = append(all, c.Data...)
			}
			return Plan{{Data: all}}
		}
		return p
	}
	var rec, at, oob, ttl []int
	var pause time.Duration
	for _, it := range sp {
		var places []int
		for _, p := range it.pos {
			places = append(places, p.at(h))
		}
		switch it.kind {
		case "rec":
			for _, o := range places {
				if o > 5 && o < h.Rec0End {
					rec = append(rec, o)
				}
			}
			sort.Ints(rec)
			rec = slices.Compact(rec)
		case "cut":
			at = append(at, places...)
		case "eq":
			at = append(at, equalCuts(h, it.n[0])...)
		case "labels":
			at = append(at, labelCuts(b, h, r)...)
			pause = time.Duration(it.n[0]) * time.Millisecond
		case "delay": // after "labels" in the order of kinds, so it wins
			pause = time.Duration(it.n[0]) * time.Millisecond
		case "oob":
			oob = it.n
		case "ttl1":
			ttl = it.n
		}
	}
	data := b
	if len(rec) > 0 {
		data = splitRecords(b, h, rec)
		// A cut is written against the hello as it was: each record header added before it moves it by 5.
		for i, o := range at {
			at[i] = o + 5*sort.SearchInts(rec, o)
		}
	}
	sort.Ints(at)
	p := cut(data, at...)
	if pause > 0 {
		p = delayed(p, pause)
	}
	for _, i := range ttl {
		if i < len(p) {
			p[i].TTL = 1
		}
	}
	if len(oob) == 0 {
		return p
	}
	var out Plan
	for i, c := range p {
		out = append(out, c)
		if slices.Contains(oob, i) {
			out = append(out, Chunk{Data: []byte{oobByte}, OOB: true})
		}
	}
	return out
}

// labelCuts picks one place inside every label of the name that is longer than one byte.
func labelCuts(b []byte, h Hello, r *rand.Rand) []int {
	var at []int
	for p := h.HostStart; p < h.HostEnd; {
		end := p
		for end < h.HostEnd && b[end] != '.' {
			end++
		}
		if end-p > 1 {
			at = append(at, p+1+r.Intn(end-p-1))
		}
		p = end + 1
	}
	return at
}
