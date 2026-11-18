package dpi

import (
	"hash/fnv"
	"math/rand"
	"slices"
	"time"
)

// Chunk is one write of a send plan.
type Chunk struct {
	Data  []byte
	Delay time.Duration // pause before this chunk
	OOB   bool          // send as urgent (MSG_OOB) data
	TTL   int           // IP TTL for this chunk; 0 keeps the connection's own
}

// Plan is the ordered writes that replace the first write of a connection.
type Plan []Chunk

// Strategy is a named way of cutting the first write of a connection.
type Strategy struct {
	Num          int // permanent number: the column of the strategy in every report; never reused
	Name         string
	Experimental bool // depends on how the path handles a low-TTL segment; may do nothing or stall
	seed         int64
	spec         Spec
}

const (
	oobByte = 'a' // never reaches the application on a peer that keeps urgent data out of the stream

	// DefaultSeed is the seed Ladder uses for the strategies that draw random cut points.
	DefaultSeed = 1
)

// NewStrategy builds a strategy from the text form of a Spec. The random cut points of the spec depend only on
// seed and the server name.
func NewStrategy(num int, name, spec string, seed int64) (Strategy, error) {
	sp, err := ParseSpec(spec)
	if err != nil {
		return Strategy{}, err
	}
	return Strategy{Num: num, Name: name, Experimental: sp.Experimental(), seed: seed, spec: sp}, nil
}

// Spec is the description the strategy was built from.
func (s Strategy) Spec() Spec { return s.spec }

// Plan turns the bytes of a first write (a TLS ClientHello) into the writes to make. Input that is not a
// ClientHello with its name inside the first record is sent as it is: a strategy cannot cut what it cannot find.
// Random choices depend only on the strategy's seed and the server name, so one name always gets the same cuts.
func (s Strategy) Plan(hello []byte) Plan {
	plain := Plan{{Data: hello}}
	if len(s.spec) == 0 {
		return plain
	}
	h, err := ParseClientHello(hello)
	if err != nil || h.MidSLD >= h.Rec0End || h.Rec0End > len(hello) {
		return plain
	}
	f := fnv.New64a()
	f.Write([]byte(h.ServerName))
	return s.spec.plan(hello, h, rand.New(rand.NewSource(s.seed^int64(f.Sum64()))))
}

// The strategies from the cheapest to the most intrusive; a strategy's number is its place here, from 1.
// Never reorder or insert: the numbers are what the reports already collected call the strategies.
// The ones with TTL 1 lose some pieces on the way and TCP sends them again after the pieces that follow, so the
// path sees the pieces swapped; a loopback or a one-hop path does not drop them.
var ladder = []struct{ name, spec string }{
	{"plain", ""},
	{"tlsrec", "rec:m"},
	{"split1", "cut:1"},
	{"splitsni", "cut:m"},
	{"splitsni-delay", "cut:m; delay:100"},
	{"tlsrec+split", "rec:m; cut:s"},
	{"multisplit", "cut:1,m"},
	{"oob", "cut:m; oob:0"},
	// Records cut at random places from the start of the handshake, as a record-fragmenting proxy does.
	{"rec-multi-nodelay", "recmulti:0"},
	// One TCP cut inside every label of the name, with a short pause between the pieces.
	{"labels", "labels:30"},
	// Equal pieces over the name and two bytes around it: two pieces are not enough for some middleboxes.
	{"split5", "eq:5"},
	{"split7", "eq:7"},
	{"ladder8", "cut:s+1,s+3,s+6,s+9,s+12,s+15,s+20,s+30"},
	{"rec-multi", "recmulti:pause"},
	{"oob1+rec-5se", "rec:se-5; cut:1; oob:0"},
	{"oob1+ladder8", "cut:1,s+1,s+3,s+6,s+9,s+12,s+15,s+20,s+30; oob:0"},
	{"disorder-ttl", "cut:m; ttl1:0"},
	// Record cut at s+1; the first byte of the stream is the one that gets lost.
	{"rec1s+disorder1", "rec:s+1; cut:1; ttl1:0"},
	// The piece from s+1 to s+3 is the lost one, so the retransmission carries on from there.
	{"split1s+disorder3s", "cut:s+1,s+3; ttl1:1"},
	// Record cut at s+1 and ten cuts after it, every second piece lost on the way.
	{"ladder-mixed", "rec:s+1; cut:1,s+3,s+6,s+9,s+12,s+15,s+20,s+25,s+30,s+35; ttl1:1,3,5,7,9"},
}

// Ladder lists the strategies from the cheapest to the most intrusive, with DefaultSeed; a caller that needs one
// that works walks it from the top.
func Ladder() []Strategy { return LadderSeed(DefaultSeed) }

// LadderSeed is Ladder with the seed for the random cut points chosen by the caller.
// In the specs s is the first byte of the host name, se the byte after its last one, and "x+n" an offset from it.
func LadderSeed(seed int64) []Strategy {
	l := make([]Strategy, len(ladder))
	for i, e := range ladder {
		s, err := NewStrategy(i+1, e.name, e.spec, seed)
		if err != nil {
			panic(err) // the table is code: TestLadder parses every line
		}
		l[i] = s
	}
	return l
}

// ByName finds a strategy of the Ladder.
func ByName(name string) (Strategy, bool) {
	for _, s := range Ladder() {
		if s.Name == name {
			return s, true
		}
	}
	return Strategy{}, false
}

// ByNumber finds a strategy of the Ladder by its permanent number.
func ByNumber(num int) (Strategy, bool) {
	if l := Ladder(); num >= 1 && num <= len(l) {
		return l[num-1], true
	}
	return Strategy{}, false
}

// cut splits b at the given offsets; offsets outside (0, len) and out-of-order ones are dropped.
func cut(b []byte, at ...int) Plan {
	var p Plan
	last := 0
	for _, o := range at {
		if o > last && o < len(b) {
			p = append(p, Chunk{Data: b[last:o]})
			last = o
		}
	}
	return append(p, Chunk{Data: b[last:]})
}

// delayed pauses before every chunk but the first.
func delayed(p Plan, d time.Duration) Plan {
	for i := 1; i < len(p); i++ {
		p[i].Delay = d
	}
	return p
}

// equalCuts returns the boundaries of n equal pieces over [s-2, se+2], edges included.
func equalCuts(h Hello, n int) []int {
	lo, hi := max(h.HostStart-2, 1), h.HostEnd+2
	at := make([]int, 0, n+1)
	for k := 0; k <= n; k++ {
		at = append(at, lo+k*(hi-lo)/n)
	}
	return at
}

// splitRecords rewrites the first TLS record as several, cut at the given offsets of the input (ascending, each
// inside the payload), headers fixed up. Bytes after the first record are kept as they are.
func splitRecords(b []byte, h Hello, at []int) []byte {
	out := make([]byte, 0, len(b)+5*len(at))
	from := 5
	for _, to := range append(slices.Clone(at), h.Rec0End) {
		n := to - from
		out = append(out, b[0], b[1], b[2], byte(n>>8), byte(n))
		out = append(out, b[from:to]...)
		from = to
	}
	return append(out, b[h.Rec0End:]...)
}

// recMulti cuts the payload of the first record into several records, one chunk each: the first three of 3-20
// bytes, the rest of 10-20, at most six records, the last one holding what remains. With pauses, 10-20 ms
// precede every record after the first.
func recMulti(b []byte, h Hello, r *rand.Rand, pause bool) Plan {
	payload := b[5:h.Rec0End]
	var p Plan
	for len(p) < 5 {
		l := 10 + r.Intn(11)
		if len(p) < 3 {
			l = 3 + r.Intn(18)
		}
		if l >= len(payload) {
			break
		}
		p = append(p, Chunk{Data: record(b, payload[:l])})
		payload = payload[l:]
	}
	last := append(record(b, payload), b[h.Rec0End:]...)
	p = append(p, Chunk{Data: last})
	if pause {
		for i := 1; i < len(p); i++ {
			p[i].Delay = time.Duration(10+r.Intn(11)) * time.Millisecond
		}
	}
	return p
}

// record wraps payload in a record header copied from the first record of b, with the length fixed.
func record(b, payload []byte) []byte {
	out := append([]byte{b[0], b[1], b[2], byte(len(payload) >> 8), byte(len(payload))}, payload...)
	return out
}
