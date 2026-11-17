package dpi

import (
	"hash/fnv"
	"math/rand"
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
	Name         string
	Experimental bool // depends on how the path handles a low-TTL segment; may do nothing or stall
	seed         int64
	build        func(hello []byte, h Hello, rnd *rand.Rand) Plan
}

const (
	splitPause = 100 * time.Millisecond
	oobByte    = 'a' // never reaches the application on a peer that keeps urgent data out of the stream

	// DefaultSeed is the seed Ladder uses for the strategies that draw random cut points.
	DefaultSeed = 1
)

// Plan turns the bytes of a first write (a TLS ClientHello) into the writes to make. Input that is not a
// ClientHello with its name inside the first record is sent as it is: a strategy cannot cut what it cannot find.
// Random choices depend only on the strategy's seed and the server name, so one name always gets the same cuts.
func (s Strategy) Plan(hello []byte) Plan {
	plain := Plan{{Data: hello}}
	if s.build == nil {
		return plain
	}
	h, err := ParseClientHello(hello)
	if err != nil || h.MidSLD >= h.Rec0End || h.Rec0End > len(hello) {
		return plain
	}
	f := fnv.New64a()
	f.Write([]byte(h.ServerName))
	return s.build(hello, h, rand.New(rand.NewSource(s.seed^int64(f.Sum64()))))
}

// Ladder lists the strategies from the cheapest to the most intrusive, with DefaultSeed; a caller that needs one
// that works walks it from the top.
func Ladder() []Strategy { return LadderSeed(DefaultSeed) }

// LadderSeed is Ladder with the seed for the random cut points chosen by the caller.
// In the comments s is the first byte of the host name, se the byte after its last one, and "x+n" an offset from it.
func LadderSeed(seed int64) []Strategy {
	l := []Strategy{
		{Name: "plain"},
		{Name: "tlsrec", build: func(b []byte, h Hello, _ *rand.Rand) Plan { return Plan{{Data: splitRecord(b, h)}} }},
		{Name: "split1", build: func(b []byte, h Hello, _ *rand.Rand) Plan { return cut(b, 1) }},
		{Name: "splitsni", build: func(b []byte, h Hello, _ *rand.Rand) Plan { return cut(b, h.MidSLD) }},
		{Name: "splitsni-delay", build: func(b []byte, h Hello, _ *rand.Rand) Plan {
			p := cut(b, h.MidSLD)
			p[len(p)-1].Delay = splitPause
			return p
		}},
		{Name: "tlsrec+split", build: func(b []byte, h Hello, _ *rand.Rand) Plan { return cut(splitRecord(b, h), h.HostStart) }},
		{Name: "multisplit", build: func(b []byte, h Hello, _ *rand.Rand) Plan { return cut(b, 1, h.MidSLD) }},
		{Name: "oob", build: func(b []byte, h Hello, _ *rand.Rand) Plan { return oobAfter(cut(b, h.MidSLD), 0) }},

		// Records cut at random places from the start of the handshake, as a record-fragmenting proxy does.
		{Name: "rec-multi-nodelay", build: func(b []byte, h Hello, r *rand.Rand) Plan {
			var all []byte
			for _, c := range recMulti(b, h, r, false) {
				all = append(all, c.Data...)
			}
			return Plan{{Data: all}}
		}},
		// One TCP cut inside every label of the name, with a short pause between the pieces.
		{Name: "labels", build: func(b []byte, h Hello, r *rand.Rand) Plan {
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
			return delayed(cut(b, at...), 30*time.Millisecond)
		}},
		// Equal pieces over the name and two bytes around it: two pieces are not enough for some middleboxes.
		{Name: "split5", build: func(b []byte, h Hello, _ *rand.Rand) Plan { return cut(b, equalCuts(h, 5)...) }},
		{Name: "split7", build: func(b []byte, h Hello, _ *rand.Rand) Plan { return cut(b, equalCuts(h, 7)...) }},
		{Name: "ladder8", build: func(b []byte, h Hello, _ *rand.Rand) Plan { return cut(b, ladder8(h)...) }},
		{Name: "rec-multi", build: func(b []byte, h Hello, r *rand.Rand) Plan { return recMulti(b, h, r, true) }},
		{Name: "oob1+rec-5se", build: func(b []byte, h Hello, _ *rand.Rand) Plan {
			return oobAfter(cut(splitRecordAt(b, h, h.HostEnd-5), 1), 0)
		}},
		{Name: "oob1+ladder8", build: func(b []byte, h Hello, _ *rand.Rand) Plan {
			return oobAfter(cut(b, append([]int{1}, ladder8(h)...)...), 0)
		}},

		// The strategies below send some pieces with TTL 1: they die on the way and TCP sends them again after
		// the pieces that follow, so the path sees the pieces swapped. A loopback or a one-hop path does not drop them.
		{Name: "disorder-ttl", Experimental: true, build: func(b []byte, h Hello, _ *rand.Rand) Plan {
			p := cut(b, h.MidSLD)
			p[0].TTL = 1
			return p
		}},
		// Record cut at s+1; the first byte of the stream is the one that gets lost.
		{Name: "rec1s+disorder1", Experimental: true, build: func(b []byte, h Hello, _ *rand.Rand) Plan {
			p := cut(splitRecordAt(b, h, h.HostStart+1), 1)
			p[0].TTL = 1
			return p
		}},
		// Cut at s+1; the piece from s+1 to s+3 is the lost one, so the retransmission carries on from there.
		{Name: "split1s+disorder3s", Experimental: true, build: func(b []byte, h Hello, _ *rand.Rand) Plan {
			p := cut(b, h.HostStart+1, h.HostStart+3)
			if len(p) == 3 {
				p[1].TTL = 1
			}
			return p
		}},
		// Record cut at s+1 and ten cuts after it, every second piece lost on the way.
		{Name: "ladder-mixed", Experimental: true, build: func(b []byte, h Hello, _ *rand.Rand) Plan {
			s, rec := h.HostStart, h.HostStart+1
			var at []int
			for _, o := range []int{1, s + 3, s + 6, s + 9, s + 12, s + 15, s + 20, s + 25, s + 30, s + 35} {
				if o > rec {
					o += 5 // the record header added at s+1 moves everything after it
				}
				at = append(at, o)
			}
			p := cut(splitRecordAt(b, h, rec), at...)
			for i := 1; i < len(p); i += 2 {
				p[i].TTL = 1
			}
			return p
		}},
	}
	for i := range l {
		l[i].seed = seed
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

// oobAfter puts one urgent byte after chunk i.
func oobAfter(p Plan, i int) Plan {
	out := append(Plan{}, p[:i+1]...)
	out = append(out, Chunk{Data: []byte{oobByte}, OOB: true})
	return append(out, p[i+1:]...)
}

// delayed pauses before every chunk but the first.
func delayed(p Plan, d time.Duration) Plan {
	for i := 1; i < len(p); i++ {
		p[i].Delay = d
	}
	return p
}

func ladder8(h Hello) []int {
	s := h.HostStart
	return []int{s + 1, s + 3, s + 6, s + 9, s + 12, s + 15, s + 20, s + 30}
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

// splitRecord rewrites the first TLS record as two records cut inside the server name, headers fixed up.
// Bytes after the first record are kept as they are.
func splitRecord(b []byte, h Hello) []byte { return splitRecordAt(b, h, h.MidSLD) }

// splitRecordAt cuts the first record at offset pos of the input (inside its payload); out of range it returns b.
func splitRecordAt(b []byte, h Hello, pos int) []byte {
	if pos <= 5 || pos >= h.Rec0End {
		return b
	}
	k := pos - 5 // payload bytes that stay in the first record
	n := h.Rec0End - 5
	out := make([]byte, 0, len(b)+5)
	out = append(out, b[:3]...)
	out = append(out, byte(k>>8), byte(k))
	out = append(out, b[5:5+k]...)
	out = append(out, b[:3]...)
	out = append(out, byte((n-k)>>8), byte(n-k))
	return append(out, b[5+k:]...)
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
