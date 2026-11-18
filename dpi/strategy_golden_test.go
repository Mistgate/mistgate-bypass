package dpi

import (
	"hash/fnv"
	"math/rand"
	"time"
)

// legacy is a strategy as the library wrote it before specs existed: a closure. It is kept, with its helpers, as
// the reference the specs of the permanent strategies 1-20 must reproduce byte for byte: those numbers are the
// columns of reports already collected. Do not change it to follow the specs.
type legacy struct {
	name  string
	build func(hello []byte, h Hello, rnd *rand.Rand) Plan
}

func legacyLadder() []legacy {
	return []legacy{
		{name: "plain"},
		{name: "tlsrec", build: func(b []byte, h Hello, _ *rand.Rand) Plan { return Plan{{Data: legacySplitRecordAt(b, h, h.MidSLD)}} }},
		{name: "split1", build: func(b []byte, h Hello, _ *rand.Rand) Plan { return cut(b, 1) }},
		{name: "splitsni", build: func(b []byte, h Hello, _ *rand.Rand) Plan { return cut(b, h.MidSLD) }},
		{name: "splitsni-delay", build: func(b []byte, h Hello, _ *rand.Rand) Plan {
			p := cut(b, h.MidSLD)
			p[len(p)-1].Delay = 100 * time.Millisecond
			return p
		}},
		{name: "tlsrec+split", build: func(b []byte, h Hello, _ *rand.Rand) Plan {
			return cut(legacySplitRecordAt(b, h, h.MidSLD), h.HostStart)
		}},
		{name: "multisplit", build: func(b []byte, h Hello, _ *rand.Rand) Plan { return cut(b, 1, h.MidSLD) }},
		{name: "oob", build: func(b []byte, h Hello, _ *rand.Rand) Plan { return legacyOOBAfter(cut(b, h.MidSLD), 0) }},

		// Records cut at random places from the start of the handshake, as a record-fragmenting proxy does.
		{name: "rec-multi-nodelay", build: func(b []byte, h Hello, r *rand.Rand) Plan {
			var all []byte
			for _, c := range recMulti(b, h, r, false) {
				all = append(all, c.Data...)
			}
			return Plan{{Data: all}}
		}},
		// One TCP cut inside every label of the name, with a short pause between the pieces.
		{name: "labels", build: func(b []byte, h Hello, r *rand.Rand) Plan {
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
		{name: "split5", build: func(b []byte, h Hello, _ *rand.Rand) Plan { return cut(b, equalCuts(h, 5)...) }},
		{name: "split7", build: func(b []byte, h Hello, _ *rand.Rand) Plan { return cut(b, equalCuts(h, 7)...) }},
		{name: "ladder8", build: func(b []byte, h Hello, _ *rand.Rand) Plan { return cut(b, legacyLadder8(h)...) }},
		{name: "rec-multi", build: func(b []byte, h Hello, r *rand.Rand) Plan { return recMulti(b, h, r, true) }},
		{name: "oob1+rec-5se", build: func(b []byte, h Hello, _ *rand.Rand) Plan {
			return legacyOOBAfter(cut(legacySplitRecordAt(b, h, h.HostEnd-5), 1), 0)
		}},
		{name: "oob1+ladder8", build: func(b []byte, h Hello, _ *rand.Rand) Plan {
			return legacyOOBAfter(cut(b, append([]int{1}, legacyLadder8(h)...)...), 0)
		}},

		// The strategies below send some pieces with TTL 1: they die on the way and TCP sends them again after
		// the pieces that follow, so the path sees the pieces swapped. A loopback or a one-hop path does not drop them.
		{name: "disorder-ttl", build: func(b []byte, h Hello, _ *rand.Rand) Plan {
			p := cut(b, h.MidSLD)
			p[0].TTL = 1
			return p
		}},
		// Record cut at s+1; the first byte of the stream is the one that gets lost.
		{name: "rec1s+disorder1", build: func(b []byte, h Hello, _ *rand.Rand) Plan {
			p := cut(legacySplitRecordAt(b, h, h.HostStart+1), 1)
			p[0].TTL = 1
			return p
		}},
		// Cut at s+1; the piece from s+1 to s+3 is the lost one, so the retransmission carries on from there.
		{name: "split1s+disorder3s", build: func(b []byte, h Hello, _ *rand.Rand) Plan {
			p := cut(b, h.HostStart+1, h.HostStart+3)
			if len(p) == 3 {
				p[1].TTL = 1
			}
			return p
		}},
		// Record cut at s+1 and ten cuts after it, every second piece lost on the way.
		{name: "ladder-mixed", build: func(b []byte, h Hello, _ *rand.Rand) Plan {
			s, rec := h.HostStart, h.HostStart+1
			var at []int
			for _, o := range []int{1, s + 3, s + 6, s + 9, s + 12, s + 15, s + 20, s + 25, s + 30, s + 35} {
				if o > rec {
					o += 5 // the record header added at s+1 moves everything after it
				}
				at = append(at, o)
			}
			p := cut(legacySplitRecordAt(b, h, rec), at...)
			for i := 1; i < len(p); i += 2 {
				p[i].TTL = 1
			}
			return p
		}},
	}
}

func legacyLadder8(h Hello) []int {
	s := h.HostStart
	return []int{s + 1, s + 3, s + 6, s + 9, s + 12, s + 15, s + 20, s + 30}
}

// legacySplitRecordAt cuts the first record at offset pos of the input (inside its payload); out of range it returns b.
func legacySplitRecordAt(b []byte, h Hello, pos int) []byte {
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

// legacyOOBAfter puts one urgent byte after chunk i.
func legacyOOBAfter(p Plan, i int) Plan {
	out := append(Plan{}, p[:i+1]...)
	out = append(out, Chunk{Data: []byte{oobByte}, OOB: true})
	return append(out, p[i+1:]...)
}

// plan is Strategy.Plan for a legacy closure.
func (l legacy) plan(seed int64, hello []byte) Plan {
	plain := Plan{{Data: hello}}
	if l.build == nil {
		return plain
	}
	h, err := ParseClientHello(hello)
	if err != nil || h.MidSLD >= h.Rec0End || h.Rec0End > len(hello) {
		return plain
	}
	f := fnv.New64a()
	f.Write([]byte(h.ServerName))
	return l.build(hello, h, rand.New(rand.NewSource(seed^int64(f.Sum64()))))
}
