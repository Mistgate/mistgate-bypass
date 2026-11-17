package dpi

import (
	"bytes"
	"testing"
	"time"
)

func join(p Plan) (stream, oob []byte) {
	for _, c := range p {
		if c.OOB {
			oob = append(oob, c.Data...)
		} else {
			stream = append(stream, c.Data...)
		}
	}
	return
}

// records returns the fragments of the TLS records in b.
func records(t *testing.T, b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		if len(b) < 5 || b[0] != 0x16 {
			t.Fatalf("bad record header %x", b[:min(5, len(b))])
		}
		n := int(b[3])<<8 | int(b[4])
		if len(b) < 5+n {
			t.Fatalf("record of %d bytes, %d left", n, len(b)-5)
		}
		out = append(out, b[5:5+n])
		b = b[5+n:]
	}
	return out
}

// bounds returns the offsets in the stream where the plan's non-urgent chunks end, the last one excluded.
func bounds(p Plan) (at []int) {
	n := 0
	for _, c := range p {
		if c.OOB {
			continue
		}
		n += len(c.Data)
		at = append(at, n)
	}
	return at[:len(at)-1]
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Record-cutting strategies change the bytes: the records' payloads must still add up to the original handshake.
var cutsRecords = map[string]bool{"tlsrec": true, "tlsrec+split": true, "rec-multi": true, "rec-multi-nodelay": true,
	"oob1+rec-5se": true, "rec1s+disorder1": true, "ladder-mixed": true}

func TestPlans(t *testing.T) {
	const host = "www.youtube.com"
	for _, pq := range []bool{false, true} {
		hello := helloFor(t, host, pq)
		h, err := ParseClientHello(hello)
		if err != nil {
			t.Fatal(err)
		}
		s, se := h.HostStart, h.HostEnd
		for _, st := range Ladder() {
			p := st.Plan(hello)
			stream, oob := join(p)
			var sizes []int
			for _, c := range p {
				if len(c.Data) == 0 {
					t.Errorf("%s: empty chunk", st.Name)
				}
				sizes = append(sizes, len(c.Data))
			}
			var recs [][]byte
			if cutsRecords[st.Name] {
				recs = records(t, stream)
				if !bytes.Equal(bytes.Join(recs, nil), hello[5:]) {
					t.Fatalf("%s: records do not add up to the handshake", st.Name)
				}
			} else if !bytes.Equal(stream, hello) {
				t.Errorf("%s: pieces do not add up to the hello", st.Name)
			}
			bad := func(format string, a ...any) { t.Errorf(st.Name+": "+format+" (sizes %v)", append(a, sizes)...) }
			hasOOB := len(oob) == 1
			if hasOOB != (st.Name == "oob" || st.Name == "oob1+rec-5se" || st.Name == "oob1+ladder8") {
				bad("urgent bytes: %d", len(oob))
			}
			ttl1 := func(i int) bool { return p[i].TTL == 1 }

			switch st.Name {
			case "plain":
				if len(p) != 1 {
					bad("chunks")
				}
			case "tlsrec", "tlsrec+split":
				// The cut is inside the name, so no record holds the whole of it.
				if len(recs) != 2 || len(recs[0])+5 != h.MidSLD || bytes.Contains(recs[0], []byte(host)) || bytes.Contains(recs[1], []byte(host)) {
					bad("%d records, first ends at %d, midsld %d", len(recs), len(recs[0])+5, h.MidSLD)
				}
				if st.Name == "tlsrec" && len(p) != 1 || st.Name == "tlsrec+split" && (len(p) != 2 || sizes[0] != h.HostStart) {
					bad("chunks")
				}
			case "split1":
				if !equalInts(bounds(p), []int{1}) {
					bad("bounds %v", bounds(p))
				}
			case "splitsni", "splitsni-delay":
				if !equalInts(bounds(p), []int{h.MidSLD}) {
					t.Fatalf("%s: %v", st.Name, sizes)
				}
				if (st.Name == "splitsni-delay") != (p[1].Delay == 100*time.Millisecond) || p[0].Delay != 0 {
					bad("delays %v %v", p[0].Delay, p[1].Delay)
				}
			case "multisplit":
				if !equalInts(bounds(p), []int{1, h.MidSLD}) {
					bad("bounds")
				}
			case "oob":
				if len(p) != 3 || !p[1].OOB || sizes[0] != h.MidSLD {
					bad("chunks")
				}
			case "rec-multi", "rec-multi-nodelay":
				if len(recs) < 2 || len(recs) > 6 {
					t.Fatalf("%s: %d records", st.Name, len(recs))
				}
				for i, r := range recs[:len(recs)-1] {
					lo, hi := 10, 20
					if i < 3 {
						lo = 3
					}
					if len(r) < lo || len(r) > hi {
						bad("record %d is %d bytes", i, len(r))
					}
				}
				if st.Name == "rec-multi-nodelay" {
					if len(p) != 1 {
						bad("not glued into one write")
					}
					break
				}
				if len(p) != len(recs) || p[0].Delay != 0 {
					bad("one chunk per record expected")
				}
				for _, c := range p[1:] {
					if c.Delay < 10*time.Millisecond || c.Delay > 20*time.Millisecond {
						bad("pause %v", c.Delay)
					}
				}
			case "labels":
				// one cut inside each of www, youtube, com
				at := bounds(p)
				if len(at) != 3 || at[0] <= s || at[0] >= s+3 || at[1] <= s+4 || at[1] >= s+11 || at[2] <= s+12 || at[2] >= se {
					bad("cuts %v, name at %d-%d", at, s, se)
				}
				for _, c := range p[1:] {
					if c.Delay != 30*time.Millisecond {
						bad("pause %v", c.Delay)
					}
				}
			case "split5", "split7":
				n := map[string]int{"split5": 5, "split7": 7}[st.Name]
				if len(p) != n+2 || sizes[0] != s-2 || len(stream) != len(hello) {
					t.Fatalf("%s: %v", st.Name, sizes)
				}
				width := (se + 2 - (s - 2)) / n
				for _, z := range sizes[1 : len(sizes)-1] {
					if z < width-1 || z > width+1 {
						bad("piece of %d, expected about %d", z, width)
					}
				}
			case "ladder8":
				if !equalInts(bounds(p), []int{s + 1, s + 3, s + 6, s + 9, s + 12, s + 15, s + 20, s + 30}) {
					bad("bounds %v", bounds(p))
				}
			case "oob1+ladder8":
				if !equalInts(bounds(p), []int{1, s + 1, s + 3, s + 6, s + 9, s + 12, s + 15, s + 20, s + 30}) || !p[1].OOB || sizes[0] != 1 {
					bad("bounds %v", bounds(p))
				}
			case "oob1+rec-5se":
				if len(recs) != 2 || len(recs[0])+5 != se-5 || len(p) != 3 || sizes[0] != 1 || !p[1].OOB {
					bad("records %d, first %d, want end at %d", len(recs), len(recs[0])+5, se-5)
				}
			case "disorder-ttl":
				if len(p) != 2 || !ttl1(0) || p[1].TTL != 0 || !st.Experimental {
					bad("%+v", p)
				}
			case "rec1s+disorder1":
				if len(recs) != 2 || len(recs[0])+5 != s+1 || len(p) != 2 || sizes[0] != 1 || !ttl1(0) || ttl1(1) {
					bad("records %d, first %d", len(recs), len(recs[0])+5)
				}
			case "split1s+disorder3s":
				if !equalInts(bounds(p), []int{s + 1, s + 3}) || ttl1(0) || !ttl1(1) || ttl1(2) {
					bad("bounds %v", bounds(p))
				}
			case "ladder-mixed":
				// the record header added at s+1 moves the later cuts by 5
				want := []int{1}
				for _, o := range []int{3, 6, 9, 12, 15, 20, 25, 30, 35} {
					if s+o+5 < len(stream) {
						want = append(want, s+o+5)
					}
				}
				if len(recs) != 2 || len(recs[0])+5 != s+1 || !equalInts(bounds(p), want) {
					bad("bounds %v, want %v", bounds(p), want)
				}
				for i := range p {
					if ttl1(i) != (i%2 == 1) {
						bad("chunk %d: TTL %d", i, p[i].TTL)
					}
				}
			default:
				t.Errorf("strategy %s has no expectations in this test", st.Name)
			}
			for _, name := range []string{"disorder-ttl", "rec1s+disorder1", "split1s+disorder3s", "ladder-mixed"} {
				if st.Name == name && !st.Experimental {
					bad("uses TTL but is not marked experimental")
				}
			}
		}
	}
}

// Random cuts come from the seed and the name: the same inputs give the same plan, other seeds other cuts.
func TestSeededPlans(t *testing.T) {
	hello := helloFor(t, "www.youtube.com", true)
	for _, name := range []string{"rec-multi", "rec-multi-nodelay", "labels"} {
		var first []int
		differs := false
		for seed := int64(1); seed <= 6; seed++ {
			var st Strategy
			for _, s := range LadderSeed(seed) {
				if s.Name == name {
					st = s
				}
			}
			sig := func(p Plan) []int {
				if name == "labels" {
					return bounds(p)
				}
				stream, _ := join(p)
				var l []int
				for _, r := range records(t, stream) {
					l = append(l, len(r))
				}
				return l
			}
			a, b := sig(st.Plan(hello)), sig(st.Plan(hello))
			if !equalInts(a, b) {
				t.Fatalf("%s: the same seed gave different cuts", name)
			}
			if seed == 1 {
				first = a
			} else if !equalInts(first, a) {
				differs = true
			}
		}
		if !differs {
			t.Errorf("%s: six seeds, one plan", name)
		}
	}
}

func TestPlanLeavesOtherInputAlone(t *testing.T) {
	for _, in := range [][]byte{[]byte("GET / HTTP/1.1\r\n\r\n"), nil, {0x16, 3, 1, 0, 2, 1, 0}} {
		for _, s := range Ladder() {
			if p := s.Plan(in); len(p) != 1 || !bytes.Equal(p[0].Data, in) {
				t.Errorf("%s changed %q", s.Name, in)
			}
		}
	}
	// A hello cut short is not touched either: the record header promises bytes that are not there.
	hello := helloFor(t, "www.youtube.com", false)
	if p := Ladder()[1].Plan(hello[:len(hello)-10]); len(p) != 1 {
		t.Errorf("a truncated hello was cut")
	}
	// A short name leaves some of the fixed offsets beyond the packet's end: they are dropped, not an error.
	short := helloFor(t, "a.io", false)
	for _, s := range Ladder() {
		stream, _ := join(s.Plan(short))
		if !cutsRecords[s.Name] && !bytes.Equal(stream, short) {
			t.Errorf("%s: short name", s.Name)
		}
	}
}

func TestLadder(t *testing.T) {
	want := []string{"plain", "tlsrec", "split1", "splitsni", "splitsni-delay", "tlsrec+split", "multisplit", "oob",
		"rec-multi-nodelay", "labels", "split5", "split7", "ladder8", "rec-multi", "oob1+rec-5se", "oob1+ladder8",
		"disorder-ttl", "rec1s+disorder1", "split1s+disorder3s", "ladder-mixed"}
	got := Ladder()
	if len(got) != len(want) {
		t.Fatalf("%d strategies", len(got))
	}
	for i, s := range got {
		if s.Name != want[i] {
			t.Errorf("rung %d is %s, want %s", i, s.Name, want[i])
		}
		if b, ok := ByName(s.Name); !ok || b.Name != s.Name {
			t.Errorf("ByName(%s)", s.Name)
		}
	}
}
