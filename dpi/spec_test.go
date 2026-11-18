package dpi

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The permanent strategies, written as specs, give the same plan as the closures they replaced, byte for byte:
// the columns of the reports already collected must not change meaning. The inputs cover an ordinary and a
// post-quantum hello, names of one, two and three labels, one that is short, and several seeds for the random cuts.
func TestSpecsMatchClosures(t *testing.T) {
	old := legacyLadder()
	if len(old) != len(Ladder()) {
		t.Fatalf("%d strategies, %d closures", len(Ladder()), len(old))
	}
	for _, host := range []string{"www.youtube.com", "discord.com", "cdn.discordapp.com", "a.io", "ya.ru", "localhost", "bbc.co.uk"} {
		for _, pq := range []bool{false, true} {
			hello := helloFor(t, host, pq)
			inputs := map[string][]byte{"hello": hello, "truncated": hello[:len(hello)-10], "not a hello": []byte("GET / HTTP/1.1\r\n\r\n")}
			for _, seed := range []int64{DefaultSeed, 7, 20261117} {
				for i, s := range LadderSeed(seed) {
					if s.Name != old[i].name || s.Num != i+1 {
						t.Fatalf("place %d is %d %s, the closure is %s", i+1, s.Num, s.Name, old[i].name)
					}
					for what, in := range inputs {
						want, got := old[i].plan(seed, in), s.Plan(in)
						if !reflect.DeepEqual(got, want) {
							t.Errorf("%d %s, %s pq=%v seed %d, %s: spec %q\n got  %s\n want %s", s.Num, s.Name, host, pq, seed, what, s.Spec(), describe(got), describe(want))
						}
					}
				}
			}
		}
	}
}

// describe prints the shape of a plan: the size of each chunk with its flags.
func describe(p Plan) string {
	var parts []string
	for _, c := range p {
		s := fmt.Sprint(len(c.Data))
		if c.OOB {
			s += "!"
		}
		if c.TTL != 0 {
			s += "t"
		}
		if c.Delay != 0 {
			s += "@" + c.Delay.String()
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " ")
}

func TestSpecRoundTrip(t *testing.T) {
	for _, e := range ladder {
		sp, err := ParseSpec(e.spec)
		if err != nil {
			t.Fatalf("%s: %v", e.name, err)
		}
		if sp.String() != e.spec {
			t.Errorf("%s: %q prints as %q", e.name, e.spec, sp.String())
		}
	}
	// The same strategy written loosely prints in one form, and that form reads back as the same spec.
	for in, want := range map[string]string{
		"":                         "",
		"  ":                       "",
		"cut:s+0 ; rec: m":         "rec:m; cut:s",
		"oob:2,0,2; cut: 1 , m":    "cut:1,m; oob:0,2",
		"ttl1:1;delay:5;labels:30": "labels:30; delay:5; ttl1:1",
		"cut:se-5,5+3,sni+4,s+020": "cut:se-5,8,sni+4,s+20",
		"rec:m,s+1;cut:0":          "rec:m,s+1; cut:0",
		"recmulti: pause":          "recmulti:pause",
		"eq:5;oob:0;ttl1:0":        "eq:5; oob:0; ttl1:0",
	} {
		sp, err := ParseSpec(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		again, err := ParseSpec(sp.String())
		if sp.String() != want || err != nil || !reflect.DeepEqual(again, sp) {
			t.Errorf("%q prints as %q, want %q (reads back: %v, %v)", in, sp.String(), want, again, err)
		}
	}
}

// Rubbish is an error that wraps ErrBadSpec, never a panic, and never half a spec.
func TestSpecRejectsRubbish(t *testing.T) {
	for _, in := range []string{
		"bogus", "cut", "cut:", "cut:,", "cut:x", "cut:s+", "cut:s-", "cut:-1", "cut:s+-1", "cut:s+x", "cut:S", "CUT:1",
		"cut:1;;oob:0", ";", "cut:1;", ":1", "rec:m;rec:s", "recmulti:1", "recmulti:0; cut:1", "cut:1; recmulti:pause",
		"eq:0", "eq:65", "eq:1,2", "eq:", "labels:", "labels:10001", "delay:-5", "delay:1,2", "oob:-1", "oob:", "ttl1:s",
		"cut:99999999999999999999", "cut:" + strings.Repeat("1,", 100) + "1", strings.Repeat("cut:1;", 300), "cut:1\x00",
	} {
		sp, err := ParseSpec(in)
		if err == nil || !errors.Is(err, ErrBadSpec) || sp != nil {
			t.Errorf("%q: spec %v, error %v", in, sp, err)
		}
		if _, err := NewStrategy(100, "x", in, 1); err == nil {
			t.Errorf("%q: NewStrategy accepted it", in)
		}
	}
}

// What the grammar promises beyond the permanent strategies.
func TestSpecSemantics(t *testing.T) {
	const host = "www.youtube.com"
	hello := helloFor(t, host, false)
	h, err := ParseClientHello(hello)
	if err != nil {
		t.Fatal(err)
	}
	plan := func(spec string) Plan {
		t.Helper()
		s, err := NewStrategy(100, "t", spec, 1)
		if err != nil {
			t.Fatal(err)
		}
		return s.Plan(hello)
	}
	stream := func(p Plan) []byte { s, _ := join(p); return s }

	// Places outside the packet are dropped, as they always were: what is left is sent as it is.
	for _, spec := range []string{"cut:99999", "cut:0", "rec:2", "rec:99999", "rec:5", "cut:s+99999; oob:7; ttl1:9", "oob:3"} {
		if p := plan(spec); len(p) != 1 || !bytes.Equal(p[0].Data, hello) || p[0].TTL != 0 {
			t.Errorf("%q changed the hello: %s", spec, describe(p))
		}
	}

	// A cut is written against the hello as the application wrote it: records added before it do not move it.
	p := plan("rec:s; cut:s+2")
	if len(p) != 2 || !bytes.HasPrefix(p[1].Data, []byte(host[2:])) {
		t.Errorf("rec:s; cut:s+2 -> %s", describe(p))
	}
	// A cut exactly where a record ends stays before the header of the next one.
	p = plan("rec:m; cut:m")
	if len(p) != 2 || p[1].Data[0] != 0x16 || len(p[0].Data) != h.MidSLD {
		t.Errorf("rec:m; cut:m -> %s", describe(p))
	}
	// Several record cuts: one record more for each, the payloads still add up.
	recs := records(t, stream(plan("rec:s,m,se")))
	if len(recs) != 4 || !bytes.Equal(bytes.Join(recs, nil), hello[5:]) {
		t.Errorf("rec:s,m,se gave %d records", len(recs))
	}
	// Urgent bytes and TTL count the pieces of the stream, not each other.
	var shape []string
	for _, c := range plan("cut:1,s,m; oob:0,2; ttl1:1,2") {
		switch {
		case c.OOB:
			shape = append(shape, "oob")
		case c.TTL == 1:
			shape = append(shape, "ttl")
		default:
			shape = append(shape, "-")
		}
	}
	if got := strings.Join(shape, " "); got != "- oob ttl ttl oob -" {
		t.Errorf("cut:1,s,m; oob:0,2; ttl1:1,2 -> %s", got)
	}
	// "delay" wins over the pause "labels" brings with it.
	for _, c := range plan("labels:30; delay:5")[1:] {
		if c.Delay != 5*time.Millisecond {
			t.Errorf("delay %v", c.Delay)
		}
	}
	// A strategy of the Ladder is its spec and nothing more: the same text built by hand gives the same plan.
	for _, st := range Ladder() {
		mine, err := NewStrategy(st.Num, st.Name, st.Spec().String(), DefaultSeed)
		if err != nil || !reflect.DeepEqual(mine.Plan(hello), st.Plan(hello)) || mine.Experimental != st.Experimental {
			t.Errorf("%s rebuilt from %q: %v", st.Name, st.Spec(), err)
		}
	}
}

func FuzzSpec(f *testing.F) {
	hello := helloFor(f, "www.youtube.com", true)
	for _, e := range ladder {
		f.Add(e.spec)
	}
	for _, s := range []string{"rec:s,m,se; cut:sni+1,s; eq:3; labels:1; delay:2", "cut:s+-1", "rec:5,6,7", "oob:0,0,1000000"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		sp, err := ParseSpec(in)
		if err != nil {
			return
		}
		if again, err := ParseSpec(sp.String()); err != nil || !reflect.DeepEqual(again, sp) {
			t.Fatalf("%q prints as %q, which reads as %v (%v)", in, sp, again, err)
		}
		p := Strategy{spec: sp, seed: 1}.Plan(hello)
		stream, _ := join(p)
		if extra := len(stream) - len(hello); extra < 0 || extra%5 != 0 || extra > 5*maxList {
			t.Fatalf("%q: stream of %d bytes from a hello of %d", in, len(stream), len(hello))
		}
		for _, c := range p {
			if len(c.Data) == 0 || c.Delay < 0 || c.Delay > maxPause*time.Millisecond || c.TTL < 0 || c.TTL > 1 {
				t.Fatalf("%q: bad chunk %+v", in, c)
			}
		}
	})
}
