package flow

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mistgate/mistgate-bypass/dpi"
)

var (
	partVideo = partKey{"yt", "video"}
	partChat  = partKey{"dc", "chat"}
)

func win(m *Memory, t target, first, winner int, src source) change {
	nm, _ := m.plan(t)
	return m.record(nm, verdict{t: t, first: first, src: src, winner: winner, ladder: first != winner, pause: time.Minute})
}

// What the file holds: the results of service parts and own sites, the wins, a salt; the names of the sites that
// are not the user's own are nowhere, and the user's own are under a hash.
func TestMemoryRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "bypass.json")
	clk := newClock()
	m := OpenMemory(path, clk.Now)
	m.SetNetwork("net-a")
	win(m, target{name: "rr1.googlevideo.com", part: partVideo}, 1, 6, srcNone)
	win(m, target{name: "discord.com", part: partChat}, 1, 1, srcNone)
	win(m, target{name: "mysite.example.org", own: true}, 1, 3, srcNone)
	win(m, target{name: "stranger.example.net"}, 1, 5, srcNone)
	salt := m.Salt()
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"example", "googlevideo", "discord.com"} {
		if bytes.Contains(data, []byte(leak)) {
			t.Errorf("the file holds %q:\n%s", leak, data)
		}
	}
	if _, err := os.Stat(path + ".tmp"); err == nil {
		t.Error("the temporary file is left")
	}

	m2 := OpenMemory(path, clk.Now)
	if m2.Salt() != salt {
		t.Error("the salt changed")
	}
	if known := m2.SetNetwork("net-a"); !known {
		t.Error("the network is not known after a restart")
	}
	if known := m2.SetNetwork("net-b"); known {
		t.Error("a network never seen is known")
	}
	m2.SetNetwork("net-a")
	p := m2.Parts()
	if len(p) != 2 || p[0].Service != "dc" || p[0].Strategy != 1 || p[1].Service != "yt" || p[1].Part != "video" || p[1].Strategy != 6 {
		t.Errorf("parts %+v", p)
	}
	if s, _, ok := m2.Site("mysite.example.org"); !ok || s != 3 {
		t.Errorf("own site: %d %v", s, ok)
	}
	if _, _, ok := m2.Site("stranger.example.net"); ok {
		t.Error("a stranger's name was kept")
	}
	if m2.cur.wins[6] != 1 || m2.cur.wins[3] != 1 || m2.cur.wins[5] != 1 {
		t.Errorf("wins %v", m2.cur.wins)
	}
	// An own site that was kept on disk is found by the first connection to it.
	if _, h := m2.plan(target{name: "mysite.example.org", own: true}); h.first != 3 {
		t.Errorf("hint %+v", h)
	}
	// The file is JSON of version 1 with the fields of the plan.
	var d struct {
		V        int
		Networks map[string]struct{ Seen_unix int64 }
	}
	if err := json.Unmarshal(data, &d); err != nil || d.V != 1 || len(d.Networks) != 1 {
		t.Errorf("%v: %s", err, data)
	}
	// Nothing changed since the write: no new write.
	os.Remove(path)
	if err := m2.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("a clean memory was written again")
	}
}

// A file that cannot be used is an empty memory, not a failure, and the next Save puts a good file in its place.
func TestDamagedFileIsAnEmptyMemory(t *testing.T) {
	good := `{"v":1,"salt":"` + strings.Repeat("ab", 32) + `","networks":{"n":{"seen_unix":1800000000,"parts":{"yt/video":{"o":"bypass","s":6,"at":1800000000}}}}}`
	for name, content := range map[string]string{
		"empty":         "",
		"cut":           good[:len(good)/2],
		"not json":      "\x00\x01 binary \xff",
		"other version": strings.Replace(good, `"v":1`, `"v":2`, 1),
		"no salt":       strings.Replace(good, strings.Repeat("ab", 32), "", 1),
		"short salt":    strings.Replace(good, strings.Repeat("ab", 32), "abab", 1),
		"too large":     `{"v":1,"pad":"` + strings.Repeat("x", maxFile) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bypass.json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			m := OpenMemory(path, newClock().Now)
			if len(m.Parts()) != 0 || m.Salt() == [32]byte{} {
				t.Fatalf("parts %v, salt %x", m.Parts(), m.Salt())
			}
			m.SetNetwork("t")
			win(m, target{name: "a.googlevideo.com", part: partVideo}, 1, 6, srcNone)
			if err := m.Save(); err != nil {
				t.Fatal(err)
			}
			m2 := OpenMemory(path, newClock().Now)
			m2.SetNetwork("t")
			if len(m2.Parts()) != 1 {
				t.Errorf("the file was not repaired: %v", m2.Parts())
			}
		})
	}
	t.Run("good", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bypass.json")
		os.WriteFile(path, []byte(good), 0o600)
		m := OpenMemory(path, newClock().Now)
		m.SetNetwork("n")
		if p := m.Parts(); len(p) != 1 || p[0].Strategy != 6 {
			t.Errorf("parts %v", p)
		}
	})
	t.Run("implausible records are skipped", func(t *testing.T) {
		bad := `{"v":1,"salt":"` + strings.Repeat("ab", 32) + `","networks":{"n":{"seen_unix":1800000000,"parts":{` +
			`"yt/video":{"o":"bypass","s":6,"at":1800000000},"nopart":{"o":"self","at":1800000000},"/x":{"o":"self","at":1800000000},` +
			`"a/b":{"o":"bypass","s":1,"at":1800000000},"a/c":{"o":"bypass","s":99999,"at":1800000000},"a/d":{"o":"other","at":1800000000},` +
			`"a/e":{"o":"self","at":1}},"sites":{"short":{"o":"self","at":1800000000}},"wins":{"x":3,"1":2,"6":-1,"7":4}}}}`
		path := filepath.Join(t.TempDir(), "bypass.json")
		os.WriteFile(path, []byte(bad), 0o600)
		m := OpenMemory(path, newClock().Now)
		m.SetNetwork("n")
		if p := m.Parts(); len(p) != 1 || p[0].Part != "video" {
			t.Errorf("parts %v", p)
		}
		if len(m.cur.sites) != 0 || len(m.cur.wins) != 1 || m.cur.wins[7] != 4 {
			t.Errorf("sites %v wins %v", m.cur.sites, m.cur.wins)
		}
	})
}

// No more than 32 networks, and nothing older than 30 days, on disk or in the memory after a restart.
func TestMemoryForgets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bypass.json")
	clk := newClock()
	m := OpenMemory(path, clk.Now)
	for i := range 40 {
		clk.Advance(time.Hour)
		m.SetNetwork(fmt.Sprint("net", i))
		win(m, target{name: "a.googlevideo.com", part: partVideo}, 1, 6, srcNone)
	}
	if len(m.nets) > maxNets {
		t.Errorf("%d networks in RAM", len(m.nets))
	}
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	m2 := OpenMemory(path, clk.Now)
	if len(m2.nets) > maxNets {
		t.Errorf("%d networks after a restart", len(m2.nets))
	}
	if m2.SetNetwork("net0") || !m2.SetNetwork("net39") {
		t.Error("the oldest network is kept and the newest is not")
	}

	clk.Advance(31 * 24 * time.Hour)
	m3 := OpenMemory(path, clk.Now)
	if len(m3.nets) != 0 {
		t.Errorf("networks of a month ago are kept: %d", len(m3.nets))
	}

	// A result older than 30 days is left out of the file, though its network is not.
	m4 := OpenMemory("", clk.Now)
	m4.SetNetwork("n")
	win(m4, target{name: "a.googlevideo.com", part: partVideo}, 1, 6, srcNone)
	win(m4, target{name: "discord.com", part: partChat}, 1, 1, srcNone)
	clk.Advance(20 * 24 * time.Hour)
	win(m4, target{name: "discord.com", part: partChat}, 1, 1, srcNone)
	m4.cur.parts[partChat].at = clk.Now()
	clk.Advance(15 * 24 * time.Hour)
	m4.cur.seen = clk.Now()
	m4.mu.Lock()
	data, _ := m4.encode()
	m4.mu.Unlock()
	if bytes.Contains(data, []byte("yt/video")) || !bytes.Contains(data, []byte("dc/chat")) {
		t.Errorf("%s", data)
	}
}

// A result shows what a connection saw. After a week it is a hint: plain goes first, and the strategy follows it.
func TestResultGrowsStale(t *testing.T) {
	clk := newClock()
	m := OpenMemory("", clk.Now)
	m.SetNetwork("t")
	tg := target{name: "a.googlevideo.com", part: partVideo}
	win(m, tg, 1, 6, srcNone)
	clk.Advance(6 * 24 * time.Hour)
	if _, h := m.plan(tg); h.first != 6 || h.stale != 0 {
		t.Errorf("after 6 days %+v", h)
	}
	clk.Advance(2 * 24 * time.Hour)
	if _, h := m.plan(tg); h.first != 1 || h.stale != 6 {
		t.Errorf("after 8 days %+v", h)
	}
	// Plain answering while the result is stale makes the part "opens as it is".
	win(m, tg, 1, 1, srcNone)
	if p := m.Parts(); p[0].Strategy != 1 {
		t.Errorf("parts %+v", p)
	}
}

// A name that is down is left alone for a time, and so is an address that does not answer.
func TestDownNamesAreLeftAloneForAWhile(t *testing.T) {
	clk := newClock()
	m := OpenMemory("", clk.Now)
	m.SetNetwork("t")
	tg := target{name: "a.example.org"}
	nm, _ := m.plan(tg)
	m.record(nm, verdict{t: tg, first: 1, pause: 10 * time.Minute})
	if _, h := m.plan(tg); !h.dead || h.unreachable {
		t.Errorf("%+v", h)
	}
	clk.Advance(10*time.Minute + time.Second)
	if _, h := m.plan(tg); h.dead {
		t.Errorf("after the pause %+v", h)
	}
	m.record(nm, verdict{t: tg, fail: failUnreachable, pause: 5 * time.Minute})
	if _, h := m.plan(tg); !h.unreachable {
		t.Errorf("%+v", h)
	}
	clk.Advance(5*time.Minute + time.Second)
	if _, h := m.plan(tg); h.unreachable {
		t.Errorf("after the pause %+v", h)
	}
	// An answer ends the pause at once.
	m.record(nm, verdict{t: tg, first: 1, pause: 10 * time.Minute})
	win(m, tg, 1, 1, srcNone)
	if _, h := m.plan(tg); h.dead {
		t.Errorf("after an answer %+v", h)
	}
}

// What a connection learns belongs to the network it started on.
func TestResultOfAnotherNetworkIsDropped(t *testing.T) {
	m := OpenMemory("", newClock().Now)
	m.SetNetwork("a")
	tg := target{name: "a.googlevideo.com", part: partVideo}
	nm, _ := m.plan(tg)
	m.SetNetwork("b")
	m.record(nm, verdict{t: tg, first: 1, winner: 6})
	if len(m.Parts()) != 0 {
		t.Error("recorded on the new network")
	}
	m.SetNetwork("a")
	if len(m.Parts()) != 0 || len(m.cur.wins) != 0 {
		t.Error("recorded on the old network, which was left")
	}
}

// Three silences of the strategy a part asked for, in a row, and the part is forgotten; a success of it in between
// starts the count again.
func TestGuardDropsAPartAfterThreeInARow(t *testing.T) {
	m := OpenMemory("", newClock().Now)
	m.SetNetwork("t")
	part := target{name: "a.googlevideo.com", part: partVideo}
	win(m, part, 1, 6, srcNone)
	for i, name := range []string{"b", "c", "d"} {
		ch := win(m, target{name: name + ".googlevideo.com", part: partVideo}, 6, 1, srcPart)
		if (ch.broken == 6) != (i == 2) {
			t.Errorf("silence %d: %+v", i+1, ch)
		}
	}
	if len(m.Parts()) != 0 {
		t.Errorf("parts %v", m.Parts())
	}

	win(m, part, 1, 6, srcNone)
	win(m, target{name: "b.googlevideo.com", part: partVideo}, 6, 1, srcPart)
	win(m, target{name: "c.googlevideo.com", part: partVideo}, 6, 1, srcPart)
	win(m, part, 6, 6, srcPart) // answered again
	if ch := win(m, target{name: "d.googlevideo.com", part: partVideo}, 6, 1, srcPart); ch.broken != 0 || len(m.Parts()) != 1 {
		t.Errorf("%+v %v", ch, m.Parts())
	}

}

// A ladder in which nothing answered, not even the ordinary connection, says that the network or the site is down,
// and nothing about the strategy the name started with: three of them in a row do not make it forgotten.
func TestNothingAnsweringDoesNotCountAgainstAStrategy(t *testing.T) {
	m := OpenMemory("", newClock().Now)
	m.SetNetwork("t")
	own := target{name: "mine.example.org", own: true}
	part := target{name: "rr1.googlevideo.com", part: partVideo}
	win(m, own, 1, 3, srcNone)
	win(m, part, 1, 6, srcNone)
	for range 5 {
		for _, tg := range []target{own, {name: "rr2.googlevideo.com", part: partVideo}} {
			nm, h := m.plan(tg)
			if ch := m.record(nm, verdict{t: tg, first: h.first, src: h.src, pause: time.Minute}); ch.broken != 0 {
				t.Fatalf("%+v", ch)
			}
		}
	}
	if _, h := m.plan(own); h.first != 3 {
		t.Errorf("an own site that nothing opened lost its strategy: %+v", h)
	}
	if p := m.Parts(); len(p) != 1 || p[0].Strategy != 6 {
		t.Errorf("a part that nothing opened lost its strategy: %+v", p)
	}
}

// The strategies that lose to plain go to the end, the ones that win come first.
func TestRankPutsWinnersFirstAndHarmfulLast(t *testing.T) {
	m := OpenMemory("", newClock().Now)
	m.SetNetwork("t")
	nm, _ := m.plan(target{})
	cands := []dpi.Strategy{{Num: 6}, {Num: 16}, {Num: 8}, {Num: 15}}
	nm.wins = map[int]int{8: 5, 16: 1}
	nm.harms = map[int]int{6: harmLimit}
	m.rank(nm, cands)
	var got []int
	for _, c := range cands {
		got = append(got, c.Num)
	}
	if fmt.Sprint(got) != "[8 16 15 6]" {
		t.Errorf("%v", got)
	}
}

// The table of names does not grow past its limit, and what is dropped is what was used least lately.
func TestNamesAreBounded(t *testing.T) {
	clk := newClock()
	m := OpenMemory("", clk.Now)
	m.SetNetwork("t")
	nm, _ := m.plan(target{})
	for i := range maxNames + 100 {
		clk.Advance(time.Millisecond)
		tg := target{name: fmt.Sprint("n", i, ".example.org")}
		m.record(nm, verdict{t: tg, first: 1, pause: time.Hour})
	}
	if len(nm.names) != maxNames {
		t.Errorf("%d names", len(nm.names))
	}
	if nm.names["n0.example.org"] != nil || nm.names[fmt.Sprint("n", maxNames+99, ".example.org")] == nil {
		t.Error("the oldest is kept and the newest is not")
	}
}

// Everything at once, for the race detector: lookups, results, network changes and saves.
func TestMemoryIsSafeForConcurrentUse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bypass.json")
	m := OpenMemory(path, nil)
	m.SetNetwork("t")
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 300 {
				tg := target{name: fmt.Sprint("h", i%7, ".example.org"), own: i%5 == 0}
				if i%3 == 0 {
					tg = target{name: fmt.Sprint("rr", i%7, ".googlevideo.com"), part: partVideo}
				}
				nm, h := m.plan(tg)
				m.hintFor(nm, tg)
				m.record(nm, verdict{t: tg, first: h.first, src: h.src, winner: []int{0, 1, 6, 7}[(i+g)%4], pause: time.Minute})
				switch i % 50 {
				case 0:
					m.SetNetwork(fmt.Sprint("net", (i+g)%3))
				case 10:
					m.Save()
				case 20:
					m.Parts()
					m.Site("h1.example.org")
				}
			}
		}()
	}
	wg.Wait()
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
}

func TestSaveFailureKeepsTheMemoryDirty(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	os.WriteFile(blocker, nil, 0o600)
	m := OpenMemory(filepath.Join(blocker, "bypass.json"), nil) // a directory cannot be made under a file
	m.SetNetwork("t")
	win(m, target{name: "a.googlevideo.com", part: partVideo}, 1, 6, srcNone)
	if err := m.Save(); err == nil {
		t.Fatal("no error")
	}
	if !m.dirty {
		t.Error("a failed write forgot that there is something to write")
	}
}

// A strategy that keeps working is not a reason to write the file: confirmations that change nothing are not
// written, and the count of its wins is written once, when the strategy is new to the network, and then once an hour.
func TestRememberedStrategyKeepsTheFileQuiet(t *testing.T) {
	clk := newClock()
	m := OpenMemory(filepath.Join(t.TempDir(), "bypass.json"), clk.Now)
	m.SetNetwork("a")
	tg := target{name: "a.googlevideo.com", part: partVideo}
	win(m, tg, 1, 6, srcNone) // the ladder that found it
	if err := m.Save(); err != nil || m.dirty {
		t.Fatalf("save: %v, dirty %v", err, m.dirty)
	}
	for i := range 5 {
		win(m, tg, 6, 6, srcPart) // the connections that went straight to it
		if m.dirty {
			t.Fatalf("connection %d made the memory dirty", i)
		}
	}
	win(m, tg, 1, 6, srcNone) // another ladder, minutes later: the count grows in RAM only
	if m.dirty || m.cur.wins[6] != 2 {
		t.Errorf("dirty %v, wins %v", m.dirty, m.cur.wins)
	}
	clk.Advance(touchEach + time.Minute)
	win(m, tg, 1, 6, srcNone)
	if !m.dirty {
		t.Error("an hour later the count was still not written")
	}
}
