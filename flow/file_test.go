package flow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Tests of what is written to the file and what is read from it.

// readsAs makes the next reads of the memory file go through f, for the length of the test.
func readsAs(t *testing.T, f func(path string) ([]byte, error)) {
	t.Helper()
	was, wasWait := readFile, rereadAfter
	readFile, rereadAfter = f, time.Millisecond
	t.Cleanup(func() { readFile, rereadAfter = was, wasWait })
}

// A file that another program holds open at the moment the service starts (a scanner, a backup: usual on Windows)
// is not an empty memory. It is read again; and if it stays busy, the run goes on in RAM with a salt of its own and
// does not write over it, so that the next start finds the memory of the runs before, and the salt, and with it the
// fingerprint of every network it knows.
func TestBusyFileAtStartKeepsTheMemory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bypass.json")
	clk := newClock()
	m := OpenMemory(path, clk.Now)
	m.SetNetwork("home")
	win(m, target{name: "a.googlevideo.com", part: partVideo}, 1, 6, srcNone)
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	salt := m.Salt()
	good, _ := os.ReadFile(path)
	busy := errors.New("the process cannot access the file because it is being used by another process")

	// Busy for a moment: the second read gets it.
	calls := 0
	readsAs(t, func(p string) ([]byte, error) {
		if calls++; calls == 1 {
			return nil, busy
		}
		return readCapped(p)
	})
	m2 := OpenMemory(path, clk.Now)
	if known := m2.SetNetwork("home"); !known || m2.Salt() != salt || len(m2.Parts()) != 1 || calls != 2 {
		t.Errorf("busy for a moment: known %v, same salt %v, parts %v, %d reads", known, m2.Salt() == salt, m2.Parts(), calls)
	}

	// Busy for the whole run.
	readsAs(t, func(string) ([]byte, error) { return nil, busy })
	m3 := OpenMemory(path, clk.Now)
	m3.SetNetwork("home")
	win(m3, target{name: "b.googlevideo.com", part: partVideo}, 1, 7, srcNone)
	if p := m3.Parts(); len(p) != 1 || p[0].Strategy != 7 {
		t.Errorf("the run does not learn in RAM: %+v", p)
	}
	if err := m3.Save(); !errors.Is(err, ErrFileUnread) {
		t.Errorf("save: %v", err)
	}
	if now, _ := os.ReadFile(path); !bytes.Equal(now, good) {
		t.Fatalf("the file was written over:\n%s", now)
	}
	readsAs(t, readCapped)
	m4 := OpenMemory(path, clk.Now)
	if known := m4.SetNetwork("home"); !known || m4.Salt() != salt || len(m4.Parts()) != 1 || m4.Parts()[0].Strategy != 6 {
		t.Errorf("the next start: known %v, same salt %v, parts %v", known, m4.Salt() == salt, m4.Parts())
	}
}

// A network the service stays on, used every day, is not forgotten after 30 days because SetNetwork was not called:
// what is in use is seen now when the file is written.
func TestNetworkInUseDoesNotAgeOut(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bypass.json")
	clk := newClock()
	m := OpenMemory(path, clk.Now)
	m.SetNetwork("home")
	tg := target{name: "a.googlevideo.com", part: partVideo}
	win(m, tg, 1, 6, srcNone)
	for range 31 {
		clk.Advance(24 * time.Hour)
		win(m, tg, 6, 6, srcPart) // used every day
	}
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	m2 := OpenMemory(path, clk.Now)
	if known := m2.SetNetwork("home"); !known || len(m2.Parts()) != 1 {
		t.Errorf("after a restart: known %v, parts %+v", known, m2.Parts())
	}
}

// Whatever the memory can hold is a file it can read back: the counts of wins are bounded, a network that is full is
// whole in the file, and the file of 32 full networks is under the limit.
func TestFullMemoryIsReadBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bypass.json")
	clk := newClock()
	m := OpenMemory(path, clk.Now)
	at := clk.Now()
	for i := range maxNets {
		m.SetNetwork(fmt.Sprintf("%032x", i))
		nm := m.cur
		for n := range maxWins + 50 { // more than the table takes
			m.countWin(nm, 2+n, at)
		}
		nm.parts = map[partKey]*rec{}
		for n := range maxParts {
			nm.parts[partKey{fmt.Sprint("service", n), "part-of-the-service"}] = &rec{strategy: 6, at: at}
		}
		nm.sites = map[string]*rec{}
		for n := range maxSites {
			k := fmt.Sprintf("%016x", n)
			nm.sites[k] = &rec{strategy: 6, at: at, site: k}
		}
		clk.Advance(time.Minute)
	}
	if len(m.cur.wins) != maxWins {
		t.Fatalf("%d counts of wins in RAM", len(m.cur.wins))
	}
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Size() >= maxFile {
		t.Fatalf("%v, %v", fi, err)
	}
	m2 := OpenMemory(path, clk.Now)
	for i := range maxNets {
		if !m2.SetNetwork(fmt.Sprintf("%032x", i)) || len(m2.cur.parts) != maxParts || len(m2.cur.sites) != maxSites || len(m2.cur.wins) != maxWins {
			t.Fatalf("network %d: %d parts, %d sites, %d counts", i, len(m2.cur.parts), len(m2.cur.sites), len(m2.cur.wins))
		}
	}
}

// The file says on which day a network was seen and a result shown, and no more: nobody needs the minute, and it says
// when the person was where.
func TestFileHoldsDaysAndNotMinutes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bypass.json")
	clk := newClock()
	clk.Advance(7*time.Hour + 13*time.Minute + 5*time.Second)
	m := OpenMemory(path, clk.Now)
	m.SetNetwork("home")
	win(m, target{name: "a.googlevideo.com", part: partVideo}, 1, 6, srcNone)
	win(m, target{name: "mine.example.org", own: true}, 1, 3, srcNone)
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	var d diskFile
	if err := json.Unmarshal(data, &d); err != nil || len(d.Networks) != 1 {
		t.Fatalf("%v: %s", err, data)
	}
	for _, dn := range d.Networks {
		times := []int64{dn.Seen}
		for _, r := range dn.Parts {
			times = append(times, r.At)
		}
		for _, r := range dn.Sites {
			times = append(times, r.At)
		}
		if len(times) != 3 {
			t.Fatalf("%v", times)
		}
		for _, at := range times {
			if at%86400 != 0 || time.Unix(at, 0).After(clk.Now()) {
				t.Errorf("%d is not the start of a day (now %d)", at, clk.Now().Unix())
			}
		}
	}
}
