package flow

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mistgate/mistgate-bypass/dpi"
)

// What a network teaches the program, and for how long.
const (
	fileVersion = 1
	maxFile     = 1 << 20 // a larger file is damaged, not read

	maxNets   = 32                  // networks kept, the least recently seen go first (plan 4.2)
	maxAge    = 30 * 24 * time.Hour // a result or a network not seen for this long is forgotten (plan 4.2)
	freshFor  = 7 * 24 * time.Hour  // older than this a remembered strategy is a hint, not a fact (plan 4.2)
	maxNames  = 4096                // names in RAM per network (plan 4.2)
	maxParts  = 512                 // service parts with a result, per network
	maxSites  = 1024                // the user's own sites with a result, per network
	maxWins   = 128                 // strategies with a count of wins, per network
	maxKey    = 128                 // bytes of the network key
	maxStrat  = 9999                // above this a number in the file is not a strategy
	touchEach = time.Hour           // how often a confirmed result gets a new time (and the file a new write)

	// guardFails is how many times in a row the strategy a record asked for may stay silent before the record is
	// dropped and the ladder starts over (plan 4.5: three).
	guardFails = 3
	// harmLimit is how many times a strategy must have lost to plain, where plain worked, before it goes to the end
	// of the order on that network (plan 5: three).
	harmLimit = 3
)

// Memory is what the ladder has learnt, per network. A network is a key that the caller makes up from things only
// it knows (SetNetwork); this package never sees an address or an adapter.
//
// In RAM, per network: a record for each name that needs one (a strategy, "works as it is", or "silent just now"),
// the strategies that lost to plain. On disk, per network: the result of each service part, the result of each of
// the user's own sites under a keyed hash of its name, and how many times each strategy has won. No other name is
// ever written, and nothing is kept for longer than maxAge.
//
// One mutex guards everything. It is held for map lookups and nothing else: no I/O, no callback, no other lock.
type Memory struct {
	path string
	now  func() time.Time

	mu    sync.Mutex
	salt  [32]byte
	nets  map[string]*netMem
	cur   *netMem
	dirty bool

	saveMu sync.Mutex // one write of the file at a time; taken without mu held
}

type netMem struct {
	seen  time.Time
	wins  map[int]int      // strategy -> times it opened something (disk)
	parts map[partKey]*rec // service part -> result (disk)
	sites map[string]*rec  // keyed hash of an own site -> result (disk)
	names map[string]*rec  // RAM only
	harms map[int]int      // RAM only: strategy -> times it lost where plain worked
}

// partKey names a part of a service as the set does. The zero value is "no part".
type partKey struct{ svc, part string }

func (k partKey) ok() bool { return k.svc != "" }

// rec is one result. strategy 0 means nothing is known (the record carries only the marks below); 1 means the
// name opens as it is; more is the strategy it needs.
type rec struct {
	strategy int
	at       time.Time // when a connection last showed it
	fails    uint8     // times in a row the strategy that this record asked for stayed silent (RAM)
	site     string    // key in sites, when this is the record of an own site (RAM)

	deadUntil, unreachUntil time.Time // marks of a name that is down (RAM)
	used                    time.Time // for choosing what to forget (RAM)
}

// target is what a connection is for. part is set when the set says the name belongs to a service part; own when
// the caller says the name is one of the user's own sites (and no part claims it).
type target struct {
	name string
	part partKey
	own  bool
}

// OpenMemory reads the memory kept at path. A file that is missing, damaged, too large or of another version is an
// empty memory: it is never an error, the program starts from nothing and the next Save replaces the file. An
// empty path keeps everything in RAM. now is the clock; nil means time.Now.
func OpenMemory(path string, now func() time.Time) *Memory {
	if now == nil {
		now = time.Now
	}
	m := &Memory{path: path, now: now, nets: map[string]*netMem{}}
	if !m.load() {
		m.nets = map[string]*netMem{}
		rand.Read(m.salt[:]) // never fails: crypto/rand crashes the program rather than return an error
		m.dirty = true
	}
	m.cur = m.network("") // also trims a file that holds more networks than maxNets
	return m
}

// Salt is the 32 random bytes of this installation, for the caller to key its network fingerprint with. It is
// made on first use and kept in the file.
func (m *Memory) Salt() [32]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.salt
}

// SetNetwork makes key the current network and says whether it was seen before, in this run or in an earlier one.
// The key is an opaque short string. What a connection learns is kept under the network it started on: a result
// that arrives after the network has changed is dropped, not credited to the new one.
func (m *Memory) SetNetwork(key string) (known bool) {
	if len(key) > maxKey {
		key = key[:maxKey]
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_, known = m.nets[key]
	m.cur = m.network(key)
	m.cur.seen = m.now()
	return known
}

// network finds or makes the record of a network and forgets the least recently seen ones beyond maxNets.
// The caller holds mu (or has the Memory to itself).
func (m *Memory) network(key string) *netMem {
	if nm := m.nets[key]; nm != nil {
		return nm
	}
	nm := &netMem{seen: m.now()}
	m.nets[key] = nm
	for len(m.nets) > maxNets {
		var oldest string
		var at time.Time
		found := false
		for k, o := range m.nets {
			if o != nm && (!found || o.seen.Before(at)) {
				found = true
				oldest, at = k, o.seen
			}
		}
		delete(m.nets, oldest)
		m.dirty = true
	}
	return nm
}

// PartResult is what is known about a service part on the current network.
type PartResult struct {
	Service, Part string
	Strategy      int // 1: opens as it is; more: the strategy it needs
	At            time.Time
}

// Parts lists the results of the service parts on the current network, for the window to show before any
// connection has been made. Fresh or not, they are what the last connection showed.
func (m *Memory) Parts() []PartResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []PartResult
	for k, r := range m.cur.parts {
		out = append(out, PartResult{k.svc, k.part, r.strategy, r.at})
	}
	slices.SortFunc(out, func(a, b PartResult) int {
		return strings.Compare(a.Service+"/"+a.Part, b.Service+"/"+b.Part)
	})
	return out
}

// Site is the result for one of the user's own sites on the current network (Strategy as in PartResult).
func (m *Memory) Site(name string) (strategy int, at time.Time, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if n := m.cur.names[name]; n != nil && n.site != "" {
		return n.strategy, n.at, true
	}
	if r := m.cur.sites[m.siteKey(name)]; r != nil {
		return r.strategy, r.at, true
	}
	return 0, time.Time{}, false
}

// siteKey is the name an own site has on disk: a keyed hash, so that the file shows nothing about the sites.
func (m *Memory) siteKey(name string) string {
	h := hmac.New(sha256.New, m.salt[:])
	h.Write([]byte(strings.ToLower(strings.TrimSuffix(name, "."))))
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// hint is what memory says about a name when a connection to it starts.
type hint struct {
	first int // the strategy to start with: 1 (plain) or the one remembered
	stale int // a remembered strategy older than freshFor: it goes right after plain
	src   source

	dead        bool // the ladder gave up on the name lately: no ladder, plain only
	unreachable bool // nothing answered at the address lately
	settled     bool // plain answering would teach nothing new: nothing to write after it
}

// source says which record a strategy came from, so that the right one is blamed when it fails.
type source uint8

const (
	srcNone source = iota
	srcName
	srcPart
)

// plan reads what is known about a target on the current network and returns that network, for the caller to
// record under later.
func (m *Memory) plan(t target) (*netMem, hint) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cur, m.hint(m.cur, t)
}

// hintFor is plan for a connection that has been running for a while: on the network it started on, or, if that
// is no longer the current one, nothing.
func (m *Memory) hintFor(nm *netMem, t target) hint {
	m.mu.Lock()
	defer m.mu.Unlock()
	if nm != m.cur {
		return hint{first: 1, settled: true}
	}
	return m.hint(nm, t)
}

func (m *Memory) hint(nm *netMem, t target) (h hint) {
	now := m.now()
	h.first = 1
	n := m.lookup(nm, t)
	marked := false
	if n != nil {
		n.used = now
		h.unreachable = now.Before(n.unreachUntil)
		h.dead = now.Before(n.deadUntil)
		marked = !n.deadUntil.IsZero() || !n.unreachUntil.IsZero()
	}
	r, src := n, srcName
	if r == nil || r.strategy == 0 {
		r, src = nm.parts[t.part], srcPart
	}
	switch {
	case r != nil && r.strategy > 1:
		if now.Sub(r.at) > freshFor {
			h.stale = r.strategy
		} else {
			h.first = r.strategy
		}
		h.src = src
	case r != nil && r.strategy == 1:
		h.settled = !marked
	default:
		// No result: plain answering teaches something only for a part (its result is "opens as it is") and an
		// own site; any other name is not remembered when it works.
		h.settled = !marked && !t.part.ok() && !t.own
	}
	return h
}

// lookup finds the record of a name in RAM, bringing an own site's record up from the disk part on first sight.
func (m *Memory) lookup(nm *netMem, t target) *rec {
	if n := nm.names[t.name]; n != nil {
		return n
	}
	if t.own {
		if r := nm.sites[m.siteKey(t.name)]; r != nil {
			m.keep(nm, t.name, r)
			return r
		}
	}
	return nil
}

// keep puts a record in the names of the network, forgetting the one least used when the table is full.
// ponytail: a scan of the table for each insertion at the limit; a heap or a clock hand if it ever shows up.
func (m *Memory) keep(nm *netMem, name string, r *rec) {
	if len(nm.names) >= maxNames {
		var oldest string
		var at time.Time
		found := false
		for k, o := range nm.names {
			if !found || o.used.Before(at) {
				found = true
				oldest, at = k, o.used
			}
		}
		delete(nm.names, oldest)
	}
	if nm.names == nil {
		nm.names = map[string]*rec{}
	}
	r.used = m.now()
	nm.names[name] = r
}

// nameRec is lookup that makes the record when there is none.
func (m *Memory) nameRec(nm *netMem, t target) *rec {
	if n := m.lookup(nm, t); n != nil {
		return n
	}
	n := &rec{}
	m.keep(nm, t.name, n)
	return n
}

// rank puts the candidates in the order of this network: the ones that have won most first, the ones that have
// lost to plain too often last, the order of the set otherwise. It sorts the slice it is given.
func (m *Memory) rank(nm *netMem, l []dpi.Strategy) {
	m.mu.Lock()
	defer m.mu.Unlock()
	slices.SortStableFunc(l, func(a, b dpi.Strategy) int {
		ha, hb := nm.harms[a.Num] >= harmLimit, nm.harms[b.Num] >= harmLimit
		switch {
		case ha != hb && ha:
			return 1
		case ha != hb:
			return -1
		}
		return nm.wins[b.Num] - nm.wins[a.Num]
	})
}

// failKind says why nothing opened.
type failKind uint8

const (
	failNoWay failKind = iota // connected, and nothing answered
	failUnreachable
)

// verdict is what a connection showed.
type verdict struct {
	t      target
	first  int    // the strategy the connection started with
	src    source // the record that asked for it
	winner int    // the strategy that opened it; 0: none did
	fail   failKind
	pause  time.Duration // how long to leave a name that is down alone
}

// change is what recording a verdict did that the caller may want to tell.
type change struct {
	changed bool // the result of a part or of an own site on disk is new
	broken  int  // the remembered strategy the guard has dropped
}

// record writes what a connection showed into the network it started on.
func (m *Memory) record(nm *netMem, v verdict) (ch change) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if nm != m.cur {
		return
	}
	now := m.now()
	switch {
	case v.winner != 0:
		return m.win(nm, v, now)
	case v.fail == failUnreachable:
		m.nameRec(nm, v.t).unreachUntil = now.Add(v.pause)
	default:
		m.nameRec(nm, v.t).deadUntil = now.Add(v.pause)
		if v.first > 1 {
			ch.broken = m.lose(nm, v)
		}
	}
	return
}

func (m *Memory) win(nm *netMem, v verdict, now time.Time) (ch change) {
	t, w := v.t, v.winner
	if w > 1 {
		nm.wins = bump(nm.wins, w)
		m.dirty = true
	}
	n := nm.names[t.name]
	if n != nil {
		n.deadUntil, n.unreachUntil = time.Time{}, time.Time{}
	}
	// Plain answered where the strategy the memory asked for had stayed silent: the strategy does harm here.
	harm := w == 1 && v.first > 1
	if harm {
		nm.harms = bump(nm.harms, v.first)
	}
	switch {
	case !t.part.ok():
		// A name of no service has a record when it needs one, or when the user has listed it.
		if n != nil || t.own || w > 1 {
			ch.changed = m.set(nm, t, m.nameRec(nm, t), w, now) && t.own
		}
	case w > 1:
		ch.changed = m.setPart(nm, t.part, w, now)
		if n != nil {
			n.strategy, n.at, n.fails = w, now, 0
		}
	case harm:
		// The part needs a strategy, this name does not: the name is remembered as it is, the part is blamed.
		n = m.nameRec(nm, t)
		n.strategy, n.at, n.fails = 1, now, 0
		if v.src == srcPart {
			ch.broken = m.lose(nm, v)
		}
	default:
		if n != nil {
			n.strategy, n.at, n.fails = 1, now, 0
		}
		if p := nm.parts[t.part]; p == nil || p.strategy <= 1 || now.Sub(p.at) > freshFor {
			ch.changed = m.setPart(nm, t.part, 1, now)
		}
	}
	return
}

// set gives a record a result. An own site's record is also the one on disk, under the hash of its name.
func (m *Memory) set(nm *netMem, t target, n *rec, s int, now time.Time) (changed bool) {
	changed = n.strategy != s
	stale := now.Sub(n.at) > touchEach
	n.strategy, n.at, n.fails = s, now, 0
	if t.own {
		if n.site == "" {
			n.site = m.siteKey(t.name)
			changed = true
		}
		if _, ok := nm.sites[n.site]; !ok && len(nm.sites) >= maxSites {
			return changed
		}
		if nm.sites == nil {
			nm.sites = map[string]*rec{}
		}
		nm.sites[n.site] = n
		m.dirty = m.dirty || changed || stale
	}
	return changed
}

func (m *Memory) setPart(nm *netMem, k partKey, s int, now time.Time) (changed bool) {
	p := nm.parts[k]
	if p == nil {
		if len(nm.parts) >= maxParts {
			return false
		}
		if nm.parts == nil {
			nm.parts = map[partKey]*rec{}
		}
		p = &rec{}
		nm.parts[k] = p
	}
	changed = p.strategy != s
	p.strategy, p.fails = s, 0
	if changed || now.Sub(p.at) > touchEach {
		p.at = now
		m.dirty = true
	}
	return changed
}

// lose counts one silence of the strategy a record asked for, and drops the record at guardFails in a row, so that
// the next connection starts from nothing and the ladder runs again. A success of any kind resets the count.
func (m *Memory) lose(nm *netMem, v verdict) (dropped int) {
	var d *rec
	if v.src == srcPart {
		d = nm.parts[v.t.part]
	} else {
		d = nm.names[v.t.name]
	}
	if d == nil || d.strategy != v.first {
		return 0 // another connection has already changed it
	}
	if d.fails++; d.fails < guardFails {
		return 0
	}
	if v.src == srcPart {
		delete(nm.parts, v.t.part)
	} else {
		d.strategy, d.fails = 0, 0
		if d.site != "" {
			delete(nm.sites, d.site)
			d.site = ""
		}
	}
	m.dirty = true
	return v.first
}

func bump(m map[int]int, k int) map[int]int {
	if m == nil {
		m = map[int]int{}
	}
	m[k]++
	return m
}

// The file. Every number in it is checked on the way in: what is not plausible is left out, and a file that is not
// plausible as a whole is an empty memory.

type diskFile struct {
	V        int                 `json:"v"`
	Salt     string              `json:"salt"`
	Networks map[string]*diskNet `json:"networks,omitempty"`
}

type diskNet struct {
	Seen  int64              `json:"seen_unix"`
	Wins  map[string]int     `json:"wins,omitempty"`
	Parts map[string]diskRec `json:"parts,omitempty"` // "service/part"
	Sites map[string]diskRec `json:"sites,omitempty"` // keyed hash of the name
}

type diskRec struct {
	O  string `json:"o"` // "self" or "bypass"
	S  int    `json:"s,omitempty"`
	At int64  `json:"at"`
}

// load reads the file into m, and reports whether it was usable (a salt that was there, a version that is known).
func (m *Memory) load() bool {
	if m.path == "" {
		return false
	}
	f, err := os.Open(m.path)
	if err != nil {
		return false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	var d diskFile
	if err != nil || len(data) > maxFile || json.Unmarshal(data, &d) != nil || d.V != fileVersion {
		return false
	}
	salt, err := hex.DecodeString(d.Salt)
	if err != nil || len(salt) != len(m.salt) {
		return false
	}
	copy(m.salt[:], salt)
	now := m.now()
	for key, dn := range d.Networks {
		if dn == nil || len(key) > maxKey || len(dn.Parts) > maxParts || len(dn.Sites) > maxSites || len(dn.Wins) > maxWins {
			continue
		}
		seen := time.Unix(dn.Seen, 0)
		if now.Sub(seen) > maxAge {
			continue
		}
		if seen.After(now) {
			seen = now // a clock that went back
		}
		nm := &netMem{seen: seen}
		for k, c := range dn.Wins {
			if s, err := strconv.Atoi(k); err == nil && s > 1 && s <= maxStrat && c > 0 {
				nm.wins = bump(nm.wins, s)
				nm.wins[s] = min(c, 1<<30)
			}
		}
		for k, r := range dn.Parts {
			svc, part, ok := strings.Cut(k, "/")
			if rr := fromDisk(r, now); ok && svc != "" && part != "" && rr != nil {
				if nm.parts == nil {
					nm.parts = map[partKey]*rec{}
				}
				nm.parts[partKey{svc, part}] = rr
			}
		}
		for k, r := range dn.Sites {
			if rr := fromDisk(r, now); rr != nil && len(k) == 16 && isHex(k) {
				if nm.sites == nil {
					nm.sites = map[string]*rec{}
				}
				rr.site = k
				nm.sites[k] = rr
			}
		}
		m.nets[key] = nm
	}
	return true
}

// fromDisk turns a record of the file into one in RAM, or nil if it is not plausible or has aged out.
func fromDisk(r diskRec, now time.Time) *rec {
	at := time.Unix(r.At, 0)
	if now.Sub(at) > maxAge {
		return nil
	}
	if at.After(now) {
		at = now // a clock that has gone back must not make a result fresher than it is
	}
	switch {
	case r.O == "self":
		return &rec{strategy: 1, at: at}
	case r.O == "bypass" && r.S > 1 && r.S <= maxStrat:
		return &rec{strategy: r.S, at: at}
	}
	return nil
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

// Save writes the memory to its file if anything worth keeping has changed since the last write. The write is
// atomic: the file is whole before and after it. Call it from time to time and when the program stops.
func (m *Memory) Save() error {
	if m.path == "" {
		return nil
	}
	m.saveMu.Lock()
	defer m.saveMu.Unlock()
	m.mu.Lock()
	if !m.dirty {
		m.mu.Unlock()
		return nil
	}
	data, err := m.encode()
	m.dirty = false
	m.mu.Unlock()
	if err == nil {
		err = writeAtomic(m.path, data)
	}
	if err != nil {
		m.mu.Lock()
		m.dirty = true
		m.mu.Unlock()
	}
	return err
}

// encode makes the bytes of the file. The caller holds mu.
func (m *Memory) encode() ([]byte, error) {
	now := m.now()
	d := diskFile{V: fileVersion, Salt: hex.EncodeToString(m.salt[:]), Networks: map[string]*diskNet{}}
	for key, nm := range m.nets {
		dn := &diskNet{Seen: nm.seen.Unix(), Wins: map[string]int{}, Parts: map[string]diskRec{}, Sites: map[string]diskRec{}}
		for s, c := range nm.wins {
			dn.Wins[strconv.Itoa(s)] = c
		}
		for k, r := range nm.parts {
			if dr, ok := toDisk(r, now); ok {
				dn.Parts[k.svc+"/"+k.part] = dr
			}
		}
		for k, r := range nm.sites {
			if dr, ok := toDisk(r, now); ok {
				dn.Sites[k] = dr
			}
		}
		if len(dn.Wins)+len(dn.Parts)+len(dn.Sites) > 0 && now.Sub(nm.seen) <= maxAge {
			d.Networks[key] = dn
		}
	}
	return json.Marshal(d)
}

func toDisk(r *rec, now time.Time) (diskRec, bool) {
	if r.strategy == 0 || now.Sub(r.at) > maxAge {
		return diskRec{}, false
	}
	if r.strategy == 1 {
		return diskRec{O: "self", At: r.at.Unix()}, true
	}
	return diskRec{O: "bypass", S: r.strategy, At: r.at.Unix()}, true
}

// writeAtomic replaces the file at path with data: the bytes go to a file beside it, are flushed, and the new file
// is renamed over the old one, so that a crash leaves one or the other whole.
func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}
