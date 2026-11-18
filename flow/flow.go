// Package flow is the ladder a new TLS connection climbs on a network that filters its first packet: the ordinary
// connection first; if the server has not answered after a short wait, the strategies of package dpi one after the
// other, beside the ordinary connection, which stays open; the first connection that gets a byte from the server
// is the one the caller keeps. What a network has taught is remembered (Memory), so that the next connection to
// the same name goes straight to what worked.
//
// The caller gives Open the name it has read from the ClientHello, the ClientHello itself, and a function that
// makes a new outgoing TCP connection (bound to the right interface, which is none of this package's business).
// It gets back a connection with the first bytes of the server's answer already read, or an error that says why
// the ladder gave up, so that it can hand the flow to something else.
//
// Why a retry is safe: the only bytes ever sent twice are the ClientHello that the caller has already read from
// the application, and the application's later bytes wait in the caller's buffer until a connection is chosen.
// A connection that has answered is the last one tried, and the answers of the losers are never passed on.
package flow

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/mistgate/mistgate-bypass/dpi"
	"github.com/mistgate/mistgate-bypass/sets"
)

// The ladder gave up. Both errors carry no name and no address; the cause is the error itself.
var (
	// ErrUnreachable: no connection could be made at all (no answer to the SYN, a refusal, no route). Nothing but
	// the address can be wrong, and no strategy changes that: the ladder does not run.
	ErrUnreachable = errors.New("flow: unreachable")
	// ErrNoWay: connections were made and none was answered: within the budget, with the ordinary connection and the
	// strategies tried; or within T, for a name that has just been found to be down; or each one was broken by the
	// network.
	ErrNoWay = errors.New("flow: ladder exhausted")
)

// DialFunc makes a new outgoing TCP connection. It must return when ctx ends: Open waits for it. ctx has the
// end of the ladder's budget as its deadline, and says nothing about the life of the connection once made.
type DialFunc func(ctx context.Context) (*net.TCPConn, error)

// Result is a connection to keep.
type Result struct {
	Conn *net.TCPConn
	// First is what the server has sent so far, already read from Conn: the caller writes it to the application
	// first, then copies the rest. Empty only for a flow that is not TLS.
	First []byte
	// Strategy is the number of the strategy that opened it; 1 is the ordinary connection.
	Strategy int
}

// Timing holds the numbers of the ladder. A zero field takes the default, which is the number of the plan.
// They are knobs to measure, not settings: nothing here has been measured on a real network yet.
type Timing struct {
	// A silent server is given T to answer, from 2 round trips of the connect and TSlack, between TMin and TMax;
	// then the next strategy starts. (plan 3.2: 0.7 s to 2.5 s, 2 RTT + 400 ms)
	TMin, TMax, TSlack time.Duration
	// Budget is the time the whole ladder of one connection has, dialling included. (plan 3.2: 8 s)
	Budget time.Duration
	// DeadFor is how long a name that nothing opened is left alone; UnreachFor the same for an address that did not
	// answer. (plan 3.2: 10 min, 5 min)
	DeadFor, UnreachFor time.Duration
	// MaxAttempts is how many connections one ladder opens, the ordinary one included. (plan 3.2: 5)
	MaxAttempts int
	// MaxLadders is how many ladders run at once in all. (plan 3.2: 32)
	MaxLadders int
}

func (t Timing) withDefaults() Timing {
	def := func(p *time.Duration, d time.Duration) {
		if *p <= 0 {
			*p = d
		}
	}
	def(&t.TMin, 700*time.Millisecond)
	def(&t.TMax, 2500*time.Millisecond)
	def(&t.TSlack, 400*time.Millisecond)
	def(&t.Budget, 8*time.Second)
	def(&t.DeadFor, 10*time.Minute)
	def(&t.UnreachFor, 5*time.Minute)
	if t.MaxAttempts <= 0 {
		t.MaxAttempts = 5
	}
	if t.MaxLadders <= 0 {
		t.MaxLadders = 32
	}
	return t
}

// Config is what New needs. Every field may be left zero.
type Config struct {
	// Memory is what the ladder learns. Nil: a memory in RAM only.
	Memory *Memory
	// Set is the current set of strategies, asked for on every connection so that a new one takes effect at once.
	// Nil, or nil result: the set built into the library.
	Set func() *sets.Set
	// Country is the two-letter code of the country whose list of strategies is tried; "" is the general list.
	Country func() string
	// Own says whether a name is one of the user's own sites. Their results are kept on disk under a hash, and the
	// events about them carry the name. It is not asked for names that belong to a service of the set.
	Own func(name string) bool
	// Events hears what the ladder has found, see Event. It is called on the goroutine of Open, with no lock held,
	// and must not block.
	Events func(Event)
	Timing Timing

	// OnSend is for tests: it is called with every connection and the plan about to be sent on it, before the
	// first byte is written, so that a filter on loopback can be told how the flight is cut. num is the strategy.
	OnSend func(c *net.TCPConn, num int, p dpi.Plan)
}

// Flows runs ladders. It is safe for use by any number of goroutines.
type Flows struct {
	cfg Config
	tm  Timing
	mem *Memory
	sem chan struct{} // one token per running ladder

	mu      sync.Mutex // guards ladders; nothing else is done under it
	ladders map[ladderKey]*ladder
}

// New makes a Flows.
func New(cfg Config) *Flows {
	f := &Flows{cfg: cfg, tm: cfg.Timing.withDefaults(), mem: cfg.Memory, ladders: map[ladderKey]*ladder{}}
	if f.mem == nil {
		f.mem = OpenMemory("", nil)
	}
	f.sem = make(chan struct{}, f.tm.MaxLadders)
	return f
}

// plain is the ordinary connection, as a strategy: it has no spec and sends the ClientHello as it is.
var plain = sync.OnceValue(func() dpi.Strategy { s, _ := dpi.ByNumber(1); return s })

// builtin is the ladder of dpi, built once: strategies that memory names by number are found here.
var builtin = sync.OnceValue(dpi.Ladder)

// resolve finds the strategy a number stands for: in the list of the set for this name, then among the permanent
// ones. A number that is neither (a strategy a former set defined) is unknown, and the caller goes without it.
func resolve(num int, cands []dpi.Strategy) (dpi.Strategy, bool) {
	if num == 1 {
		return plain(), true
	}
	for _, s := range cands {
		if s.Num == num {
			return s, true
		}
	}
	if l := builtin(); num > 1 && num <= len(l) {
		return l[num-1], true
	}
	return dpi.Strategy{}, false
}

func (f *Flows) set() *sets.Set {
	if f.cfg.Set != nil {
		if s := f.cfg.Set(); s != nil {
			return s
		}
	}
	return sets.Embedded()
}

// request is everything one Open knows; it is passed by value to the slow path so that the fast one allocates
// nothing for it.
type request struct {
	ctx   context.Context
	nm    *netMem
	t     target
	h     hint
	hello []byte
	dial  DialFunc

	first   dpi.Strategy   // the strategy attempt 0 uses
	cands   []dpi.Strategy // the set's strategies for this name; shared, read only
	ladder  bool           // there is something to try after the first attempt
	t0, end time.Time      // start and end of the budget
	step    time.Duration  // T
}

// Open makes the connection for a TLS flow. name is the host name from hello, which is the whole ClientHello
// (read-only until Open returns); the application's later bytes must be held back by the caller.
//
// On the fast path, when the ordinary or the remembered connection is answered within T, Open runs on the
// caller's goroutine only: it starts no goroutine, and takes the lock of memory once to read, and once more to write
// only when there is something to write (a remembered strategy that won, a result that is new).
//
// A flow that is not TLS, or has no name, gets one ordinary connection with hello written, and nothing more.
// An error is ErrUnreachable, ErrNoWay, or the error of ctx.
func (f *Flows) Open(ctx context.Context, name string, hello []byte, dial DialFunc) (Result, error) {
	if name == "" || !isClientHello(hello) {
		return f.direct(ctx, hello, dial)
	}
	set := f.set()
	q := request{ctx: ctx, hello: hello, dial: dial}
	q.t.name = name
	if m, ok := set.Match(name); ok && m.Part.Kind == sets.KindTLS {
		q.t.part = partKey{m.Service.ID, m.Part.ID}
		q.cands = set.Candidates(f.country(), m)
	} else {
		if f.cfg.Own != nil {
			q.t.own = f.cfg.Own(name)
		}
		q.cands = set.Site(f.country())
	}
	q.nm, q.h = f.mem.plan(q.t)
	if q.h.unreachable {
		return Result{}, ErrUnreachable
	}
	var ok bool
	if q.first, ok = resolve(q.h.first, q.cands); !ok {
		q.first, q.h.first, q.h.src = plain(), 1, srcNone
	}
	// With nothing to try after the first connection there is no ladder: it is given the whole budget, so that a
	// slow site is not cut off. A name that is down is given T only, so that the caller can go elsewhere at once.
	q.ladder = !q.h.dead && (q.h.first > 1 || q.h.stale > 1 || len(q.cands) > 0)

	q.t0 = time.Now()
	q.end = q.t0.Add(f.tm.Budget)
	conn, rtt, err := f.connect(ctx, dial, q.end)
	if err != nil {
		return Result{}, f.unreachable(&q, err)
	}
	q.step = min(max(2*rtt+f.tm.TSlack, f.tm.TMin), f.tm.TMax)
	wait := q.step
	if !q.ladder && !q.h.dead {
		wait = f.tm.Budget
	}

	st := stBroke
	var first []byte
	if f.send(conn, q.first, hello) == nil {
		first, st = readFirst(ctx, conn, q.t0.Add(wait))
	}
	switch st {
	case stAnswer:
		conn.SetReadDeadline(time.Time{})
		f.won(&q, q.first.Num, false)
		return Result{Conn: conn, First: first, Strategy: q.first.Num}, nil
	case stCanceled:
		conn.Close()
		return Result{}, ctx.Err()
	}
	return f.slow(q, conn, st == stSilent)
}

// direct is the flow that the ladder does not touch: one ordinary connection, the bytes written, no wait.
func (f *Flows) direct(ctx context.Context, hello []byte, dial DialFunc) (Result, error) {
	conn, _, err := f.connect(ctx, dial, time.Now().Add(f.tm.Budget))
	if err != nil {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		return Result{}, ErrUnreachable
	}
	if len(hello) > 0 {
		if _, err := conn.Write(hello); err != nil {
			conn.Close()
			return Result{}, ErrNoWay
		}
	}
	return Result{Conn: conn, Strategy: 1}, nil
}

func (f *Flows) country() string {
	if f.cfg.Country != nil {
		return f.cfg.Country()
	}
	return ""
}

// isClientHello is the cheap test of the first bytes: a handshake record whose message is a ClientHello.
func isClientHello(b []byte) bool {
	return len(b) >= 6 && b[0] == 0x16 && b[1] == 3 && b[5] == 1
}

// connect dials with the end of the budget as the deadline: a SYN that is never answered must end the ladder.
// The error is the dial's own and may hold an address: it never leaves this package.
func (f *Flows) connect(ctx context.Context, dial DialFunc, end time.Time) (*net.TCPConn, time.Duration, error) {
	dctx, cancel := context.WithDeadline(ctx, end)
	t := time.Now()
	c, err := dial(dctx)
	rtt := time.Since(t)
	cancel()
	if err == nil && c == nil {
		err = errors.New("no connection")
	}
	return c, rtt, err
}

// unreachable ends an Open whose first connection could not be made.
func (f *Flows) unreachable(q *request, err error) error {
	if e := q.ctx.Err(); e != nil {
		return e
	}
	f.mem.record(q.nm, verdict{t: q.t, fail: failUnreachable, pause: f.tm.UnreachFor})
	f.emit(q, Event{Kind: EventFailed, Reason: ReasonUnreachable})
	return ErrUnreachable
}

// send writes the ClientHello on a new connection as the strategy says.
func (f *Flows) send(c *net.TCPConn, s dpi.Strategy, hello []byte) error {
	if s.Num == 1 {
		if f.cfg.OnSend != nil {
			f.cfg.OnSend(c, 1, dpi.Plan{{Data: hello}})
		}
		_, err := c.Write(hello)
		return err
	}
	p := s.Plan(hello)
	if f.cfg.OnSend != nil {
		f.cfg.OnSend(c, s.Num, p)
	}
	// ponytail: Execute pauses with time.Sleep between pieces (at most a few hundred ms in all, in the strategies of
	// the ladder), so a ladder that is cancelled waits for them; make them interruptible if a strategy needs longer.
	return dpi.Execute(c, p)
}

// readState is how waiting for the first byte of an answer ended.
type readState uint8

const (
	stAnswer   readState = iota // a TLS record has started: this connection is answered
	stSilent                    // nothing came before the deadline
	stBroke                     // the connection ended, or what came is not TLS: injected or broken
	stCanceled                  // the context ended
)

// pollCtx is how often a wait for an answer looks at its context. The ordinary connection is waited for on the
// goroutine of the caller, which has no other way to be woken; polling costs nothing while the answer is quick.
const pollCtx = 250 * time.Millisecond

// readFirst waits until end for the first bytes of a TLS answer: a handshake (0x16) or an alert (0x15) record.
// Anything else is not the server's: a filter that cannot drop a connection can still inject a page or a reset.
func readFirst(ctx context.Context, c *net.TCPConn, end time.Time) ([]byte, readState) {
	buf := make([]byte, 5) // a record header: enough to tell TLS, and all the caller gets to write first
	for {
		if ctx.Err() != nil {
			return nil, stCanceled
		}
		dl := end
		if p := time.Now().Add(pollCtx); p.Before(dl) {
			dl = p
		}
		c.SetReadDeadline(dl)
		n, err := c.Read(buf)
		if n > 0 {
			if (buf[0] == 0x16 || buf[0] == 0x15) && (n < 2 || buf[1] == 3) {
				return buf[:n], stAnswer
			}
			return nil, stBroke
		}
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			return nil, stBroke
		}
		if !time.Now().Before(end) {
			return nil, stSilent
		}
	}
}
