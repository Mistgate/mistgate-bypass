package flow

import (
	"context"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/mistgate/mistgate-bypass/dpi"
)

// EventKind is what an Event reports.
type EventKind string

const (
	// EventOpened: a connection to a name was opened. Sent when it took a ladder (the ordinary connection was silent
	// for T), and when the result kept for the part or the own site is new.
	EventOpened EventKind = "opened"
	// EventFailed: the ladder gave up; Reason says why.
	EventFailed EventKind = "failed"
	// EventBroken: the strategy kept for a part or a site stayed silent guardFails times in a row and has been
	// forgotten; the next connection starts the ladder from the beginning.
	EventBroken EventKind = "broken"
)

// Reasons of EventFailed, as codes.
const (
	ReasonUnreachable = "unreachable" // no connection could be made
	ReasonNoWay       = "no_way"      // connected, and nothing answered whatever was tried
)

// Event is what the window is told. It never holds a name or an address, with one exception: the name of one of
// the user's own sites, which the caller has said is its own (Config.Own) and which it knows already.
type Event struct {
	Kind EventKind
	// Service and Part are the identifiers of the set when the name belongs to a part of a service; empty for any
	// other name (the event is then only for counting).
	Service, Part string
	// Name is set for an own site and for nothing else.
	Name string
	// Strategy is, for EventOpened, what opened the connection (1: no bypass was needed); for EventBroken, the
	// strategy that was forgotten.
	Strategy int
	// Ladder, for EventOpened: the ordinary connection was silent for T before this one opened.
	Ladder bool
	Reason string // EventFailed
	At     time.Time
}

func (f *Flows) emit(q *request, e Event) {
	if f.cfg.Events == nil {
		return
	}
	e.Service, e.Part = q.t.part.svc, q.t.part.part
	if q.t.own {
		e.Name = q.t.name
	}
	e.At = f.mem.now()
	f.cfg.Events(e)
}

// won records an opened connection and tells the window what changed. On the fast path a plain answer that teaches
// nothing is not even written down.
func (f *Flows) won(q *request, num int, ladder bool) {
	if !ladder && num == 1 && q.h.settled {
		return
	}
	ch := f.mem.record(q.nm, verdict{t: q.t, first: q.first.Num, src: q.h.src, winner: num})
	if ladder || ch.changed {
		f.emit(q, Event{Kind: EventOpened, Strategy: num, Ladder: ladder})
	}
	if ch.broken > 0 {
		f.emit(q, Event{Kind: EventBroken, Strategy: ch.broken})
	}
}

// failed records a ladder that found nothing.
func (f *Flows) failed(q *request) {
	ch := f.mem.record(q.nm, verdict{t: q.t, first: q.first.Num, src: q.h.src, pause: f.tm.DeadFor})
	f.emit(q, Event{Kind: EventFailed, Reason: ReasonNoWay})
	if ch.broken > 0 {
		f.emit(q, Event{Kind: EventBroken, Strategy: ch.broken})
	}
}

// A ladder is the work of one goroutine for a name (or a service part: its names share an answer). The others who
// come to the same key while it runs wait for it and then try what it found.
type ladderKey struct {
	nm   *netMem
	part partKey
	name string
}

type ladder struct {
	done chan struct{} // closed when the leader is through; st and won are final before that
	st   ladderState
	won  int
}

type ladderState uint8

const (
	ladderWon     ladderState = iota // won is the strategy that opened a connection
	ladderFailed                     // every attempt was silent or broken
	ladderAborted                    // the leader's context ended: nothing is known
)

// join makes the caller the leader of the key, or gives it the ladder that is running. With neither, because
// MaxLadders are running already, it returns (nil, false): the caller waits for the connection it has and tries
// nothing more.
func (f *Flows) join(k ladderKey) (l *ladder, lead bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if l := f.ladders[k]; l != nil {
		return l, false
	}
	select {
	case f.sem <- struct{}{}:
	default:
		return nil, false
	}
	l = &ladder{done: make(chan struct{})}
	f.ladders[k] = l
	return l, true
}

// leave ends the leader's ladder. What the ladder learnt is in memory before this is called, so that whoever
// finds the key free afterwards finds the answer too.
func (f *Flows) leave(k ladderKey, l *ladder, st ladderState, won int) {
	f.mu.Lock()
	delete(f.ladders, k)
	f.mu.Unlock()
	l.st, l.won = st, won
	close(l.done)
	<-f.sem
}

// slow is what an Open does when its first connection has not been answered within T, or has failed. conn is that
// connection; silent says it is still open and may yet be answered. The first goroutine of the ladder starts here.
func (f *Flows) slow(q request, conn *net.TCPConn, silent bool) (Result, error) {
	if !q.ladder {
		// Nothing more to try. A name already known to be down is not marked again; any other is now.
		conn.Close()
		if !q.h.dead {
			f.failed(&q)
		}
		return Result{}, ErrNoWay
	}
	r := &run{f: f, q: &q, results: make(chan outcome, f.tm.MaxAttempts+2)}
	r.actx, r.cancel = context.WithCancel(q.ctx)
	defer r.finish()
	r.nums = append(r.nums, q.first.Num)
	if silent {
		r.adopt(conn, q.first.Num)
	} else {
		conn.Close()
	}

	key := ladderKey{nm: q.nm, part: q.t.part}
	if !q.t.part.ok() {
		key.name = q.t.name
	}
	l, lead := f.join(key)
	if lead {
		o, err := f.lead(r, key, l) // it has recorded what it found
		if err != nil {
			return Result{}, err
		}
		return r.commit(o), nil
	}
	// Another ladder is running for the name: keep the connection that is open, and when that ladder is through
	// try what it found, once. With no room for another ladder (l is nil) there is only the connection that is open.
	// Only a leader records a failure: what a follower saw is what the leader has.
	o, err := r.race(nil, l)
	if err != nil {
		return Result{}, err
	}
	f.won(&q, o.a.num, true)
	return r.commit(o), nil
}

// lead runs the ladder for a key: the strategies after the first connection, one more each time T passes without
// an answer, or at once when a connection is broken. Whatever happens, it tells the followers.
func (f *Flows) lead(r *run, key ladderKey, l *ladder) (o outcome, err error) {
	q := r.q
	st, won := ladderAborted, 0
	defer func() { f.leave(key, l, st, won) }()

	// The order is made now, not when the Open began: a ladder that has just ended may have taught what this one
	// would have found.
	h := f.mem.hintFor(q.nm, q.t)
	if h.unreachable {
		st = ladderFailed
		return outcome{}, ErrUnreachable
	}
	if h.dead {
		st = ladderFailed
		return outcome{}, ErrNoWay
	}
	o, err = r.race(f.order(q, h), nil)
	switch err {
	case nil:
		st, won = ladderWon, o.a.num
		f.won(q, o.a.num, true) // before leave: whoever finds the key free finds the result
	case ErrNoWay:
		st = ladderFailed
		f.failed(q)
	}
	return
}

// order is the strategies a ladder tries after the first connection, in order. The ordinary connection is among
// them when the first was a strategy; the stale one goes right after it; then the set's list for the name, the
// strategies that have won most on this network first and the ones that lose to plain last.
func (f *Flows) order(q *request, h hint) []dpi.Strategy {
	var l []dpi.Strategy
	add := func(s dpi.Strategy, ok bool) {
		if ok && !slices.ContainsFunc(l, func(o dpi.Strategy) bool { return o.Num == s.Num }) {
			l = append(l, s)
		}
	}
	if h.first > 1 {
		add(resolve(h.first, q.cands))
	}
	add(plain(), true)
	if h.stale > 1 {
		add(resolve(h.stale, q.cands))
	}
	cands := slices.Clone(q.cands)
	f.mem.rank(q.nm, cands)
	for _, s := range cands {
		add(s, true)
	}
	// What the first connection has already tried is not tried again; the whole ladder is MaxAttempts long.
	l = slices.DeleteFunc(l, func(s dpi.Strategy) bool { return s.Num == q.first.Num })
	return l[:min(len(l), f.tm.MaxAttempts-1)]
}

// An attempt is one connection of a ladder. Its goroutine owns the reading; the Open that started it owns the
// closing, and may close it from outside to wake the reader.
type attempt struct {
	num int

	mu   sync.Mutex
	conn *net.TCPConn // set once, by attach
	shut bool
}

// attach gives the attempt its connection, unless it has been shut already.
func (a *attempt) attach(c *net.TCPConn) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.shut {
		return false
	}
	a.conn = c
	return true
}

// close shuts the attempt and its connection, whenever it comes.
func (a *attempt) close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.shut = true
	if a.conn != nil {
		a.conn.Close()
	}
}

// outcome is how an attempt ended. Every attempt sends exactly one.
type outcome struct {
	a     *attempt
	first []byte
	st    readState
}

// run holds the attempts of one Open. Invariants:
//   - atts, nums and win belong to the goroutine of Open; the attempt goroutines touch only their attempt, the
//     request (read only) and results.
//   - results has room for every attempt that can ever be started (MaxAttempts, and one more for a follower), so
//     an attempt goroutine never blocks sending its outcome, whether anyone is listening or not.
//   - finish closes every attempt but the winner and waits for all the goroutines: when Open returns there is
//     nothing of the ladder left but the connection it hands over.
type run struct {
	f       *Flows
	q       *request
	actx    context.Context // ends the dials of the attempts when the ladder is over
	cancel  context.CancelFunc
	results chan outcome
	atts    []*attempt
	nums    []int // strategies started, those whose connection failed at once included
	win     *attempt
	wg      sync.WaitGroup
	live    int // attempts started and not heard from
}

func (r *run) finish() {
	for _, a := range r.atts {
		if a != r.win {
			a.close()
		}
	}
	r.cancel()
	r.wg.Wait()
}

// commit makes the outcome the connection to keep. Nothing the losers read is looked at again.
func (r *run) commit(o outcome) Result {
	r.win = o.a
	o.a.conn.SetReadDeadline(time.Time{})
	return Result{Conn: o.a.conn, First: o.first, Strategy: o.a.num}
}

// adopt starts the reading of a connection that is open already.
func (r *run) adopt(c *net.TCPConn, num int) {
	a := &attempt{num: num, conn: c}
	r.spawn(a, plain())
}

// start opens a new connection and sends the ClientHello on it as s says.
func (r *run) start(s dpi.Strategy) {
	r.nums = append(r.nums, s.Num)
	r.spawn(&attempt{num: s.Num}, s)
}

func (r *run) spawn(a *attempt, s dpi.Strategy) {
	r.atts = append(r.atts, a)
	r.live++
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.results <- r.work(a, s)
	}()
}

func (r *run) work(a *attempt, s dpi.Strategy) outcome {
	if a.conn == nil {
		c, _, err := r.f.connect(r.actx, r.q.dial, r.q.end)
		if err != nil {
			return outcome{a: a, st: stBroke}
		}
		if !a.attach(c) {
			c.Close()
			return outcome{a: a, st: stCanceled}
		}
		if r.f.send(c, s, r.q.hello) != nil {
			return outcome{a: a, st: stBroke}
		}
	}
	b, st := readFirst(r.actx, a.conn, r.q.end)
	return outcome{a, b, st}
}

// race waits for the first answer. pending are the strategies to start, one when the run begins and then one for
// each T without an answer, or at once for each connection that breaks. A follower has none, and l, the ladder it
// waits for: when that is through with a winner, the follower starts that strategy unless it has already.
func (r *run) race(pending []dpi.Strategy, l *ladder) (outcome, error) {
	q := r.q
	budget := time.NewTimer(time.Until(q.end))
	defer budget.Stop()
	tick := time.NewTimer(q.step)
	defer tick.Stop()
	var wake <-chan struct{}
	if l != nil {
		wake = l.done
	}
	launch := func() {
		r.start(pending[0])
		pending = pending[1:]
		tick.Reset(q.step)
	}
	if len(pending) > 0 {
		launch()
	}
	for {
		var tickC <-chan time.Time
		if len(pending) > 0 {
			tickC = tick.C
		}
		if r.live == 0 && len(pending) == 0 && wake == nil {
			return outcome{}, ErrNoWay
		}
		select {
		case o := <-r.results:
			r.live--
			if o.st == stAnswer {
				return o, nil
			}
			if o.st == stCanceled {
				return outcome{}, q.ctx.Err()
			}
			o.a.close()
			if len(pending) > 0 {
				launch() // a broken connection is replaced at once; a silent one waits for its T
			}
		case <-tickC:
			launch()
		case <-wake:
			wake = nil
			switch l.st {
			case ladderFailed:
				return outcome{}, ErrNoWay
			// ponytail: when the leader was cancelled (ladderAborted) a follower waits out its budget on the connection it has;
			// the flows of one service share a context, so they end together; promote a follower if they ever get their own.
			case ladderWon:
				if s, ok := resolve(l.won, q.cands); ok && !slices.Contains(r.nums, l.won) {
					pending = []dpi.Strategy{s}
					launch()
				}
			}
		case <-budget.C:
			return outcome{}, ErrNoWay
		case <-q.ctx.Done():
			return outcome{}, q.ctx.Err()
		}
	}
}
