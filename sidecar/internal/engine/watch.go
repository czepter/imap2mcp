package engine

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/imap2mcp/sidecar/internal/imapx"
)

// Connection states reported by Status.
const (
	StateConnected    = "connected"
	StateReconnecting = "reconnecting"
	StateAuthFailed   = "auth_failed"
	StateClosed       = "closed"
)

const minEventGap = 250 * time.Millisecond // event-driven syncs of one folder are at least this far apart

// Status is the result of the status RPC (docs/DESIGN_V2.md "Sidecar additions").
type Status struct {
	State         string `json:"state"`
	Since         string `json:"since"`
	LastErrorCode string `json:"lastErrorCode,omitempty"`
	NextRetryAt   string `json:"nextRetryAt,omitempty"`
	Idle          bool   `json:"idle"`
	Reconnects    int    `json:"reconnects"`
}

// BackoffDelay is the reconnect delay after n consecutive failures:
// min(max, initial*2^n) with full jitter (uniform in [0, delay]) but never
// below floor (500 ms by contract; scaled down only when initial itself is
// smaller, which only tests do).
func BackoffDelay(n int, initial, max time.Duration, rnd func() float64) time.Duration {
	d := initial
	for i := 0; i < n && d < max; i++ {
		d *= 2
	}
	if d > max {
		d = max
	}
	floor := 500 * time.Millisecond
	if initial < floor {
		floor = initial
	}
	j := time.Duration(rnd() * float64(d))
	if j < floor {
		j = floor
	}
	if j > d {
		j = d
	}
	return j
}

// supervisor owns the resilience state of one mailbox: the reconnecting
// watchers (INBOX is the primary one that defines the mailbox state, plus one
// per warm folder), the auth latch view, and the status.
type supervisor struct {
	e    *Engine
	mb   *mailbox
	acct *imapx.Account

	ctx    context.Context
	cancel context.CancelFunc

	mu         sync.Mutex
	state      string
	since      time.Time
	lastErr    string
	nextRetry  time.Time
	idle       bool
	reconnects int
	retryCh    chan struct{}
	watching   map[string]context.CancelFunc
	seen       map[string]bool // folder had a connection before => reconcile on the next one
}

func (e *Engine) newSupervisor(mb *mailbox, acct *imapx.Account) *supervisor {
	ctx, cancel := context.WithCancel(context.Background())
	s := &supervisor{
		e: e, mb: mb, acct: acct, ctx: ctx, cancel: cancel,
		state: StateConnected, since: e.opts.Now(),
		retryCh: make(chan struct{}), watching: map[string]context.CancelFunc{}, seen: map[string]bool{},
	}
	acct.SetOnAuthFailed(s.setAuthFailed)
	return s
}

func (s *supervisor) start() {
	if s.e.opts.DisableWatch {
		return
	}
	go s.watchLoop(s.ctx, "INBOX", true)
	go s.manage()
}

func (s *supervisor) stop() { s.cancel() }

func (s *supervisor) logf(format string, args ...any) { s.e.opts.Logf(format, args...) }

func (s *supervisor) status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{State: s.state, Since: ts(s.since), LastErrorCode: s.lastErr, Idle: s.idle, Reconnects: s.reconnects}
	if s.state == StateReconnecting && !s.nextRetry.IsZero() {
		st.NextRetryAt = ts(s.nextRetry)
	}
	return st
}

func ts(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

func (s *supervisor) setState(state, code string, next time.Time) {
	if s.state != state {
		s.since = s.e.opts.Now()
	}
	s.state, s.lastErr, s.nextRetry = state, code, next
	if state != StateConnected {
		s.idle = false
	}
}

func (s *supervisor) setAuthFailed() {
	s.mu.Lock()
	s.setState(StateAuthFailed, "AUTH_FAILED", time.Time{})
	s.mu.Unlock()
}

func (s *supervisor) setIdle(v bool) {
	s.mu.Lock()
	s.idle = v && s.state == StateConnected
	s.mu.Unlock()
}

// retry lifts the latch and wakes every waiting loop (backoff sleeps included).
func (s *supervisor) retry() {
	s.mu.Lock()
	if s.state == StateAuthFailed {
		s.setState(StateReconnecting, "", time.Time{})
	}
	close(s.retryCh)
	s.retryCh = make(chan struct{})
	s.mu.Unlock()
}

func (s *supervisor) retrySignal() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.retryCh
}

// sleep waits d (or until retry/cancel); false means cancelled.
func (s *supervisor) sleep(ctx context.Context, d time.Duration) bool {
	sig := s.retrySignal()
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-sig:
	case <-t.C:
	}
	return ctx.Err() == nil
}

func (s *supervisor) waitRetry(ctx context.Context) bool {
	sig := s.retrySignal()
	select {
	case <-ctx.Done():
		return false
	case <-sig:
		return true
	}
}

// markConnected records a (re)established connection and reports whether the
// folder had one before (=> a reconcile is due).
func (s *supervisor) markConnected(folder string, primary bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	had := s.seen[folder]
	s.seen[folder] = true
	if primary {
		if had {
			s.reconnects++
		}
		s.setState(StateConnected, "", time.Time{})
	}
	return had
}

func (s *supervisor) watchLoop(ctx context.Context, folder string, primary bool) {
	attempt := 0
	for ctx.Err() == nil {
		if s.acct.AuthFailed() {
			s.setAuthFailed()
			if !s.waitRetry(ctx) {
				return
			}
			continue
		}
		w, err := s.acct.OpenWatch(ctx, folder, s.e.opts.OpTimeout)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, imapx.ErrAuth) {
				continue // the latch is set; the loop top waits for retry
			}
			if !s.backoff(ctx, primary, folder, err, &attempt) {
				return
			}
			continue
		}
		start := time.Now()
		if s.markConnected(folder, primary) {
			s.reconcileAfterReconnect(ctx, folder, primary)
		}
		err = s.serve(ctx, w, folder, primary)
		w.Close()
		if primary {
			s.setIdle(false)
		}
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) >= s.e.opts.HealthyReset {
			attempt = 0
		}
		if !s.backoff(ctx, primary, folder, err, &attempt) {
			return
		}
	}
}

func (s *supervisor) backoff(ctx context.Context, primary bool, folder string, err error, attempt *int) bool {
	o := s.e.opts
	d := BackoffDelay(*attempt, o.ReconnectInitial, o.ReconnectMax, o.Rand)
	*attempt++
	if primary {
		s.mu.Lock()
		s.setState(StateReconnecting, ErrorCode(err), o.Now().Add(d))
		s.mu.Unlock()
	}
	_, cr := s.mb.account()
	s.logf("mailbox=%s folder=%q connection lost (%s): %s; reconnecting in %s", s.mb.id, folder, ErrorCode(err), cr.Redact(err.Error()), d.Round(time.Millisecond))
	return s.sleep(ctx, d)
}

// serve waits for changes on one connection. It returns when the connection
// failed or ctx ended.
func (s *supervisor) serve(ctx context.Context, w *imapx.Watch, folder string, primary bool) error {
	o := s.e.opts
	var last time.Time
	changed := func() {
		if gap := minEventGap - time.Since(last); gap > 0 {
			t := time.NewTimer(gap)
			select {
			case <-t.C:
			case <-ctx.Done():
			}
			t.Stop()
		}
		s.onChange(ctx, folder)
		last = time.Now()
	}
	if w.CanIdle() {
		for {
			if primary {
				s.setIdle(true)
			}
			res, err := w.Idle(ctx, o.IdleRenew)
			if err != nil {
				return err
			}
			if res == imapx.IdleEvent {
				if primary {
					s.setIdle(false)
				}
				changed()
			}
		}
	}
	t := time.NewTicker(o.PollEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-w.Closed():
			return imapx.ErrConnClosed
		case <-w.Events():
			changed()
		case <-t.C:
			if err := w.Noop(ctx); err != nil {
				return err
			}
			s.syncWarm(ctx, folder, false)
		}
	}
}

// onChange: untagged EXISTS/EXPUNGE/FETCH => mark the folder stale and run an
// incremental sync (which reconciles because the folder is stale).
func (s *supervisor) onChange(ctx context.Context, folder string) {
	if f := s.mb.folder(folder, false); f != nil {
		f.mu.Lock()
		f.stale = true
		f.gen++
		f.mu.Unlock()
	}
	s.syncWarm(ctx, folder, false)
}

// syncWarm runs a background sync of a folder if (and only if) its cache is
// warm; cold folders are never synced unprompted. A failure leaves the folder
// stale so the next read reconciles it.
func (s *supervisor) syncWarm(ctx context.Context, folder string, force bool) {
	f := s.mb.folder(folder, false)
	if f == nil {
		return
	}
	f.mu.RLock()
	warm := f.synced
	f.mu.RUnlock()
	if !warm {
		return
	}
	bctx, cancel := context.WithTimeout(ctx, s.e.opts.BackgroundCap)
	defer cancel()
	if err := f.syncMu.Lock(bctx); err != nil {
		return
	}
	defer f.syncMu.Unlock()
	if _, err := s.e.syncLocked(bctx, s.mb, f, folder, force); err != nil && ctx.Err() == nil {
		f.mu.Lock()
		f.stale = true
		f.gen++
		f.mu.Unlock()
		s.logf("mailbox=%s folder=%q background sync failed: %v", s.mb.id, folder, err)
	}
}

// reconcileAfterReconnect runs a full reconcile (sync mode "full") for the
// watcher's folder; the primary watcher also covers warm folders that have no
// watcher of their own.
func (s *supervisor) reconcileAfterReconnect(ctx context.Context, folder string, primary bool) {
	names := []string{folder}
	if primary {
		s.mu.Lock()
		for _, n := range s.warmFolders() {
			if _, ok := s.watching[n]; !ok && !strings.EqualFold(n, folder) {
				names = append(names, n)
			}
		}
		s.mu.Unlock()
	}
	for _, n := range names {
		if ctx.Err() != nil {
			return
		}
		s.syncWarm(ctx, n, true)
	}
}

// warmFolders lists synced folders, most recently used first.
func (s *supervisor) warmFolders() []string {
	type fa struct {
		name string
		at   time.Time
	}
	var out []fa
	s.mb.mu.RLock()
	for name, f := range s.mb.folders {
		f.mu.RLock()
		if f.synced {
			out = append(out, fa{name, f.lastAccess})
		}
		f.mu.RUnlock()
	}
	s.mb.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if !out[i].at.Equal(out[j].at) {
			return out[i].at.After(out[j].at)
		}
		return out[i].name < out[j].name
	})
	names := make([]string, len(out))
	for i, x := range out {
		names[i] = x.name
	}
	return names
}

// manage keeps one watcher per warm folder (up to MaxWatched including INBOX).
func (s *supervisor) manage() {
	t := time.NewTicker(s.e.opts.WatchScan)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
		}
		warm := s.warmFolders()
		want := map[string]struct{}{}
		for _, n := range warm {
			if strings.EqualFold(n, "INBOX") {
				continue
			}
			if len(want) >= s.e.opts.MaxWatched-1 {
				break
			}
			want[n] = struct{}{}
		}
		s.mu.Lock()
		for n, cancel := range s.watching {
			if _, ok := want[n]; !ok {
				cancel()
				delete(s.watching, n)
			}
		}
		for n := range want {
			if _, ok := s.watching[n]; ok {
				continue
			}
			wctx, cancel := context.WithCancel(s.ctx)
			s.watching[n] = cancel
			go s.watchLoop(wctx, n, false)
		}
		s.mu.Unlock()
	}
}

// Status reports the connection state of a mailbox.
func (e *Engine) Status(id string) Status {
	e.mu.RLock()
	fo, rejected := e.failedOpen[id]
	mb := e.mailboxes[id]
	e.mu.RUnlock()
	if rejected {
		return Status{State: StateAuthFailed, Since: ts(fo.since), LastErrorCode: "AUTH_FAILED"}
	}
	if mb == nil {
		return Status{State: StateClosed, Since: ts(e.opts.Now())}
	}
	mb.mu.RLock()
	sup := mb.sup
	mb.mu.RUnlock()
	if sup == nil {
		return Status{State: StateClosed, Since: ts(e.opts.Now())}
	}
	return sup.status()
}
