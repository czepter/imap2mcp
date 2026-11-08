package engine

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/imap2mcp/sidecar/internal/imapx"
)

const (
	coldChunk      = 1000 // headers per UID FETCH during cold sync / fetch of missing UIDs
	flagChunk      = 2000 // UIDs per UID FETCH (FLAGS) during reconcile
	maxResults     = 500  // hard cap for any result list
	defaultLimit   = 50
	maxSyncRetries = 3
)

// Options configures the engine.
type Options struct {
	TLS            func(serverName string) *tls.Config // must validate certificates
	ReconcileEvery time.Duration                       // SYNC_RECONCILE_SECS (default 30 s)
	AutoSyncEvery  time.Duration                       // implicit status sync on read when older (default 5 s)
	FolderIdle     time.Duration                       // evict folders unused for this long (default 1 h)
	Logf           func(format string, args ...any)    // never receives credentials
	Now            func() time.Time

	// Resilience (docs/DESIGN_V2.md "IDLE", "Backoff").
	IdleRenew        time.Duration // IDLE_RENEW_SECS, default 25 min
	PollEvery        time.Duration // polling fallback when the server lacks IDLE, default 60 s
	ReconnectInitial time.Duration // RECONNECT_INITIAL_MS, default 1 s
	ReconnectMax     time.Duration // RECONNECT_MAX_MS, default 60 s
	HealthyReset     time.Duration // a connection healthy this long resets the backoff, default 30 s
	OpTimeout        time.Duration // bound for each watcher protocol operation, default 30 s
	BackgroundCap    time.Duration // cap for one background sync job, default 300 s
	WatchScan        time.Duration // how often warm folders are (re)evaluated for watching, default 1 s
	MaxWatched       int           // watched folders per mailbox (INBOX + warm folders), default 4
	Rand             func() float64
	DisableWatch     bool // tests only: no IDLE watchers / reconnect loop
}

func (o *Options) defaults() {
	if o.ReconcileEvery <= 0 {
		o.ReconcileEvery = 30 * time.Second
	}
	if o.AutoSyncEvery <= 0 {
		o.AutoSyncEvery = 5 * time.Second
	}
	if o.FolderIdle <= 0 {
		o.FolderIdle = time.Hour
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.IdleRenew <= 0 {
		o.IdleRenew = 25 * time.Minute
	}
	if o.PollEvery <= 0 {
		o.PollEvery = 60 * time.Second
	}
	if o.ReconnectInitial <= 0 {
		o.ReconnectInitial = time.Second
	}
	if o.ReconnectMax <= 0 {
		o.ReconnectMax = 60 * time.Second
	}
	if o.ReconnectMax < o.ReconnectInitial {
		o.ReconnectMax = o.ReconnectInitial
	}
	if o.HealthyReset <= 0 {
		o.HealthyReset = 30 * time.Second
	}
	if o.OpTimeout <= 0 {
		o.OpTimeout = 30 * time.Second
	}
	if o.BackgroundCap <= 0 {
		o.BackgroundCap = 300 * time.Second
	}
	if o.WatchScan <= 0 {
		o.WatchScan = time.Second
	}
	if o.MaxWatched <= 0 {
		o.MaxWatched = 4
	}
	if o.Rand == nil {
		o.Rand = rand.Float64
	}
}

// Engine owns all mailboxes.
type Engine struct {
	opts Options

	mu        sync.RWMutex
	mailboxes map[string]*mailbox
	// failedOpen remembers credentials the server rejected at open time, so
	// that repeated opens with the same credentials do not hit the server.
	failedOpen map[string]failedOpen
}

type failedOpen struct {
	fp    [sha256.Size]byte
	since time.Time
}

func fingerprint(cr imapx.Creds) [sha256.Size]byte {
	h := sha256.New()
	for _, p := range []string{cr.Host, cr.IP, cr.ServerName, cr.User, cr.Pass} {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	h.Write([]byte{byte(cr.Port >> 8), byte(cr.Port)})
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

type mailbox struct {
	id string

	mu      sync.RWMutex
	acct    *imapx.Account
	creds   imapx.Creds
	folders map[string]*folderCache
	sup     *supervisor
}

// New creates an engine.
func New(opts Options) *Engine {
	opts.defaults()
	return &Engine{opts: opts, mailboxes: map[string]*mailbox{}, failedOpen: map[string]failedOpen{}}
}

func (e *Engine) mailbox(id string) (*mailbox, error) {
	e.mu.RLock()
	mb := e.mailboxes[id]
	e.mu.RUnlock()
	if mb == nil {
		return nil, errUnknownMailbox()
	}
	return mb, nil
}

func (mb *mailbox) account() (*imapx.Account, imapx.Creds) {
	mb.mu.RLock()
	defer mb.mu.RUnlock()
	return mb.acct, mb.creds
}

func (mb *mailbox) folder(name string, create bool) *folderCache {
	mb.mu.RLock()
	f := mb.folders[name]
	mb.mu.RUnlock()
	if f != nil || !create {
		return f
	}
	mb.mu.Lock()
	defer mb.mu.Unlock()
	if f = mb.folders[name]; f == nil {
		f = &folderCache{}
		mb.folders[name] = f
	}
	return f
}

// Open registers (or replaces the credentials of) a mailbox and verifies that
// it can log in. Credentials are kept in memory only. Opening with credentials
// the server already rejected does not contact the server again; it fails
// until Retry or an Open with different credentials.
func (e *Engine) Open(ctx context.Context, id string, cr imapx.Creds) error {
	if id == "" || cr.Host == "" || cr.IP == "" || cr.User == "" {
		return errf(CodeInvalidParams, "mailboxId, host, ip and user are required")
	}
	fp := fingerprint(cr)
	e.mu.RLock()
	fo, rejected := e.failedOpen[id]
	mb := e.mailboxes[id]
	e.mu.RUnlock()
	if rejected && fo.fp == fp {
		return errAuthFailed()
	}
	if mb != nil {
		mb.mu.RLock()
		same, acct := mb.acct != nil && mb.creds == cr, mb.acct
		mb.mu.RUnlock()
		if same {
			// Idempotent re-open: keep the account, watchers and cache.
			if acct.AuthFailed() {
				return errAuthFailed()
			}
			if err := acct.Verify(ctx); err != nil {
				return upstream(cr, err)
			}
			return nil
		}
	}
	acct := imapx.NewAccount(cr, e.opts.TLS)
	if err := acct.Verify(ctx); err != nil {
		acct.Close()
		if errors.Is(err, imapx.ErrAuth) {
			e.mu.Lock()
			e.failedOpen[id] = failedOpen{fp: fp, since: e.opts.Now()}
			e.mu.Unlock()
		}
		return upstream(cr, err)
	}
	e.mu.Lock()
	delete(e.failedOpen, id)
	mb = e.mailboxes[id]
	if mb == nil {
		mb = &mailbox{id: id, folders: map[string]*folderCache{}}
		e.mailboxes[id] = mb
	}
	e.mu.Unlock()
	mb.mu.Lock()
	old, oldSup := mb.acct, mb.sup
	if old != nil && !old.Creds().SameEndpoint(cr) {
		mb.folders = map[string]*folderCache{} // different account: nothing is reusable
	}
	mb.acct, mb.creds = acct, cr
	mb.sup = e.newSupervisor(mb, acct)
	sup := mb.sup
	mb.mu.Unlock()
	if oldSup != nil {
		oldSup.stop()
	}
	if old != nil {
		old.Close()
	}
	if sup != nil {
		sup.start()
	}
	return nil
}

// Retry clears the auth-failure latch of a mailbox (after an admin edited the
// credentials or pressed "Retry") and wakes its reconnect loop. Unknown
// mailboxes are fine: there is nothing latched.
func (e *Engine) Retry(id string) {
	e.mu.Lock()
	delete(e.failedOpen, id)
	mb := e.mailboxes[id]
	e.mu.Unlock()
	if mb == nil {
		return
	}
	mb.mu.RLock()
	acct, sup := mb.acct, mb.sup
	mb.mu.RUnlock()
	if acct != nil {
		acct.ClearAuthFailure()
	}
	if sup != nil {
		sup.retry()
	}
}

// Close forgets a mailbox, its credentials and its cache.
func (e *Engine) Close(id string) {
	e.mu.Lock()
	mb := e.mailboxes[id]
	delete(e.mailboxes, id)
	delete(e.failedOpen, id)
	e.mu.Unlock()
	if mb != nil {
		mb.mu.Lock()
		acct, sup := mb.acct, mb.sup
		mb.folders = map[string]*folderCache{}
		mb.acct, mb.creds, mb.sup = nil, imapx.Creds{}, nil
		mb.mu.Unlock()
		if sup != nil {
			sup.stop()
		}
		if acct != nil {
			acct.Close()
		}
	}
}

// Shutdown closes everything.
func (e *Engine) Shutdown() {
	e.mu.RLock()
	ids := make([]string, 0, len(e.mailboxes))
	for id := range e.mailboxes {
		ids = append(ids, id)
	}
	e.mu.RUnlock()
	for _, id := range ids {
		e.Close(id)
	}
}

// ListFolders runs LIST.
func (e *Engine) ListFolders(ctx context.Context, id string) ([]imapx.Folder, error) {
	mb, err := e.mailbox(id)
	if err != nil {
		return nil, err
	}
	acct, cr := mb.account()
	fs, err := acct.ListFolders(ctx)
	if err != nil {
		return nil, upstream(cr, err)
	}
	return fs, nil
}

// SyncResult is the result of Sync.
type SyncResult struct {
	UIDValidity uint32
	UIDNext     uint32
	Count       int
	Fetched     int
	Expunged    int
	FlagChanges int
	Reconciled  bool
	DurationMs  int64
	Reset       bool
}

// Sync synchronises one folder. mode is "auto" or "full" ("full" always
// reconciles).
func (e *Engine) Sync(ctx context.Context, id, folder, mode string) (SyncResult, error) {
	if folder == "" || (mode != "" && mode != "auto" && mode != "full") {
		return SyncResult{}, errf(CodeInvalidParams, "folder required; mode must be auto or full")
	}
	mb, err := e.mailbox(id)
	if err != nil {
		return SyncResult{}, err
	}
	f := mb.folder(folder, true)
	if err := f.syncMu.Lock(ctx); err != nil {
		return SyncResult{}, upstream(imapx.Creds{}, err)
	}
	defer f.syncMu.Unlock()
	return e.syncLocked(ctx, mb, f, folder, mode == "full")
}

// ensureFresh makes sure the folder cache is usable and not older than
// AutoSyncEvery; it coalesces concurrent callers on the folder lock.
func (e *Engine) ensureFresh(ctx context.Context, mb *mailbox, folder string) (*folderCache, error) {
	f := mb.folder(folder, true)
	now := e.opts.Now()
	fresh := func() bool {
		f.mu.RLock()
		defer f.mu.RUnlock()
		return f.synced && !f.stale && now.Sub(f.lastSync) < e.opts.AutoSyncEvery
	}
	if fresh() {
		f.mu.Lock()
		f.lastAccess = now
		f.mu.Unlock()
		return f, nil
	}
	if err := f.syncMu.Lock(ctx); err != nil {
		return nil, upstream(imapx.Creds{}, err)
	}
	defer f.syncMu.Unlock()
	if fresh() {
		return f, nil
	}
	if _, err := e.syncLocked(ctx, mb, f, folder, false); err != nil {
		return nil, err
	}
	return f, nil
}

type restart struct{}

func (restart) Error() string { return "restart" }

// syncLocked implements the cold / incremental / reconcile state machine.
// The caller holds f.syncMu.
func (e *Engine) syncLocked(ctx context.Context, mb *mailbox, f *folderCache, folder string, forceReconcile bool) (SyncResult, error) {
	start := e.opts.Now()
	acct, cr := mb.account()
	if acct == nil {
		return SyncResult{}, errUnknownMailbox()
	}
	var res SyncResult
	for attempt := 0; attempt < maxSyncRetries; attempt++ {
		err := e.syncOnce(ctx, acct, f, folder, forceReconcile, &res)
		if _, ok := err.(restart); ok {
			res.Reset = true
			continue
		}
		if err != nil {
			return res, upstream(cr, err)
		}
		f.mu.RLock()
		res.UIDValidity, res.UIDNext, res.Count = f.uv, f.uidNext, len(f.hdrs)
		f.mu.RUnlock()
		res.DurationMs = e.opts.Now().Sub(start).Milliseconds()
		return res, nil
	}
	return res, errf(CodeUpstream, "folder changed repeatedly during sync")
}

// dropIfChanged resets the cache when the observed UIDVALIDITY differs from the
// cached one; it returns true if the caller must start over.
func (f *folderCache) dropIfChanged(observed uint32) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.synced && f.uv != observed {
		f.resetLocked()
		return true
	}
	return false
}

func chunk(uids []uint32, n int) [][]uint32 {
	var out [][]uint32
	for len(uids) > 0 {
		k := n
		if k > len(uids) {
			k = len(uids)
		}
		out = append(out, uids[:k])
		uids = uids[k:]
	}
	return out
}

func (e *Engine) syncOnce(ctx context.Context, acct *imapx.Account, f *folderCache, folder string, forceReconcile bool, res *SyncResult) error {
	f.mu.RLock()
	gen := f.gen
	f.mu.RUnlock()

	st, err := acct.Status(ctx, folder)
	if err != nil {
		return err
	}
	if f.dropIfChanged(st.UIDValidity) {
		res.Reset = true
	}

	f.mu.RLock()
	synced, uv, uidNext, count := f.synced, f.uv, f.uidNext, len(f.hdrs)
	f.mu.RUnlock()

	now := e.opts.Now()
	if !synced {
		return e.coldSync(ctx, acct, f, folder, st, gen, res)
	}

	// Incremental: UIDNEXT guides which UIDs to fetch.
	if st.UIDNext > uidNext {
		sel, hdrs, err := acct.FetchHeaders(ctx, folder, nil, uidNext)
		if err != nil {
			return err
		}
		if sel.UIDValidity != uv {
			f.dropIfChanged(sel.UIDValidity)
			return restart{}
		}
		f.mu.Lock()
		f.upsertLocked(hdrs)
		next := st.UIDNext
		if sel.UIDNext > next {
			next = sel.UIDNext
		}
		if m := f.maxUIDLocked() + 1; m > next {
			next = m
		}
		f.uidNext = next
		count = len(f.hdrs)
		f.mu.Unlock()
		res.Fetched += len(hdrs)
	}

	f.mu.RLock()
	lastRec, stale := f.lastReconcile, f.stale
	f.mu.RUnlock()
	due := forceReconcile || stale || now.Sub(lastRec) >= e.opts.ReconcileEvery ||
		int(st.Messages) != count // message count drift => expunge (or arrival race): reconcile now
	if due {
		if err := e.reconcile(ctx, acct, f, folder, uv, res); err != nil {
			return err
		}
	}

	f.mu.Lock()
	f.lastSync = e.opts.Now()
	if due && f.gen == gen {
		f.stale = false
	}
	f.lastAccess = f.lastSync
	f.mu.Unlock()
	return nil
}

func (e *Engine) coldSync(ctx context.Context, acct *imapx.Account, f *folderCache, folder string, st imapx.Status, gen uint64, res *SyncResult) error {
	sel, uids, err := acct.SearchAll(ctx, folder)
	if err != nil {
		return err
	}
	var all []imapx.Header
	for _, c := range chunk(uids, coldChunk) {
		s2, hdrs, err := acct.FetchHeaders(ctx, folder, c, 0)
		if err != nil {
			return err
		}
		if s2.UIDValidity != sel.UIDValidity {
			return restart{}
		}
		all = append(all, hdrs...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].UID < all[j].UID })
	f.mu.Lock()
	defer f.mu.Unlock()
	next := st.UIDNext
	if sel.UIDNext > next {
		next = sel.UIDNext
	}
	if len(all) > 0 && all[len(all)-1].UID+1 > next {
		next = all[len(all)-1].UID + 1
	}
	f.hdrs = all
	f.uv, f.uidNext, f.synced = sel.UIDValidity, next, true
	now := e.opts.Now()
	f.lastSync, f.lastReconcile, f.lastAccess = now, now, now
	if f.gen == gen {
		f.stale = false
	}
	res.Fetched += len(all)
	return nil
}

// reconcile detects expunges and flag changes: UID SEARCH ALL, then UID FETCH
// (FLAGS). UIDs present on the server but missing from the cache are fetched.
func (e *Engine) reconcile(ctx context.Context, acct *imapx.Account, f *folderCache, folder string, uv uint32, res *SyncResult) error {
	sel, serverUIDs, err := acct.SearchAll(ctx, folder)
	if err != nil {
		return err
	}
	if sel.UIDValidity != uv {
		f.dropIfChanged(sel.UIDValidity)
		return restart{}
	}
	onServer := make(map[uint32]struct{}, len(serverUIDs))
	for _, u := range serverUIDs {
		onServer[u] = struct{}{}
	}

	// 1. expunges
	f.mu.Lock()
	kept := f.hdrs[:0]
	for _, h := range f.hdrs {
		if _, ok := onServer[h.UID]; ok {
			kept = append(kept, h)
		} else {
			res.Expunged++
		}
	}
	for i := len(kept); i < len(f.hdrs); i++ {
		f.hdrs[i] = imapx.Header{} // release strings
	}
	f.hdrs = kept
	have := make(map[uint32]struct{}, len(f.hdrs))
	for _, h := range f.hdrs {
		have[h.UID] = struct{}{}
	}
	f.mu.Unlock()

	// 2. UIDs the cache does not know about (never trust UIDNEXT alone)
	var missing []uint32
	for _, u := range serverUIDs {
		if _, ok := have[u]; !ok {
			missing = append(missing, u)
		}
	}
	justFetched := map[uint32]struct{}{}
	for _, c := range chunk(missing, coldChunk) {
		s2, hdrs, err := acct.FetchHeaders(ctx, folder, c, 0)
		if err != nil {
			return err
		}
		if s2.UIDValidity != uv {
			f.dropIfChanged(s2.UIDValidity)
			return restart{}
		}
		f.mu.Lock()
		f.upsertLocked(hdrs)
		f.mu.Unlock()
		for _, h := range hdrs {
			justFetched[h.UID] = struct{}{}
		}
		res.Fetched += len(hdrs)
	}

	// 3. flag changes
	var toCheck []uint32
	f.mu.RLock()
	for _, h := range f.hdrs {
		if _, ok := justFetched[h.UID]; !ok {
			toCheck = append(toCheck, h.UID)
		}
	}
	f.mu.RUnlock()
	for _, c := range chunk(toCheck, flagChunk) {
		s2, flags, err := acct.FetchFlags(ctx, folder, c)
		if err != nil {
			return err
		}
		if s2.UIDValidity != uv {
			f.dropIfChanged(s2.UIDValidity)
			return restart{}
		}
		f.mu.Lock()
		for uid, nf := range flags {
			if i, ok := f.indexLocked(uid); ok && !f.hdrs[i].Flags.Equal(nf) {
				f.hdrs[i].Flags = nf
				res.FlagChanges++
			}
		}
		f.mu.Unlock()
	}

	f.mu.Lock()
	if sel.UIDNext > f.uidNext {
		f.uidNext = sel.UIDNext
	}
	if m := f.maxUIDLocked() + 1; m > f.uidNext {
		f.uidNext = m
	}
	f.lastReconcile = e.opts.Now()
	f.mu.Unlock()
	res.Reconciled = true
	return nil
}

// Invalidate marks one folder (or, when folder is empty, all folders of the
// mailbox) stale; the next call syncs and reconciles.
func (e *Engine) Invalidate(id, folder string) error {
	mb, err := e.mailbox(id)
	if err != nil {
		return err
	}
	mark := func(f *folderCache) {
		f.mu.Lock()
		f.stale = true
		f.gen++
		f.mu.Unlock()
	}
	if folder != "" {
		if f := mb.folder(folder, false); f != nil {
			mark(f)
		}
		return nil
	}
	mb.mu.RLock()
	defer mb.mu.RUnlock()
	for _, f := range mb.folders {
		mark(f)
	}
	return nil
}

// RunReconciler periodically reconciles every cached folder and evicts idle
// ones. It returns when ctx is cancelled.
func (e *Engine) RunReconciler(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			e.reconcileDue(ctx)
		}
	}
}

func (e *Engine) reconcileDue(ctx context.Context) {
	type job struct {
		mb    *mailbox
		name  string
		f     *folderCache
		evict bool
	}
	var jobs []job
	now := e.opts.Now()
	e.mu.RLock()
	for _, mb := range e.mailboxes {
		mb.mu.RLock()
		for name, f := range mb.folders {
			f.mu.RLock()
			synced, rec, acc := f.synced, f.lastReconcile, f.lastAccess
			f.mu.RUnlock()
			if !synced {
				continue
			}
			if now.Sub(acc) > e.opts.FolderIdle {
				jobs = append(jobs, job{mb, name, f, true})
			} else if now.Sub(rec) >= e.opts.ReconcileEvery {
				jobs = append(jobs, job{mb, name, f, false})
			}
		}
		mb.mu.RUnlock()
	}
	e.mu.RUnlock()

	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for _, j := range jobs {
		if j.evict {
			j.mb.mu.Lock()
			if j.mb.folders[j.name] == j.f {
				delete(j.mb.folders, j.name)
			}
			j.mb.mu.Unlock()
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(j job) {
			defer wg.Done()
			defer func() { <-sem }()
			if !j.f.syncMu.TryLock() {
				return // a foreground sync is running
			}
			defer j.f.syncMu.Unlock()
			rctx, cancel := context.WithTimeout(ctx, e.opts.BackgroundCap)
			defer cancel()
			if _, err := e.syncLocked(rctx, j.mb, j.f, j.name, true); err != nil {
				// retry after the next interval rather than hammering the server
				j.f.mu.Lock()
				j.f.lastReconcile = e.opts.Now()
				j.f.mu.Unlock()
				e.opts.Logf("background reconcile failed mailbox=%s folder=%q: %v", j.mb.id, j.name, err)
			}
		}(j)
	}
	wg.Wait()
}

// FolderStat describes one cached folder.
type FolderStat struct {
	Folder        string `json:"folder"`
	UIDValidity   uint32 `json:"uidValidity"`
	UIDNext       uint32 `json:"uidNext"`
	Count         int    `json:"count"`
	LastSync      string `json:"lastSync,omitempty"`
	LastReconcile string `json:"lastReconcile,omitempty"`
	Stale         bool   `json:"stale"`
}

// MailboxStat describes one mailbox.
type MailboxStat struct {
	MailboxID string       `json:"mailboxId"`
	Folders   []FolderStat `json:"folders"`
}

// Stats returns cache sizes and last sync times.
func (e *Engine) Stats() []MailboxStat {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := []MailboxStat{}
	for id, mb := range e.mailboxes {
		ms := MailboxStat{MailboxID: id, Folders: []FolderStat{}}
		mb.mu.RLock()
		for name, f := range mb.folders {
			f.mu.RLock()
			if f.synced {
				fs := FolderStat{Folder: name, UIDValidity: f.uv, UIDNext: f.uidNext, Count: len(f.hdrs), Stale: f.stale}
				if !f.lastSync.IsZero() {
					fs.LastSync = f.lastSync.UTC().Format(time.RFC3339)
				}
				if !f.lastReconcile.IsZero() {
					fs.LastReconcile = f.lastReconcile.UTC().Format(time.RFC3339)
				}
				ms.Folders = append(ms.Folders, fs)
			}
			f.mu.RUnlock()
		}
		mb.mu.RUnlock()
		sort.Slice(ms.Folders, func(i, j int) bool { return ms.Folders[i].Folder < ms.Folders[j].Folder })
		out = append(out, ms)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MailboxID < out[j].MailboxID })
	return out
}
