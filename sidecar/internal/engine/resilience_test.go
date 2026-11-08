package engine_test

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/imap2mcp/sidecar/internal/engine"
	"github.com/imap2mcp/sidecar/internal/imapx"
	"github.com/imap2mcp/sidecar/internal/testimap"
)

// Scaled timers: the contract values (1 s initial / 60 s cap / 30 s healthy /
// 1500 s IDLE renewal) divided so that the whole suite runs in seconds. The
// logic under test is identical; BackoffDelay is also tested at contract scale.
const (
	tInitial = 100 * time.Millisecond
	tMax     = 800 * time.Millisecond
	tHealthy = 600 * time.Millisecond
	tRenew   = 700 * time.Millisecond
)

type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.b.WriteString(format + "\n")
	for _, a := range args {
		if s, ok := a.(string); ok {
			l.b.WriteString(s + "\n")
		}
		if e, ok := a.(error); ok {
			l.b.WriteString(e.Error() + "\n")
		}
	}
}
func (l *logBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func newWatchEngine(t *testing.T, srv *testimap.Server, mod func(*engine.Options)) (*engine.Engine, *logBuf) {
	t.Helper()
	lb := &logBuf{}
	e := newEngine(t, srv, func(o *engine.Options) {
		o.DisableWatch = false
		o.IdleRenew = tRenew
		o.PollEvery = 400 * time.Millisecond
		o.ReconnectInitial, o.ReconnectMax, o.HealthyReset = tInitial, tMax, tHealthy
		o.OpTimeout = 2 * time.Second
		o.WatchScan = 100 * time.Millisecond
		o.Logf = lb.logf
		if mod != nil {
			mod(o)
		}
	})
	return e, lb
}

func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) time.Duration {
	t.Helper()
	start := time.Now()
	for time.Since(start) < d {
		if cond() {
			return time.Since(start)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout after %s waiting for %s", d, what)
	return 0
}

func count(e *engine.Engine, folder string) int {
	for _, m := range e.Stats() {
		for _, f := range m.Folders {
			if f.Folder == folder {
				return f.Count
			}
		}
	}
	return -1
}

func flagsOf(t *testing.T, e *engine.Engine, folder string, uid uint32) []string {
	t.Helper()
	pg, err := e.List(ctx(), "mb1", folder, 500, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range pg.Items {
		if h.UID == uid {
			return h.Flags.Names()
		}
	}
	return nil
}

func state(e *engine.Engine) string { return e.Status("mb1").State }

func noSecrets(t *testing.T, lb *logBuf) {
	t.Helper()
	out := lb.String()
	for _, s := range []string{testimap.Pass, testimap.User} {
		if strings.Contains(out, s) {
			t.Fatalf("log leaks %q:\n%s", s, out)
		}
	}
}

func warmInbox(t *testing.T, e *engine.Engine, srv *testimap.Server, n int) []imap.UID {
	t.Helper()
	uids := seed(srv, "INBOX", n)
	open(t, e, srv)
	if _, err := e.Sync(ctx(), "mb1", "INBOX", "auto"); err != nil {
		t.Fatal(err)
	}
	return uids
}

func TestBackoffDelayContractScale(t *testing.T) {
	const s = time.Second
	// rnd=1 gives the un-jittered ceiling: 1,2,4,8,16,32,60,60
	want := []time.Duration{1 * s, 2 * s, 4 * s, 8 * s, 16 * s, 32 * s, 60 * s, 60 * s, 60 * s}
	for n, w := range want {
		if got := engine.BackoffDelay(n, s, 60*s, func() float64 { return 1 }); got != w {
			t.Fatalf("n=%d ceiling: got %s want %s", n, got, w)
		}
		// full jitter never exceeds the ceiling and never drops below 500 ms
		if got := engine.BackoffDelay(n, s, 60*s, func() float64 { return 0 }); got != 500*time.Millisecond {
			t.Fatalf("n=%d floor: got %s", n, got)
		}
		if got := engine.BackoffDelay(n, s, 60*s, func() float64 { return 0.5 }); got < 500*time.Millisecond || got > w {
			t.Fatalf("n=%d half: got %s", n, got)
		}
	}
	// huge n must not overflow
	if got := engine.BackoffDelay(1000, s, 60*s, func() float64 { return 1 }); got != 60*s {
		t.Fatalf("overflow: %s", got)
	}
	// scaled timers (tests): floor shrinks with the initial delay
	if got := engine.BackoffDelay(0, tInitial, tMax, func() float64 { return 0 }); got != tInitial {
		t.Fatalf("scaled floor: %s", got)
	}
}

func TestIdleDeliversArrivalsFlagsAndExpunges(t *testing.T) {
	srv := testimap.New(t)
	e, lb := newWatchEngine(t, srv, func(o *engine.Options) { o.IdleRenew = time.Minute })
	uids := warmInbox(t, e, srv, 5)
	waitFor(t, 3*time.Second, "primary watcher IDLE", func() bool { return e.Status("mb1").Idle && srv.IdleActive() >= 1 })

	t0 := time.Now()
	srv.Append("INBOX", testimap.Msg(100, "late arrival", "Bob <bob@example.org>", "alice@example.test", 200))
	d := waitFor(t, 3*time.Second, "arrival via IDLE", func() bool { return count(e, "INBOX") == 6 })
	t.Logf("IDLE arrival visible in cache after %s (no foreground call)", d)

	srv.SetFlags(t, "INBOX", uids[0], imap.FlagSeen, imap.FlagFlagged)
	waitFor(t, 3*time.Second, "flag change via IDLE", func() bool {
		return strings.Join(flagsOf(t, e, "INBOX", uint32(uids[0])), ",") == `\Seen,\Flagged`
	})
	srv.Expunge(t, "INBOX", uids[1], uids[2])
	waitFor(t, 3*time.Second, "expunge via IDLE", func() bool { return count(e, "INBOX") == 4 })
	if time.Since(t0) > 10*time.Second {
		t.Fatal("too slow")
	}
	noSecrets(t, lb)
}

func TestWarmFolderIsWatchedToo(t *testing.T) {
	srv := testimap.New(t, "Archive")
	e, _ := newWatchEngine(t, srv, func(o *engine.Options) { o.IdleRenew = time.Minute })
	seed(srv, "Archive", 3)
	open(t, e, srv)
	if _, err := e.Sync(ctx(), "mb1", "Archive", "auto"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, "IDLE on INBOX and Archive", func() bool { return srv.IdleActive() >= 2 })
	srv.Append("Archive", testimap.Msg(50, "in archive", "Bob <bob@example.org>", "alice@example.test", 200))
	waitFor(t, 3*time.Second, "Archive arrival", func() bool { return count(e, "Archive") == 4 })
}

func TestColdFoldersAreNotSyncedByWatchers(t *testing.T) {
	srv := testimap.New(t)
	seed(srv, "INBOX", 3)
	e, _ := newWatchEngine(t, srv, func(o *engine.Options) { o.IdleRenew = time.Minute })
	open(t, e, srv)
	waitFor(t, 3*time.Second, "IDLE", func() bool { return srv.IdleActive() >= 1 })
	srv.Append("INBOX", testimap.Msg(9, "x", "Bob <bob@example.org>", "alice@example.test", 100))
	time.Sleep(700 * time.Millisecond)
	if n := count(e, "INBOX"); n != -1 {
		t.Fatalf("cold INBOX was synced unprompted (count %d)", n)
	}
}

func TestIdleRenewedBeforeProviderDeadline(t *testing.T) {
	srv := testimap.New(t)
	srv.SetIdleLimit(1500 * time.Millisecond) // "provider" drops IDLEs older than 1.5 s ...
	e, _ := newWatchEngine(t, srv, nil)       // ... we renew every 700 ms (the 1500 s / ~1800 s ratio, scaled)
	warmInbox(t, e, srv, 2)
	time.Sleep(4500 * time.Millisecond)
	st := e.Status("mb1")
	starts := srv.IdleStarts()
	if starts < 5 || srv.IdleKills() != 0 || st.Reconnects != 0 || st.State != "connected" {
		t.Fatalf("renewal: idleStarts=%d kills=%d status=%+v", starts, srv.IdleKills(), st)
	}
	// gaps between consecutive IDLEs on the watcher connection stay below the deadline
	times := srv.IdleTimes()
	for i := 1; i < len(times); i++ {
		if g := times[i].Sub(times[i-1]); g > 1500*time.Millisecond {
			t.Fatalf("gap %s between IDLEs exceeds the provider deadline", g)
		}
	}
	t.Logf("IDLE started %d times in 4.5 s with renew=700ms, deadline kills=%d, reconnects=%d", starts, srv.IdleKills(), st.Reconnects)
}

func TestIdleNotRenewedIsKilledAndRecovered(t *testing.T) {
	// control for the test above: if we did not renew in time, the server drops us
	srv := testimap.New(t)
	srv.SetIdleLimit(500 * time.Millisecond)
	e, _ := newWatchEngine(t, srv, func(o *engine.Options) { o.IdleRenew = time.Minute })
	warmInbox(t, e, srv, 2)
	waitFor(t, 4*time.Second, "server killed IDLE and we reconnected", func() bool {
		st := e.Status("mb1")
		return srv.IdleKills() >= 1 && st.Reconnects >= 1 && st.State == "connected"
	})
}

func TestConnectionDropResumesAndReconcilesMissedChanges(t *testing.T) {
	srv := testimap.New(t)
	e, lb := newWatchEngine(t, srv, func(o *engine.Options) { o.IdleRenew = time.Minute })
	uids := warmInbox(t, e, srv, 6)
	waitFor(t, 3*time.Second, "IDLE", func() bool { return e.Status("mb1").Idle })

	srv.SetBlocked(true) // connectivity gone
	srv.DropAll()
	waitFor(t, 3*time.Second, "reconnecting state", func() bool { return state(e) == "reconnecting" })
	st := e.Status("mb1")
	if st.LastErrorCode == "" || st.NextRetryAt == "" || st.Idle {
		t.Fatalf("reconnecting status incomplete: %+v", st)
	}

	// changes made by another client while we are offline (also: no sidecar session is open)
	srv.Append("INBOX", testimap.Msg(200, "missed 1", "Bob <bob@example.org>", "alice@example.test", 100))
	srv.Append("INBOX", testimap.Msg(201, "missed 2", "Bob <bob@example.org>", "alice@example.test", 100))
	srv.Expunge(t, "INBOX", uids[0])
	srv.SetFlags(t, "INBOX", uids[3], imap.FlagSeen)
	if count(e, "INBOX") != 6 {
		t.Fatal("cache changed while offline?")
	}

	// let it fail a few times, then connectivity returns
	time.Sleep(1200 * time.Millisecond)
	attempts := srv.Accepted()
	srv.SetBlocked(false)
	back := time.Now()
	waitFor(t, 5*time.Second, "reconnected", func() bool { return state(e) == "connected" })
	resume := time.Since(back)
	waitFor(t, 3*time.Second, "reconciled missed changes", func() bool {
		return count(e, "INBOX") == 7 && strings.Contains(strings.Join(flagsOf(t, e, "INBOX", uint32(uids[3])), ","), `\Seen`)
	})
	st = e.Status("mb1")
	if st.Reconnects < 1 || st.LastErrorCode != "" || st.NextRetryAt != "" {
		t.Fatalf("status after recovery: %+v", st)
	}
	t.Logf("scaled resume (cap %s, initial %s): connected %s after connectivity returned, reconciled %s; %d connection attempts while down",
		tMax, tInitial, resume, time.Since(back), attempts)
	// scaled equivalent of "resume < 90 s": cap + connect/login, with a wide margin
	if resume > tMax+3*time.Second {
		t.Fatalf("resume took %s", resume)
	}
	// and IDLE works again afterwards
	waitFor(t, 3*time.Second, "IDLE after reconnect", func() bool { return e.Status("mb1").Idle })
	srv.Append("INBOX", testimap.Msg(202, "after", "Bob <bob@example.org>", "alice@example.test", 100))
	waitFor(t, 3*time.Second, "arrival after reconnect", func() bool { return count(e, "INBOX") == 8 })
	noSecrets(t, lb)
}

func TestReconnectAttemptsAreBackedOff(t *testing.T) {
	srv := testimap.New(t)
	e, _ := newWatchEngine(t, srv, func(o *engine.Options) { o.IdleRenew = time.Minute })
	warmInbox(t, e, srv, 1)
	waitFor(t, 3*time.Second, "IDLE", func() bool { return e.Status("mb1").Idle })
	srv.SetBlocked(true)
	srv.DropAll()
	time.Sleep(100 * time.Millisecond)
	base := srv.Accepted()
	time.Sleep(3 * time.Second)
	n := srv.Accepted() - base
	// delays are in [initial, <=max]; with the 100 ms floor at most ~30 attempts fit in 3 s,
	// and the exponential ramp makes it far fewer on average. A storm would be hundreds.
	if n < 2 || n > 30 {
		t.Fatalf("%d reconnect attempts in 3 s", n)
	}
	t.Logf("%d reconnect attempts in 3 s with initial=%s cap=%s", n, tInitial, tMax)
}

func TestIdleDropAndServerLogoutRecover(t *testing.T) {
	srv := testimap.New(t)
	e, _ := newWatchEngine(t, srv, func(o *engine.Options) { o.IdleRenew = time.Minute })
	warmInbox(t, e, srv, 2)
	waitFor(t, 3*time.Second, "IDLE", func() bool { return e.Status("mb1").Idle })

	srv.DropAll() // IDLE connection dies
	waitFor(t, 5*time.Second, "reconnect after IDLE drop", func() bool {
		return e.Status("mb1").Reconnects >= 1 && e.Status("mb1").Idle
	})

	srv.Logout() // "* BYE" + close
	waitFor(t, 5*time.Second, "reconnect after server logout", func() bool {
		return e.Status("mb1").Reconnects >= 2 && e.Status("mb1").Idle
	})
	// foreground calls keep working over fresh pool connections
	if _, err := e.Sync(ctx(), "mb1", "INBOX", "full"); err != nil {
		t.Fatal(err)
	}
}

func TestMalformedServerReplyDoesNotCrashOrWedge(t *testing.T) {
	srv := testimap.New(t)
	e, lb := newWatchEngine(t, srv, func(o *engine.Options) { o.IdleRenew = time.Minute })
	warmInbox(t, e, srv, 2)
	waitFor(t, 3*time.Second, "IDLE", func() bool { return e.Status("mb1").Idle })
	srv.Inject("* 1 FETCH (((((\x00\x01 garbage\r\n")
	waitFor(t, 5*time.Second, "reconnect after garbage", func() bool { return e.Status("mb1").Reconnects >= 1 && state(e) == "connected" })
	if _, err := e.Sync(ctx(), "mb1", "INBOX", "full"); err != nil {
		t.Fatal(err)
	}
	srv.Append("INBOX", testimap.Msg(300, "ok", "Bob <bob@example.org>", "alice@example.test", 100))
	waitFor(t, 5*time.Second, "arrival after garbage", func() bool { return count(e, "INBOX") == 3 })
	noSecrets(t, lb)
}

func TestAuthRejectionLatchesAndStopsAttempts(t *testing.T) {
	srv := testimap.New(t)
	e, lb := newWatchEngine(t, srv, func(o *engine.Options) { o.IdleRenew = time.Minute })
	warmInbox(t, e, srv, 3)
	waitFor(t, 3*time.Second, "IDLE", func() bool { return e.Status("mb1").Idle })

	srv.SetRejectLogin(true) // credentials revoked / password changed
	srv.DropAll()
	waitFor(t, 5*time.Second, "auth_failed", func() bool { return state(e) == "auth_failed" })
	st := e.Status("mb1")
	if st.LastErrorCode != "AUTH_FAILED" || st.NextRetryAt != "" || st.Idle {
		t.Fatalf("status %+v", st)
	}
	time.Sleep(300 * time.Millisecond)
	fails, accepted := srv.LoginFailures(), srv.Accepted()
	if fails < 1 || fails > 2 {
		t.Fatalf("login failures before settling: %d", fails)
	}

	// no retry storm: many backoff periods (scaled 100-800 ms) pass without a single new attempt
	time.Sleep(3 * time.Second)
	if srv.LoginFailures() != fails || srv.Accepted() != accepted {
		t.Fatalf("attempts continued while latched: failures %d->%d, connections %d->%d", fails, srv.LoginFailures(), accepted, srv.Accepted())
	}
	// foreground calls answer immediately without contacting the server
	t0 := time.Now()
	_, err := e.Sync(ctx(), "mb1", "INBOX", "auto")
	assertCode(t, err, engine.CodeUpstream)
	if !strings.Contains(err.Error(), "authentication failed") || time.Since(t0) > 500*time.Millisecond {
		t.Fatalf("latched sync: %v after %s", err, time.Since(t0))
	}
	if _, err := e.ListFolders(ctx(), "mb1"); err == nil {
		t.Fatal("ListFolders succeeded while latched")
	}
	// an open with the same (rejected) credentials does not touch the server either
	assertCode(t, e.Open(ctx(), "mb1", creds(srv)), engine.CodeUpstream)
	if srv.LoginFailures() != fails || srv.Accepted() != accepted {
		t.Fatalf("open/sync contacted the server while latched")
	}

	// retry with the server still rejecting: exactly one more attempt, then latched again
	e.Retry("mb1")
	waitFor(t, 5*time.Second, "latched again", func() bool { return srv.LoginFailures() > fails && state(e) == "auth_failed" })
	again := srv.LoginFailures()
	time.Sleep(1500 * time.Millisecond)
	if srv.LoginFailures() != again {
		t.Fatalf("attempts continued after a failed retry: %d -> %d", again, srv.LoginFailures())
	}

	// operator fixed the problem; retry resumes and reconciles
	srv.SetRejectLogin(false)
	srv.Append("INBOX", testimap.Msg(400, "while locked out", "Bob <bob@example.org>", "alice@example.test", 100))
	e.Retry("mb1")
	waitFor(t, 5*time.Second, "connected after retry", func() bool { return state(e) == "connected" })
	waitFor(t, 5*time.Second, "reconciled after retry", func() bool { return count(e, "INBOX") == 4 })
	noSecrets(t, lb)
}

func TestOpenWithDifferentCredentialsClearsLatch(t *testing.T) {
	srv := testimap.New(t)
	e, _ := newWatchEngine(t, srv, nil)
	srv.SetRejectLogin(true)
	err := e.Open(ctx(), "mb1", creds(srv))
	assertCode(t, err, engine.CodeUpstream)
	if st := e.Status("mb1"); st.State != "auth_failed" {
		t.Fatalf("status after rejected open: %+v", st)
	}
	n := srv.LoginFailures()
	assertCode(t, e.Open(ctx(), "mb1", creds(srv)), engine.CodeUpstream) // same creds: no new attempt
	if srv.LoginFailures() != n {
		t.Fatal("same credentials were tried again")
	}
	srv.SetRejectLogin(false)
	other := creds(srv)
	other.Host = "mail-b.example.test" // different credentials/endpoint identity
	if err := e.Open(ctx(), "mb1", other); err != nil {
		t.Fatal(err)
	}
	if st := e.Status("mb1"); st.State != "connected" {
		t.Fatalf("status %+v", st)
	}
	// Retry (admin pressed the button) also clears a rejected open
	srv.SetRejectLogin(true)
	e.Close("mb1")
	assertCode(t, e.Open(ctx(), "mb1", creds(srv)), engine.CodeUpstream)
	srv.SetRejectLogin(false)
	e.Retry("mb1")
	if err := e.Open(ctx(), "mb1", creds(srv)); err != nil {
		t.Fatal(err)
	}
}

func TestPollingFallbackWithoutIdle(t *testing.T) {
	srv := testimap.New(t)
	srv.SetHideIdle(true)
	e, _ := newWatchEngine(t, srv, func(o *engine.Options) { o.PollEvery = 300 * time.Millisecond })
	warmInbox(t, e, srv, 2)
	srv.Append("INBOX", testimap.Msg(500, "polled", "Bob <bob@example.org>", "alice@example.test", 100))
	d := waitFor(t, 4*time.Second, "arrival via polling", func() bool { return count(e, "INBOX") == 3 })
	if srv.IdleStarts() != 0 || e.Status("mb1").Idle {
		t.Fatalf("IDLE used although not advertised (starts=%d)", srv.IdleStarts())
	}
	t.Logf("polling fallback (PollEvery=300ms) delivered the arrival after %s", d)
}

// Regression for the benchmark run that hung in the UIDVALIDITY phase on a
// loaded host: every request must end at its deadline, whatever the upstream or
// a background job holding the folder lock is doing, and the engine must stay
// usable afterwards.
func TestHungServerRequestsMeetDeadlinesAndDoNotDeadlock(t *testing.T) {
	srv := testimap.New(t)
	e, _ := newWatchEngine(t, srv, func(o *engine.Options) { o.DisableWatch = true })
	warmInbox(t, e, srv, 5)
	srv.SetHang(true)

	short := func(d time.Duration) (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), d)
	}

	// 1. a long-running holder of the folder lock (the background reconcile in the incident)
	holderCtx, stopHolder := short(8 * time.Second)
	holderDone := make(chan error, 1)
	go func() { _, err := e.Sync(holderCtx, "mb1", "INBOX", "full"); holderDone <- err }()
	time.Sleep(200 * time.Millisecond)

	// 2. a queued request with a 600 ms budget must fail at ~600 ms, not wait for the holder
	for name, call := range map[string]func(c context.Context) error{
		"sync":  func(c context.Context) error { _, err := e.Sync(c, "mb1", "INBOX", "auto"); return err },
		"list":  func(c context.Context) error { _, err := e.List(c, "mb1", "INBOX", 10, 0); return err },
		"body":  func(c context.Context) error { _, err := e.FetchBody(c, "mb1", "INBOX", 1, 1, 100); return err },
		"text":  func(c context.Context) error { _, err := e.SearchText(c, "mb1", "INBOX", "x", 10); return err },
		"folds": func(c context.Context) error { _, err := e.ListFolders(c, "mb1"); return err },
	} {
		c, cancel := short(600 * time.Millisecond)
		t0 := time.Now()
		err := call(c)
		cancel()
		if name == "list" || name == "sync" {
			// `list` on a stale-free cache may legitimately answer from memory; sync must time out
			if name == "sync" {
				assertCode(t, err, engine.CodeTimeout)
			}
		} else if err == nil {
			t.Fatalf("%s succeeded against a hung server", name)
		}
		if el := time.Since(t0); el > 1500*time.Millisecond {
			t.Fatalf("%s took %s with a 600 ms budget", name, el)
		}
	}

	// 3. unhang: the holder finishes or times out, and everything works again without restart
	srv.SetHang(false)
	stopHolder()
	select {
	case <-holderDone:
	case <-time.After(5 * time.Second):
		t.Fatal("holder never returned")
	}
	c, cancel := short(10 * time.Second)
	defer cancel()
	if _, err := e.Sync(c, "mb1", "INBOX", "full"); err != nil {
		t.Fatalf("engine unusable after the hang: %v", err)
	}
}

func TestStatusForUnknownMailbox(t *testing.T) {
	srv := testimap.New(t)
	e, _ := newWatchEngine(t, srv, nil)
	if st := e.Status("nope"); st.State != "closed" {
		t.Fatalf("%+v", st)
	}
	open(t, e, srv)
	if st := e.Status("mb1"); st.State != "connected" || st.Since == "" {
		t.Fatalf("%+v", st)
	}
	e.Close("mb1")
	if st := e.Status("mb1"); st.State != "closed" {
		t.Fatalf("%+v", st)
	}
}

var _ = imapx.Creds{}
