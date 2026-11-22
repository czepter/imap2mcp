package engine_test

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/imap2mcp/sidecar/internal/engine"
	"github.com/imap2mcp/sidecar/internal/imapx"
	"github.com/imap2mcp/sidecar/internal/testimap"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func guardEngine(t *testing.T, srv *testimap.Server) (*engine.Engine, *fakeClock) {
	clk := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	e := newEngine(t, srv, func(o *engine.Options) {
		o.AuthStrikes = 3
		o.AuthCooldown = 30 * time.Second
		o.Now = clk.Now
	})
	return e, clk
}

func TestTransientLoginRefusalDoesNotLatchUntilConfirmed(t *testing.T) {
	srv := testimap.New(t)
	e, clk := guardEngine(t, srv)
	srv.SetRejectLogin(true)

	refused := func(err error) {
		t.Helper()
		assertCode(t, err, engine.CodeUpstream)
		m := strings.ToLower(err.Error())
		if !strings.Contains(m, "refused the login") || strings.Contains(m, "authentication failed") || strings.Contains(m, "login failed") || strings.Contains(m, "invalid credentials") {
			t.Fatalf("unexpected message %q", err)
		}
	}

	refused(e.Open(ctx(), "mb1", creds(srv))) // strike 1, cooldown 30 s
	if n := srv.Logins(); n != 1 {
		t.Fatalf("logins %d", n)
	}
	if st := e.Status("mb1"); st.State == "auth_failed" {
		t.Fatalf("latched after one refusal: %+v", st)
	}
	clk.Advance(20 * time.Second)
	refused(e.Open(ctx(), "mb1", creds(srv))) // still cooling down: no dial
	if n := srv.Logins(); n != 1 {
		t.Fatalf("dialed during cooldown: %d", n)
	}

	clk.Advance(11 * time.Second)
	refused(e.Open(ctx(), "mb1", creds(srv))) // strike 2, cooldown 2 min
	if n := srv.Logins(); n != 2 {
		t.Fatalf("logins %d", n)
	}
	clk.Advance(90 * time.Second)
	refused(e.Open(ctx(), "mb1", creds(srv)))
	if n := srv.Logins(); n != 2 {
		t.Fatalf("dialed during second cooldown: %d", n)
	}

	clk.Advance(31 * time.Second)
	err := e.Open(ctx(), "mb1", creds(srv)) // strike 3 latches
	assertCode(t, err, engine.CodeUpstream)
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("third refusal: %v", err)
	}
	if n := srv.Logins(); n != 3 {
		t.Fatalf("logins %d", n)
	}
	if st := e.Status("mb1"); st.State != "auth_failed" {
		t.Fatalf("status %+v", st)
	}
	clk.Advance(time.Hour)
	assertCode(t, e.Open(ctx(), "mb1", creds(srv)), engine.CodeUpstream)
	if n := srv.Logins(); n != 3 {
		t.Fatalf("contacted the server while latched: %d", n)
	}

	// Retry clears the guard: one new attempt is allowed.
	e.Retry("mb1")
	srv.SetRejectLogin(false)
	if err := e.Open(ctx(), "mb1", creds(srv)); err != nil {
		t.Fatal(err)
	}
}

func TestGuardSurvivesFailedOpensAndPasswordChangeResetsIt(t *testing.T) {
	srv := testimap.New(t)
	e, clk := guardEngine(t, srv)
	bad := creds(srv)
	bad.Pass = "wrong-password"
	for i := 0; i < 3; i++ {
		_ = e.Open(ctx(), "mb1", bad)
		clk.Advance(5 * time.Minute)
	}
	n := srv.Logins()
	if n != 3 {
		t.Fatalf("logins %d, want 3", n)
	}
	for i := 0; i < 5; i++ {
		_ = e.Open(ctx(), "mb1", bad)
		clk.Advance(5 * time.Minute)
	}
	if srv.Logins() != n {
		t.Fatalf("kept contacting the server after the latch: %d -> %d", n, srv.Logins())
	}
	if err := e.Open(ctx(), "mb1", creds(srv)); err != nil { // corrected password: fresh guard
		t.Fatal(err)
	}
}

func TestOpenIgnoresIPOnlyChange(t *testing.T) {
	srv := testimap.New(t)
	seed(srv, "INBOX", 5)
	e, _ := guardEngine(t, srv)
	open(t, e, srv)
	if _, err := e.Sync(ctx(), "mb1", "INBOX", "auto"); err != nil {
		t.Fatal(err)
	}
	logins := srv.Logins()

	cr := creds(srv)
	cr.IP = "localhost" // a different address of the same server
	if err := e.Open(ctx(), "mb1", cr); err != nil {
		t.Fatal(err)
	}
	if srv.Logins() != logins {
		t.Fatalf("IP change caused a new login: %d -> %d", logins, srv.Logins())
	}
	r, err := e.Sync(ctx(), "mb1", "INBOX", "auto")
	if err != nil || r.Fetched != 0 || r.Count != 5 {
		t.Fatalf("cache lost on IP change: %+v %v", r, err)
	}
	// Future dials use the new IP.
	srv.DropAll()
	waitFor(t, 5*time.Second, "dial via the new IP", func() bool {
		_, err := e.ListFolders(ctx(), "mb1")
		return err == nil && srv.Logins() > logins
	})
}

func TestSameEndpointIgnoresIP(t *testing.T) {
	a := imapx.Creds{Host: "h", IP: "1.1.1.1", Port: 993, User: "u"}
	b := a
	b.IP = "2.2.2.2"
	if !a.SameEndpoint(b) {
		t.Fatal("IP must not be part of the identity")
	}
	b.User = "v"
	if a.SameEndpoint(b) {
		t.Fatal("user is part of the identity")
	}
}

func TestLoginUsesSASLPlainWhenAdvertised(t *testing.T) {
	srv := testimap.New(t)
	e, _ := guardEngine(t, srv)
	srv.SetRejectLoginCommand(true) // like a provider that refuses LOGIN but accepts SASL
	if err := e.Open(ctx(), "mb1", creds(srv)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ListFolders(ctx(), "mb1"); err != nil {
		t.Fatal(err)
	}
	if srv.LoginCommands() != 0 || srv.AuthAttempts() < 1 {
		t.Fatalf("LOGIN commands %d, AUTHENTICATE attempts %d", srv.LoginCommands(), srv.AuthAttempts())
	}
}

func TestLoginCommandWhenPlainNotAdvertised(t *testing.T) {
	srv := testimap.New(t)
	e, _ := guardEngine(t, srv)
	srv.SetNoAuthPlain(true)
	if err := e.Open(ctx(), "mb1", creds(srv)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ListFolders(ctx(), "mb1"); err != nil {
		t.Fatal(err)
	}
	if srv.AuthAttempts() != 0 || srv.LoginCommands() < 1 {
		t.Fatalf("LOGIN commands %d, AUTHENTICATE attempts %d", srv.LoginCommands(), srv.AuthAttempts())
	}
}

func TestRefusedAuthenticateCountsOneStrikeWithoutLoginFallback(t *testing.T) {
	srv := testimap.New(t)
	e, _ := guardEngine(t, srv)
	srv.SetRejectLogin(true)
	assertCode(t, e.Open(ctx(), "mb1", creds(srv)), engine.CodeUpstream)
	if srv.AuthAttempts() != 1 || srv.LoginCommands() != 0 || srv.LoginFailures() != 1 {
		t.Fatalf("auth %d, login cmds %d, failures %d", srv.AuthAttempts(), srv.LoginCommands(), srv.LoginFailures())
	}
}
