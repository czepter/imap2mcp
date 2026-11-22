package imapx

import (
	"errors"
	"sync"
	"time"
)

// ErrLoginRefused is returned when the server refused a login but the refusal
// is not yet confirmed as bad credentials (or the account is cooling down
// after such a refusal). The message deliberately avoids the words the Node
// layer treats as an authentication failure.
var ErrLoginRefused = errors.New("mail server refused the login; will retry later")

const (
	DefaultAuthStrikes  = 3
	DefaultAuthCooldown = 30 * time.Second
	maxAuthCooldown     = 30 * time.Minute
)

// AuthGuard decides when repeated login refusals mean "bad credentials".
// Large providers answer a plain NO transiently (rate limits, too many
// sessions), so one refusal must not latch a mailbox: only `strikes`
// consecutive refusals do, each followed by a growing cooldown during which
// the server is not contacted. A guard outlives Account replacement.
type AuthGuard struct {
	now      func() time.Time
	strikes  int
	cooldown time.Duration

	mu        sync.Mutex
	count     int
	notBefore time.Time
	latched   bool
}

// NewAuthGuard creates a guard. Non-positive values select the defaults; a nil
// now uses time.Now.
func NewAuthGuard(strikes int, cooldown time.Duration, now func() time.Time) *AuthGuard {
	if strikes <= 0 {
		strikes = DefaultAuthStrikes
	}
	if cooldown <= 0 {
		cooldown = DefaultAuthCooldown
	}
	if now == nil {
		now = time.Now
	}
	return &AuthGuard{now: now, strikes: strikes, cooldown: cooldown}
}

// Latched reports whether the credentials are confirmed bad.
func (g *AuthGuard) Latched() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.latched
}

// Clear lifts the latch and forgets all strikes.
func (g *AuthGuard) Clear() {
	g.mu.Lock()
	g.latched, g.count, g.notBefore = false, 0, time.Time{}
	g.mu.Unlock()
}

// admit reports whether a login attempt may be made now.
func (g *AuthGuard) admit() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.latched {
		return ErrAuth
	}
	if !g.notBefore.IsZero() && g.now().Before(g.notBefore) {
		return ErrLoginRefused
	}
	return nil
}

// reject records a refused login and reports whether it latched. Refusals
// that arrive while a cooldown is already running come from logins started in
// parallel before it (watchers and tool calls reconnecting together), so a
// burst counts as one strike.
func (g *AuthGuard) reject() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.latched {
		return true
	}
	if !g.notBefore.IsZero() && g.now().Before(g.notBefore) {
		return false
	}
	g.count++
	if g.count >= g.strikes {
		g.latched = true
		return true
	}
	d := g.cooldown
	for i := 1; i < g.count && d < maxAuthCooldown; i++ {
		d *= 4
	}
	if d > maxAuthCooldown {
		d = maxAuthCooldown
	}
	g.notBefore = g.now().Add(d)
	return false
}

// ok records a successful login.
func (g *AuthGuard) ok() {
	g.mu.Lock()
	g.count, g.notBefore = 0, time.Time{}
	g.mu.Unlock()
}
