package testimap

import (
	"bytes"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emersion/go-imap/v2/imapserver"
)

// faults holds the fault-injection switches and observation counters of a
// test server. All methods are safe for concurrent use.
type faults struct {
	mu    sync.Mutex
	conns map[*faultConn]struct{}

	rejectLogin atomic.Bool
	hang        atomic.Bool
	blocked     atomic.Bool
	hideIdle    atomic.Bool
	idleLimit   atomic.Int64 // ns; the server kills a connection that stays in IDLE this long

	accepted      atomic.Int64
	logins        atomic.Int64
	loginFailures atomic.Int64
	idleStarts    atomic.Int64
	idleKills     atomic.Int64
	idleActive    atomic.Int64

	timesMu    sync.Mutex
	idleTimes  []time.Time
	loginTimes []time.Time
}

func (f *faults) init() { f.conns = map[*faultConn]struct{}{} }

// SetRejectLogin makes every LOGIN fail with NO [AUTHENTICATIONFAILED].
func (f *faults) SetRejectLogin(v bool) { f.rejectLogin.Store(v) }

// SetHang stops the server from reading and writing on every connection
// (existing and new): requests sent to it get no answer.
func (f *faults) SetHang(v bool) { f.hang.Store(v) }

// SetBlocked makes the server close every new connection right after accept
// (like a firewall / refused connection after TCP connect).
func (f *faults) SetBlocked(v bool) { f.blocked.Store(v) }

// SetHideIdle removes IDLE from the advertised capabilities (polling fallback).
func (f *faults) SetHideIdle(v bool) { f.hideIdle.Store(v) }

// SetIdleLimit makes the server drop a connection that stays in IDLE longer
// than d (a provider's IDLE deadline); 0 disables.
func (f *faults) SetIdleLimit(d time.Duration) { f.idleLimit.Store(int64(d)) }

// DropAll closes every open connection (network drop / server restart).
func (f *faults) DropAll() {
	f.mu.Lock()
	cs := make([]*faultConn, 0, len(f.conns))
	for c := range f.conns {
		cs = append(cs, c)
	}
	f.mu.Unlock()
	for _, c := range cs {
		_ = c.Close()
	}
}

// Logout sends "* BYE" on every connection and closes it (server-side logout).
func (f *faults) Logout() { f.Inject("* BYE server is shutting down\r\n"); f.DropAll() }

// Inject writes raw bytes to every open connection, bypassing the IMAP
// server (malformed replies, unsolicited data).
func (f *faults) Inject(raw string) {
	f.mu.Lock()
	cs := make([]*faultConn, 0, len(f.conns))
	for c := range f.conns {
		cs = append(cs, c)
	}
	f.mu.Unlock()
	for _, c := range cs {
		_, _ = c.Conn.Write([]byte(raw))
	}
}

// Accepted is the number of TCP connections accepted so far.
func (f *faults) Accepted() int64 { return f.accepted.Load() }

// Open is the number of currently open connections.
func (f *faults) Open() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.conns) }

// Logins is the number of LOGIN attempts seen (successful or not).
func (f *faults) Logins() int64 { return f.logins.Load() }

// LoginFailures is the number of rejected LOGIN attempts.
func (f *faults) LoginFailures() int64 { return f.loginFailures.Load() }

// IdleStarts is the number of IDLE commands seen.
func (f *faults) IdleStarts() int64 { return f.idleStarts.Load() }

// IdleKills is the number of connections the server dropped for exceeding the IDLE limit.
func (f *faults) IdleKills() int64 { return f.idleKills.Load() }

// IdleActive is the number of sessions currently in IDLE.
func (f *faults) IdleActive() int64 { return f.idleActive.Load() }

// IdleTimes returns the start time of every IDLE seen.
func (f *faults) IdleTimes() []time.Time {
	f.timesMu.Lock()
	defer f.timesMu.Unlock()
	return append([]time.Time(nil), f.idleTimes...)
}

// LoginTimes returns the time of every LOGIN attempt.
func (f *faults) LoginTimes() []time.Time {
	f.timesMu.Lock()
	defer f.timesMu.Unlock()
	return append([]time.Time(nil), f.loginTimes...)
}

type faultListener struct {
	net.Listener
	f *faults
}

func (l *faultListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		l.f.accepted.Add(1)
		if l.f.blocked.Load() && !isExempt(c) {
			_ = c.Close()
			continue
		}
		fc := &faultConn{Conn: c, f: l.f, closed: make(chan struct{})}
		l.f.mu.Lock()
		l.f.conns[fc] = struct{}{}
		l.f.mu.Unlock()
		return fc, nil
	}
}

type faultConn struct {
	net.Conn
	f      *faults
	once   sync.Once
	closed chan struct{}
}

func (c *faultConn) waitHang() error {
	for c.f.hang.Load() {
		select {
		case <-c.closed:
			return net.ErrClosed
		case <-time.After(5 * time.Millisecond):
		}
	}
	return nil
}

func (c *faultConn) Read(p []byte) (int, error) {
	if err := c.waitHang(); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

func (c *faultConn) Write(p []byte) (int, error) {
	if err := c.waitHang(); err != nil {
		return 0, err
	}
	if c.f.hideIdle.Load() && bytes.Contains(p, []byte(" IDLE")) {
		q := bytes.ReplaceAll(p, []byte(" IDLE"), []byte(" XIDL"))
		if _, err := c.Conn.Write(q); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func (c *faultConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
		c.f.mu.Lock()
		delete(c.f.conns, c)
		c.f.mu.Unlock()
	})
	return c.Conn.Close()
}

// faultSession wraps the in-memory session to observe and break LOGIN / IDLE.
type faultSession struct {
	imapserver.SessionIMAP4rev2
	srv  *Server
	conn *imapserver.Conn
}

func (s *faultSession) Login(user, pass string) error {
	f := &s.srv.faults
	f.logins.Add(1)
	f.timesMu.Lock()
	f.loginTimes = append(f.loginTimes, time.Now())
	f.timesMu.Unlock()
	if f.rejectLogin.Load() {
		f.loginFailures.Add(1)
		return imapserver.ErrAuthFailed
	}
	return s.SessionIMAP4rev2.Login(user, pass)
}

func (s *faultSession) Idle(w *imapserver.UpdateWriter, stop <-chan struct{}) error {
	f := &s.srv.faults
	f.idleStarts.Add(1)
	f.idleActive.Add(1)
	defer f.idleActive.Add(-1)
	f.timesMu.Lock()
	f.idleTimes = append(f.idleTimes, time.Now())
	f.timesMu.Unlock()
	if d := time.Duration(f.idleLimit.Load()); d > 0 {
		t := time.AfterFunc(d, func() {
			f.idleKills.Add(1)
			_ = s.conn.NetConn().Close()
		})
		defer t.Stop()
	}
	return s.SessionIMAP4rev2.Idle(w, stop)
}

func isExempt(c net.Conn) bool {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return a.IP.String() == ExemptIP
	}
	return false
}
