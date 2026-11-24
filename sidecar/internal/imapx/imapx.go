// Package imapx is the read-only upstream IMAP layer of the sidecar: TLS
// dialing (always validated), a tiny per-mailbox connection pool, and the
// handful of read operations the engine needs. It never issues STORE, APPEND,
// MOVE or EXPUNGE.
package imapx

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-message/charset"
	"github.com/emersion/go-sasl"
)

// Creds holds the connection parameters of one mailbox. It lives in memory
// only. Its String/GoString methods never print secrets.
type Creds struct {
	Host       string
	IP         string
	Port       int
	ServerName string
	User       string
	Pass       string
}

func (c Creds) String() string   { return "Creds{" + c.Host + "}" }
func (c Creds) GoString() string { return c.String() }

// SameEndpoint reports whether two credential sets address the same account on
// the same server (a password change or a re-resolved IP does not change the
// identity).
func (c Creds) SameEndpoint(o Creds) bool {
	return c.Host == o.Host && c.Port == o.Port && c.User == o.User
}

// Redact removes the user name and password from a string.
func (c Creds) Redact(s string) string {
	for _, secret := range []string{c.Pass, c.User} {
		if secret != "" {
			s = strings.ReplaceAll(s, secret, "[redacted]")
		}
	}
	return s
}

// Header is the cached per-message metadata.
type Header struct {
	UID          uint32
	Flags        Flags
	Subject      string
	From         []Addr
	To           []Addr
	Cc           []Addr
	Date         time.Time
	InternalDate time.Time
	MessageID    string
	Size         uint32
}

// Addr is a mailbox address.
type Addr struct {
	Name    string
	Address string
}

// Flags is a compact flag set: system flags as bits plus rare keywords.
type Flags struct {
	Bits  uint8
	Extra []string
}

const (
	FlagSeen uint8 = 1 << iota
	FlagAnswered
	FlagFlagged
	FlagDeleted
	FlagDraft
)

var sysFlags = []struct {
	bit  uint8
	name string
}{
	{FlagSeen, `\Seen`}, {FlagAnswered, `\Answered`}, {FlagFlagged, `\Flagged`},
	{FlagDeleted, `\Deleted`}, {FlagDraft, `\Draft`},
}

// ParseFlags converts IMAP flags to the compact form.
func ParseFlags(in []imap.Flag) Flags {
	var f Flags
	for _, fl := range in {
		s := string(fl)
		matched := false
		for _, sf := range sysFlags {
			if strings.EqualFold(s, sf.name) {
				f.Bits |= sf.bit
				matched = true
				break
			}
		}
		if !matched && !strings.EqualFold(s, `\Recent`) {
			f.Extra = append(f.Extra, s)
		}
	}
	if len(f.Extra) > 1 {
		sort.Strings(f.Extra)
	}
	return f
}

// Names returns the flag names in a stable order.
func (f Flags) Names() []string {
	out := make([]string, 0, 3+len(f.Extra))
	for _, sf := range sysFlags {
		if f.Bits&sf.bit != 0 {
			out = append(out, sf.name)
		}
	}
	return append(out, f.Extra...)
}

// Equal compares flag sets.
func (f Flags) Equal(o Flags) bool {
	if f.Bits != o.Bits || len(f.Extra) != len(o.Extra) {
		return false
	}
	for i := range f.Extra {
		if f.Extra[i] != o.Extra[i] {
			return false
		}
	}
	return true
}

// Folder is a LIST result.
type Folder struct {
	Path      string
	Delimiter string
	Flags     []string
}

// Status is a STATUS result.
type Status struct {
	UIDValidity uint32
	UIDNext     uint32
	Messages    uint32
}

// ErrAuth is returned when the server rejects the credentials.
var ErrAuth = errors.New("authentication failed")

// Account is a pooled set of connections for one mailbox.
type Account struct {
	creds  Creds
	tlsCfg func(serverName string) *tls.Config

	mu       sync.Mutex
	idle     []*conn
	closed   bool
	guard    *AuthGuard // latch + strike policy; may be shared across Account replacements
	authSeen bool       // onAuth already fired for the current latch
	onAuth   func()     // called (once per latch) when the guard latches
	logf     func(format string, args ...any) // never receives credentials
	noID     bool                              // do not send the IMAP ID command before login
	okLogged bool                              // the first successful login was logged
	relay    *relayCfg                         // when set, TLS is terminated by the Node server behind a unix socket
}

type conn struct {
	c *imapclient.Client
	// fresh is true until the first operation completes.
	fresh bool
}

// NewAccount creates an account pool. tlsCfg must return a validating config.
func NewAccount(creds Creds, tlsCfg func(serverName string) *tls.Config) *Account {
	return NewAccountWithGuard(creds, tlsCfg, nil)
}

// NewAccountWithGuard is NewAccount with a caller-owned guard, so strikes and
// the latch survive the replacement of the account. A nil guard creates a
// default one.
func NewAccountWithGuard(creds Creds, tlsCfg func(serverName string) *tls.Config, g *AuthGuard) *Account {
	if g == nil {
		g = NewAuthGuard(0, 0, nil)
	}
	return &Account{creds: creds, tlsCfg: tlsCfg, guard: g}
}

// SetLogf installs the logger used for login failures. Lines carry the
// server's reply text, redacted of user and password.
func (a *Account) SetLogf(f func(format string, args ...any)) {
	a.mu.Lock()
	a.logf = f
	a.mu.Unlock()
}

// SetSendID switches the IMAP ID command (RFC 2971) sent before login on or
// off. It is on by default and only sent when the server advertises ID.
func (a *Account) SetSendID(on bool) {
	a.mu.Lock()
	a.noID = !on
	a.mu.Unlock()
}

// SetRelay routes every upstream connection through the TLS relay listening on
// the unix socket at path: the relay authenticates with secret, looks the
// destination up by mailboxID and terminates TLS itself, so this process only
// speaks plain IMAP over the socket.
func (a *Account) SetRelay(path, secret, mailboxID string) {
	a.mu.Lock()
	a.relay = &relayCfg{path: path, secret: secret, mailboxID: mailboxID}
	a.mu.Unlock()
}

// Creds returns the account credentials (in-memory copy).
func (a *Account) Creds() Creds {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.creds
}

// SetIP changes the pinned IP used for future dials.
func (a *Account) SetIP(ip string) {
	a.mu.Lock()
	a.creds.IP = ip
	a.mu.Unlock()
}

// Close closes all pooled connections; in-flight ones close on release.
func (a *Account) Close() {
	a.mu.Lock()
	a.closed = true
	idle := a.idle
	a.idle = nil
	a.mu.Unlock()
	for _, c := range idle {
		closeAsync(c.c)
	}
}

// closeAsync closes a client without ever blocking the caller (Client.Close
// waits for the decoder goroutine).
func closeAsync(c *imapclient.Client) { go func() { _ = c.Close() }() }

// SetOnAuthFailed registers a callback invoked when the account latches.
func (a *Account) SetOnAuthFailed(f func()) {
	a.mu.Lock()
	a.onAuth = f
	a.mu.Unlock()
}

// AuthFailed reports whether the credentials were rejected (latched).
func (a *Account) AuthFailed() bool {
	return a.guard.Latched()
}

// ClearAuthFailure lifts the latch so the next operation may try to log in.
func (a *Account) ClearAuthFailure() {
	a.guard.Clear()
	a.mu.Lock()
	a.authSeen = false
	a.mu.Unlock()
}

func (a *Account) latchAuth() {
	a.mu.Lock()
	was := a.authSeen
	a.authSeen = true
	cb := a.onAuth
	idle := a.idle
	a.idle = nil
	a.mu.Unlock()
	for _, c := range idle {
		closeAsync(c.c)
	}
	if !was && cb != nil {
		cb()
	}
}

// isAuthRejection decides whether a failed LOGIN means "bad credentials" (as
// opposed to a temporary server-side condition).
func isAuthRejection(err error) bool {
	var ie *imap.Error
	if !errors.As(err, &ie) || ie.Type != imap.StatusResponseTypeNo {
		return false
	}
	switch ie.Code {
	case imap.ResponseCodeUnavailable, imap.ResponseCodeServerBug, imap.ResponseCodeInUse,
		imap.ResponseCodeLimit, imap.ResponseCodeOverQuota:
		return false
	}
	return true
}

func (a *Account) dial(ctx context.Context) (*conn, error) {
	cl, err := a.dialClient(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &conn{c: cl, fresh: true}, nil
}

// dialClient connects, logs in and returns the client. It refuses to contact
// the server while the auth latch is set.
func (a *Account) dialClient(ctx context.Context, h *imapclient.UnilateralDataHandler) (*imapclient.Client, error) {
	if err := a.guard.admit(); err != nil {
		return nil, err
	}
	cr := a.Creds()
	if cr.IP == "" {
		return nil, errors.New("no pinned ip for mailbox")
	}
	port := cr.Port
	if port == 0 {
		port = 993
	}
	sn := cr.ServerName
	if sn == "" {
		sn = cr.Host
	}
	remote := net.JoinHostPort(cr.IP, strconv.Itoa(port))
	di := &dialInfo{sni: sn, remote: remote}
	a.mu.Lock()
	rl := a.relay
	a.mu.Unlock()
	var transport net.Conn
	if rl != nil {
		raw, err := dialRelay(ctx, rl)
		if err != nil {
			return nil, err
		}
		transport = raw
		di.tls, di.cipher = "via-node-relay", "-"
	} else {
		d := net.Dialer{Timeout: 30 * time.Second}
		raw, err := d.DialContext(ctx, "tcp", remote)
		if err != nil {
			return nil, err
		}
		tc := tls.Client(raw, a.tlsCfg(sn))
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("tls: %w", err)
		}
		st := tc.ConnectionState()
		di.tls, di.cipher = tls.VersionName(st.Version), tls.CipherSuiteName(st.CipherSuite)
		transport = tc
	}
	gc := &greetConn{Conn: transport}
	cl := imapclient.New(gc, &imapclient.Options{
		WordDecoder:           &mime.WordDecoder{CharsetReader: charset.Reader},
		UnilateralDataHandler: h,
	})
	stop := context.AfterFunc(ctx, func() { _ = cl.Close() })
	defer stop()
	if err := cl.WaitGreeting(); err != nil {
		closeAsync(cl)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	di.greeting = gc.line()
	a.sendID(cl, cr, di)
	method, err := authenticate(cl, cr)
	if err != nil {
		closeAsync(cl)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		rejection := isAuthRejection(err)
		var strike int
		var latched bool
		if rejection {
			strike, latched = a.guard.rejectN()
		}
		a.logLoginFailure(cr, method, err, rejection, strike, latched, di)
		if rejection {
			if latched {
				a.latchAuth()
				return nil, ErrAuth
			}
			return nil, newLoginRefused(err)
		}
		return nil, err
	}
	a.guard.ok()
	a.logFirstSuccess(cr, method, di)
	return cl, nil
}

// authenticate logs in with SASL PLAIN when the server advertises it (some
// providers refuse the LOGIN command for credentials AUTHENTICATE accepts), and
// with LOGIN otherwise. Exactly one attempt is made: a refused AUTHENTICATE is
// not retried as LOGIN. Caps asks the server when the greeting carried none.
func authenticate(cl *imapclient.Client, cr Creds) (string, error) {
	caps := cl.Caps()
	if caps.Has(imap.AuthCap("PLAIN")) {
		// go-imap puts the PLAIN initial response inline whenever SASL-IR is
		// advertised. Dropping SASL-IR from the client's cached capabilities
		// (Caps returns the live map; nothing else is in flight before login)
		// makes it send "AUTHENTICATE PLAIN", wait for the "+" continuation and
		// answer it, the exchange imapflow uses and web.de accepts from the
		// production host.
		delete(caps, imap.CapSASLIR)
		return "AUTHENTICATE PLAIN (no SASL-IR)", cl.Authenticate(sasl.NewPlainClient("", cr.User, cr.Pass))
	}
	return "LOGIN", cl.Login(cr.User, cr.Pass).Wait()
}

// logLoginFailure writes one line with the server's reply to a failed login.
// Every string passes through Redact; the password and user name never appear.
func (a *Account) logLoginFailure(cr Creds, method string, err error, rejection bool, strike int, latched bool, di *dialInfo) {
	a.mu.Lock()
	logf := a.logf
	a.mu.Unlock()
	if logf == nil {
		return
	}
	var ie *imap.Error
	if errors.As(err, &ie) {
		logf("imap login rejected host=%s method=%q status=%s code=%q text=%q auth_rejection=%t strike=%d/%d latched=%t %s",
			cr.Host, method, cr.Redact(string(ie.Type)), cr.Redact(string(ie.Code)), cr.Redact(ie.Text),
			rejection, strike, a.guard.strikes, latched, di.describe(cr))
		return
	}
	logf("imap login error host=%s method=%q error=%q auth_rejection=%t %s", cr.Host, method, cr.Redact(err.Error()), rejection, di.describe(cr))
}

func (a *Account) acquire(ctx context.Context) (*conn, bool, error) {
	a.mu.Lock()
	for len(a.idle) > 0 {
		c := a.idle[len(a.idle)-1]
		a.idle = a.idle[:len(a.idle)-1]
		select {
		case <-c.c.Closed():
			continue
		default:
		}
		a.mu.Unlock()
		return c, true, nil
	}
	a.mu.Unlock()
	c, err := a.dial(ctx)
	return c, false, err
}

func (a *Account) release(c *conn, ok bool) {
	c.fresh = false
	if !ok {
		closeAsync(c.c)
		return
	}
	a.mu.Lock()
	if a.closed || a.guard.Latched() || len(a.idle) >= 2 {
		a.mu.Unlock()
		closeAsync(c.c)
		return
	}
	a.idle = append(a.idle, c)
	a.mu.Unlock()
}

// Verify opens a connection (login included) and parks it in the pool.
func (a *Account) Verify(ctx context.Context) error {
	c, _, err := a.acquire(ctx)
	if err != nil {
		return err
	}
	a.release(c, true)
	return nil
}

// with runs fn on a pooled connection. Errors are NOT retried here: the Node
// layer owns read retries (see below).
// fn runs in its own goroutine and ctx is enforced by watching it from the
// outside: when the deadline passes, the connection is closed and with
// returns ctx.Err() even if fn (a library call) is wedged. Callers must not
// read fn's outputs after an error.
func (a *Account) with(ctx context.Context, fn func(c *imapclient.Client) error) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		c, reused, err := a.acquire(ctx)
		if err != nil {
			return err
		}
		stop := context.AfterFunc(ctx, func() { closeAsync(c.c) })
		done := make(chan error, 1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					done <- errors.New("internal error in imap operation")
				}
			}()
			done <- fn(c.c)
		}()
		select {
		case err = <-done:
		case <-ctx.Done():
			err = ctx.Err()
		}
		stop()
		if ctx.Err() != nil {
			a.release(c, false)
			return ctx.Err()
		}
		var ie *imap.Error
		protocolOnly := err == nil || errors.As(err, &ie)
		a.release(c, protocolOnly)
		// No internal retry: reads are retried at exactly one layer (the Node tool wrapper, at most 2 retries,
		// docs/DESIGN_V2.md "Retries"), so a persistently failing fetch costs 1+2 upstream attempts, not more.
		_ = reused
		return err
	}
}

// ListFolders runs LIST "" "*".
func (a *Account) ListFolders(ctx context.Context) ([]Folder, error) {
	var out []Folder
	err := a.with(ctx, func(c *imapclient.Client) error {
		out = out[:0]
		items, err := c.List("", "*", nil).Collect()
		if err != nil {
			return err
		}
		for _, it := range items {
			f := Folder{Path: it.Mailbox, Flags: []string{}}
			if it.Delim != 0 {
				f.Delimiter = string(it.Delim)
			}
			for _, at := range it.Attrs {
				f.Flags = append(f.Flags, string(at))
			}
			out = append(out, f)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Status runs STATUS (UIDVALIDITY UIDNEXT MESSAGES).
func (a *Account) Status(ctx context.Context, folder string) (Status, error) {
	var st Status
	err := a.with(ctx, func(c *imapclient.Client) error {
		d, err := c.Status(folder, &imap.StatusOptions{NumMessages: true, UIDNext: true, UIDValidity: true}).Wait()
		if err != nil {
			return err
		}
		st = Status{UIDValidity: d.UIDValidity, UIDNext: uint32(d.UIDNext)}
		if d.NumMessages != nil {
			st.Messages = *d.NumMessages
		}
		return nil
	})
	if err != nil {
		return Status{}, err
	}
	return st, nil
}

// Selected is the state observed when a folder is examined.
type Selected struct {
	UIDValidity uint32
	UIDNext     uint32
	Messages    uint32
}

func examine(c *imapclient.Client, folder string) (Selected, error) {
	d, err := c.Select(folder, &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		return Selected{}, err
	}
	return Selected{UIDValidity: d.UIDValidity, UIDNext: uint32(d.UIDNext), Messages: d.NumMessages}, nil
}

func uidSetOf(uids []uint32) imap.UIDSet {
	var s imap.UIDSet
	for _, u := range uids {
		s.AddNum(imap.UID(u))
	}
	return s
}

func numsOf(s imap.NumSet) []uint32 {
	us, ok := s.(imap.UIDSet)
	if !ok {
		return nil
	}
	nums, _ := us.Nums()
	out := make([]uint32, len(nums))
	for i, n := range nums {
		out[i] = uint32(n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// searchOptions returns the RETURN (ALL) options only when the server can
// parse them (ESEARCH, RFC 4731, or IMAP4rev2). Without either a nil value
// makes go-imap send a plain UID SEARCH; the classic "* SEARCH n n n" reply
// then fills SearchData.All just the same.
func searchOptions(c *imapclient.Client) *imap.SearchOptions {
	caps := c.Caps()
	if caps.Has(imap.CapESearch) || caps.Has(imap.CapIMAP4rev2) {
		return &imap.SearchOptions{ReturnAll: true}
	}
	return nil
}

// SearchAll runs UID SEARCH ALL and reports the examined state.
func (a *Account) SearchAll(ctx context.Context, folder string) (Selected, []uint32, error) {
	var sel Selected
	var uids []uint32
	err := a.with(ctx, func(c *imapclient.Client) error {
		var err error
		if sel, err = examine(c, folder); err != nil {
			return err
		}
		d, err := c.UIDSearch(&imap.SearchCriteria{}, searchOptions(c)).Wait()
		if err != nil {
			return err
		}
		uids = numsOf(d.All)
		return nil
	})
	if err != nil {
		return Selected{}, nil, err
	}
	return sel, uids, nil
}

// SearchText runs UID SEARCH TEXT <text>.
func (a *Account) SearchText(ctx context.Context, folder, text string) (Selected, []uint32, error) {
	var sel Selected
	var uids []uint32
	err := a.with(ctx, func(c *imapclient.Client) error {
		var err error
		if sel, err = examine(c, folder); err != nil {
			return err
		}
		d, err := c.UIDSearch(&imap.SearchCriteria{Text: []string{text}}, searchOptions(c)).Wait()
		if err != nil {
			return err
		}
		uids = numsOf(d.All)
		return nil
	})
	if err != nil {
		return Selected{}, nil, err
	}
	return sel, uids, nil
}

// FetchHeaders runs UID FETCH <set> (UID FLAGS ENVELOPE RFC822.SIZE INTERNALDATE).
// A nil uids slice with from>0 fetches "from:*" and filters out UIDs below from.
func (a *Account) FetchHeaders(ctx context.Context, folder string, uids []uint32, from uint32) (Selected, []Header, error) {
	var sel Selected
	var out []Header
	err := a.with(ctx, func(c *imapclient.Client) error {
		var err error
		out = out[:0]
		if sel, err = examine(c, folder); err != nil {
			return err
		}
		var set imap.UIDSet
		if uids != nil {
			if len(uids) == 0 {
				return nil
			}
			set = uidSetOf(uids)
		} else {
			set.AddRange(imap.UID(from), 0)
		}
		msgs, err := c.Fetch(set, &imap.FetchOptions{
			UID: true, Flags: true, Envelope: true, RFC822Size: true, InternalDate: true,
		}).Collect()
		if err != nil {
			return err
		}
		for _, m := range msgs {
			if uids == nil && uint32(m.UID) < from {
				continue // "n:*" always returns the last message
			}
			out = append(out, headerOf(m))
		}
		return nil
	})
	if err != nil {
		return Selected{}, nil, err
	}
	return sel, out, nil
}

func headerOf(m *imapclient.FetchMessageBuffer) Header {
	h := Header{
		UID:          uint32(m.UID),
		Flags:        ParseFlags(m.Flags),
		InternalDate: m.InternalDate,
		Size:         uint32(m.RFC822Size),
	}
	if e := m.Envelope; e != nil {
		h.Subject = e.Subject
		h.Date = e.Date
		h.MessageID = e.MessageID
		if h.MessageID != "" && !strings.HasPrefix(h.MessageID, "<") {
			h.MessageID = "<" + h.MessageID + ">" // go-imap strips the angle brackets
		}
		h.From = addrs(e.From)
		h.To = addrs(e.To)
		h.Cc = addrs(e.Cc)
	}
	return h
}

func addrs(in []imap.Address) []Addr {
	if len(in) == 0 {
		return nil
	}
	out := make([]Addr, 0, len(in))
	for _, a := range in {
		ad := a.Addr()
		if ad == "" && a.Name == "" {
			continue
		}
		out = append(out, Addr{Name: a.Name, Address: ad})
	}
	return out
}

// FetchFlags runs UID FETCH <uids> (FLAGS).
func (a *Account) FetchFlags(ctx context.Context, folder string, uids []uint32) (Selected, map[uint32]Flags, error) {
	var sel Selected
	out := make(map[uint32]Flags, len(uids))
	err := a.with(ctx, func(c *imapclient.Client) error {
		var err error
		if sel, err = examine(c, folder); err != nil {
			return err
		}
		if len(uids) == 0 {
			return nil
		}
		msgs, err := c.Fetch(uidSetOf(uids), &imap.FetchOptions{UID: true, Flags: true}).Collect()
		if err != nil {
			return err
		}
		for _, m := range msgs {
			out[uint32(m.UID)] = ParseFlags(m.Flags)
		}
		return nil
	})
	if err != nil {
		return Selected{}, nil, err
	}
	return sel, out, nil
}

// RawBody is a (possibly truncated) raw RFC 5322 message.
type RawBody struct {
	Selected  Selected
	Bytes     []byte
	Size      int64
	Truncated bool
	Found     bool
	// Structure is the message's BODYSTRUCTURE (nil if the server sent none).
	Structure imap.BodyStructure
}

// FetchRaw runs UID FETCH uid (RFC822.SIZE BODYSTRUCTURE BODY.PEEK[]<0.max>).
func (a *Account) FetchRaw(ctx context.Context, folder string, uid uint32, max int64) (RawBody, error) {
	var rb RawBody
	err := a.with(ctx, func(c *imapclient.Client) error {
		var err error
		rb = RawBody{}
		if rb.Selected, err = examine(c, folder); err != nil {
			return err
		}
		sec := &imap.FetchItemBodySection{Peek: true}
		if max > 0 {
			sec.Partial = &imap.SectionPartial{Offset: 0, Size: max}
		}
		msgs, err := c.Fetch(imap.UIDSetNum(imap.UID(uid)), &imap.FetchOptions{
			UID: true, RFC822Size: true, BodySection: []*imap.FetchItemBodySection{sec},
			BodyStructure: &imap.FetchItemBodyStructure{Extended: true},
		}).Collect()
		if err != nil {
			return err
		}
		for _, m := range msgs {
			if uint32(m.UID) != uid {
				continue
			}
			rb.Found = true
			rb.Size = m.RFC822Size
			rb.Structure = m.BodyStructure
			if len(m.BodySection) > 0 {
				rb.Bytes = m.BodySection[0].Bytes
			}
			rb.Truncated = max > 0 && rb.Size > int64(len(rb.Bytes))
		}
		return nil
	})
	if err != nil {
		return RawBody{}, err
	}
	return rb, nil
}

// RawPart is one (possibly truncated) MIME part, still transfer-encoded.
type RawPart struct {
	Selected  Selected
	Structure imap.BodyStructure
	Bytes     []byte
	Found     bool
}

// FetchPart runs UID FETCH uid (BODYSTRUCTURE BODY.PEEK[part]<0.max>). The
// part bytes are returned as stored on the server (transfer-encoded).
func (a *Account) FetchPart(ctx context.Context, folder string, uid uint32, part []int, max int64) (RawPart, error) {
	var rp RawPart
	err := a.with(ctx, func(c *imapclient.Client) error {
		var err error
		rp = RawPart{}
		if rp.Selected, err = examine(c, folder); err != nil {
			return err
		}
		sec := &imap.FetchItemBodySection{Peek: true, Part: part}
		if max > 0 {
			sec.Partial = &imap.SectionPartial{Offset: 0, Size: max}
		}
		msgs, err := c.Fetch(imap.UIDSetNum(imap.UID(uid)), &imap.FetchOptions{
			UID: true, BodySection: []*imap.FetchItemBodySection{sec},
			BodyStructure: &imap.FetchItemBodyStructure{Extended: true},
		}).Collect()
		if err != nil {
			return err
		}
		for _, m := range msgs {
			if uint32(m.UID) != uid {
				continue
			}
			rp.Found = true
			rp.Structure = m.BodyStructure
			if len(m.BodySection) > 0 {
				rp.Bytes = m.BodySection[0].Bytes
			}
		}
		return nil
	})
	if err != nil {
		return RawPart{}, err
	}
	return rp, nil
}

// RawHeader is the (possibly truncated) RFC 5322 header block of one message.
type RawHeader struct {
	Selected  Selected
	Bytes     []byte
	Found     bool
	Truncated bool
}

// FetchHeaderBlock runs UID FETCH uid (BODY.PEEK[HEADER]<0.max>). Nothing else
// is requested: no structure, no size, no flags.
func (a *Account) FetchHeaderBlock(ctx context.Context, folder string, uid uint32, max int64) (RawHeader, error) {
	var rh RawHeader
	err := a.with(ctx, func(c *imapclient.Client) error {
		var err error
		rh = RawHeader{}
		if rh.Selected, err = examine(c, folder); err != nil {
			return err
		}
		sec := &imap.FetchItemBodySection{Peek: true, Specifier: imap.PartSpecifierHeader}
		if max > 0 {
			sec.Partial = &imap.SectionPartial{Offset: 0, Size: max}
		}
		msgs, err := c.Fetch(imap.UIDSetNum(imap.UID(uid)), &imap.FetchOptions{
			UID: true, BodySection: []*imap.FetchItemBodySection{sec},
		}).Collect()
		if err != nil {
			return err
		}
		for _, m := range msgs {
			if uint32(m.UID) != uid {
				continue
			}
			rh.Found = true
			if len(m.BodySection) > 0 {
				rh.Bytes = m.BodySection[0].Bytes
			}
			rh.Truncated = max > 0 && int64(len(rh.Bytes)) >= max
		}
		return nil
	})
	if err != nil {
		return RawHeader{}, err
	}
	return rh, nil
}

// clientID is what the sidecar tells servers about itself: nothing about the
// user, the mailbox or the host it connects to.
var clientID = &imap.IDData{Name: "imap2mcp", Version: "1", Vendor: "imap2mcp"}

// dialInfo collects what is worth knowing about one connection attempt when a
// login is refused.
type dialInfo struct {
	tls, cipher, sni, remote string
	idSent                   bool
	serverID                 string
	greeting                 string
}

func (d *dialInfo) describe(cr Creds) string {
	return fmt.Sprintf("tls=%s cipher=%s sni=%s remote=%s id_sent=%t server_id=%q greeting=%q",
		d.tls, d.cipher, d.sni, d.remote, d.idSent, cr.Redact(d.serverID), cr.Redact(d.greeting))
}

// sendID sends the IMAP ID command before login when the server advertises it
// (some providers treat anonymous clients from data centres with suspicion).
// A failure is logged and never blocks the login.
func (a *Account) sendID(cl *imapclient.Client, cr Creds, di *dialInfo) {
	a.mu.Lock()
	off, logf := a.noID, a.logf
	a.mu.Unlock()
	if off || !cl.Caps().Has(imap.CapID) {
		return
	}
	di.idSent = true
	got, err := cl.ID(clientID).Wait()
	if err != nil {
		if logf != nil {
			logf("imap ID failed host=%s error=%q", cr.Host, cr.Redact(err.Error()))
		}
		return
	}
	if got != nil {
		di.serverID = fmt.Sprintf("name=%s vendor=%s version=%s", got.Name, got.Vendor, got.Version)
	}
}

// logFirstSuccess logs once per Account what a working login looked like.
func (a *Account) logFirstSuccess(cr Creds, method string, di *dialInfo) {
	a.mu.Lock()
	logf, done := a.logf, a.okLogged
	a.okLogged = true
	a.mu.Unlock()
	if logf == nil || done {
		return
	}
	logf("imap login ok host=%s method=%q tls=%s id_sent=%t server_id=%q", cr.Host, method, di.tls, di.idSent, cr.Redact(di.serverID))
}

// greetConn remembers the server's first line (the greeting), which the IMAP
// client does not expose.
type greetConn struct {
	net.Conn
	mu   sync.Mutex
	buf  []byte
	done bool
}

func (g *greetConn) Read(p []byte) (int, error) {
	n, err := g.Conn.Read(p)
	g.mu.Lock()
	if !g.done && n > 0 {
		g.buf = append(g.buf, p[:n]...)
		if i := strings.IndexByte(string(g.buf), '\n'); i >= 0 || len(g.buf) > 512 {
			g.done = true
		}
	}
	g.mu.Unlock()
	return n, err
}

func (g *greetConn) line() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	l := string(g.buf)
	if i := strings.IndexByte(l, '\n'); i >= 0 {
		l = l[:i]
	}
	if len(l) > 300 {
		l = l[:300]
	}
	return strings.TrimSpace(l)
}
