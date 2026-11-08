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
// the same server (a password change alone does not change the identity).
func (c Creds) SameEndpoint(o Creds) bool {
	return c.Host == o.Host && c.IP == o.IP && c.Port == o.Port && c.User == o.User
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

	mu         sync.Mutex
	idle       []*conn
	closed     bool
	authFailed bool   // latched: the server rejected the credentials; no dial happens until ClearAuthFailure
	onAuth     func() // called (once per latch) when authFailed is set
}

type conn struct {
	c *imapclient.Client
	// fresh is true until the first operation completes.
	fresh bool
}

// NewAccount creates an account pool. tlsCfg must return a validating config.
func NewAccount(creds Creds, tlsCfg func(serverName string) *tls.Config) *Account {
	return &Account{creds: creds, tlsCfg: tlsCfg}
}

// Creds returns the account credentials (in-memory copy).
func (a *Account) Creds() Creds { return a.creds }

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
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.authFailed
}

// ClearAuthFailure lifts the latch so the next operation may try to log in.
func (a *Account) ClearAuthFailure() {
	a.mu.Lock()
	a.authFailed = false
	a.mu.Unlock()
}

func (a *Account) latchAuth() {
	a.mu.Lock()
	was := a.authFailed
	a.authFailed = true
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
	if a.AuthFailed() {
		return nil, ErrAuth
	}
	cr := a.creds
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
	d := net.Dialer{Timeout: 30 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(cr.IP, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, a.tlsCfg(sn))
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("tls: %w", err)
	}
	cl := imapclient.New(tc, &imapclient.Options{
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
	if err := cl.Login(cr.User, cr.Pass).Wait(); err != nil {
		closeAsync(cl)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if isAuthRejection(err) {
			a.latchAuth()
			return nil, ErrAuth
		}
		return nil, err
	}
	return cl, nil
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
	if a.closed || a.authFailed || len(a.idle) >= 2 {
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

// SearchAll runs UID SEARCH ALL and reports the examined state.
func (a *Account) SearchAll(ctx context.Context, folder string) (Selected, []uint32, error) {
	var sel Selected
	var uids []uint32
	err := a.with(ctx, func(c *imapclient.Client) error {
		var err error
		if sel, err = examine(c, folder); err != nil {
			return err
		}
		d, err := c.UIDSearch(&imap.SearchCriteria{}, &imap.SearchOptions{ReturnAll: true}).Wait()
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
		d, err := c.UIDSearch(&imap.SearchCriteria{Text: []string{text}}, &imap.SearchOptions{ReturnAll: true}).Wait()
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
}

// FetchRaw runs UID FETCH uid (RFC822.SIZE BODY.PEEK[]<0.max>).
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
