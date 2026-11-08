// Package rpc implements the newline-delimited JSON-RPC 2.0 server on a Unix
// domain socket.
package rpc

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/imap2mcp/sidecar/internal/engine"
	"github.com/imap2mcp/sidecar/internal/imapx"
)

const (
	Version        = "1.0.0"
	maxLine        = 4 << 20
	maxInflight    = 64
	CodeParse      = -32700
	CodeInvalidReq = -32600
	CodeNoMethod   = -32601
)

// Config configures the server.
type Config struct {
	Socket         string
	Secret         string        // read from stdin by main; never logged
	RequestTimeout time.Duration // per request, default 30 s
	Logf           func(format string, args ...any)
}

// Server serves RPC requests for an engine.
type Server struct {
	cfg     Config
	eng     *engine.Engine
	secret  [sha256.Size]byte
	started time.Time

	ln       net.Listener
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	inflight chan struct{}
}

// New creates a server. The secret must be non-empty.
func New(cfg Config, eng *engine.Engine) (*Server, error) {
	if len(cfg.Secret) < 16 {
		return nil, errors.New("auth secret too short")
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 30 * time.Second
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	s := &Server{cfg: cfg, eng: eng, started: time.Now(), conns: map[net.Conn]struct{}{}, inflight: make(chan struct{}, maxInflight)}
	s.secret = sha256.Sum256([]byte(cfg.Secret))
	s.cfg.Secret = "" // keep only the digest
	return s, nil
}

// Listen creates the socket (directory 0700, socket 0600).
func (s *Server) Listen() error {
	dir := filepath.Dir(s.cfg.Socket)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if fi, err := os.Lstat(s.cfg.Socket); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("%s exists and is not a socket", s.cfg.Socket)
		}
		_ = os.Remove(s.cfg.Socket)
	}
	old := setUmask(0o077)
	ln, err := net.Listen("unix", s.cfg.Socket)
	setUmask(old)
	if err != nil {
		return err
	}
	if err := os.Chmod(s.cfg.Socket, 0o600); err != nil {
		_ = ln.Close()
		return err
	}
	s.ln = ln
	return nil
}

// Serve accepts connections until the listener is closed.
func (s *Server) Serve() error {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		s.mu.Lock()
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		go s.handleConn(c)
	}
}

// Close stops listening and drops all connections.
func (s *Server) Close() {
	if s.ln != nil {
		_ = s.ln.Close()
	}
	s.mu.Lock()
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	_ = os.Remove(s.cfg.Socket)
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

func (s *Server) authOK(given string) bool {
	h := sha256.Sum256([]byte(given))
	return subtle.ConstantTimeCompare(h[:], s.secret[:]) == 1
}

func (s *Server) handleConn(c net.Conn) {
	defer func() {
		_ = c.Close()
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
	}()
	var wmu sync.Mutex
	enc := json.NewEncoder(c)
	write := func(r response) {
		r.JSONRPC = "2.0"
		if len(r.ID) == 0 {
			r.ID = json.RawMessage("null")
		}
		wmu.Lock()
		defer wmu.Unlock()
		_ = c.SetWriteDeadline(time.Now().Add(30 * time.Second))
		_ = enc.Encode(r)
	}
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 64*1024), maxLine)
	var wg sync.WaitGroup
	defer wg.Wait()
	for sc.Scan() {
		line := append([]byte(nil), sc.Bytes()...)
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			write(response{Error: &rpcError{CodeParse, "parse error"}})
			continue
		}
		var p struct {
			Auth string `json:"auth"`
		}
		_ = json.Unmarshal(req.Params, &p)
		if !s.authOK(p.Auth) {
			write(response{ID: req.ID, Error: &rpcError{engine.CodeAuth, "unauthorized"}})
			return // close the connection
		}
		if req.JSONRPC != "2.0" || req.Method == "" {
			write(response{ID: req.ID, Error: &rpcError{CodeInvalidReq, "invalid request"}})
			continue
		}
		s.inflight <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-s.inflight }()
			write(s.dispatch(req))
		}()
	}
}

func (s *Server) dispatch(req request) (resp response) {
	resp.ID = req.ID
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.RequestTimeout)
	defer cancel()
	// The handler runs in its own goroutine and the deadline is enforced from
	// the outside: even a wedged upstream call cannot keep the caller waiting
	// past RequestTimeout (its context is cancelled and abandoned work ends
	// when its connection is closed).
	type outcome struct {
		res any
		err error
	}
	ch := make(chan outcome, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.cfg.Logf("panic in %s", req.Method) // value deliberately not logged (may contain params)
				ch <- outcome{err: &engine.Error{Code: engine.CodeUpstream, Msg: "internal error"}}
			}
		}()
		res, err := s.call(ctx, req.Method, req.Params)
		ch <- outcome{res, err}
	}()
	var res any
	var err error
	select {
	case o := <-ch:
		res, err = o.res, o.err
	case <-ctx.Done():
		err = ctx.Err()
	}
	if err != nil {
		var ee *engine.Error
		if errors.As(err, &ee) {
			resp.Error = &rpcError{ee.Code, ee.Msg}
		} else if errors.Is(err, errNoMethod) {
			resp.Error = &rpcError{CodeNoMethod, "method not found"}
		} else if errors.Is(err, context.DeadlineExceeded) {
			resp.Error = &rpcError{engine.CodeTimeout, "request timed out"}
		} else {
			resp.Error = &rpcError{engine.CodeInvalidParams, err.Error()}
		}
		return
	}
	resp.Result = res
	return
}

var errNoMethod = errors.New("method not found")

type addrJSON struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

// HeaderJSON is the wire form of a cached header.
type HeaderJSON struct {
	UID          uint32     `json:"uid"`
	UIDValidity  uint32     `json:"uidValidity"`
	Flags        []string   `json:"flags"`
	Subject      string     `json:"subject"`
	From         []addrJSON `json:"from"`
	To           []addrJSON `json:"to"`
	Cc           []addrJSON `json:"cc"`
	Date         string     `json:"date"`
	InternalDate string     `json:"internalDate"`
	MessageID    string     `json:"messageId"`
	Size         uint32     `json:"size"`
}

func addrsJSON(in []imapx.Addr) []addrJSON {
	out := make([]addrJSON, len(in))
	for i, a := range in {
		out[i] = addrJSON{a.Name, a.Address}
	}
	return out
}

func tsJSON(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func toJSON(h imapx.Header, uv uint32) HeaderJSON {
	d := h.Date
	if d.IsZero() {
		d = h.InternalDate
	}
	return HeaderJSON{
		UID: h.UID, UIDValidity: uv, Flags: h.Flags.Names(), Subject: h.Subject,
		From: addrsJSON(h.From), To: addrsJSON(h.To), Cc: addrsJSON(h.Cc),
		Date: tsJSON(d), InternalDate: tsJSON(h.InternalDate), MessageID: h.MessageID, Size: h.Size,
	}
}

func itemsJSON(hs []imapx.Header, uv uint32) []HeaderJSON {
	out := make([]HeaderJSON, len(hs))
	for i, h := range hs {
		out[i] = toJSON(h, uv)
	}
	return out
}

func parseParams(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		return errors.New("params required")
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return errors.New("invalid params")
	}
	return nil
}

type criteriaJSON struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Cc       string `json:"cc"`
	Subject  string `json:"subject"`
	Since    string `json:"since"`
	Before   string `json:"before"`
	Seen     *bool  `json:"seen"`
	Flagged  *bool  `json:"flagged"`
	Answered *bool  `json:"answered"`
	MinSize  *int64 `json:"minSize"`
	MaxSize  *int64 `json:"maxSize"`
}

func parseDate(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	for _, layout := range []string{"2006-01-02", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t, nil
		}
	}
	return nil, fmt.Errorf("invalid date %q", s)
}

func (c criteriaJSON) toCriteria() (engine.Criteria, error) {
	since, err := parseDate(c.Since)
	if err != nil {
		return engine.Criteria{}, err
	}
	before, err := parseDate(c.Before)
	if err != nil {
		return engine.Criteria{}, err
	}
	return engine.Criteria{From: c.From, To: c.To, Cc: c.Cc, Subject: c.Subject, Since: since, Before: before,
		Seen: c.Seen, Flagged: c.Flagged, Answered: c.Answered, MinSize: c.MinSize, MaxSize: c.MaxSize}, nil
}

func (s *Server) call(ctx context.Context, method string, raw json.RawMessage) (any, error) {
	switch method {
	case "ping":
		return map[string]any{"version": Version, "uptimeSecs": int64(time.Since(s.started).Seconds()), "rssBytes": RSSBytes()}, nil
	case "stats":
		return map[string]any{"mailboxes": s.eng.Stats(), "rssBytes": RSSBytes()}, nil
	case "open":
		var p struct {
			MailboxID  string `json:"mailboxId"`
			Host       string `json:"host"`
			IP         string `json:"ip"`
			Port       int    `json:"port"`
			ServerName string `json:"servername"`
			User       string `json:"user"`
			Pass       string `json:"pass"`
		}
		if err := parseParams(raw, &p); err != nil {
			return nil, err
		}
		if net.ParseIP(p.IP) == nil {
			return nil, &engine.Error{Code: engine.CodeInvalidParams, Msg: "ip must be an IP address"}
		}
		if err := s.eng.Open(ctx, p.MailboxID, imapx.Creds{Host: p.Host, IP: p.IP, Port: p.Port, ServerName: p.ServerName, User: p.User, Pass: p.Pass}); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, nil
	case "close":
		var p struct {
			MailboxID string `json:"mailboxId"`
		}
		if err := parseParams(raw, &p); err != nil {
			return nil, err
		}
		s.eng.Close(p.MailboxID)
		return map[string]any{"ok": true}, nil
	case "status":
		var p struct {
			MailboxID string `json:"mailboxId"`
		}
		if err := parseParams(raw, &p); err != nil {
			return nil, err
		}
		return s.eng.Status(p.MailboxID), nil
	case "retry":
		var p struct {
			MailboxID string `json:"mailboxId"`
		}
		if err := parseParams(raw, &p); err != nil {
			return nil, err
		}
		s.eng.Retry(p.MailboxID)
		return map[string]any{"ok": true}, nil
	case "invalidate":
		var p struct {
			MailboxID string `json:"mailboxId"`
			Folder    string `json:"folder"`
		}
		if err := parseParams(raw, &p); err != nil {
			return nil, err
		}
		if err := s.eng.Invalidate(p.MailboxID, p.Folder); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, nil
	case "listFolders":
		var p struct {
			MailboxID string `json:"mailboxId"`
		}
		if err := parseParams(raw, &p); err != nil {
			return nil, err
		}
		fs, err := s.eng.ListFolders(ctx, p.MailboxID)
		if err != nil {
			return nil, err
		}
		type f struct {
			Path      string   `json:"path"`
			Delimiter string   `json:"delimiter"`
			Flags     []string `json:"flags"`
		}
		out := make([]f, len(fs))
		for i, x := range fs {
			out[i] = f{x.Path, x.Delimiter, x.Flags}
		}
		return map[string]any{"folders": out}, nil
	case "sync":
		var p struct {
			MailboxID string `json:"mailboxId"`
			Folder    string `json:"folder"`
			Mode      string `json:"mode"`
		}
		if err := parseParams(raw, &p); err != nil {
			return nil, err
		}
		r, err := s.eng.Sync(ctx, p.MailboxID, p.Folder, p.Mode)
		if err != nil {
			return nil, err
		}
		return map[string]any{"uidValidity": r.UIDValidity, "uidNext": r.UIDNext, "count": r.Count, "fetched": r.Fetched,
			"expunged": r.Expunged, "flagChanges": r.FlagChanges, "reconciled": r.Reconciled,
			"durationMs": r.DurationMs, "reset": r.Reset}, nil
	case "list", "search":
		var p struct {
			MailboxID string        `json:"mailboxId"`
			Folder    string        `json:"folder"`
			Limit     int           `json:"limit"`
			BeforeUID uint32        `json:"beforeUid"`
			Criteria  *criteriaJSON `json:"criteria"`
		}
		if err := parseParams(raw, &p); err != nil {
			return nil, err
		}
		var pg engine.Page
		var err error
		if method == "list" {
			pg, err = s.eng.List(ctx, p.MailboxID, p.Folder, p.Limit, p.BeforeUID)
		} else {
			var cj criteriaJSON
			if p.Criteria != nil {
				cj = *p.Criteria
			}
			// strict criteria: unknown keys (e.g. a body "text") must not be ignored silently
			if err := strictCriteria(raw); err != nil {
				return nil, err
			}
			var crit engine.Criteria
			if crit, err = cj.toCriteria(); err != nil {
				return nil, err
			}
			pg, err = s.eng.Search(ctx, p.MailboxID, p.Folder, crit, p.Limit, p.BeforeUID)
		}
		if err != nil {
			return nil, err
		}
		res := map[string]any{"uidValidity": pg.UIDValidity, "items": itemsJSON(pg.Items, pg.UIDValidity)}
		if pg.NextBeforeUID != 0 {
			res["nextBeforeUid"] = pg.NextBeforeUID
		}
		return res, nil
	case "searchText":
		var p struct {
			MailboxID string `json:"mailboxId"`
			Folder    string `json:"folder"`
			Text      string `json:"text"`
			Limit     int    `json:"limit"`
		}
		if err := parseParams(raw, &p); err != nil {
			return nil, err
		}
		r, err := s.eng.SearchText(ctx, p.MailboxID, p.Folder, p.Text, p.Limit)
		if err != nil {
			return nil, err
		}
		return map[string]any{"uidValidity": r.UIDValidity, "uids": r.UIDs}, nil
	case "fetchHeaders":
		var p struct {
			MailboxID   string   `json:"mailboxId"`
			Folder      string   `json:"folder"`
			UIDValidity uint32   `json:"uidValidity"`
			UIDs        []uint32 `json:"uids"`
		}
		if err := parseParams(raw, &p); err != nil {
			return nil, err
		}
		hs, err := s.eng.FetchHeaders(ctx, p.MailboxID, p.Folder, p.UIDValidity, p.UIDs)
		if err != nil {
			return nil, err
		}
		return map[string]any{"items": itemsJSON(hs, p.UIDValidity)}, nil
	case "fetchBody":
		var p struct {
			MailboxID   string `json:"mailboxId"`
			Folder      string `json:"folder"`
			UIDValidity uint32 `json:"uidValidity"`
			UID         uint32 `json:"uid"`
			MaxBytes    int64  `json:"maxBytes"`
		}
		if err := parseParams(raw, &p); err != nil {
			return nil, err
		}
		b, err := s.eng.FetchBody(ctx, p.MailboxID, p.Folder, p.UIDValidity, p.UID, p.MaxBytes)
		if err != nil {
			return nil, err
		}
		res := map[string]any{"text": b.Text, "truncated": b.Truncated}
		if b.HTML != "" {
			res["html"] = b.HTML
		}
		return res, nil
	}
	return nil, errNoMethod
}

func strictCriteria(raw json.RawMessage) error {
	var outer struct {
		Criteria json.RawMessage `json:"criteria"`
	}
	if err := json.Unmarshal(raw, &outer); err != nil || len(outer.Criteria) == 0 || string(outer.Criteria) == "null" {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(string(outer.Criteria)))
	dec.DisallowUnknownFields()
	var c criteriaJSON
	if err := dec.Decode(&c); err != nil {
		return &engine.Error{Code: engine.CodeInvalidParams, Msg: "invalid criteria: " + err.Error()}
	}
	return nil
}

// RSSBytes returns the resident set size of this process.
func RSSBytes() int64 {
	if b, err := os.ReadFile("/proc/self/statm"); err == nil {
		f := strings.Fields(string(b))
		if len(f) >= 2 {
			if pages, err := strconv.ParseInt(f[1], 10, 64); err == nil {
				return pages * int64(os.Getpagesize())
			}
		}
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.Sys)
}
