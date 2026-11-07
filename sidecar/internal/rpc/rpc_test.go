package rpc_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/imap2mcp/sidecar/internal/engine"
	"github.com/imap2mcp/sidecar/internal/rpc"
	"github.com/imap2mcp/sidecar/internal/testimap"
)

const secret = "0123456789abcdef0123456789abcdef-test-secret"

type harness struct {
	t    *testing.T
	srv  *testimap.Server
	sock string
	logs *bytes.Buffer
	s    *rpc.Server
}

func newHarness(t *testing.T, timeout time.Duration) *harness {
	t.Helper()
	srv := testimap.New(t)
	dir, err := os.MkdirTemp("", "sc") // short path: unix socket limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d", "sidecar.sock")
	logs := &bytes.Buffer{}
	var logMu = make(chan struct{}, 1)
	logf := func(f string, a ...any) {
		logMu <- struct{}{}
		defer func() { <-logMu }()
		logs.WriteString(strings.TrimSpace(strings.ReplaceAll(f, "%v", "?")) + "\n")
	}
	eng := engine.New(engine.Options{
		TLS: func(sn string) *tls.Config {
			return &tls.Config{RootCAs: srv.CAPool, ServerName: sn, MinVersion: tls.VersionTLS12}
		},
		AutoSyncEvery: time.Hour, ReconcileEvery: time.Hour, Logf: logf,
	})
	s, err := rpc.New(rpc.Config{Socket: sock, Secret: secret, RequestTimeout: timeout, Logf: logf}, eng)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	go s.Serve()
	t.Cleanup(func() { s.Close(); eng.Shutdown() })
	return &harness{t: t, srv: srv, sock: sock, logs: logs, s: s}
}

type rpcClient struct {
	c  net.Conn
	r  *bufio.Reader
	id int
}

func (h *harness) dial() *rpcClient {
	c, err := net.Dial("unix", h.sock)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { c.Close() })
	return &rpcClient{c: c, r: bufio.NewReader(c)}
}

type resp struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (c *rpcClient) call(method string, params map[string]any) resp {
	if params == nil {
		params = map[string]any{}
	}
	if _, ok := params["auth"]; !ok {
		params["auth"] = secret
	}
	c.id++
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.id, "method": method, "params": params})
	c.c.Write(append(b, '\n'))
	_ = c.c.SetReadDeadline(time.Now().Add(20 * time.Second))
	line, err := c.r.ReadBytes('\n')
	if err != nil {
		return resp{Error: &struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}{Code: -1, Message: "read: " + err.Error()}}
	}
	var r resp
	json.Unmarshal(line, &r)
	return r
}

func (h *harness) open(c *rpcClient, id string) resp {
	return c.call("open", map[string]any{"mailboxId": id, "host": "mail.example.test", "ip": h.srv.IP, "port": h.srv.Port,
		"servername": testimap.ServerName, "user": testimap.User, "pass": testimap.Pass})
}

func TestSocketPermissions(t *testing.T) {
	h := newHarness(t, 0)
	fi, err := os.Stat(h.sock)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket mode %v", fi.Mode())
	}
	di, _ := os.Stat(filepath.Dir(h.sock))
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", di.Mode().Perm())
	}
}

func TestAuthRejectionClosesConnection(t *testing.T) {
	h := newHarness(t, 0)
	for name, params := range map[string]map[string]any{
		"wrong":   {"auth": "nope"},
		"missing": {"auth": ""},
		"prefix":  {"auth": secret[:len(secret)-1]},
		"suffix":  {"auth": secret + "x"},
	} {
		c := h.dial()
		r := c.call("ping", params)
		if r.Error == nil || r.Error.Code != engine.CodeAuth {
			t.Fatalf("%s: want -32001, got %+v", name, r)
		}
		// connection must be closed by the server
		_ = c.c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.r.ReadByte(); err == nil {
			t.Fatalf("%s: connection still open after auth failure", name)
		}
	}
	// no params at all
	c := h.dial()
	c.c.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n"))
	line, _ := c.r.ReadBytes('\n')
	if !strings.Contains(string(line), "-32001") {
		t.Fatalf("no-params ping not rejected: %s", line)
	}
	// good auth still works afterwards
	good := h.dial()
	if r := good.call("ping", nil); r.Error != nil {
		t.Fatalf("%+v", r)
	}
}

func TestPingStatsAndUnknownMailbox(t *testing.T) {
	h := newHarness(t, 0)
	c := h.dial()
	r := c.call("ping", nil)
	var p struct {
		Version  string `json:"version"`
		RSSBytes int64  `json:"rssBytes"`
	}
	json.Unmarshal(r.Result, &p)
	if p.Version == "" || p.RSSBytes <= 0 {
		t.Fatalf("ping %s", r.Result)
	}
	r = c.call("list", map[string]any{"mailboxId": "ghost", "folder": "INBOX"})
	if r.Error == nil || r.Error.Code != engine.CodeUnknownMailbox {
		t.Fatalf("%+v", r)
	}
	if r = c.call("bogus", nil); r.Error == nil || r.Error.Code != -32601 {
		t.Fatalf("%+v", r)
	}
}

func TestEndToEndRPC(t *testing.T) {
	h := newHarness(t, 0)
	for i := 1; i <= 30; i++ {
		h.srv.Append("INBOX", testimap.Msg(i, "Hello "+strings.Repeat("x", i%3), "Bob <bob@example.org>", "alice@example.test", 200))
	}
	c := h.dial()
	if r := h.open(c, "m1"); r.Error != nil {
		t.Fatalf("%+v", r.Error)
	}
	var sync struct {
		UIDValidity uint32 `json:"uidValidity"`
		Count       int    `json:"count"`
		Fetched     int    `json:"fetched"`
		Reset       bool   `json:"reset"`
	}
	r := c.call("sync", map[string]any{"mailboxId": "m1", "folder": "INBOX", "mode": "auto"})
	json.Unmarshal(r.Result, &sync)
	if r.Error != nil || sync.Count != 30 || sync.Fetched != 30 || sync.UIDValidity == 0 {
		t.Fatalf("%+v %s", r.Error, r.Result)
	}
	r = c.call("list", map[string]any{"mailboxId": "m1", "folder": "INBOX", "limit": 5})
	var l struct {
		UIDValidity   uint32 `json:"uidValidity"`
		NextBeforeUID uint32 `json:"nextBeforeUid"`
		Items         []struct {
			UID         uint32   `json:"uid"`
			UIDValidity uint32   `json:"uidValidity"`
			Flags       []string `json:"flags"`
			From        []struct{ Name, Address string }
			MessageID   string `json:"messageId"`
			Date        string `json:"date"`
		}
	}
	json.Unmarshal(r.Result, &l)
	if len(l.Items) != 5 || l.Items[0].UID != 30 || l.NextBeforeUID != 26 || l.Items[0].UIDValidity != sync.UIDValidity ||
		l.Items[0].From[0].Address != "bob@example.org" || l.Items[0].Date == "" || l.Items[0].Flags == nil {
		t.Fatalf("%s", r.Result)
	}
	// search via cache
	r = c.call("search", map[string]any{"mailboxId": "m1", "folder": "INBOX", "limit": 100, "criteria": map[string]any{"from": "bob", "seen": false}})
	var s struct{ Items []json.RawMessage }
	json.Unmarshal(r.Result, &s)
	if r.Error != nil || len(s.Items) != 30 {
		t.Fatalf("%+v %s", r.Error, r.Result)
	}
	// unknown criteria (e.g. body text) are rejected, not ignored
	r = c.call("search", map[string]any{"mailboxId": "m1", "folder": "INBOX", "criteria": map[string]any{"text": "x"}})
	if r.Error == nil || r.Error.Code != engine.CodeInvalidParams {
		t.Fatalf("%+v", r)
	}
	// stale reference
	r = c.call("fetchHeaders", map[string]any{"mailboxId": "m1", "folder": "INBOX", "uidValidity": sync.UIDValidity + 1, "uids": []int{1}})
	if r.Error == nil || r.Error.Code != engine.CodeStaleRef {
		t.Fatalf("%+v", r)
	}
	r = c.call("fetchHeaders", map[string]any{"mailboxId": "m1", "folder": "INBOX", "uidValidity": sync.UIDValidity, "uids": []int{1, 2, 999}})
	json.Unmarshal(r.Result, &s)
	if r.Error != nil || len(s.Items) != 2 {
		t.Fatalf("%+v %s", r.Error, r.Result)
	}
	// body + searchText
	r = c.call("fetchBody", map[string]any{"mailboxId": "m1", "folder": "INBOX", "uidValidity": sync.UIDValidity, "uid": 3, "maxBytes": 4096})
	var b struct {
		Text      string
		Truncated bool
	}
	json.Unmarshal(r.Result, &b)
	if r.Error != nil || !strings.Contains(b.Text, "body of message 3") {
		t.Fatalf("%+v %s", r.Error, r.Result)
	}
	r = c.call("searchText", map[string]any{"mailboxId": "m1", "folder": "INBOX", "text": "message 12", "limit": 10})
	var st struct{ UIDs []uint32 }
	json.Unmarshal(r.Result, &st)
	if r.Error != nil || len(st.UIDs) == 0 {
		t.Fatalf("%+v %s", r.Error, r.Result)
	}
	// invalidate + stats + listFolders + close
	if r = c.call("invalidate", map[string]any{"mailboxId": "m1", "folder": "INBOX"}); r.Error != nil {
		t.Fatal(r.Error)
	}
	if r = c.call("stats", nil); r.Error != nil || !strings.Contains(string(r.Result), `"count":30`) {
		t.Fatalf("%s", r.Result)
	}
	if r = c.call("listFolders", map[string]any{"mailboxId": "m1"}); r.Error != nil || !strings.Contains(string(r.Result), "INBOX") {
		t.Fatalf("%s", r.Result)
	}
	c.call("close", map[string]any{"mailboxId": "m1"})
	r = c.call("list", map[string]any{"mailboxId": "m1", "folder": "INBOX"})
	if r.Error == nil || r.Error.Code != engine.CodeUnknownMailbox {
		t.Fatalf("%+v", r)
	}
}

func TestPipelinedRequestsOnOneConnection(t *testing.T) {
	h := newHarness(t, 0)
	h.srv.Append("INBOX", testimap.Msg(1, "x", "a@b.example", "c@d.example", 100))
	c := h.dial()
	h.open(c, "m1")
	c.call("sync", map[string]any{"mailboxId": "m1", "folder": "INBOX"})
	for i := 0; i < 40; i++ {
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1000 + i, "method": "list", "params": map[string]any{"auth": secret, "mailboxId": "m1", "folder": "INBOX"}})
		c.c.Write(append(b, '\n'))
	}
	seen := map[int]bool{}
	for i := 0; i < 40; i++ {
		line, err := c.r.ReadBytes('\n')
		if err != nil {
			t.Fatal(err)
		}
		var r resp
		json.Unmarshal(line, &r)
		if r.Error != nil {
			t.Fatalf("%+v", r.Error)
		}
		seen[r.ID] = true
	}
	if len(seen) != 40 {
		t.Fatalf("ids lost: %d", len(seen))
	}
}

func TestRequestTimeout(t *testing.T) {
	// A TCP server that accepts but never speaks TLS: the open must time out.
	h := newHarness(t, 400*time.Millisecond)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	var accepted atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c
		}
	}()
	c := h.dial()
	start := time.Now()
	r := c.call("open", map[string]any{"mailboxId": "slow", "host": "mail.example.test", "ip": "127.0.0.1", "port": ln.Addr().(*net.TCPAddr).Port,
		"servername": testimap.ServerName, "user": "u", "pass": "p"})
	if r.Error == nil || r.Error.Code != engine.CodeTimeout {
		t.Fatalf("want -32030, got %+v", r)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("timeout not enforced")
	}
}

func TestCredentialsMemoryOnlyAndRedacted(t *testing.T) {
	h := newHarness(t, 0)
	c := h.dial()
	badPass := "Wr0ng-HUNTER2-p4ssw0rd"
	r := c.call("open", map[string]any{"mailboxId": "m1", "host": "mail.example.test", "ip": h.srv.IP, "port": h.srv.Port,
		"servername": testimap.ServerName, "user": testimap.User, "pass": badPass})
	if r.Error == nil || r.Error.Code != engine.CodeUpstream {
		t.Fatalf("%+v", r)
	}
	if r2 := h.open(c, "m1"); r2.Error != nil {
		t.Fatal(r2.Error)
	}
	// errors that go through upstream must not carry the credentials
	r = c.call("sync", map[string]any{"mailboxId": "m1", "folder": "Does/Not/Exist"})
	if r.Error == nil {
		t.Fatal("expected error")
	}
	all := string(mustJSON(r)) + h.logs.String()
	for _, s := range []string{badPass, testimap.Pass, testimap.User} {
		if strings.Contains(all, s) {
			t.Fatalf("secret %q leaked into reply/logs: %s", s, all)
		}
	}
	// nothing is persisted: the data dir only holds the socket
	entries, _ := os.ReadDir(filepath.Dir(h.sock))
	if len(entries) != 1 || entries[0].Name() != "sidecar.sock" {
		t.Fatalf("unexpected files next to socket: %v", entries)
	}
	// Close forgets the mailbox entirely
	c.call("close", map[string]any{"mailboxId": "m1"})
	if r = c.call("sync", map[string]any{"mailboxId": "m1", "folder": "INBOX"}); r.Error == nil || r.Error.Code != engine.CodeUnknownMailbox {
		t.Fatalf("%+v", r)
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestShortSecretRejected(t *testing.T) {
	if _, err := rpc.New(rpc.Config{Socket: "x", Secret: "short"}, nil); err == nil {
		t.Fatal("short secret accepted")
	}
}
