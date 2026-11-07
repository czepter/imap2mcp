package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/imap2mcp/sidecar/internal/testimap"
)

const secret = "binary-test-secret-0123456789abcdef"

type proc struct {
	cmd   *exec.Cmd
	stdin interface{ Close() error }
	sock  string
}

func startBinary(t *testing.T, ca string, extraEnv ...string) (*proc, func(method string, params map[string]any) (json.RawMessage, error)) {
	t.Helper()
	bin, _ := filepath.Abs("../../bin/sidecar")
	if _, err := os.Stat(bin); err != nil {
		t.Skip("bin/sidecar not built (scripts/go.sh build -o bin/sidecar ./cmd/sidecar)")
	}
	dir, _ := os.MkdirTemp("", "sb")
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "x", "sidecar.sock")
	cmd := exec.Command(bin)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "SIDECAR_SOCKET=" + sock, "SIDECAR_EXTRA_CA_FILE=" + ca}, extraEnv...)
	in, _ := cmd.StdinPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(in, secret)
	t.Cleanup(func() { in.Close(); cmd.Process.Kill(); cmd.Wait() })
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	var mu sync.Mutex
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	r := bufio.NewReaderSize(conn, 1<<20)
	id := 0
	call := func(method string, params map[string]any) (json.RawMessage, error) {
		mu.Lock()
		defer mu.Unlock()
		id++
		params["auth"] = secret
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
		conn.Write(append(b, '\n'))
		line, err := r.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		var resp struct {
			Result json.RawMessage
			Error  *struct {
				Code    int
				Message string
			}
		}
		json.Unmarshal(line, &resp)
		if resp.Error != nil {
			return nil, fmt.Errorf("%d %s", resp.Error.Code, resp.Error.Message)
		}
		return resp.Result, nil
	}
	return &proc{cmd: cmd, stdin: in, sock: sock}, call
}

func open(t *testing.T, call func(string, map[string]any) (json.RawMessage, error), srv *testimap.Server) {
	t.Helper()
	if _, err := call("open", map[string]any{"mailboxId": "m", "host": "mail.example.test", "ip": srv.IP, "port": srv.Port,
		"servername": testimap.ServerName, "user": testimap.User, "pass": testimap.Pass}); err != nil {
		t.Fatal(err)
	}
}

// TestBinaryStdinHandshake runs the real binary: the secret is read from stdin,
// the socket is 0600, TLS trust comes from SIDECAR_EXTRA_CA_FILE.
func TestBinaryStdinHandshake(t *testing.T) {
	srv := testimap.New(t)
	srv.Append("INBOX", testimap.Msg(1, "hi", "a@b.example", "c@d.example", 100))
	p, call := startBinary(t, srv.CAFile)
	fi, err := os.Stat(p.sock)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket: %v %v", fi, err)
	}
	open(t, call, srv)
	res, err := call("sync", map[string]any{"mailboxId": "m", "folder": "INBOX"})
	if err != nil || !strings.Contains(string(res), `"count":1`) {
		t.Fatalf("%s %v", res, err)
	}
	// the secret must not be visible in argv or environment of the process
	cl, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", p.cmd.Process.Pid))
	env, _ := os.ReadFile(fmt.Sprintf("/proc/%d/environ", p.cmd.Process.Pid))
	if strings.Contains(string(cl), secret) || strings.Contains(string(env), secret) {
		t.Fatal("secret visible in argv/environ")
	}
	// stdin EOF (parent death) makes the sidecar exit and remove the socket
	p.stdin.Close()
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("sidecar did not exit on stdin EOF")
	}
}

func TestBinaryRejectsMissingSecret(t *testing.T) {
	bin, _ := filepath.Abs("../../bin/sidecar")
	if _, err := os.Stat(bin); err != nil {
		t.Skip("bin/sidecar not built")
	}
	cmd := exec.Command(bin)
	cmd.Env = []string{"SIDECAR_SOCKET=" + filepath.Join(t.TempDir(), "s.sock")}
	cmd.Stdin = strings.NewReader("short\n")
	if err := cmd.Run(); err == nil {
		t.Fatal("started with a short secret")
	}
}

// TestRSS10k measures a 10,000 message mailbox against the real binary.
// Opt in with SIDECAR_BENCH=1 (see docs in the task report).
func TestRSS10k(t *testing.T) {
	if os.Getenv("SIDECAR_BENCH") == "" {
		t.Skip("set SIDECAR_BENCH=1")
	}
	srv := testimap.New(t)
	const n = 10000
	var to, cc []string
	for i := 0; i < 6; i++ {
		to = append(to, fmt.Sprintf("Recipient Number %d <recipient.number.%d@department%d.example-company.example>", i, i, i))
		cc = append(cc, fmt.Sprintf("Copy Person %d <copy.person.%d@other%d.example-company.example>", i, i, i))
	}
	for i := 1; i <= n; i++ {
		subj := fmt.Sprintf("Re: Quarterly planning review %d - %s", i, strings.Repeat("agenda item discussion ", 12))
		raw := []byte(fmt.Sprintf("From: Sender Name %d <sender%d@some-long-company-domain.example>\r\nTo: %s\r\nCc: %s\r\nSubject: %s\r\nMessage-ID: <%d.%s@mail.some-long-company-domain.example>\r\nDate: %s\r\n\r\nbody %d\r\n",
			i, i, strings.Join(to, ", "), strings.Join(cc, ", "), subj, i, strings.Repeat("abcdef", 6),
			time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(i)*time.Minute).Format(time.RFC1123Z), i))
		srv.Append("INBOX", raw)
	}
	p, call := startBinary(t, srv.CAFile)
	open(t, call, srv)
	rss := func() int64 {
		res, _ := call("ping", map[string]any{})
		var pr struct{ RssBytes int64 }
		json.Unmarshal(res, &pr)
		return pr.RssBytes
	}
	before := rss()
	t0 := time.Now()
	res, err := call("sync", map[string]any{"mailboxId": "m", "folder": "INBOX"})
	if err != nil {
		t.Fatal(err)
	}
	cold := time.Since(t0)
	var items []time.Duration
	for i := 0; i < 100; i++ {
		s := time.Now()
		call("search", map[string]any{"mailboxId": "m", "folder": "INBOX", "limit": 100, "criteria": map[string]any{"subject": "planning review 99"}})
		call("list", map[string]any{"mailboxId": "m", "folder": "INBOX", "limit": 100})
		items = append(items, time.Since(s))
	}
	sort.Slice(items, func(i, j int) bool { return items[i] < items[j] })
	after := rss()
	hdr, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", p.cmd.Process.Pid))
	var hwm string
	for _, l := range strings.Split(string(hdr), "\n") {
		if strings.HasPrefix(l, "VmHWM") {
			hwm = l
		}
	}
	t.Logf("10k messages: cold sync %v (%s)", cold, res)
	t.Logf("RSS before open-sync=%.1f MiB, after sync+200 queries=%.1f MiB, %s", float64(before)/1048576, float64(after)/1048576, hwm)
	t.Logf("warm search+list (2 calls) p50=%v p95=%v max=%v", items[50], items[95], items[99])
}
