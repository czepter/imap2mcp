package engine_test

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/imap2mcp/sidecar/internal/engine"
	"github.com/imap2mcp/sidecar/internal/imapx"
	"github.com/imap2mcp/sidecar/internal/testimap"
)

func newEngine(t *testing.T, srv *testimap.Server, mod func(*engine.Options)) *engine.Engine {
	t.Helper()
	o := engine.Options{
		TLS: func(sn string) *tls.Config {
			return &tls.Config{RootCAs: srv.CAPool, ServerName: sn, MinVersion: tls.VersionTLS12}
		},
		ReconcileEvery: time.Hour, // tests drive reconcile explicitly
		AutoSyncEvery:  time.Hour,
	}
	if mod != nil {
		mod(&o)
	}
	e := engine.New(o)
	t.Cleanup(e.Shutdown)
	return e
}

func creds(srv *testimap.Server) imapx.Creds {
	return imapx.Creds{Host: "mail.example.test", IP: srv.IP, Port: srv.Port, ServerName: testimap.ServerName, User: testimap.User, Pass: testimap.Pass}
}

func open(t *testing.T, e *engine.Engine, srv *testimap.Server) {
	t.Helper()
	if err := e.Open(context.Background(), "mb1", creds(srv)); err != nil {
		t.Fatal(err)
	}
}

func seed(srv *testimap.Server, folder string, n int) []imap.UID {
	var uids []imap.UID
	for i := 1; i <= n; i++ {
		uids = append(uids, srv.Append(folder, testimap.Msg(i, "Subject number "+string(rune('A'+i%26)), "Bob <bob@example.org>", "alice@example.test", 300)))
	}
	return uids
}

func ctx() context.Context { return context.Background() }

func TestColdSyncAndList(t *testing.T) {
	srv := testimap.New(t)
	seed(srv, "INBOX", 25)
	e := newEngine(t, srv, nil)
	open(t, e, srv)
	r, err := e.Sync(ctx(), "mb1", "INBOX", "auto")
	if err != nil {
		t.Fatal(err)
	}
	if r.Count != 25 || r.Fetched != 25 || r.UIDValidity == 0 || r.UIDNext != 26 {
		t.Fatalf("unexpected sync result %+v", r)
	}
	pg, err := e.List(ctx(), "mb1", "INBOX", 10, 0)
	if err != nil || len(pg.Items) != 10 || pg.Items[0].UID != 25 || pg.NextBeforeUID != 16 {
		t.Fatalf("page %+v err %v", pg, err)
	}
	pg2, _ := e.List(ctx(), "mb1", "INBOX", 100, pg.NextBeforeUID)
	if len(pg2.Items) != 15 || pg2.Items[0].UID != 15 || pg2.NextBeforeUID != 0 {
		t.Fatalf("page2 len=%d next=%d", len(pg2.Items), pg2.NextBeforeUID)
	}
	h := pg.Items[0]
	if h.MessageID != "<m25@example.test>" || len(h.From) != 1 || h.From[0].Address != "bob@example.org" || h.From[0].Name != "Bob" || h.Size == 0 || h.Date.IsZero() {
		t.Fatalf("bad header %+v", h)
	}
}

func TestIncrementalArrivalFetchesOnlyNew(t *testing.T) {
	srv := testimap.New(t)
	seed(srv, "INBOX", 20)
	e := newEngine(t, srv, nil)
	open(t, e, srv)
	if _, err := e.Sync(ctx(), "mb1", "INBOX", "auto"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		srv.Append("INBOX", testimap.Msg(100+i, "Brand new invoice", "carol@example.org", "alice@example.test", 200))
	}
	r, err := e.Sync(ctx(), "mb1", "INBOX", "auto")
	if err != nil {
		t.Fatal(err)
	}
	if r.Fetched != 5 || r.Count != 25 || r.Reset || r.Reconciled || r.UIDNext != 26 {
		t.Fatalf("incremental result %+v", r)
	}
	pg, _ := e.Search(ctx(), "mb1", "INBOX", engine.Criteria{Subject: "invoice"}, 50, 0)
	if len(pg.Items) != 5 {
		t.Fatalf("expected 5 new messages searchable, got %d", len(pg.Items))
	}
	// nothing new: nothing fetched
	r, _ = e.Sync(ctx(), "mb1", "INBOX", "auto")
	if r.Fetched != 0 {
		t.Fatalf("refetched unchanged messages: %+v", r)
	}
}

func TestUIDValidityChangeDropsCache(t *testing.T) {
	srv := testimap.New(t)
	seed(srv, "INBOX", 10)
	e := newEngine(t, srv, nil)
	open(t, e, srv)
	r1, _ := e.Sync(ctx(), "mb1", "INBOX", "auto")

	srv.ResetFolder("INBOX")
	for i := 0; i < 3; i++ {
		srv.Append("INBOX", testimap.Msg(500+i, "after reset", "dave@example.org", "alice@example.test", 100))
	}
	r2, err := e.Sync(ctx(), "mb1", "INBOX", "auto")
	if err != nil {
		t.Fatal(err)
	}
	if !r2.Reset || r2.UIDValidity == r1.UIDValidity || r2.Count != 3 || r2.Fetched != 3 {
		t.Fatalf("reset result %+v (before %+v)", r2, r1)
	}
	// no stale mappings: old uid 5 is gone, old uidValidity is rejected
	_, err = e.FetchHeaders(ctx(), "mb1", "INBOX", r1.UIDValidity, []uint32{1})
	assertCode(t, err, engine.CodeStaleRef)
	hs, err := e.FetchHeaders(ctx(), "mb1", "INBOX", r2.UIDValidity, []uint32{1, 5})
	if err != nil || len(hs) != 1 || !strings.Contains(hs[0].Subject, "after reset") {
		t.Fatalf("hs=%+v err=%v", hs, err)
	}
	pg, _ := e.List(ctx(), "mb1", "INBOX", 50, 0)
	if len(pg.Items) != 3 || pg.UIDValidity != r2.UIDValidity {
		t.Fatalf("stale items survived: %d", len(pg.Items))
	}
}

func TestExpungeDetectedByReconcile(t *testing.T) {
	srv := testimap.New(t)
	uids := seed(srv, "INBOX", 12)
	e := newEngine(t, srv, nil)
	open(t, e, srv)
	e.Sync(ctx(), "mb1", "INBOX", "auto")
	srv.Expunge(t, "INBOX", uids[2], uids[7])

	r, err := e.Sync(ctx(), "mb1", "INBOX", "full")
	if err != nil {
		t.Fatal(err)
	}
	if r.Expunged != 2 || r.Count != 10 || !r.Reconciled || r.Fetched != 0 {
		t.Fatalf("expunge result %+v", r)
	}
	hs, _ := e.FetchHeaders(ctx(), "mb1", "INBOX", r.UIDValidity, []uint32{uint32(uids[2]), uint32(uids[3])})
	if len(hs) != 1 || hs[0].UID != uint32(uids[3]) {
		t.Fatalf("expunged uid still served: %+v", hs)
	}
}

func TestExpungeDetectedWithoutExplicitFull(t *testing.T) {
	// STATUS MESSAGES drift triggers reconcile even in auto mode
	srv := testimap.New(t)
	uids := seed(srv, "INBOX", 6)
	e := newEngine(t, srv, nil)
	open(t, e, srv)
	e.Sync(ctx(), "mb1", "INBOX", "auto")
	srv.Expunge(t, "INBOX", uids[0])
	r, _ := e.Sync(ctx(), "mb1", "INBOX", "auto")
	if r.Expunged != 1 || r.Count != 5 {
		t.Fatalf("%+v", r)
	}
}

func TestFlagChangeDetectedByReconcile(t *testing.T) {
	srv := testimap.New(t)
	uids := seed(srv, "INBOX", 8)
	e := newEngine(t, srv, nil)
	open(t, e, srv)
	e.Sync(ctx(), "mb1", "INBOX", "auto")

	seen := true
	pg, _ := e.Search(ctx(), "mb1", "INBOX", engine.Criteria{Seen: &seen}, 50, 0)
	if len(pg.Items) != 0 {
		t.Fatal("nothing should be seen yet")
	}
	srv.SetFlags(t, "INBOX", uids[4], imap.FlagSeen, imap.FlagFlagged)

	// UIDNEXT and message count are unchanged: only the periodic reconcile can notice
	r, _ := e.Sync(ctx(), "mb1", "INBOX", "auto")
	if r.FlagChanges != 0 || r.Reconciled {
		t.Fatalf("auto sync should not have reconciled: %+v", r)
	}
	r, err := e.Sync(ctx(), "mb1", "INBOX", "full")
	if err != nil || r.FlagChanges != 1 || r.Fetched != 0 {
		t.Fatalf("flag reconcile %+v err %v", r, err)
	}
	pg, _ = e.Search(ctx(), "mb1", "INBOX", engine.Criteria{Seen: &seen}, 50, 0)
	if len(pg.Items) != 1 || pg.Items[0].UID != uint32(uids[4]) {
		t.Fatalf("seen search %+v", pg.Items)
	}
	if got := strings.Join(pg.Items[0].Flags.Names(), ","); got != `\Seen,\Flagged` {
		t.Fatalf("flags %q", got)
	}
}

func TestInvalidateForcesReconcile(t *testing.T) {
	srv := testimap.New(t)
	uids := seed(srv, "INBOX", 4)
	e := newEngine(t, srv, func(o *engine.Options) { o.AutoSyncEvery = time.Millisecond })
	open(t, e, srv)
	e.Sync(ctx(), "mb1", "INBOX", "auto")
	srv.SetFlags(t, "INBOX", uids[0], imap.FlagFlagged)
	if err := e.Invalidate("mb1", "INBOX"); err != nil {
		t.Fatal(err)
	}
	flagged := true
	pg, err := e.Search(ctx(), "mb1", "INBOX", engine.Criteria{Flagged: &flagged}, 10, 0) // implicit sync
	if err != nil || len(pg.Items) != 1 {
		t.Fatalf("invalidate did not trigger reconcile: %+v %v", pg, err)
	}
}

func TestBackgroundReconciler(t *testing.T) {
	srv := testimap.New(t)
	uids := seed(srv, "INBOX", 5)
	e := newEngine(t, srv, func(o *engine.Options) { o.ReconcileEvery = 1 * time.Second })
	open(t, e, srv)
	e.Sync(ctx(), "mb1", "INBOX", "auto")
	c, cancel := context.WithCancel(ctx())
	defer cancel()
	go e.RunReconciler(c)
	srv.SetFlags(t, "INBOX", uids[1], imap.FlagAnswered)
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		ans := true
		pg, _ := e.Search(ctx(), "mb1", "INBOX", engine.Criteria{Answered: &ans}, 10, 0)
		if len(pg.Items) == 1 {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("background reconciler did not pick up the flag change")
}

func TestHeaderSearchFromCacheNoRemote(t *testing.T) {
	srv := testimap.New(t)
	srv.Append("INBOX", testimap.Msg(1, "Quarterly report", "Erin <erin@corp.example>", "alice@example.test", 100))
	srv.Append("INBOX", testimap.Msg(2, "Lunch?", "Frank <frank@other.example>", "alice@example.test", 100))
	e := newEngine(t, srv, nil)
	open(t, e, srv)
	e.Sync(ctx(), "mb1", "INBOX", "auto")
	pg, _ := e.Search(ctx(), "mb1", "INBOX", engine.Criteria{From: "CORP.example"}, 10, 0)
	if len(pg.Items) != 1 || pg.Items[0].Subject != "Quarterly report" {
		t.Fatalf("%+v", pg.Items)
	}
	pg, _ = e.Search(ctx(), "mb1", "INBOX", engine.Criteria{Subject: "lunch", From: "frank"}, 10, 0)
	if len(pg.Items) != 1 {
		t.Fatal("combined criteria")
	}
	min := int64(1 << 20)
	pg, _ = e.Search(ctx(), "mb1", "INBOX", engine.Criteria{MinSize: &min}, 10, 0)
	if len(pg.Items) != 0 {
		t.Fatal("size filter")
	}
	// body-only word is NOT found by header search...
	srv.Append("INBOX", []byte("From: g@x.example\r\nSubject: plain\r\n\r\nzebra-needle in body\r\n"))
	e.Invalidate("mb1", "INBOX")
	pg, _ = e.Search(ctx(), "mb1", "INBOX", engine.Criteria{Subject: "zebra-needle"}, 10, 0)
	if len(pg.Items) != 0 {
		t.Fatal("header search matched body")
	}
	// ...but is by remote text search
	tr, err := e.SearchText(ctx(), "mb1", "INBOX", "zebra-needle", 10)
	if err != nil || len(tr.UIDs) != 1 || tr.UIDs[0] != 3 {
		t.Fatalf("searchText %+v %v", tr, err)
	}
}

func TestFetchBodyAndStaleRef(t *testing.T) {
	srv := testimap.New(t)
	raw := "From: a@x.example\r\nSubject: s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=BB\r\n\r\n" +
		"--BB\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nhello plain\r\n--BB\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>hello html</p>\r\n--BB--\r\n"
	srv.Append("INBOX", []byte(raw))
	e := newEngine(t, srv, nil)
	open(t, e, srv)
	r, _ := e.Sync(ctx(), "mb1", "INBOX", "auto")
	b, err := e.FetchBody(ctx(), "mb1", "INBOX", r.UIDValidity, 1, 0)
	if err != nil || !strings.Contains(b.Text, "hello plain") || !strings.Contains(b.HTML, "hello html") || b.Truncated {
		t.Fatalf("body %+v err %v", b, err)
	}
	// BODY.PEEK: \Seen must not be set
	c := srv.Client(t)
	c.Select("INBOX", &imap.SelectOptions{ReadOnly: true}).Wait()
	msgs, _ := c.Fetch(imap.UIDSetNum(1), &imap.FetchOptions{UID: true, Flags: true}).Collect()
	for _, f := range msgs[0].Flags {
		if f == imap.FlagSeen {
			t.Fatal("fetchBody marked the message as seen")
		}
	}
	small, err := e.FetchBody(ctx(), "mb1", "INBOX", r.UIDValidity, 1, 5)
	if err != nil || !small.Truncated || len(small.Text) > 5 {
		t.Fatalf("maxBytes: %+v %v", small, err)
	}
	_, err = e.FetchBody(ctx(), "mb1", "INBOX", r.UIDValidity+7, 1, 0)
	assertCode(t, err, engine.CodeStaleRef)
	_, err = e.FetchBody(ctx(), "mb1", "INBOX", r.UIDValidity, 99, 0)
	assertCode(t, err, engine.CodeStaleRef)
}

func TestUnknownMailboxAndClose(t *testing.T) {
	srv := testimap.New(t)
	e := newEngine(t, srv, nil)
	_, err := e.Sync(ctx(), "nope", "INBOX", "auto")
	assertCode(t, err, engine.CodeUnknownMailbox)
	open(t, e, srv)
	e.Close("mb1")
	_, err = e.List(ctx(), "mb1", "INBOX", 1, 0)
	assertCode(t, err, engine.CodeUnknownMailbox)
}

func TestListFolders(t *testing.T) {
	srv := testimap.New(t, "Archive", "Archive/2024")
	e := newEngine(t, srv, nil)
	open(t, e, srv)
	fs, err := e.ListFolders(ctx(), "mb1")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range fs {
		got[f.Path] = true
		if f.Delimiter != "/" {
			t.Fatalf("delimiter %q", f.Delimiter)
		}
	}
	if !got["INBOX"] || !got["Archive"] || !got["Archive/2024"] {
		t.Fatalf("%v", got)
	}
}

func TestConcurrentSyncAndReads(t *testing.T) {
	srv := testimap.New(t)
	seed(srv, "INBOX", 200)
	e := newEngine(t, srv, func(o *engine.Options) { o.AutoSyncEvery = time.Millisecond })
	open(t, e, srv)
	done := make(chan error, 20)
	for i := 0; i < 20; i++ {
		go func(i int) {
			var err error
			switch i % 3 {
			case 0:
				_, err = e.Sync(ctx(), "mb1", "INBOX", "full")
			case 1:
				_, err = e.List(ctx(), "mb1", "INBOX", 50, 0)
			default:
				_, err = e.Search(ctx(), "mb1", "INBOX", engine.Criteria{Subject: "subject"}, 50, 0)
			}
			done <- err
		}(i)
	}
	for i := 0; i < 20; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	pg, _ := e.List(ctx(), "mb1", "INBOX", 500, 0)
	if len(pg.Items) != 200 {
		t.Fatalf("cache corrupted by concurrent sync: %d", len(pg.Items))
	}
}

func TestTLSValidationAndPinnedIP(t *testing.T) {
	srv := testimap.New(t)
	e := newEngine(t, srv, nil)
	// wrong servername => certificate validation must fail (no insecure fallback)
	cr := creds(srv)
	cr.ServerName = "evil.example.test"
	err := e.Open(ctx(), "mb1", cr)
	assertCode(t, err, engine.CodeUpstream)
	// no system roots / extra CA => unknown authority
	e2 := newEngine(t, srv, func(o *engine.Options) {
		o.TLS = func(sn string) *tls.Config { return &tls.Config{ServerName: sn, MinVersion: tls.VersionTLS12} }
	})
	assertCode(t, e2.Open(ctx(), "mb1", creds(srv)), engine.CodeUpstream)
	// ip is required: the sidecar never resolves host names itself
	cr = creds(srv)
	cr.IP = ""
	assertCode(t, e.Open(ctx(), "mb1", cr), engine.CodeInvalidParams)
}

func TestAuthFailureRedactedAndNotOpened(t *testing.T) {
	srv := testimap.New(t)
	e := newEngine(t, srv, nil)
	cr := creds(srv)
	cr.Pass = "wrong-password-HUNTER2"
	err := e.Open(ctx(), "mb1", cr)
	assertCode(t, err, engine.CodeUpstream)
	for _, secret := range []string{cr.Pass, testimap.User, testimap.Pass} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error leaks secret: %v", err)
		}
	}
	_, err = e.Sync(ctx(), "mb1", "INBOX", "auto")
	assertCode(t, err, engine.CodeUnknownMailbox)
}

func TestUpstreamErrorsAreRedacted(t *testing.T) {
	srv := testimap.New(t)
	e := newEngine(t, srv, nil)
	open(t, e, srv)
	_, err := e.Sync(ctx(), "mb1", "No/Such/Folder", "auto")
	assertCode(t, err, engine.CodeUpstream)
	if strings.Contains(err.Error(), testimap.Pass) || strings.Contains(err.Error(), testimap.User) {
		t.Fatalf("leak: %v", err)
	}
	var cr = creds(srv)
	if got := cr.Redact("LOGIN " + cr.User + " " + cr.Pass); strings.Contains(got, cr.Pass) || strings.Contains(got, cr.User) {
		t.Fatalf("Redact failed: %q", got)
	}
	if s := (imapx.Creds{User: "u", Pass: "p4ss"}); strings.Contains(s.String(), "p4ss") {
		t.Fatal("Creds.String leaks")
	}
}

func TestReopenKeepsCacheForSameAccount(t *testing.T) {
	srv := testimap.New(t)
	seed(srv, "INBOX", 7)
	e := newEngine(t, srv, nil)
	open(t, e, srv)
	e.Sync(ctx(), "mb1", "INBOX", "auto")
	open(t, e, srv) // idempotent
	r, _ := e.Sync(ctx(), "mb1", "INBOX", "auto")
	if r.Fetched != 0 || r.Count != 7 {
		t.Fatalf("cache lost on idempotent open: %+v", r)
	}
}

func assertCode(t *testing.T, err error, code int) {
	t.Helper()
	var ee *engine.Error
	if !errors.As(err, &ee) || ee.Code != code {
		t.Fatalf("want error code %d, got %v", code, err)
	}
}
