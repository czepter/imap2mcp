package engine_test

import (
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/imap2mcp/sidecar/internal/engine"
	"github.com/imap2mcp/sidecar/internal/testimap"
)

func TestFetchRawHeader(t *testing.T) {
	srv := testimap.New(t)
	raw := "From: a@x.example\r\nAuthentication-Results: mx.recv.example;\r\n\tspf=pass smtp.mailfrom=a@x.example;\r\n dkim=pass header.d=x.example\r\nReply-To: Help <help@evil.example>\r\nSubject: s\r\n\r\nSECRET-BODY-TEXT\r\n"
	srv.Append("INBOX", []byte(raw))
	e := newEngine(t, srv, nil)
	open(t, e, srv)
	r, _ := e.Sync(ctx(), "mb1", "INBOX", "auto")

	h, err := e.FetchRawHeader(ctx(), "mb1", "INBOX", r.UIDValidity, 1, 0)
	if err != nil || h.Truncated {
		t.Fatalf("header %+v err %v", h, err)
	}
	got := string(h.Data)
	for _, want := range []string{"From: a@x.example", "Authentication-Results: mx.recv.example;", "\tspf=pass", " dkim=pass header.d=x.example", "Reply-To: Help <help@evil.example>", "Subject: s"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %q", want, got)
		}
	}
	if strings.Contains(got, "SECRET-BODY-TEXT") {
		t.Fatalf("body text leaked into header block: %q", got)
	}

	// BODY.PEEK: \Seen must not be set
	c := srv.Client(t)
	c.Select("INBOX", &imap.SelectOptions{ReadOnly: true}).Wait()
	msgs, _ := c.Fetch(imap.UIDSetNum(1), &imap.FetchOptions{UID: true, Flags: true}).Collect()
	for _, f := range msgs[0].Flags {
		if f == imap.FlagSeen {
			t.Fatal("fetchRawHeader marked the message as seen")
		}
	}

	small, err := e.FetchRawHeader(ctx(), "mb1", "INBOX", r.UIDValidity, 1, 40)
	if err != nil || !small.Truncated || len(small.Data) > 40 || len(small.Data) == 0 {
		t.Fatalf("maxBytes: %d bytes truncated=%v err=%v", len(small.Data), small.Truncated, err)
	}
	// above the hard cap is clamped, and still works
	big, err := e.FetchRawHeader(ctx(), "mb1", "INBOX", r.UIDValidity, 1, 1<<40)
	if err != nil || big.Truncated || string(big.Data) != got {
		t.Fatalf("clamped: %+v %v", big, err)
	}

	_, err = e.FetchRawHeader(ctx(), "mb1", "INBOX", r.UIDValidity+7, 1, 0)
	assertCode(t, err, engine.CodeStaleRef)
	_, err = e.FetchRawHeader(ctx(), "mb1", "INBOX", r.UIDValidity, 99, 0)
	assertCode(t, err, engine.CodeStaleRef)
	_, err = e.FetchRawHeader(ctx(), "mb1", "INBOX", r.UIDValidity, 0, 0)
	assertCode(t, err, engine.CodeInvalidParams)
	_, err = e.FetchRawHeader(ctx(), "mb1", "", r.UIDValidity, 1, 0)
	assertCode(t, err, engine.CodeInvalidParams)
	_, err = e.FetchRawHeader(ctx(), "nope", "INBOX", r.UIDValidity, 1, 0)
	assertCode(t, err, engine.CodeUnknownMailbox)
}
