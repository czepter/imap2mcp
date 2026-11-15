package engine_test

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/imap2mcp/sidecar/internal/engine"
	"github.com/imap2mcp/sidecar/internal/testimap"
)

func wrap76(s string) string {
	var b strings.Builder
	for len(s) > 76 {
		b.WriteString(s[:76] + "\r\n")
		s = s[76:]
	}
	b.WriteString(s)
	return b.String()
}

func TestAttachments(t *testing.T) {
	pdf := bytes.Repeat([]byte("%PDF-1.4 binary\x00\x01\xff"), 400)
	raw := "From: a@x.example\r\nSubject: offer\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=MM\r\n\r\n" +
		"--MM\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nsee attached\r\n" +
		"--MM\r\nContent-Type: application/pdf; name=\"Angebot.pdf\"\r\nContent-Disposition: attachment; filename=\"=?utf-8?q?Angebot_M=C3=BCller.pdf?=\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		wrap76(base64.StdEncoding.EncodeToString(pdf)) + "\r\n" +
		"--MM\r\nContent-Type: text/csv; charset=utf-8\r\nContent-Disposition: attachment; filename=list.csv\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\na;b=3Dc\r\n" +
		"--MM--\r\n"
	srv := testimap.New(t)
	srv.Append("INBOX", []byte(raw))
	e := newEngine(t, srv, nil)
	open(t, e, srv)
	r, _ := e.Sync(ctx(), "mb1", "INBOX", "auto")

	b, err := e.FetchBody(ctx(), "mb1", "INBOX", r.UIDValidity, 1, 0)
	if err != nil || !strings.Contains(b.Text, "see attached") {
		t.Fatalf("body %+v err %v", b, err)
	}
	if len(b.Attachments) != 2 {
		t.Fatalf("attachments %+v", b.Attachments)
	}
	a := b.Attachments[0]
	if a.Part != "2" || a.Filename != "Angebot Müller.pdf" || a.ContentType != "application/pdf" || a.Disposition != "attachment" || a.Size < int64(len(pdf))-100 {
		t.Fatalf("pdf meta %+v", a)
	}

	got, err := e.FetchAttachment(ctx(), "mb1", "INBOX", r.UIDValidity, 1, "2", 0)
	if err != nil || got.NotFound || got.TooLarge || !bytes.Equal(got.Data, pdf) {
		t.Fatalf("pdf fetch: notFound=%v tooLarge=%v len=%d err=%v", got.NotFound, got.TooLarge, len(got.Data), err)
	}
	csv, err := e.FetchAttachment(ctx(), "mb1", "INBOX", r.UIDValidity, 1, "3", 0)
	if err != nil || string(csv.Data) != "a;b=c" || csv.Filename != "list.csv" {
		t.Fatalf("csv fetch %+v %v", csv, err)
	}
	// the text body is not an attachment
	body, err := e.FetchAttachment(ctx(), "mb1", "INBOX", r.UIDValidity, 1, "1", 0)
	if err != nil || !body.NotFound {
		t.Fatalf("body part must not be fetchable: %+v %v", body, err)
	}
	big, err := e.FetchAttachment(ctx(), "mb1", "INBOX", r.UIDValidity, 1, "2", 100)
	if err != nil || !big.TooLarge || big.Data != nil {
		t.Fatalf("limit: %+v %v", big, err)
	}
	_, err = e.FetchAttachment(ctx(), "mb1", "INBOX", r.UIDValidity, 1, "x", 0)
	assertCode(t, err, engine.CodeInvalidParams)
	_, err = e.FetchAttachment(ctx(), "mb1", "INBOX", r.UIDValidity+1, 1, "2", 0)
	assertCode(t, err, engine.CodeStaleRef)

	// BODY.PEEK: \Seen must not be set
	c := srv.Client(t)
	c.Select("INBOX", &imap.SelectOptions{ReadOnly: true}).Wait()
	msgs, _ := c.Fetch(imap.UIDSetNum(1), &imap.FetchOptions{UID: true, Flags: true}).Collect()
	for _, f := range msgs[0].Flags {
		if f == imap.FlagSeen {
			t.Fatal("fetchAttachment marked the message as seen")
		}
	}
}

func TestAttachmentsPlainMessage(t *testing.T) {
	srv := testimap.New(t)
	srv.Append("INBOX", []byte("From: g@x.example\r\nSubject: plain\r\n\r\njust text\r\n"))
	e := newEngine(t, srv, nil)
	open(t, e, srv)
	r, _ := e.Sync(ctx(), "mb1", "INBOX", "auto")
	b, err := e.FetchBody(ctx(), "mb1", "INBOX", r.UIDValidity, 1, 0)
	if err != nil || b.Attachments == nil || len(b.Attachments) != 0 {
		t.Fatalf("plain message: %+v %v", b, err)
	}
}
