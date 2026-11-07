package engine

import (
	"bytes"
	"context"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/emersion/go-message/mail"

	// registers charset decoders for text parts
	_ "github.com/emersion/go-message/charset"
)

const (
	defaultMaxBody = 1 << 20
	hardMaxBody    = 10 << 20
)

// Body is the decoded text/html of a message. Bodies are never cached.
type Body struct {
	Text      string
	HTML      string
	Truncated bool
}

// FetchBody fetches a message with BODY.PEEK and extracts text/plain and
// text/html. The uidValidity must match the folder's current one.
func (e *Engine) FetchBody(ctx context.Context, id, folder string, uv, uid uint32, maxBytes int64) (Body, error) {
	mb, err := e.mailbox(id)
	if err != nil {
		return Body{}, err
	}
	if folder == "" || uid == 0 {
		return Body{}, errf(CodeInvalidParams, "folder and uid required")
	}
	if maxBytes <= 0 {
		maxBytes = defaultMaxBody
	}
	if maxBytes > hardMaxBody {
		maxBytes = hardMaxBody
	}
	// Transfer encodings can inflate (quoted-printable up to 3x); fetch a
	// bounded multiple of what the caller wants.
	raw := maxBytes*4 + 64*1024
	acct, cr := mb.account()
	rb, err := acct.FetchRaw(ctx, folder, uid, raw)
	if err != nil {
		return Body{}, upstream(cr, err)
	}
	if rb.Selected.UIDValidity != uv {
		_ = e.Invalidate(id, folder)
		return Body{}, errStale("uidValidity changed")
	}
	if !rb.Found {
		_ = e.Invalidate(id, folder)
		return Body{}, errStale("message no longer exists")
	}
	b := parseBody(rb.Bytes, maxBytes)
	b.Truncated = b.Truncated || rb.Truncated
	return b, nil
}

func clip(s string, max int64) (string, bool) {
	if int64(len(s)) <= max {
		return s, false
	}
	s = s[:max]
	for !utf8.ValidString(s) && len(s) > 0 {
		s = s[:len(s)-1]
	}
	return s, true
}

// parseBody is best effort: truncated MIME input yields whatever parsed.
func parseBody(raw []byte, max int64) Body {
	var out Body
	mr, err := mail.CreateReader(bytes.NewReader(raw))
	if err != nil && mr == nil {
		return out
	}
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		h, ok := p.Header.(*mail.InlineHeader)
		if !ok {
			continue // attachment
		}
		ct, _, _ := h.ContentType()
		ct = strings.ToLower(ct)
		if ct != "text/plain" && ct != "text/html" {
			continue
		}
		if (ct == "text/plain" && out.Text != "") || (ct == "text/html" && out.HTML != "") {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(p.Body, max+1))
		s, cut := clip(string(data), max)
		out.Truncated = out.Truncated || cut
		if ct == "text/plain" {
			out.Text = s
		} else {
			out.HTML = s
		}
	}
	return out
}
