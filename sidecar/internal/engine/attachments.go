package engine

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"mime"
	"mime/quotedprintable"
	"strconv"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-message/charset"
)

const (
	defaultMaxAttachment = 10 << 20
	hardMaxAttachment    = 25 << 20
)

// Attachment describes one attachment of a message (from BODYSTRUCTURE).
type Attachment struct {
	Part        string `json:"part"`
	Filename    string `json:"filename,omitempty"`
	ContentType string `json:"contentType"`
	Disposition string `json:"disposition,omitempty"`
	ContentID   string `json:"contentId,omitempty"`
	// Size is the approximate decoded size in bytes.
	Size int64 `json:"size"`
}

// AttachmentData is a decoded attachment. Data is nil when the part was not
// found (NotFound) or is larger than the requested limit (TooLarge).
type AttachmentData struct {
	Attachment
	Data     []byte
	NotFound bool
	TooLarge bool
}

var wordDecoder = &mime.WordDecoder{CharsetReader: charset.Reader}

func decodeWord(s string) string {
	if d, err := wordDecoder.DecodeHeader(s); err == nil {
		return d
	}
	return s
}

func partString(path []int) string {
	p := make([]string, len(path))
	for i, n := range path {
		p[i] = strconv.Itoa(n)
	}
	return strings.Join(p, ".")
}

func parsePart(s string) ([]int, bool) {
	if s == "" || len(s) > 64 {
		return nil, false
	}
	var out []int
	for _, x := range strings.Split(s, ".") {
		n, err := strconv.Atoi(x)
		if err != nil || n <= 0 || n > 10000 {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

func decodedSize(encoding string, size uint32) int64 {
	n := int64(size)
	if strings.EqualFold(encoding, "base64") {
		// 76 characters + CRLF per line, 4 characters encode 3 bytes.
		return n * 76 / 78 * 3 / 4
	}
	return n
}

// isAttachment reports whether a leaf part is an attachment rather than the
// readable body: anything marked as an attachment, anything carrying a file
// name, and any part that is neither text/plain nor text/html.
func isAttachment(p *imap.BodyStructureSinglePart) bool {
	if d := p.Disposition(); d != nil && strings.EqualFold(d.Value, "attachment") {
		return true
	}
	if p.Filename() != "" {
		return true
	}
	mt := p.MediaType()
	return mt != "text/plain" && mt != "text/html"
}

func attachmentOf(path []int, p *imap.BodyStructureSinglePart) Attachment {
	a := Attachment{
		Part:        partString(path),
		Filename:    decodeWord(p.Filename()),
		ContentType: p.MediaType(),
		ContentID:   strings.Trim(p.ID, "<>"),
		Size:        decodedSize(p.Encoding, p.Size),
	}
	if d := p.Disposition(); d != nil {
		a.Disposition = strings.ToLower(d.Value)
	}
	return a
}

// attachmentsOf lists the attachments of a body structure. A forwarded
// message (message/rfc822) counts as one attachment; its own parts are not
// listed.
func attachmentsOf(bs imap.BodyStructure) []Attachment {
	out := []Attachment{}
	if bs == nil {
		return out
	}
	bs.Walk(func(path []int, part imap.BodyStructure) bool {
		p, ok := part.(*imap.BodyStructureSinglePart)
		if !ok || !isAttachment(p) {
			return true
		}
		out = append(out, attachmentOf(path, p))
		return false
	})
	return out
}

func findAttachment(bs imap.BodyStructure, part string) (*imap.BodyStructureSinglePart, []int) {
	var found *imap.BodyStructureSinglePart
	var at []int
	if bs == nil {
		return nil, nil
	}
	bs.Walk(func(path []int, p imap.BodyStructure) bool {
		sp, ok := p.(*imap.BodyStructureSinglePart)
		if ok && found == nil && isAttachment(sp) && partString(path) == part {
			found, at = sp, append([]int(nil), path...)
		}
		return found == nil
	})
	return found, at
}

type stripSpace struct{ r io.Reader }

func (s stripSpace) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	j := 0
	for _, c := range p[:n] {
		if c != '\r' && c != '\n' && c != ' ' && c != '\t' {
			p[j] = c
			j++
		}
	}
	return j, err
}

// decodeTransfer undoes the Content-Transfer-Encoding of a part, reading at
// most max+1 decoded bytes.
func decodeTransfer(encoding string, raw []byte, max int64) ([]byte, error) {
	var r io.Reader
	switch strings.ToLower(encoding) {
	case "base64":
		r = base64.NewDecoder(base64.StdEncoding, stripSpace{bytes.NewReader(raw)})
	case "quoted-printable":
		r = quotedprintable.NewReader(bytes.NewReader(raw))
	default:
		r = bytes.NewReader(raw)
	}
	return io.ReadAll(io.LimitReader(r, max+1))
}

// FetchAttachment fetches one attachment part with BODY.PEEK and returns its
// decoded bytes. Only parts that attachmentsOf lists can be fetched. The
// uidValidity must match the folder's current one.
func (e *Engine) FetchAttachment(ctx context.Context, id, folder string, uv, uid uint32, part string, maxBytes int64) (AttachmentData, error) {
	mb, err := e.mailbox(id)
	if err != nil {
		return AttachmentData{}, err
	}
	path, ok := parsePart(part)
	if folder == "" || uid == 0 || !ok {
		return AttachmentData{}, errf(CodeInvalidParams, "folder, uid and a valid part required")
	}
	if maxBytes <= 0 {
		maxBytes = defaultMaxAttachment
	}
	if maxBytes > hardMaxAttachment {
		maxBytes = hardMaxAttachment
	}
	// quoted-printable can inflate up to 3x; base64 by 4/3 plus line breaks.
	raw := maxBytes*3 + 64*1024
	acct, cr := mb.account()
	rp, err := acct.FetchPart(ctx, folder, uid, path, raw)
	if err != nil {
		return AttachmentData{}, upstream(cr, err)
	}
	if rp.Selected.UIDValidity != uv {
		_ = e.Invalidate(id, folder)
		return AttachmentData{}, errStale("uidValidity changed")
	}
	if !rp.Found {
		_ = e.Invalidate(id, folder)
		return AttachmentData{}, errStale("message no longer exists")
	}
	sp, at := findAttachment(rp.Structure, part)
	if sp == nil {
		return AttachmentData{NotFound: true}, nil
	}
	out := AttachmentData{Attachment: attachmentOf(at, sp)}
	if int64(len(rp.Bytes)) >= raw {
		out.TooLarge = true
		return out, nil
	}
	data, err := decodeTransfer(sp.Encoding, rp.Bytes, maxBytes)
	if err != nil {
		return AttachmentData{}, errf(CodeUpstream, "attachment has a damaged transfer encoding")
	}
	if int64(len(data)) > maxBytes {
		out.TooLarge = true
		return out, nil
	}
	out.Data = data
	out.Size = int64(len(data))
	return out, nil
}
