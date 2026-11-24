package engine

import "context"

// defaultMaxRawHeader is both the default and the hard cap of FetchRawHeader.
const defaultMaxRawHeader = 256 << 10

// RawHeader is the raw header block of one message (bytes as stored on the
// server, cut at the cap).
type RawHeader struct {
	Data      []byte
	Truncated bool
}

// FetchRawHeader fetches the header block of one message with
// BODY.PEEK[HEADER]. The uidValidity must match the folder's current one.
// The block is never cached.
func (e *Engine) FetchRawHeader(ctx context.Context, id, folder string, uv, uid uint32, maxBytes int64) (RawHeader, error) {
	mb, err := e.mailbox(id)
	if err != nil {
		return RawHeader{}, err
	}
	if folder == "" || uid == 0 {
		return RawHeader{}, errf(CodeInvalidParams, "folder and uid required")
	}
	if maxBytes <= 0 || maxBytes > defaultMaxRawHeader {
		maxBytes = defaultMaxRawHeader
	}
	acct, cr := mb.account()
	rh, err := acct.FetchHeaderBlock(ctx, folder, uid, maxBytes)
	if err != nil {
		return RawHeader{}, upstream(cr, err)
	}
	if rh.Selected.UIDValidity != uv {
		_ = e.Invalidate(id, folder)
		return RawHeader{}, errStale("uidValidity changed")
	}
	if !rh.Found {
		_ = e.Invalidate(id, folder)
		return RawHeader{}, errStale("message no longer exists")
	}
	return RawHeader{Data: rh.Bytes, Truncated: rh.Truncated}, nil
}
