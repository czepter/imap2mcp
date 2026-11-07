package engine

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/imap2mcp/sidecar/internal/imapx"
)

// Criteria are header-level search criteria answered from the cache.
// All set fields are ANDed. Text matches are case-insensitive substrings.
type Criteria struct {
	From     string     `json:"from,omitempty"` // matches display name or address
	To       string     `json:"to,omitempty"`
	Cc       string     `json:"cc,omitempty"`
	Subject  string     `json:"subject,omitempty"`
	Since    *time.Time `json:"-"` // inclusive
	Before   *time.Time `json:"-"` // exclusive
	Seen     *bool      `json:"seen,omitempty"`
	Flagged  *bool      `json:"flagged,omitempty"`
	Answered *bool      `json:"answered,omitempty"`
	MinSize  *int64     `json:"minSize,omitempty"` // inclusive
	MaxSize  *int64     `json:"maxSize,omitempty"` // inclusive
}

func (c *Criteria) prepare() {
	c.From, c.To, c.Cc, c.Subject = strings.ToLower(c.From), strings.ToLower(c.To), strings.ToLower(c.Cc), strings.ToLower(c.Subject)
}

func addrMatch(list []imapx.Addr, q string) bool {
	for _, a := range list {
		if strings.Contains(strings.ToLower(a.Address), q) || strings.Contains(strings.ToLower(a.Name), q) {
			return true
		}
	}
	return false
}

func flagIs(h *imapx.Header, bit uint8, want *bool) bool {
	return want == nil || (h.Flags.Bits&bit != 0) == *want
}

func (c *Criteria) match(h *imapx.Header) bool {
	if c.Subject != "" && !strings.Contains(strings.ToLower(h.Subject), c.Subject) {
		return false
	}
	if c.From != "" && !addrMatch(h.From, c.From) {
		return false
	}
	if c.To != "" && !addrMatch(h.To, c.To) {
		return false
	}
	if c.Cc != "" && !addrMatch(h.Cc, c.Cc) {
		return false
	}
	if !flagIs(h, imapx.FlagSeen, c.Seen) || !flagIs(h, imapx.FlagFlagged, c.Flagged) || !flagIs(h, imapx.FlagAnswered, c.Answered) {
		return false
	}
	if c.MinSize != nil && int64(h.Size) < *c.MinSize {
		return false
	}
	if c.MaxSize != nil && int64(h.Size) > *c.MaxSize {
		return false
	}
	if c.Since != nil || c.Before != nil {
		d := h.Date
		if d.IsZero() {
			d = h.InternalDate
		}
		if c.Since != nil && d.Before(*c.Since) {
			return false
		}
		if c.Before != nil && !d.Before(*c.Before) {
			return false
		}
	}
	return true
}

// Page is a newest-first page of headers.
type Page struct {
	UIDValidity   uint32
	Items         []imapx.Header
	NextBeforeUID uint32 // 0 = no more
}

func clampLimit(n int) int {
	if n <= 0 {
		return defaultLimit
	}
	if n > maxResults {
		return maxResults
	}
	return n
}

func (e *Engine) page(ctx context.Context, id, folder string, limit int, before uint32, crit *Criteria) (Page, error) {
	mb, err := e.mailbox(id)
	if err != nil {
		return Page{}, err
	}
	if folder == "" {
		return Page{}, errf(CodeInvalidParams, "folder required")
	}
	limit = clampLimit(limit)
	f, err := e.ensureFresh(ctx, mb, folder)
	if err != nil {
		return Page{}, err
	}
	if crit != nil {
		crit.prepare()
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	// start below beforeUid (exclusive); 0 means from the newest
	end := len(f.hdrs)
	if before != 0 {
		end = sort.Search(len(f.hdrs), func(i int) bool { return f.hdrs[i].UID >= before })
	}
	p := Page{UIDValidity: f.uv, Items: []imapx.Header{}}
	i := end - 1
	for ; i >= 0 && len(p.Items) < limit; i-- {
		if crit == nil || crit.match(&f.hdrs[i]) {
			p.Items = append(p.Items, f.hdrs[i])
		}
	}
	// more results exist if any remaining header matches
	for ; i >= 0; i-- {
		if crit == nil || crit.match(&f.hdrs[i]) {
			p.NextBeforeUID = p.Items[len(p.Items)-1].UID
			break
		}
	}
	return p, nil
}

// List returns headers newest first from the cache.
func (e *Engine) List(ctx context.Context, id, folder string, limit int, before uint32) (Page, error) {
	return e.page(ctx, id, folder, limit, before, nil)
}

// Search answers header-level criteria from the cache.
func (e *Engine) Search(ctx context.Context, id, folder string, crit Criteria, limit int, before uint32) (Page, error) {
	return e.page(ctx, id, folder, limit, before, &crit)
}

// TextResult is the result of a remote body-text search.
type TextResult struct {
	UIDValidity uint32
	UIDs        []uint32 // newest first
}

// SearchText runs UID SEARCH TEXT on the server. It never touches the cache,
// except to mark it stale when the folder's UIDVALIDITY differs.
func (e *Engine) SearchText(ctx context.Context, id, folder, text string, limit int) (TextResult, error) {
	mb, err := e.mailbox(id)
	if err != nil {
		return TextResult{}, err
	}
	if folder == "" || text == "" {
		return TextResult{}, errf(CodeInvalidParams, "folder and text required")
	}
	acct, cr := mb.account()
	sel, uids, err := acct.SearchText(ctx, folder, text)
	if err != nil {
		return TextResult{}, upstream(cr, err)
	}
	if f := mb.folder(folder, false); f != nil {
		f.mu.RLock()
		differs := f.synced && f.uv != sel.UIDValidity
		f.mu.RUnlock()
		if differs {
			_ = e.Invalidate(id, folder)
		}
	}
	limit = clampLimit(limit)
	sort.Slice(uids, func(i, j int) bool { return uids[i] > uids[j] })
	if len(uids) > limit {
		uids = uids[:limit]
	}
	if uids == nil {
		uids = []uint32{}
	}
	return TextResult{UIDValidity: sel.UIDValidity, UIDs: uids}, nil
}

// FetchHeaders returns cached headers for the given UIDs. A uidValidity that
// no longer matches the folder yields STALE_REFERENCE. UIDs that were expunged
// are omitted.
func (e *Engine) FetchHeaders(ctx context.Context, id, folder string, uv uint32, uids []uint32) ([]imapx.Header, error) {
	mb, err := e.mailbox(id)
	if err != nil {
		return nil, err
	}
	if folder == "" {
		return nil, errf(CodeInvalidParams, "folder required")
	}
	if len(uids) > maxResults {
		return nil, errf(CodeInvalidParams, "at most %d uids", maxResults)
	}
	f, err := e.ensureFresh(ctx, mb, folder)
	if err != nil {
		return nil, err
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.uv != uv {
		return nil, errStale("uidValidity changed")
	}
	out := make([]imapx.Header, 0, len(uids))
	for _, u := range uids {
		if i, ok := f.indexLocked(u); ok {
			out = append(out, f.hdrs[i])
		}
	}
	return out, nil
}
