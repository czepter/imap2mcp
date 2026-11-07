package engine

import (
	"sort"
	"sync"
	"time"

	"github.com/imap2mcp/sidecar/internal/imapx"
)

// folderCache is the cache for one (mailbox, folder, uidValidity). Identity
// includes uidValidity: when it changes the whole struct content is dropped.
type folderCache struct {
	syncMu sync.Mutex // serialises syncs of this folder

	mu            sync.RWMutex
	synced        bool
	uv            uint32
	uidNext       uint32
	hdrs          []imapx.Header // sorted by UID ascending; no bodies
	lastSync      time.Time
	lastReconcile time.Time
	lastAccess    time.Time
	stale         bool
	gen           uint64 // bumped by invalidate
}

func (f *folderCache) resetLocked() {
	f.synced = false
	f.uv = 0
	f.uidNext = 0
	f.hdrs = nil
	f.lastReconcile = time.Time{}
	f.lastSync = time.Time{}
}

func (f *folderCache) indexLocked(uid uint32) (int, bool) {
	i := sort.Search(len(f.hdrs), func(i int) bool { return f.hdrs[i].UID >= uid })
	return i, i < len(f.hdrs) && f.hdrs[i].UID == uid
}

// upsertLocked inserts or replaces headers, keeping UID order.
func (f *folderCache) upsertLocked(in []imapx.Header) {
	if len(in) == 0 {
		return
	}
	sort.Slice(in, func(i, j int) bool { return in[i].UID < in[j].UID })
	// fast path: strictly newer than everything cached
	if len(f.hdrs) == 0 || in[0].UID > f.hdrs[len(f.hdrs)-1].UID {
		f.hdrs = append(f.hdrs, in...)
		return
	}
	for _, h := range in {
		if i, ok := f.indexLocked(h.UID); ok {
			f.hdrs[i] = h
			continue
		}
		i, _ := f.indexLocked(h.UID)
		f.hdrs = append(f.hdrs, imapx.Header{})
		copy(f.hdrs[i+1:], f.hdrs[i:])
		f.hdrs[i] = h
	}
}

func (f *folderCache) maxUIDLocked() uint32 {
	if len(f.hdrs) == 0 {
		return 0
	}
	return f.hdrs[len(f.hdrs)-1].UID
}
