package engine

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/imap2mcp/sidecar/internal/imapx"
)

// folderCache is the cache for one (mailbox, folder, uidValidity). Identity
// includes uidValidity: when it changes the whole struct content is dropped.
type folderCache struct {
	syncMu ctxLock // serialises syncs of this folder (context-aware)

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

// ctxLock is a mutex whose Lock honours a context, so a request that is
// queued behind a long-running sync still meets its own deadline.
type ctxLock struct {
	once sync.Once
	ch   chan struct{}
}

func (l *ctxLock) init() { l.once.Do(func() { l.ch = make(chan struct{}, 1) }) }

// Lock acquires the lock or returns ctx.Err().
func (l *ctxLock) Lock(ctx context.Context) error {
	l.init()
	select {
	case l.ch <- struct{}{}:
		return nil
	default:
	}
	select {
	case l.ch <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TryLock acquires the lock without waiting.
func (l *ctxLock) TryLock() bool {
	l.init()
	select {
	case l.ch <- struct{}{}:
		return true
	default:
		return false
	}
}

// Unlock releases the lock.
func (l *ctxLock) Unlock() { <-l.ch }
