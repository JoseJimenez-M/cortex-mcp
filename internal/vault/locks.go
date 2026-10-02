package vault

import (
	"slices"
	"sync"
)

// lockMap serializes writes per note. Entries are reference-counted and
// removed when the last holder or waiter unlocks, so the map only holds
// paths with a write in flight. Without that, an assistant sending writes to
// many distinct (even non-existent) paths would grow it without bound.
type lockMap struct {
	mu sync.Mutex
	m  map[string]*lockEntry
}

type lockEntry struct {
	mu   sync.Mutex
	refs int // holders plus waiters; guarded by lockMap.mu
}

// acquire returns the entry for key with its reference taken.
func (l *lockMap) acquire(key string) *lockEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = make(map[string]*lockEntry)
	}
	e, ok := l.m[key]
	if !ok {
		e = &lockEntry{}
		l.m[key] = e
	}
	e.refs++
	return e
}

// release drops one reference and deletes the entry when it was the last.
func (l *lockMap) release(key string, e *lockEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.refs--
	if e.refs == 0 {
		delete(l.m, key)
	}
}

// lock locks every key in sorted order, so two moves over the same pair of
// notes can never deadlock, and returns the unlock function.
func (l *lockMap) lock(keys ...string) func() {
	// Folded (see fold) so "A.md" and "a.md" share a mutex on case-insensitive
	// filesystems; on case-sensitive ones it only over-serializes.
	ks := make([]string, len(keys))
	for i, k := range keys {
		ks[i] = fold(k)
	}
	slices.Sort(ks)
	ks = slices.Compact(ks)
	es := make([]*lockEntry, len(ks))
	for i, k := range ks {
		es[i] = l.acquire(k)
		es[i].mu.Lock()
	}
	return func() {
		for i := len(es) - 1; i >= 0; i-- {
			es[i].mu.Unlock()
			l.release(ks[i], es[i])
		}
	}
}
