package vault

import (
	"slices"
	"sync"
)

// lockMap serializes writes per note. Entries are never removed: the map is
// bounded by the number of notes ever written, a few KB for a personal vault.
type lockMap struct {
	mu sync.Mutex
	m  map[string]*sync.Mutex
}

func (l *lockMap) get(key string) *sync.Mutex {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = make(map[string]*sync.Mutex)
	}
	mu, ok := l.m[key]
	if !ok {
		mu = &sync.Mutex{}
		l.m[key] = mu
	}
	return mu
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
	mus := make([]*sync.Mutex, len(ks))
	for i, k := range ks {
		mus[i] = l.get(k)
		mus[i].Lock()
	}
	return func() {
		for i := len(mus) - 1; i >= 0; i-- {
			mus[i].Unlock()
		}
	}
}
