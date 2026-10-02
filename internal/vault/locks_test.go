package vault

import (
	"sync"
	"testing"
	"time"
)

func TestLockSerializesSameKey(t *testing.T) {
	var l lockMap
	unlock := l.lock("a.md")
	got := make(chan struct{})
	go func() {
		u := l.lock("a.md")
		close(got)
		u()
	}()
	select {
	case <-got:
		t.Fatal("second lock acquired while the first was held")
	case <-time.After(50 * time.Millisecond):
	}
	unlock()
	select {
	case <-got:
	case <-time.After(time.Second):
		t.Fatal("second lock never acquired")
	}
}

func TestLockDuplicateKeysDoNotDeadlock(t *testing.T) {
	var l lockMap
	done := make(chan struct{})
	go func() {
		l.lock("a.md", "a.md")()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("locking the same key twice deadlocked")
	}
}

func TestLockOppositeOrderDoesNotDeadlock(t *testing.T) {
	var l lockMap
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); l.lock("a.md", "b.md")() }()
		go func() { defer wg.Done(); l.lock("b.md", "a.md")() }()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("opposite-order locking deadlocked")
	}
}

func TestLockDifferentKeysDoNotBlock(t *testing.T) {
	var l lockMap
	defer l.lock("a.md")()
	got := make(chan struct{})
	go func() { l.lock("b.md")(); close(got) }()
	select {
	case <-got:
	case <-time.After(time.Second):
		t.Fatal("lock(b.md) blocked while a.md was held")
	}
}

func TestLockFoldsCase(t *testing.T) {
	var l lockMap
	unlock := l.lock("A.md")
	got := make(chan struct{})
	go func() {
		u := l.lock("a.md")
		close(got)
		u()
	}()
	select {
	case <-got:
		t.Fatal("a.md acquired while A.md was held")
	case <-time.After(50 * time.Millisecond):
	}
	unlock()
	select {
	case <-got:
	case <-time.After(time.Second):
		t.Fatal("a.md never acquired")
	}
}
