package vault

import (
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
