package oauth

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/JoseJimenez-M/cortex-mcp/internal/authdb"
)

// testClock starts at the real time (the library computes expires_in from
// time.Now) and only moves forward.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock { return &testClock{t: time.Now().Truncate(time.Second)} }

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestStore(t *testing.T) (*Store, *testClock) {
	t.Helper()
	db, err := authdb.Open(filepath.Join(t.TempDir(), "state", "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	clk := newTestClock()
	return NewStore(db, clk.Now), clk
}

func ownerSecret(t *testing.T, s *Store) []byte {
	t.Helper()
	var secret []byte
	if err := s.db.QueryRow(`SELECT totp_secret FROM owner WHERE id = 1`).Scan(&secret); err != nil {
		t.Fatal(err)
	}
	return secret
}

// wrongTOTP returns a 6-digit code that no step in the accepted window maps to.
func wrongTOTP(secret []byte, now time.Time) string {
	valid := map[string]bool{}
	for s := totpStep(now) - 1; s <= totpStep(now)+1; s++ {
		valid[hotp(secret, uint64(s), totpDigits)] = true
	}
	for i := 0; ; i++ {
		if c := fmt.Sprintf("%06d", i); !valid[c] {
			return c
		}
	}
}
