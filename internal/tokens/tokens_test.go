package tokens

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func open(t *testing.T) (*Store, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "state", "auth.db")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, p
}

func TestCreateAndVerify(t *testing.T) {
	s, _ := open(t)
	secret, err := s.Create("muse")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(secret, "cmcp_") || len(secret) < 40 {
		t.Fatalf("secret %q", secret)
	}
	if name, err := s.Verify(secret); err != nil || name != "muse" {
		t.Fatalf("Verify = %q, %v", name, err)
	}
	long := "cmcp_" + strings.Repeat("A", 500)
	for _, bad := range []string{"", "nope", "cmcp_", "cmcp_wrong", secret + "x", secret[:len(secret)-1], "cmcp_" + strings.Repeat("!", 43), long} {
		_, err := s.Verify(bad)
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("Verify(%q) err = %v, want ErrInvalid", bad, err)
		}
		if err != nil && bad != "" && strings.Contains(err.Error(), bad) {
			t.Errorf("error leaks the secret: %v", err)
		}
	}
}

func TestSecretsAreUnique(t *testing.T) {
	s, _ := open(t)
	a, _ := s.Create("a")
	b, _ := s.Create("b")
	if a == b {
		t.Fatal("two tokens share a secret")
	}
	if n, err := s.Verify(b); err != nil || n != "b" {
		t.Fatalf("Verify(b) = %q, %v", n, err)
	}
}

func TestCreateValidatesNames(t *testing.T) {
	s, _ := open(t)
	if _, err := s.Create("muse"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create("muse"); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate: %v", err)
	}
	for _, bad := range []string{"", "Muse", "a b", "-x", strings.Repeat("a", 41)} {
		if _, err := s.Create(bad); !errors.Is(err, ErrBadName) {
			t.Errorf("Create(%q) err = %v, want ErrBadName", bad, err)
		}
	}
}

func TestListShowsLastUse(t *testing.T) {
	s, _ := open(t)
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	secret, _ := s.Create("claude-fedora")
	recs, err := s.List()
	if err != nil || len(recs) != 1 || !recs[0].Created.Equal(now) || !recs[0].LastUsed.IsZero() {
		t.Fatalf("List before use = %+v, %v", recs, err)
	}
	now = now.Add(time.Hour)
	if _, err := s.Verify(secret); err != nil {
		t.Fatal(err)
	}
	recs, _ = s.List()
	if !recs[0].LastUsed.Equal(now) {
		t.Fatalf("LastUsed = %v, want %v", recs[0].LastUsed, now)
	}
}

func TestLastUsedIsThrottled(t *testing.T) {
	s, _ := open(t)
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	secret, _ := s.Create("muse")
	first := now
	if _, err := s.Verify(secret); err != nil {
		t.Fatal(err)
	}
	now = first.Add(59 * time.Second)
	if _, err := s.Verify(secret); err != nil {
		t.Fatal(err)
	}
	if recs, _ := s.List(); !recs[0].LastUsed.Equal(first) {
		t.Fatalf("LastUsed = %v within the window, want %v (no write)", recs[0].LastUsed, first)
	}
	now = first.Add(61 * time.Second)
	if _, err := s.Verify(secret); err != nil {
		t.Fatal(err)
	}
	if recs, _ := s.List(); !recs[0].LastUsed.Equal(now) {
		t.Fatalf("LastUsed = %v after the window, want %v", recs[0].LastUsed, now)
	}
}

func TestRevoke(t *testing.T) {
	s, _ := open(t)
	secret, _ := s.Create("muse")
	if err := s.Revoke("muse"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(secret); !errors.Is(err, ErrInvalid) {
		t.Fatalf("revoked token still valid: %v", err)
	}
	if err := s.Revoke("muse"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second revoke: %v", err)
	}
}

func TestDatabaseFilesArePrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions only")
	}
	s, p := open(t)
	if _, err := s.Create("muse"); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{p, p + "-wal", p + "-shm"} {
		info, err := os.Stat(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %v, want 0600", filepath.Base(f), info.Mode().Perm())
		}
	}
	dir, err := os.Stat(filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	if dir.Mode().Perm() != 0o700 {
		t.Errorf("state dir mode = %v, want 0700", dir.Mode().Perm())
	}
}

func TestOpenTightensExistingPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions only")
	}
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o755); err != nil { // #nosec G301 -- deliberately loose to test tightening
		t.Fatal(err)
	}
	p := filepath.Join(dir, "auth.db")
	if err := os.WriteFile(p, nil, 0o644); err != nil { // #nosec G306 -- deliberately loose to test tightening
		t.Fatal(err)
	}
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	for f, want := range map[string]os.FileMode{p: 0o600, dir: 0o700} {
		info, _ := os.Stat(f)
		if info.Mode().Perm() != want {
			t.Errorf("%s mode = %v, want %v", filepath.Base(f), info.Mode().Perm(), want)
		}
	}
}

func TestOpenAwkwardPaths(t *testing.T) {
	for _, name := range []string{"state dir", "state#dir", "state?dir", "state%20dir"} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), name, "auth.db")
			s, err := Open(p)
			if err != nil {
				t.Fatal(err)
			}
			secret, err := s.Create("muse")
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(p); err != nil {
				t.Fatalf("database not at the requested path: %v", err)
			}
			s, err = Open(p)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = s.Close() }()
			if n, err := s.Verify(secret); err != nil || n != "muse" {
				t.Fatalf("after reopen: %q, %v", n, err)
			}
		})
	}
}

func TestReopenKeepsDataAndSchemaVersion(t *testing.T) {
	s, p := open(t)
	secret, _ := s.Create("muse")
	var v int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil || v != 1 {
		t.Fatalf("user_version = %d, %v; want 1", v, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	if n, err := s2.Verify(secret); err != nil || n != "muse" {
		t.Fatalf("after reopen: %q, %v", n, err)
	}
	if err := s2.db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil || v != 1 {
		t.Fatalf("user_version after reopen = %d, %v", v, err)
	}
}

func TestOpenRejectsNewerSchema(t *testing.T) {
	s, p := open(t)
	if _, err := s.db.Exec(`PRAGMA user_version = 99`); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if s2, err := Open(p); err == nil {
		_ = s2.Close()
		t.Fatal("Open accepted a database from a newer version")
	} else if !strings.Contains(err.Error(), "schema version") {
		t.Fatalf("error does not mention the schema version: %v", err)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	s, _ := open(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestConcurrentUse(t *testing.T) {
	s, _ := open(t)
	secret, _ := s.Create("shared")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("c%d", i)
			sec, err := s.Create(name)
			if err != nil {
				t.Error(err)
				return
			}
			for j := 0; j < 20; j++ {
				if n, err := s.Verify(secret); err != nil || n != "shared" {
					t.Errorf("Verify shared = %q, %v", n, err)
				}
				if _, err := s.Verify(sec); err != nil {
					t.Errorf("Verify %s: %v", name, err)
				}
				if _, err := s.List(); err != nil {
					t.Error(err)
				}
			}
			if err := s.Revoke(name); err != nil {
				t.Error(err)
			}
			if _, err := s.Verify(sec); !errors.Is(err, ErrInvalid) {
				t.Errorf("revoked %s still valid: %v", name, err)
			}
		}(i)
	}
	wg.Wait()
}

func TestConcurrentDuplicateCreate(t *testing.T) {
	s, _ := open(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, exists := 0, 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Create("same")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrExists):
				exists++
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if ok != 1 || exists != 7 {
		t.Fatalf("ok=%d exists=%d, want 1 and 7", ok, exists)
	}
}

func TestOpenRefusesSharedStateDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions only")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777|os.ModeSticky); err != nil { // #nosec G302 -- simulates a shared /tmp
		t.Fatal(err)
	}
	s, err := Open(filepath.Join(dir, "auth.db"))
	if err == nil {
		_ = s.Close()
		t.Fatal("Open accepted a shared directory")
	}
	if !strings.Contains(err.Error(), "shared directory") {
		t.Errorf("error = %v", err)
	}
	info, _ := os.Stat(dir)
	if info.Mode()&os.ModeSticky == 0 || info.Mode().Perm() != 0o777 {
		t.Errorf("shared dir mode changed to %v", info.Mode())
	}
	if _, err := os.Stat(filepath.Join(dir, "auth.db")); err == nil {
		t.Error("database created in a shared directory")
	}
}

func TestOpenRequiresAbsolutePath(t *testing.T) {
	if s, err := Open("auth.db"); err == nil {
		_ = s.Close()
		t.Fatal("Open accepted a relative path")
	}
}

func TestPragmas(t *testing.T) {
	s, _ := open(t)
	var bt int
	var jm string
	if err := s.db.QueryRow(`PRAGMA busy_timeout`).Scan(&bt); err != nil || bt != 5000 {
		t.Errorf("busy_timeout = %d, %v", bt, err)
	}
	if err := s.db.QueryRow(`PRAGMA journal_mode`).Scan(&jm); err != nil || jm != "wal" {
		t.Errorf("journal_mode = %q, %v", jm, err)
	}
}

func TestOpenFreshChildOfTempDir(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "child", "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
}
