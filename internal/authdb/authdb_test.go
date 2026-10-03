package authdb

import (
	"database/sql"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

func tables(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

var wantTables = []string{
	"access_tokens", "auth_codes", "auth_requests", "bearer_tokens", "enrollments", "grants",
	"oauth_clients", "oauth_keys", "owner", "passkeys", "recovery_codes", "refresh_tokens",
}

func TestOpenCreatesLatestSchema(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "state", "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil || v != SchemaVersion {
		t.Fatalf("user_version = %d, %v; want %d", v, err, SchemaVersion)
	}
	if got := tables(t, db); !slices.Equal(got, wantTables) {
		t.Fatalf("tables = %v\nwant %v", got, wantTables)
	}
}

// TestMigrateFromVersion2KeepsTokens builds the database Plan 1 left behind
// and checks that version 3 adds the OAuth tables without touching tokens.
func TestMigrateFromVersion2KeepsTokens(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state", "auth.db")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	old, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE bearer_tokens (name TEXT PRIMARY KEY, hash BLOB NOT NULL UNIQUE, created INTEGER NOT NULL, last_used INTEGER NOT NULL DEFAULT 0, id TEXT)`,
		`CREATE UNIQUE INDEX bearer_tokens_id ON bearer_tokens(id)`,
		`INSERT INTO bearer_tokens(name, hash, created, id) VALUES('muse', x'00', 1, 'ID1')`,
		`PRAGMA user_version = 2`,
	} {
		if _, err := old.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	_ = old.Close()

	db, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var name, id string
	if err := db.QueryRow(`SELECT name, id FROM bearer_tokens`).Scan(&name, &id); err != nil || name != "muse" || id != "ID1" {
		t.Fatalf("token row after migration = %q %q, %v", name, id, err)
	}
	if got := tables(t, db); !slices.Equal(got, wantTables) {
		t.Fatalf("tables = %v", got)
	}
}

func TestOpenRejectsNewerSchema(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state", "auth.db")
	db, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 99`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if db, err := Open(p); err == nil {
		_ = db.Close()
		t.Fatal("Open accepted a newer schema")
	} else if !strings.Contains(err.Error(), "schema version") {
		t.Fatalf("err = %v", err)
	}
}

func TestOwnerIsASingleRow(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "state", "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	ins := `INSERT INTO owner(id, webauthn_id, totp_secret, created) VALUES(?, x'01', x'02', 1)`
	if _, err := db.Exec(ins, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ins, 2); err == nil {
		t.Fatal("a second owner row was accepted")
	}
	if _, err := db.Exec(`INSERT INTO oauth_clients(id, kind, name, redirect_uris, created) VALUES('a', 'other', 'n', '[]', 1)`); err == nil {
		t.Fatal("unknown client kind accepted")
	}
}

func TestOpenRequiresAbsolutePath(t *testing.T) {
	if db, err := Open("auth.db"); err == nil {
		_ = db.Close()
		t.Fatal("relative path accepted")
	}
}

// v2File writes the database Plan 1 left behind and returns its path.
func v2File(t *testing.T, extra ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "state", "auth.db")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	// Plan 1 always opened the file in WAL mode, so the live database is one.
	// (Switching a rollback-journal file to WAL while another connection holds
	// a lock fails at once, regardless of busy_timeout; that is not what this
	// helper is about.)
	old, err := sql.Open("sqlite", p+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = old.Close() }()
	stmts := append([]string{
		`CREATE TABLE bearer_tokens (name TEXT PRIMARY KEY, hash BLOB NOT NULL UNIQUE, created INTEGER NOT NULL, last_used INTEGER NOT NULL DEFAULT 0, id TEXT)`,
		`CREATE UNIQUE INDEX bearer_tokens_id ON bearer_tokens(id)`,
		`INSERT INTO bearer_tokens(name, hash, created, id) VALUES('muse', x'00', 1, 'ID1')`,
	}, extra...)
	stmts = append(stmts, `PRAGMA user_version = 2`)
	for _, s := range stmts {
		if _, err := old.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func TestConcurrentOpenMigratesOnce(t *testing.T) {
	p := v2File(t)
	const n = 4
	dbs := make([]*sql.DB, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			dbs[i], errs[i] = Open(p)
		}()
	}
	close(start)
	wg.Wait()
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("Open %d: %v", i, errs[i])
		}
		defer func() { _ = dbs[i].Close() }()
	}
	var v int
	var id string
	if err := dbs[0].QueryRow(`PRAGMA user_version`).Scan(&v); err != nil || v != SchemaVersion {
		t.Fatalf("user_version = %d, %v", v, err)
	}
	if err := dbs[0].QueryRow(`SELECT id FROM bearer_tokens WHERE name = 'muse'`).Scan(&id); err != nil || id != "ID1" {
		t.Fatalf("token = %q, %v", id, err)
	}
}

func TestFailedMigrationRollsBack(t *testing.T) {
	// A pre-existing passkeys table makes CREATE TABLE fail after owner was
	// already created in the same migration.
	p := v2File(t, `CREATE TABLE passkeys (x)`)
	if db, err := Open(p); err == nil {
		_ = db.Close()
		t.Fatal("migration should have failed")
	}
	raw, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	var v int
	if err := raw.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil || v != 2 {
		t.Fatalf("user_version = %d, %v; want 2", v, err)
	}
	for _, n := range tables(t, raw) {
		if n == "owner" {
			t.Fatal("owner table survived a failed migration")
		}
	}
	var name string
	if err := raw.QueryRow(`SELECT name FROM bearer_tokens`).Scan(&name); err != nil || name != "muse" {
		t.Fatalf("token lost: %q, %v", name, err)
	}
}
