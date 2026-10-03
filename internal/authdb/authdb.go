// Package authdb opens the auth database (state_dir/auth.db) and migrates its
// schema. Bearer tokens (internal/tokens) and the OAuth state
// (internal/oauth) live in this one SQLite file; inside serve they share one
// *sql.DB, so SQLite never sees two writers from the same process.
package authdb

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"github.com/JoseJimenez-M/cortex-mcp/internal/fsperm"
)

// SchemaVersion is stored in PRAGMA user_version. Version 2 added the Bearer
// token id column; version 3 added the OAuth tables.
const SchemaVersion = 3

// Open creates the database if needed and migrates it to SchemaVersion. The
// state directory is 0700 and the database and its WAL/SHM side files are
// 0600 from the moment they exist. The path must be absolute: a relative one
// would make the chmod land wherever the working directory happens to be.
func Open(path string) (*sql.DB, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("auth db: open %s: path must be absolute", path)
	}
	if err := preparePath(path); err != nil {
		return nil, fmt.Errorf("auth db: open %s: %w", path, err)
	}
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, fmt.Errorf("auth db: open %s: %w", path, err)
	}
	// One connection: the load is a handful of queries per minute, and it
	// serializes writers without SQLITE_BUSY handling. Code that holds a
	// transaction must run every query on it, or it waits on itself.
	db.SetMaxOpenConns(1)
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("auth db: open %s: %w", path, err)
	}
	return db, nil
}

// preparePath creates the state directory and database file with private
// modes before SQLite sees them. SQLite gives the -wal and -shm files the
// mode of the main file, so a 0600 main file means 0600 side files with no
// umask window.
func preparePath(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := fsperm.PrivateDir(dir); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- path is operator configuration, not request input
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		// Tighten files left by an older or manually created database.
		if err := fsperm.PrivateFile(p); err != nil {
			return err
		}
	}
	return nil
}

// dsn builds a file: URI so that spaces, '#', '?' and '%' in the path cannot
// be taken for URI syntax.
func dsn(abs string) string {
	p := filepath.ToSlash(abs)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // Windows drive paths: file:///C:/...
	}
	// _txlock=immediate: every transaction takes the write lock at BEGIN.
	// The CLI writes this file while serve has it open, and a deferred
	// transaction that reads then writes fails at once with SQLITE_BUSY
	// when the other process committed in between; busy_timeout only
	// helps when the wait happens at BEGIN.
	u := url.URL{
		Scheme:   "file",
		Path:     p,
		RawQuery: "_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_txlock=immediate",
	}
	return u.String()
}

const bearerTable = `CREATE TABLE IF NOT EXISTS bearer_tokens (
	name      TEXT PRIMARY KEY,
	hash      BLOB NOT NULL UNIQUE,
	created   INTEGER NOT NULL,
	last_used INTEGER NOT NULL DEFAULT 0
)`

// oauthSchema is the version 2 to 3 migration. Times are Unix seconds.
// Long-lived secrets (refresh tokens, authorization codes, recovery codes,
// enrollment links) are stored only as SHA-256 hashes. Exceptions: the TOTP
// secret and the signing and encryption keys, which must be usable and never
// leave state_dir, and the short-lived auth_requests.id and csrf, which are
// stored plain.
//
// There are deliberately no foreign keys. A revocation must delete across
// auth_codes, access_tokens and refresh_tokens by family in one transaction;
// Task 8 has a test asserting no rows survive a family revocation.
var oauthSchema = []string{
	// The single owner (spec 6.1). webauthn_id is the passkey user handle.
	`CREATE TABLE owner (
		id             INTEGER PRIMARY KEY CHECK (id = 1),
		webauthn_id    BLOB NOT NULL,
		totp_secret    BLOB NOT NULL,
		totp_last_step INTEGER NOT NULL DEFAULT 0,
		totp_failures  INTEGER NOT NULL DEFAULT 0,
		created        INTEGER NOT NULL
	)`,
	// credential is the JSON of a go-webauthn Credential.
	`CREATE TABLE passkeys (
		id         BLOB PRIMARY KEY,
		credential BLOB NOT NULL,
		created    INTEGER NOT NULL,
		last_used  INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE TABLE recovery_codes (hash BLOB PRIMARY KEY)`,
	`CREATE TABLE enrollments (hash BLOB PRIMARY KEY, expires INTEGER NOT NULL)`,
	// id is random for DCR and the document URL for CIMD; redirect_uris is
	// a JSON array; fetched is when a CIMD document was last fetched.
	`CREATE TABLE oauth_clients (
		id            TEXT PRIMARY KEY,
		kind          TEXT NOT NULL CHECK (kind IN ('dcr', 'cimd')),
		name          TEXT NOT NULL,
		redirect_uris TEXT NOT NULL,
		created       INTEGER NOT NULL,
		fetched       INTEGER NOT NULL DEFAULT 0
	)`,
	// request is a JSON object with the validated authorize parameters;
	// browser is the hash of the cookie that started the request; source is
	// the rate-limit key of the address that sent it (an IPv4 /32 or IPv6
	// /48 prefix, '' when unknown), which the pending caps count by. It is a
	// column, not a field of request, because the caps group and order by it
	// in SQL on every insert (the index below).
	`CREATE TABLE auth_requests (
		id        TEXT PRIMARY KEY,
		client_id TEXT NOT NULL,
		request   TEXT NOT NULL,
		browser   TEXT NOT NULL,
		csrf      TEXT NOT NULL,
		family    TEXT NOT NULL,
		amr       TEXT NOT NULL DEFAULT '',
		auth_time INTEGER NOT NULL DEFAULT 0,
		done      INTEGER NOT NULL DEFAULT 0,
		created   INTEGER NOT NULL,
		source    TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE INDEX auth_requests_pending ON auth_requests(done, source, created)`,
	// Used codes stay until authRequestTTL after issue, so a late replay can
	// still revoke the family.
	`CREATE TABLE auth_codes (
		hash            BLOB PRIMARY KEY,
		auth_request_id TEXT NOT NULL,
		family          TEXT NOT NULL,
		used            INTEGER NOT NULL DEFAULT 0,
		expires         INTEGER NOT NULL
	)`,
	// A grant is one approved connection: every access and refresh token
	// it ever issues shares its family id.
	`CREATE TABLE grants (
		family    TEXT PRIMARY KEY,
		client_id TEXT NOT NULL,
		scopes    TEXT NOT NULL,
		audience  TEXT NOT NULL,
		amr       TEXT NOT NULL,
		auth_time INTEGER NOT NULL,
		created   INTEGER NOT NULL,
		last_used INTEGER NOT NULL
	)`,
	`CREATE INDEX grants_client ON grants(client_id)`,
	`CREATE TABLE access_tokens (
		id      TEXT PRIMARY KEY,
		family  TEXT NOT NULL,
		scopes  TEXT NOT NULL,
		expires INTEGER NOT NULL
	)`,
	`CREATE INDEX access_tokens_family ON access_tokens(family)`,
	// rotated = 1 once exchanged; presenting it again is reuse.
	`CREATE TABLE refresh_tokens (
		hash    BLOB PRIMARY KEY,
		id      TEXT NOT NULL UNIQUE,
		family  TEXT NOT NULL,
		expires INTEGER NOT NULL,
		rotated INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE INDEX refresh_tokens_family ON refresh_tokens(family)`,
	// Expiry indexes serve the periodic sweeps; auth_codes(family) serves
	// family revocation.
	`CREATE INDEX auth_codes_family ON auth_codes(family)`,
	`CREATE INDEX auth_codes_expires ON auth_codes(expires)`,
	`CREATE INDEX access_tokens_expires ON access_tokens(expires)`,
	`CREATE INDEX refresh_tokens_expires ON refresh_tokens(expires)`,
	`CREATE INDEX enrollments_expires ON enrollments(expires)`,
	`CREATE INDEX auth_requests_created ON auth_requests(created)`,
	`CREATE TABLE oauth_keys (
		name     TEXT PRIMARY KEY CHECK (name IN ('signing', 'crypto')),
		kid      TEXT NOT NULL,
		material BLOB NOT NULL
	)`,
}

func userVersion(q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (int, error) {
	var v int
	err := q.QueryRowContext(context.Background(), `PRAGMA user_version`).Scan(&v)
	return v, err
}

func migrate(db *sql.DB) error {
	v, err := userVersion(db)
	if err != nil {
		return err
	}
	if v > SchemaVersion {
		return fmt.Errorf("auth database has schema version %d, this build supports up to %d", v, SchemaVersion)
	}
	if v == SchemaVersion {
		return nil
	}
	// Two processes (serve and a token command) can both see an old version
	// here. BEGIN IMMEDIATE takes the write lock up front, so the second one
	// waits (busy_timeout) instead of failing with SQLITE_BUSY on a lock
	// upgrade, and then re-reads the version inside the lock: the first
	// process has usually finished by then. database/sql's Begin issues a
	// deferred BEGIN, so the transaction is driven by hand on a dedicated
	// connection. user_version lives in the database header and is
	// transactional, so a failure leaves the database at its old version.
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, `ROLLBACK`)
		}
	}()
	if v, err = userVersion(conn); err != nil {
		return err
	}
	if v > SchemaVersion {
		return fmt.Errorf("auth database has schema version %d, this build supports up to %d", v, SchemaVersion)
	}
	if v == SchemaVersion {
		return nil
	}
	if _, err := conn.ExecContext(ctx, bearerTable); err != nil {
		return err
	}
	if v < 2 {
		if err := addIDColumn(ctx, conn); err != nil {
			return err
		}
	}
	if v < 3 {
		for _, stmt := range oauthSchema {
			if _, err := conn.ExecContext(ctx, stmt); err != nil {
				return err
			}
		}
	}
	// PRAGMA does not accept bound parameters; the value is a constant.
	if _, err := conn.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, SchemaVersion)); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return err
	}
	committed = true
	return nil
}

// addIDColumn is the version 1 to 2 migration. Name is the primary key, but a
// name is free again after a revoke, and the implicit rowid can be reused once
// the highest row is deleted, so neither identifies a token row for good. A
// random id per row does. ALTER TABLE cannot add a NOT NULL column without a
// default, so the column is nullable; every row is filled here and Create
// always sets it.
func addIDColumn(ctx context.Context, tx *sql.Conn) error {
	if _, err := tx.ExecContext(ctx, `ALTER TABLE bearer_tokens ADD COLUMN id TEXT`); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT name FROM bearer_tokens WHERE id IS NULL`)
	if err != nil {
		return err
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			_ = rows.Close()
			return err
		}
		names = append(names, n)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, n := range names {
		if _, err := tx.ExecContext(ctx, `UPDATE bearer_tokens SET id = ? WHERE name = ?`, rand.Text(), n); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `CREATE UNIQUE INDEX bearer_tokens_id ON bearer_tokens(id)`)
	return err
}
