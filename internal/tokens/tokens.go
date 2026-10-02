// Package tokens stores Bearer tokens for clients that cannot run an OAuth
// login (CLI agents, scripts). Only SHA-256 hashes are stored.
package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/JoseJimenez-M/cortex-mcp/internal/fsperm"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

var (
	// ErrInvalid means the secret is malformed, unknown or revoked. It is the
	// only error Verify returns for a bad secret, so callers cannot tell why.
	ErrInvalid = errors.New("invalid token")
	// ErrNotFound means no token has that name.
	ErrNotFound = errors.New("token not found")
	// ErrExists means a token with that name already exists.
	ErrExists = errors.New("a token with that name already exists")
	// ErrBadName means the name does not match the allowed pattern.
	ErrBadName = errors.New("token names are 1-40 characters of a-z, 0-9 and -, starting with a letter or digit")
)

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

const (
	prefix      = "cmcp_"
	secretBytes = 32
	// maxSecretLen bounds hashing work on junk input. A real secret is
	// len(prefix)+43 characters.
	maxSecretLen = 128
	// schemaVersion is stored in PRAGMA user_version so later plans (OAuth)
	// can migrate the same database.
	schemaVersion = 1
	// lastUsedGranularity limits last_used writes to one per token per
	// minute: the value is informational, and a write per request would
	// serialize every authenticated call behind SQLite's writer lock.
	lastUsedGranularity = 60
)

// Record describes a token without its secret.
type Record struct {
	Name     string
	Created  time.Time
	LastUsed time.Time // zero if never used
}

// Store is the token table inside the auth database. It is safe for
// concurrent use.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// Open creates the database if needed. The state directory is 0700 and the
// database and its WAL/SHM side files are 0600 from the moment they exist.
func Open(path string) (*Store, error) {
	// Absolute only: a relative path would make the chmod below land on
	// whatever the working directory happens to be.
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("tokens: open %s: path must be absolute", path)
	}
	if err := preparePath(path); err != nil {
		return nil, fmt.Errorf("tokens: open %s: %w", path, err)
	}
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, fmt.Errorf("tokens: open %s: %w", path, err)
	}
	// One connection is the simplest correct choice for SQLite here: the
	// load is a handful of lookups per minute, and it serializes writers
	// without SQLITE_BUSY handling.
	db.SetMaxOpenConns(1)
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("tokens: open %s: %w", path, err)
	}
	return &Store{db: db, now: time.Now}, nil
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
	u := url.URL{
		Scheme:   "file",
		Path:     p,
		RawQuery: "_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)",
	}
	return u.String()
}

func migrate(db *sql.DB) error {
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	if v > schemaVersion {
		return fmt.Errorf("auth database has schema version %d, this build supports up to %d", v, schemaVersion)
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS bearer_tokens (
		name      TEXT PRIMARY KEY,
		hash      BLOB NOT NULL UNIQUE,
		created   INTEGER NOT NULL,
		last_used INTEGER NOT NULL DEFAULT 0
	)`); err != nil {
		return err
	}
	if v < schemaVersion {
		// PRAGMA does not accept bound parameters; the value is a constant.
		if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion)); err != nil {
			return err
		}
	}
	return nil
}

func hash(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// isConstraint reports whether err is a SQLite UNIQUE or PRIMARY KEY
// violation, using the driver's typed error rather than its message.
func isConstraint(err error) bool {
	var se *sqlite.Error
	if !errors.As(err, &se) {
		return false
	}
	c := se.Code()
	return c == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY || c == sqlite3.SQLITE_CONSTRAINT_UNIQUE
}

// Create makes a token and returns its secret, which is never stored and
// cannot be shown again.
func (s *Store) Create(name string) (string, error) {
	if !nameRE.MatchString(name) {
		return "", ErrBadName
	}
	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil { // never fails since Go 1.24, but a silent zero secret would be catastrophic
		return "", err
	}
	secret := prefix + base64.RawURLEncoding.EncodeToString(b)
	_, err := s.db.Exec(`INSERT INTO bearer_tokens(name, hash, created) VALUES(?, ?, ?)`, name, hash(secret), s.now().Unix())
	if err != nil {
		if isConstraint(err) {
			return "", ErrExists
		}
		return "", err
	}
	return secret, nil
}

// wellFormed rejects input that cannot be a secret we issued, before any
// hashing or database work.
func wellFormed(secret string) bool {
	if len(secret) > maxSecretLen || !strings.HasPrefix(secret, prefix) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(secret[len(prefix):])
	return err == nil && len(raw) == secretBytes
}

// Verify returns the client name for a valid secret and records its use.
// Secrets have 256 bits of entropy, so a plain hash lookup leaks nothing
// useful through timing. The secret never appears in an error.
func (s *Store) Verify(secret string) (string, error) {
	if !wellFormed(secret) {
		return "", ErrInvalid
	}
	var name string
	err := s.db.QueryRow(`SELECT name FROM bearer_tokens WHERE hash = ?`, hash(secret)).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrInvalid
	}
	if err != nil {
		return "", err
	}
	now := s.now().Unix()
	if _, err := s.db.Exec(`UPDATE bearer_tokens SET last_used = ? WHERE name = ? AND last_used < ?`, now, name, now-lastUsedGranularity); err != nil {
		return "", err
	}
	return name, nil
}

// List returns every token, by name.
func (s *Store) List() ([]Record, error) {
	rows, err := s.db.Query(`SELECT name, created, last_used FROM bearer_tokens ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Record
	for rows.Next() {
		var r Record
		var created, last int64
		if err := rows.Scan(&r.Name, &created, &last); err != nil {
			return nil, err
		}
		r.Created = time.Unix(created, 0).UTC()
		if last > 0 {
			r.LastUsed = time.Unix(last, 0).UTC()
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Revoke deletes a token. It takes effect on the next request.
func (s *Store) Revoke(name string) error {
	res, err := s.db.Exec(`DELETE FROM bearer_tokens WHERE name = ?`, name)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Close closes the database. Calling it again is a no-op.
func (s *Store) Close() error { return s.db.Close() }
