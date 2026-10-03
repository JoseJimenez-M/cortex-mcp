// Package tokens stores Bearer tokens for clients that cannot run an OAuth
// login (CLI agents, scripts). Only SHA-256 hashes are stored.
package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/JoseJimenez-M/cortex-mcp/internal/authdb"
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

// Identity names the token row a secret belongs to. Name is the operator's
// label and can be reused after a revoke; ID is random per row and is never
// reused, so it is what an MCP session must be bound to.
type Identity struct {
	Name string
	ID   string
}

// Store is the token table inside the auth database. It is safe for
// concurrent use.
type Store struct {
	db    *sql.DB
	now   func() time.Time
	owned bool // Close closes db only when Open created it
}

// Open opens the auth database at path on its own connection (the token
// commands use this) and returns its token table. See authdb.Open for the
// file permissions and migrations.
func Open(path string) (*Store, error) {
	db, err := authdb.Open(path)
	if err != nil {
		return nil, err
	}
	return &Store{db: db, now: time.Now, owned: true}, nil
}

// New returns the token table of an auth database the caller opened with
// authdb.Open. The caller keeps ownership: Close leaves db open, so serve
// can share one connection between tokens and OAuth.
func New(db *sql.DB) *Store {
	return &Store{db: db, now: time.Now}
}

// IsBearer reports whether s has the shape of a secret from Create. The
// server uses it to route a presented token to this store or to OAuth
// without a database lookup; OAuth access tokens never start with prefix.
func IsBearer(s string) bool { return strings.HasPrefix(s, prefix) }

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
	// rand.Text has 130 bits of entropy: an id is never reused in practice,
	// and the UNIQUE index rejects the impossible collision.
	_, err := s.db.Exec(`INSERT INTO bearer_tokens(name, hash, created, id) VALUES(?, ?, ?, ?)`, name, hash(secret), s.now().Unix(), rand.Text())
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

// Verify returns the identity of a valid secret's token and records its use.
// Secrets have 256 bits of entropy, so a plain hash lookup leaks nothing
// useful through timing. The secret never appears in an error.
func (s *Store) Verify(secret string) (Identity, error) {
	if !wellFormed(secret) {
		return Identity{}, ErrInvalid
	}
	var id Identity
	err := s.db.QueryRow(`SELECT name, id FROM bearer_tokens WHERE hash = ?`, hash(secret)).Scan(&id.Name, &id.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return Identity{}, ErrInvalid
	}
	if err != nil {
		return Identity{}, err
	}
	now := s.now().Unix()
	if _, err := s.db.Exec(`UPDATE bearer_tokens SET last_used = ? WHERE name = ? AND last_used < ?`, now, id.Name, now-lastUsedGranularity); err != nil {
		return Identity{}, err
	}
	return id, nil
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

// Close closes the database if Open created it. Calling it again is a no-op.
func (s *Store) Close() error {
	if !s.owned {
		return nil
	}
	return s.db.Close()
}
