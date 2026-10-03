package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync/atomic"
	"time"
)

// Scope is the one OAuth scope; it grants the 12 vault tools (spec 6.2).
const Scope = "vault"

var (
	// ErrNotFound means no row matches: an unknown client, token, or request.
	ErrNotFound = errors.New("not found")
	// ErrNotSetUp means the owner has not run cortex-mcp setup.
	ErrNotSetUp = errors.New("OAuth is not set up: run cortex-mcp setup")
	// ErrAlreadySetUp means setup already ran; reset-auth starts over.
	ErrAlreadySetUp = errors.New("OAuth is already set up")
)

// Store is the OAuth state inside the auth database. It is safe for
// concurrent use. now is injected so tests can expire things.
type Store struct {
	db        *sql.DB
	now       func() time.Time
	lastSweep atomic.Int64 // Unix seconds of the last sweep
}

// NewStore returns the OAuth state of a database opened with authdb.Open.
// The caller keeps ownership of db. A nil now means time.Now.
func NewStore(db *sql.DB, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{db: db, now: now}
}

func (s *Store) unix() int64 { return s.now().Unix() }

// keepErr marks an error that must not undo the transaction's writes: reuse
// detection revokes a token family and still fails the request.
type keepErr struct{ error }

func (e keepErr) Unwrap() error { return e.error }

// tx runs fn in a transaction. fn must use only the *sql.Tx it receives
// (the database has one connection). A plain error rolls back; a keepErr
// commits and then returns the wrapped error.
func (s *Store) tx(fn func(*sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	err = fn(tx)
	var keep keepErr
	if err != nil && !errors.As(err, &keep) {
		_ = tx.Rollback()
		return err
	}
	if cerr := tx.Commit(); cerr != nil {
		return cerr
	}
	if err != nil {
		return keep.error
	}
	return nil
}

// hashToken is how every stored secret is kept: all of them carry at least
// 80 bits of entropy, so a fast hash leaks nothing useful.
func hashToken(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

//lint:ignore U1000 -- used by browser binding in a later task
func hashHex(s string) string { return hex.EncodeToString(hashToken(s)) }

// randBytes returns n random bytes. crypto/rand.Read never fails since Go
// 1.24 (it crashes the program instead), so there is no error to handle.
func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// randToken is a 256-bit secret in 43 base64url characters.
func randToken() string { return base64.RawURLEncoding.EncodeToString(randBytes(32)) }
