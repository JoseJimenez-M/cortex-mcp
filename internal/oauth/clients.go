package oauth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"time"
)

const (
	kindDCR  = "dcr"  // registered through /register (RFC 7591)
	kindCIMD = "cimd" // a client ID metadata document, fetched and cached
)

// clientRow is one OAuth client as stored. Name has passed cleanName and
// every redirect URI passed the allowlist when the row was written.
type clientRow struct {
	ID           string
	Kind         string
	Name         string
	RedirectURIs []string
	Created      time.Time
	Fetched      time.Time // CIMD only: when the document was last fetched
}

func (s *Store) insertClient(c clientRow) error {
	uris, err := json.Marshal(c.RedirectURIs)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO oauth_clients(id, kind, name, redirect_uris, created, fetched) VALUES(?, ?, ?, ?, ?, ?)`,
		c.ID, c.Kind, c.Name, string(uris), c.Created.Unix(), unixOrZero(c.Fetched))
	return err
}

// saveCIMD stores a freshly fetched document, keeping the original created
// time when the client was already known.
func (s *Store) saveCIMD(c clientRow) error {
	uris, err := json.Marshal(c.RedirectURIs)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO oauth_clients(id, kind, name, redirect_uris, created, fetched) VALUES(?, 'cimd', ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET name = excluded.name, redirect_uris = excluded.redirect_uris, fetched = excluded.fetched`,
		c.ID, c.Name, string(uris), c.Created.Unix(), c.Fetched.Unix())
	return err
}

// authRequestTTL is how long an authorization request stays valid. It is
// also the minimum age of a never-used DCR client before registration may
// evict it.
//
// Trade-off: a login in progress for a DCR client older than this can be
// lost when registrations churn the table, because the client row and its
// requests are evicted. That is deliberate. Exempting every client with an
// open request would let an attacker pin slots by opening requests, since
// /authorize is unauthenticated. The one exemption is a request the owner
// has already approved (done = 1, which keys on the request's created time, see registerDCR): only the owner can
// produce that state. dcr_test.go asserts that an attacker alone, limited
// by the registration rate, can never fill the table with clients younger
// than this and so cannot cause 503s.
const authRequestTTL = 10 * time.Minute

// errRegistryFull means the never-used client table is full and nothing in
// it is old enough to evict.
var errRegistryFull = errors.New("client registry full")

// registerDCR inserts a DCR client atomically with the capacity check. Only
// never-used clients (no grant) count against maxUnused. When full, the
// oldest never-used client created at least minAge ago is evicted to make
// room; if there is none, errRegistryFull. Clients with grants are never
// counted or evicted, and neither is one with an owner-approved request
// created within the last authRequestTTL (its code is about to be exchanged).
func (s *Store) registerDCR(c clientRow, maxUnused int, minAge time.Duration) error {
	uris, err := json.Marshal(c.RedirectURIs)
	if err != nil {
		return err
	}
	return s.tx(func(tx *sql.Tx) error {
		const unused = `kind = 'dcr' AND NOT EXISTS (SELECT 1 FROM grants g WHERE g.client_id = oauth_clients.id)`
		var n int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM oauth_clients WHERE ` + unused).Scan(&n); err != nil {
			return err
		}
		if n >= maxUnused {
			var victim string
			err := tx.QueryRow(`SELECT id FROM oauth_clients WHERE `+unused+` AND created <= ?
				AND NOT EXISTS (SELECT 1 FROM auth_requests a WHERE a.client_id = oauth_clients.id AND a.done = 1 AND a.created > ?)
				ORDER BY created, id LIMIT 1`,
				s.now().Add(-minAge).Unix(), s.now().Add(-authRequestTTL).Unix()).Scan(&victim)
			if errors.Is(err, sql.ErrNoRows) {
				return errRegistryFull
			}
			if err != nil {
				return err
			}
			if _, err := tx.Exec(`DELETE FROM auth_requests WHERE client_id = ?`, victim); err != nil {
				return err
			}
			if _, err := tx.Exec(`DELETE FROM oauth_clients WHERE id = ?`, victim); err != nil {
				return err
			}
		}
		_, err = tx.Exec(`INSERT INTO oauth_clients(id, kind, name, redirect_uris, created, fetched) VALUES(?, ?, ?, ?, ?, 0)`,
			c.ID, c.Kind, c.Name, string(uris), c.Created.Unix())
		return err
	})
}

func (s *Store) clientByID(id string) (clientRow, error) {
	if id == "" || len(id) > maxRedirectURIBytes {
		return clientRow{}, ErrNotFound
	}
	var c clientRow
	var uris string
	var created, fetched int64
	err := s.db.QueryRow(`SELECT id, kind, name, redirect_uris, created, fetched FROM oauth_clients WHERE id = ?`, id).
		Scan(&c.ID, &c.Kind, &c.Name, &uris, &created, &fetched)
	if errors.Is(err, sql.ErrNoRows) {
		return clientRow{}, ErrNotFound
	}
	if err != nil {
		return clientRow{}, err
	}
	if err := json.Unmarshal([]byte(uris), &c.RedirectURIs); err != nil {
		return clientRow{}, err
	}
	c.Created = time.Unix(created, 0)
	if fetched > 0 {
		c.Fetched = time.Unix(fetched, 0)
	}
	return c, nil
}

func (s *Store) countClients(kind string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM oauth_clients WHERE kind = ?`, kind).Scan(&n)
	return n, err
}

// ClientRecord describes an OAuth client for cortex-mcp clients list.
type ClientRecord struct {
	ID            string
	Kind          string // "dcr" or "cimd"
	Name          string
	RedirectHosts []string // the hosts a code can be sent to, for recognizing the client
	Created       time.Time
	LastUsed      time.Time // the latest grant activity; zero if none
	Grants        int       // live connections (token families)
}

// ListClients returns every OAuth client, oldest first.
func (s *Store) ListClients() ([]ClientRecord, error) {
	rows, err := s.db.Query(`SELECT c.id, c.kind, c.name, c.redirect_uris, c.created, COUNT(g.family), COALESCE(MAX(g.last_used), 0)
		FROM oauth_clients c LEFT JOIN grants g ON g.client_id = c.id
		GROUP BY c.id ORDER BY c.created, c.id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []ClientRecord
	for rows.Next() {
		var r ClientRecord
		var uris string
		var created, last int64
		if err := rows.Scan(&r.ID, &r.Kind, &r.Name, &uris, &created, &r.Grants, &last); err != nil {
			return nil, err
		}
		var list []string
		if err := json.Unmarshal([]byte(uris), &list); err != nil {
			return nil, err
		}
		for _, u := range list {
			if p, err := url.Parse(u); err == nil && !slices.Contains(r.RedirectHosts, p.Hostname()) {
				r.RedirectHosts = append(r.RedirectHosts, p.Hostname())
			}
		}
		r.Created = time.Unix(created, 0).UTC()
		if last > 0 {
			r.LastUsed = time.Unix(last, 0).UTC()
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RevokeClient deletes a client and everything it holds: its grants, their
// tokens, and pending authorization requests. A DCR client id is dead for
// good; a CIMD client can be fetched again, but only a new owner login can
// give it access. Revoking one client never touches another.
func (s *Store) RevokeClient(id string) error {
	return s.tx(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT family FROM grants WHERE client_id = ?`, id)
		if err != nil {
			return err
		}
		var families []string
		for rows.Next() {
			var f string
			if err := rows.Scan(&f); err != nil {
				_ = rows.Close()
				return err
			}
			families = append(families, f)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, f := range families {
			if err := revokeFamilyTx(tx, f); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(`DELETE FROM auth_requests WHERE client_id = ?`, id); err != nil {
			return err
		}
		res, err := tx.Exec(`DELETE FROM oauth_clients WHERE id = ?`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 && len(families) == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// revokeFamilyTx deletes a grant and every token and code of its family.
func revokeFamilyTx(tx *sql.Tx, family string) error {
	for _, q := range []string{
		`DELETE FROM access_tokens WHERE family = ?`,
		`DELETE FROM refresh_tokens WHERE family = ?`,
		`DELETE FROM auth_codes WHERE family = ?`,
		`DELETE FROM grants WHERE family = ?`,
	} {
		if _, err := tx.Exec(q, family); err != nil {
			return err
		}
	}
	return nil
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}
