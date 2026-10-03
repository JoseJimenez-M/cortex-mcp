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
