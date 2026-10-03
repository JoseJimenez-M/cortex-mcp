package oauth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

const (
	codeTTL         = 60 * time.Second // clients exchange within seconds
	accessTTL       = time.Hour
	refreshTTL      = 30 * 24 * time.Hour
	unusedClientTTL = 24 * time.Hour // a client that never completed a grant
	sweepEvery      = time.Minute

	// Pending (not yet approved) authorization requests are capped, since
	// /authorize is unauthenticated: beyond maxPendingPerClient for one
	// client, or maxPendingAuthRequests overall, the oldest pending ones are
	// deleted. An approved request (done = 1) is never evicted: only the
	// owner can produce one, and its code is about to be exchanged.
	maxPendingPerClient    = 20
	maxPendingAuthRequests = 200
	// ownerSubject is the sub of every token: there is one owner.
	ownerSubject = "owner"
)

// errInvalidCode is the only error a client sees for a bad code.
var errInvalidCode = errors.New("invalid authorization code")

// grantedScopes is what every grant receives: vault grants the tools, and
// offline_access makes the library issue refresh tokens (assistants are
// long-lived connectors; without refresh they would need a login every hour).
func grantedScopes() []string { return []string{Scope, oidc.ScopeOfflineAccess} }

// authRequest is a validated /authorize request (op.AuthRequest). Family is
// chosen here so that a replayed code can revoke what its first use issued.
type authRequest struct {
	ID, ClientID, RedirectURI, State, Nonce, Challenge string
	Scopes                                             []string
	Browser, CSRF, Family                              string
	AMR                                                []string
	AuthTime                                           time.Time
	IsDone                                             bool
	Created                                            time.Time
}

func (a *authRequest) GetID() string    { return a.ID }
func (a *authRequest) GetACR() string   { return "" }
func (a *authRequest) GetAMR() []string { return a.AMR }

// GetAudience is the ID token audience (the client). The access token's
// audience is the MCP endpoint, stored on the grant.
func (a *authRequest) GetAudience() []string  { return []string{a.ClientID} }
func (a *authRequest) GetAuthTime() time.Time { return a.AuthTime }
func (a *authRequest) GetClientID() string    { return a.ClientID }
func (a *authRequest) GetCodeChallenge() *oidc.CodeChallenge {
	return &oidc.CodeChallenge{Challenge: a.Challenge, Method: oidc.CodeChallengeMethodS256}
}
func (a *authRequest) GetNonce() string                   { return a.Nonce }
func (a *authRequest) GetRedirectURI() string             { return a.RedirectURI }
func (a *authRequest) GetResponseType() oidc.ResponseType { return oidc.ResponseTypeCode }
func (a *authRequest) GetResponseMode() oidc.ResponseMode { return oidc.ResponseModeQuery }
func (a *authRequest) GetScopes() []string                { return a.Scopes }
func (a *authRequest) GetState() string                   { return a.State }
func (a *authRequest) GetSubject() string                 { return ownerSubject }
func (a *authRequest) Done() bool                         { return a.IsDone }

// authParams is the request column: the authorize parameters, as validated.
type authParams struct {
	RedirectURI string   `json:"redirect_uri"`
	State       string   `json:"state"`
	Nonce       string   `json:"nonce"`
	Challenge   string   `json:"code_challenge"`
	Scopes      []string `json:"scopes"`
}

const authRequestColumns = `id, client_id, request, browser, csrf, family, amr, auth_time, done, created`

type rowScanner interface{ Scan(dest ...any) error }

func scanAuthRequest(r rowScanner) (*authRequest, error) {
	var a authRequest
	var params, amr string
	var authTime, created int64
	var done int
	err := r.Scan(&a.ID, &a.ClientID, &params, &a.Browser, &a.CSRF, &a.Family, &amr, &authTime, &done, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var p authParams
	if err := json.Unmarshal([]byte(params), &p); err != nil {
		return nil, err
	}
	a.RedirectURI, a.State, a.Nonce, a.Challenge, a.Scopes = p.RedirectURI, p.State, p.Nonce, p.Challenge, p.Scopes
	a.AMR = strings.Fields(amr)
	a.IsDone = done == 1
	a.Created = time.Unix(created, 0)
	if authTime > 0 {
		a.AuthTime = time.Unix(authTime, 0)
	}
	return &a, nil
}

func (s *Store) createAuthRequest(a *authRequest) error {
	p, err := json.Marshal(authParams{RedirectURI: a.RedirectURI, State: a.State, Nonce: a.Nonce, Challenge: a.Challenge, Scopes: a.Scopes})
	if err != nil {
		return err
	}
	return s.tx(func(tx *sql.Tx) error {
		// The client row must still exist: a CIMD revocation can delete it
		// between the library's lookup and this insert.
		res, err := tx.Exec(`INSERT INTO auth_requests(id, client_id, request, browser, csrf, family, created)
			SELECT ?, id, ?, ?, ?, ?, ? FROM oauth_clients WHERE id = ?`,
			a.ID, string(p), a.Browser, a.CSRF, a.Family, a.Created.Unix(), a.ClientID)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return ErrNotFound
		}
		// Newest first (rowid breaks ties within a second); everything past
		// the cap goes. The new row is the newest, so it always stays.
		if _, err := tx.Exec(`DELETE FROM auth_requests WHERE rowid IN (SELECT rowid FROM auth_requests
			WHERE done = 0 AND client_id = ? ORDER BY created DESC, rowid DESC LIMIT -1 OFFSET ?)`, a.ClientID, maxPendingPerClient); err != nil {
			return err
		}
		_, err = tx.Exec(`DELETE FROM auth_requests WHERE rowid IN (SELECT rowid FROM auth_requests
			WHERE done = 0 ORDER BY created DESC, rowid DESC LIMIT -1 OFFSET ?)`, maxPendingAuthRequests)
		return err
	})
}

// authRequest loads a request younger than authRequestTTL, pending or
// approved.
func (s *Store) authRequest(id string) (*authRequest, error) {
	if id == "" || len(id) > 64 {
		return nil, ErrNotFound
	}
	a, err := scanAuthRequest(s.db.QueryRow(`SELECT `+authRequestColumns+` FROM auth_requests WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	if !s.now().Before(a.Created.Add(authRequestTTL)) {
		return nil, ErrNotFound
	}
	return a, nil
}

// completeAuthRequest records the owner's approval. amr is how the owner
// authenticated: "hwk" (passkey) or "otp" (TOTP or recovery code).
func (s *Store) completeAuthRequest(id, amr string) error {
	res, err := s.db.Exec(`UPDATE auth_requests SET done = 1, amr = ?, auth_time = ? WHERE id = ? AND done = 0 AND created > ?`,
		amr, s.unix(), id, s.now().Add(-authRequestTTL).Unix())
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) deleteAuthRequest(id string) error {
	_, err := s.db.Exec(`DELETE FROM auth_requests WHERE id = ?`, id)
	return err
}

// saveAuthCode stores the hash of the code the library minted for an
// approved request, with the request's family.
func (s *Store) saveAuthCode(id, code string) error {
	return s.tx(func(tx *sql.Tx) error {
		// The client must still exist (revocation deletes it concurrently);
		// the code carries the family a grant will be created under.
		var family string
		err := tx.QueryRow(`SELECT r.family FROM auth_requests r JOIN oauth_clients c ON c.id = r.client_id
			WHERE r.id = ? AND r.done = 1 AND r.created > ?
			AND NOT EXISTS (SELECT 1 FROM auth_codes k WHERE k.auth_request_id = r.id)`, id, s.now().Add(-authRequestTTL).Unix()).Scan(&family)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		_, err = tx.Exec(`INSERT INTO auth_codes(hash, auth_request_id, family, expires) VALUES(?, ?, ?, ?)`,
			hashToken(code), id, family, s.now().Add(codeTTL).Unix())
		return err
	})
}

// authRequestByCode redeems a code. A code works once: the first use marks
// it used, and any later use revokes the family the first use created
// (RFC 9700 section 4.4.2), since a replay means the code leaked.
func (s *Store) authRequestByCode(code string) (*authRequest, error) {
	if code == "" || len(code) > 4096 {
		return nil, errInvalidCode
	}
	h := hashToken(code)
	// A plain read first: a code that matches no row (junk, or one swept
	// away) is refused without waiting for the write lock, which every
	// transaction takes at BEGIN (_txlock=immediate). The transaction below
	// reads the row again, so nothing is decided on this read alone.
	if exists, err := s.rowExists(`SELECT 1 FROM auth_codes WHERE hash = ?`, h); err != nil || !exists {
		if err != nil {
			return nil, err
		}
		return nil, errInvalidCode
	}
	var a *authRequest
	err := s.tx(func(tx *sql.Tx) error {
		var reqID, family string
		var used int
		var expires int64
		err := tx.QueryRow(`SELECT auth_request_id, family, used, expires FROM auth_codes WHERE hash = ?`, h).Scan(&reqID, &family, &used, &expires)
		if errors.Is(err, sql.ErrNoRows) {
			return errInvalidCode
		}
		if err != nil {
			return err
		}
		if used == 1 {
			if err := revokeFamilyTx(tx, family); err != nil {
				return err
			}
			return keepErr{errInvalidCode}
		}
		if expires <= s.unix() {
			return errInvalidCode
		}
		if _, err := tx.Exec(`UPDATE auth_codes SET used = 1 WHERE hash = ?`, h); err != nil {
			return err
		}
		got, err := scanAuthRequest(tx.QueryRow(`SELECT `+authRequestColumns+` FROM auth_requests WHERE id = ? AND done = 1`, reqID))
		if errors.Is(err, ErrNotFound) {
			return keepErr{errInvalidCode} // keep the used mark
		}
		if err != nil {
			return err
		}
		a = got
		return nil
	})
	return a, err
}

// sweep deletes expired state at most once a minute. It runs from the
// entry points of a new flow (CreateAuthRequest, /register), so the
// tables stay small without a background goroutine. A failure is retried
// on the next sweep; every read checks expiry itself, so a missed sweep
// never extends a lifetime.
func (s *Store) sweep() {
	now := s.unix()
	last := s.lastSweep.Load()
	if now-last < int64(sweepEvery/time.Second) || !s.lastSweep.CompareAndSwap(last, now) {
		return
	}
	_ = s.tx(func(tx *sql.Tx) error {
		for _, q := range []struct {
			sql string
			arg int64
		}{
			{`DELETE FROM auth_requests WHERE created <= ?`, now - int64(authRequestTTL/time.Second)},
			{`DELETE FROM auth_codes WHERE expires <= ?`, now},
			{`DELETE FROM access_tokens WHERE expires <= ?`, now},
			{`DELETE FROM refresh_tokens WHERE expires <= ?`, now},
			{`DELETE FROM enrollments WHERE expires <= ?`, now},
			{`DELETE FROM grants WHERE created <= ? AND NOT EXISTS (SELECT 1 FROM refresh_tokens r WHERE r.family = grants.family)
				AND NOT EXISTS (SELECT 1 FROM access_tokens a WHERE a.family = grants.family)`, now},
			{`DELETE FROM oauth_clients WHERE created <= ? AND NOT EXISTS (SELECT 1 FROM grants g WHERE g.client_id = oauth_clients.id)
				AND NOT EXISTS (SELECT 1 FROM auth_requests a WHERE a.client_id = oauth_clients.id)`, now - int64(unusedClientTTL/time.Second)},
		} {
			if _, err := tx.Exec(q.sql, q.arg); err != nil {
				return err
			}
		}
		return nil
	})
}
