package oauth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// refreshPrefix marks refresh tokens so a stray one is recognizable in a
// leak scan; the rest is 256 random bits.
const refreshPrefix = "cmcr_"

var (
	errInvalidRefresh     = errors.New("invalid refresh token")
	errRefreshReused      = errors.New("refresh token reused; the connection was revoked")
	errUnsupportedRequest = errors.New("unsupported token request")
)

var _ op.Storage = (*opStorage)(nil)

func wellFormedRefresh(s string) bool {
	rest, ok := strings.CutPrefix(s, refreshPrefix)
	if !ok || len(rest) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(rest)
	return err == nil && len(raw) == 32
}

// refreshRequest is a validated refresh token (op.RefreshTokenRequest).
type refreshRequest struct {
	family, clientID string
	scopes, amr      []string
	authTime         time.Time
}

func (r *refreshRequest) GetAMR() []string            { return r.amr }
func (r *refreshRequest) GetAudience() []string       { return []string{r.clientID} }
func (r *refreshRequest) GetAuthTime() time.Time      { return r.authTime }
func (r *refreshRequest) GetClientID() string         { return r.clientID }
func (r *refreshRequest) GetScopes() []string         { return r.scopes }
func (r *refreshRequest) GetSubject() string          { return ownerSubject }
func (r *refreshRequest) SetCurrentScopes(s []string) { r.scopes = s }

// accessInfo is what the resource server needs from an access token row.
type accessInfo struct {
	Family, ClientID, ClientName string
	Scopes, Audience             []string
	Expires                      time.Time
}

// issueForCode creates the grant (the family chosen at /authorize) and its
// first access and refresh tokens. audience is the MCP endpoint URL.
func (s *Store) issueForCode(a *authRequest, audience string) (string, string, time.Time, error) {
	var accessID, refresh string
	var exp time.Time
	err := s.tx(func(tx *sql.Tx) error {
		now := s.unix()
		// Inside the transaction: the client must still exist (a revocation
		// deletes it) and the family's redeemed code must still exist (a
		// replay revokes the family, deleting it). Either way no grant may
		// appear, because nothing would ever revoke it.
		res, err := tx.Exec(`INSERT INTO grants(family, client_id, scopes, audience, amr, auth_time, created, last_used)
			SELECT ?, c.id, ?, ?, ?, ?, ?, ? FROM oauth_clients c
			WHERE c.id = ? AND EXISTS (SELECT 1 FROM auth_codes k WHERE k.family = ? AND k.used = 1)`,
			a.Family, strings.Join(a.Scopes, " "), audience, strings.Join(a.AMR, " "), a.AuthTime.Unix(), now, now, a.ClientID, a.Family)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return ErrNotFound
		}
		accessID, refresh, exp, err = s.newTokensTx(tx, a.Family, a.Scopes)
		return err
	})
	return accessID, refresh, exp, err
}

func (s *Store) newTokensTx(tx *sql.Tx, family string, scopes []string) (string, string, time.Time, error) {
	now := s.now()
	accessID := rand.Text()
	exp := now.Add(accessTTL)
	if _, err := tx.Exec(`INSERT INTO access_tokens(id, family, scopes, expires) VALUES(?, ?, ?, ?)`,
		accessID, family, strings.Join(scopes, " "), exp.Unix()); err != nil {
		return "", "", time.Time{}, err
	}
	refresh := refreshPrefix + randToken()
	if _, err := tx.Exec(`INSERT INTO refresh_tokens(hash, id, family, expires) VALUES(?, ?, ?, ?)`,
		hashToken(refresh), rand.Text(), family, now.Add(refreshTTL).Unix()); err != nil {
		return "", "", time.Time{}, err
	}
	return accessID, refresh, exp, nil
}

// refreshByToken validates a presented refresh token. A rotated one is a
// replay: the whole family is revoked (RFC 9700 section 4.14.2).
func (s *Store) refreshByToken(token string) (*refreshRequest, error) {
	if !wellFormedRefresh(token) {
		return nil, errInvalidRefresh
	}
	var r *refreshRequest
	err := s.tx(func(tx *sql.Tx) error {
		var family, clientID, scopes, amr string
		var expires, authTime int64
		var rotated int
		err := tx.QueryRow(`SELECT r.family, r.expires, r.rotated, g.client_id, g.scopes, g.amr, g.auth_time
			FROM refresh_tokens r JOIN grants g ON g.family = r.family JOIN oauth_clients c ON c.id = g.client_id
			WHERE r.hash = ?`, hashToken(token)).Scan(&family, &expires, &rotated, &clientID, &scopes, &amr, &authTime)
		if errors.Is(err, sql.ErrNoRows) {
			return errInvalidRefresh
		}
		if err != nil {
			return err
		}
		if rotated == 1 {
			if err := revokeFamilyTx(tx, family); err != nil {
				return err
			}
			return keepErr{errRefreshReused}
		}
		if expires <= s.unix() {
			return errInvalidRefresh
		}
		r = &refreshRequest{family: family, clientID: clientID, scopes: strings.Fields(scopes), amr: strings.Fields(amr), authTime: time.Unix(authTime, 0)}
		return nil
	})
	return r, err
}

// rotate marks the presented token used and issues the next pair in the
// same family. Losing the race on the used mark means another request
// already rotated it: that is reuse, and the family is revoked.
func (s *Store) rotate(r *refreshRequest, presented string) (string, string, time.Time, error) {
	var accessID, refresh string
	var exp time.Time
	err := s.tx(func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE refresh_tokens SET rotated = 1 WHERE hash = ? AND family = ? AND rotated = 0`, hashToken(presented), r.family)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			if err := revokeFamilyTx(tx, r.family); err != nil {
				return err
			}
			return keepErr{errRefreshReused}
		}
		var grants int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM grants g JOIN oauth_clients c ON c.id = g.client_id WHERE g.family = ?`, r.family).Scan(&grants); err != nil {
			return err
		}
		if grants == 0 {
			return errInvalidRefresh
		}
		accessID, refresh, exp, err = s.newTokensTx(tx, r.family, r.scopes)
		if err != nil {
			return err
		}
		_, err = tx.Exec(`UPDATE grants SET last_used = ? WHERE family = ?`, s.unix(), r.family)
		return err
	})
	return accessID, refresh, exp, err
}

// lookupAccess is the resource server's lookup: the token row, its grant,
// and its client must all exist.
func (s *Store) lookupAccess(id string) (accessInfo, error) {
	if id == "" || len(id) > 64 {
		return accessInfo{}, ErrNotFound
	}
	var a accessInfo
	var scopes, audience string
	var expires int64
	err := s.db.QueryRow(`SELECT a.family, a.scopes, a.expires, g.client_id, g.audience, c.name
		FROM access_tokens a JOIN grants g ON g.family = a.family JOIN oauth_clients c ON c.id = g.client_id
		WHERE a.id = ?`, id).Scan(&a.Family, &scopes, &expires, &a.ClientID, &audience, &a.ClientName)
	if errors.Is(err, sql.ErrNoRows) {
		return accessInfo{}, ErrNotFound
	}
	if err != nil {
		return accessInfo{}, err
	}
	a.Scopes, a.Audience, a.Expires = strings.Fields(scopes), strings.Fields(audience), time.Unix(expires, 0)
	return a, nil
}

// familyOfToken finds the family of an access token id, a refresh token id,
// or a raw refresh token, for /revoke.
func (s *Store) familyOfToken(tokenOrID string) (string, string, error) {
	if tokenOrID == "" || len(tokenOrID) > 4096 {
		return "", "", ErrNotFound
	}
	var family, clientID string
	err := s.db.QueryRow(`SELECT a.family, g.client_id FROM access_tokens a JOIN grants g ON g.family = a.family WHERE a.id = ?
		UNION ALL
		SELECT r.family, g.client_id FROM refresh_tokens r JOIN grants g ON g.family = r.family WHERE r.id = ? OR r.hash = ?
		LIMIT 1`, tokenOrID, tokenOrID, hashToken(tokenOrID)).Scan(&family, &clientID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrNotFound
	}
	return family, clientID, err
}

func (s *Store) revokeFamily(family string) error {
	return s.tx(func(tx *sql.Tx) error { return revokeFamilyTx(tx, family) })
}

func (s *Store) refreshID(token string) (string, error) {
	var id string
	err := s.db.QueryRow(`SELECT id FROM refresh_tokens WHERE hash = ?`, hashToken(token)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return id, err
}

// CreateAccessToken is the library's path for a grant without a refresh
// token. Every grant here has offline_access and the refresh_token grant,
// so the library never takes it; refusing keeps a grant from ever existing
// without its refresh token.
func (o *opStorage) CreateAccessToken(context.Context, op.TokenRequest) (string, time.Time, error) {
	return "", time.Time{}, errUnsupportedRequest
}

// CreateAccessAndRefreshTokens issues tokens for a code exchange (a new
// grant) or a refresh (rotation within the family).
func (o *opStorage) CreateAccessAndRefreshTokens(_ context.Context, req op.TokenRequest, current string) (string, string, time.Time, error) {
	switch r := req.(type) {
	case *authRequest:
		if current != "" {
			return "", "", time.Time{}, errUnsupportedRequest
		}
		id, refresh, exp, err := o.s.issueForCode(r, o.mcpURL)
		if err != nil {
			if !errors.Is(err, ErrNotFound) {
				o.logger.Error("issue tokens failed", "err", err)
			}
			return "", "", time.Time{}, errStorage
		}
		return id, refresh, exp, nil
	case *refreshRequest:
		id, refresh, exp, err := o.s.rotate(r, current)
		switch {
		case err == nil:
			return id, refresh, exp, nil
		case errors.Is(err, errRefreshReused), errors.Is(err, errInvalidRefresh):
			return "", "", time.Time{}, oidc.ErrInvalidGrant().WithDescription("the refresh token is no longer valid").WithParent(err)
		}
		o.logger.Error("refresh rotation failed", "err", err)
		return "", "", time.Time{}, errStorage
	}
	return "", "", time.Time{}, errUnsupportedRequest
}

func (o *opStorage) TokenRequestByRefreshToken(_ context.Context, token string) (op.RefreshTokenRequest, error) {
	r, err := o.s.refreshByToken(token)
	if err != nil {
		if !errors.Is(err, errInvalidRefresh) && !errors.Is(err, errRefreshReused) {
			o.logger.Error("refresh lookup failed", "err", err)
			return nil, errStorage
		}
		return nil, err
	}
	return r, nil
}

// GetRefreshTokenInfo lets /revoke turn a refresh token into its id. It
// must return op.ErrInvalidRefreshToken for anything else, so the library
// then tries the value as an access token.
func (o *opStorage) GetRefreshTokenInfo(_ context.Context, _ string, token string) (string, string, error) {
	if !wellFormedRefresh(token) {
		return "", "", op.ErrInvalidRefreshToken
	}
	id, err := o.s.refreshID(token)
	if errors.Is(err, ErrNotFound) {
		return "", "", op.ErrInvalidRefreshToken
	}
	if err != nil {
		o.logger.Error("refresh token info failed", "err", err)
		return "", "", errStorage
	}
	return ownerSubject, id, nil
}

// RevokeToken revokes the whole family of the token (RFC 7009 allows
// revoking related tokens; a client revoking either token is disconnecting).
// Unknown tokens are not an error (RFC 7009 section 2.2); a token of another
// client is.
func (o *opStorage) RevokeToken(_ context.Context, tokenOrID, _ string, clientID string) *oidc.Error {
	family, owner, err := o.s.familyOfToken(tokenOrID)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		o.logger.Error("revoke lookup failed", "err", err)
		return oidc.ErrServerError()
	}
	if owner != clientID {
		return oidc.ErrInvalidClient().WithDescription("the token was issued to another client")
	}
	if err := o.s.revokeFamily(family); err != nil {
		o.logger.Error("revoke failed", "err", err)
		return oidc.ErrServerError()
	}
	return nil
}

// TerminateSession serves end_session, which is not mounted. There are no
// browser sessions to end: approval is per authorization request.
func (o *opStorage) TerminateSession(context.Context, string, string) error { return nil }
