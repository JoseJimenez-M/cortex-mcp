package oauth

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	ceremonyTTL = 5 * time.Minute
	// maxCeremonies bounds the open WebAuthn challenges. Passkey begins are
	// charged to the source only (loginPages.admitPasskey), so the bound
	// comes from what a begin needs: a login ceremony is keyed by a live
	// auth request, and auth requests are created only through /authorize,
	// whose global limiter and pending cap bound how many distinct ones can
	// be begun within one ceremonyTTL (TestCeremonyCapExceedsTheLoginBudget);
	// a registration ceremony needs an enrollment link, which only the owner
	// has. About 300 bytes each.
	maxCeremonies      = 1024
	maxCredentialBytes = 64 << 10
	maxEnrollBodyBytes = 4 << 10

	// csrfHeader carries the login page's CSRF token on the passkey
	// fetches. A header, not the query string, keeps the token out of
	// access logs and history; a custom header also makes any cross-origin
	// attempt a CORS preflight, which this server never answers.
	csrfHeader = "X-CSRF-Token"

	// enrollSessionHeader carries the registration ceremony key from
	// /enroll/begin to /enroll/finish, outside the URL for the same reason.
	enrollSessionHeader = "X-Enroll-Session"
)

var (
	// errCounterNotIncreased: the stored sign count is not below the new
	// one, so another login recorded it first; treated as a clone signal.
	errCounterNotIncreased = errors.New("passkey sign count did not increase")
	errPasskeyExists       = errors.New("passkey already registered")
)

// ownerUser is the single owner as a WebAuthn user.
type ownerUser struct {
	id    []byte
	creds []webauthn.Credential
}

func (u *ownerUser) WebAuthnID() []byte                         { return u.id }
func (u *ownerUser) WebAuthnName() string                       { return "owner" }
func (u *ownerUser) WebAuthnDisplayName() string                { return "cortex-mcp owner" }
func (u *ownerUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (s *Store) ownerUser() (*ownerUser, error) {
	u := &ownerUser{}
	err := s.db.QueryRow(`SELECT webauthn_id FROM owner WHERE id = 1`).Scan(&u.id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotSetUp
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT credential FROM passkeys ORDER BY created, id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var c webauthn.Credential
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, err
		}
		u.creds = append(u.creds, c)
	}
	return u, rows.Err()
}

func (s *Store) addPasskey(c *webauthn.Credential) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	res, err := s.db.Exec(`INSERT INTO passkeys(id, credential, created) VALUES(?, ?, ?) ON CONFLICT(id) DO NOTHING`, c.ID, raw, s.unix())
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return errPasskeyExists
	}
	return nil
}

// updatePasskey stores the new signature counter and flags after a login.
// The UPDATE is conditional on the stored count being lower (or both being
// zero, for authenticators that never count), so of two logins validated
// against the same stored count only the first is recorded; the other gets
// errCounterNotIncreased. signCount is omitted from the JSON when zero,
// hence the COALESCE; CAST keeps SQLite from reading the BLOB as JSONB.
func (s *Store) updatePasskey(c *webauthn.Credential) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	n := int64(c.Authenticator.SignCount)
	res, err := s.db.Exec(`UPDATE passkeys SET credential = ?, last_used = ? WHERE id = ? AND (
		COALESCE(json_extract(CAST(credential AS TEXT), '$.authenticator.signCount'), 0) < ?
		OR (? = 0 AND COALESCE(json_extract(CAST(credential AS TEXT), '$.authenticator.signCount'), 0) = 0))`,
		raw, s.unix(), c.ID, n, n)
	if err != nil {
		return err
	}
	if rows, err := res.RowsAffected(); err != nil || rows != 1 {
		return errCounterNotIncreased
	}
	return nil
}

// readBody reads at most limit bytes of r's body. On failure it answers
// with fixed text: "too large" for an oversized body, a generic message
// for anything else (the cause is never echoed).
func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err == nil {
		return body, true
	}
	if mbe := (*http.MaxBytesError)(nil); errors.As(err, &mbe) {
		oauthError(w, http.StatusRequestEntityTooLarge, "invalid_request", "the request body is too large")
	} else {
		oauthError(w, http.StatusBadRequest, "invalid_request", "the request body could not be read")
	}
	return nil, false
}

// ceremonies holds WebAuthn challenges between begin and finish, in memory:
// they live minutes, and a restart only cancels ceremonies in progress.
type ceremonies struct {
	mu  sync.Mutex
	m   map[string]ceremony
	now func() time.Time
}

type ceremony struct {
	data    webauthn.SessionData
	expires time.Time
}

func newCeremonies(now func() time.Time) *ceremonies {
	return &ceremonies{m: map[string]ceremony{}, now: now}
}

// put stores a ceremony, replacing one under the same key (a login button
// pressed twice); false when maxCeremonies others are already open, which
// bounds memory against a flood of begin requests (see maxCeremonies for
// why admitted begins alone cannot reach the cap).
func (c *ceremonies) put(key string, d *webauthn.SessionData) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for k, v := range c.m {
		if !now.Before(v.expires) {
			delete(c.m, k)
		}
	}
	if _, replacing := c.m[key]; !replacing && len(c.m) >= maxCeremonies {
		return false
	}
	c.m[key] = ceremony{data: *d, expires: now.Add(ceremonyTTL)}
	return true
}

// take removes and returns a ceremony: each challenge is answered once.
func (c *ceremonies) take(key string) (webauthn.SessionData, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[key]
	delete(c.m, key)
	if !ok || !c.now().Before(v.expires) {
		return webauthn.SessionData{}, false
	}
	return v.data, true
}

// passkeys serves passkey enrollment and passkey login.
type passkeys struct {
	store  *Store
	wa     *webauthn.WebAuthn
	cer    *ceremonies
	login  *loginPages
	logger *slog.Logger
}

// newPasskeys fails when public_url's host cannot be a relying party id
// (an IP address); the caller then runs without passkeys. The relying
// party id is the host of public_url and the only accepted origin is
// public_url's scheme://host[:port], compared exactly by the library.
func newPasskeys(store *Store, base string, login *loginPages, logger *slog.Logger) (*passkeys, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          u.Hostname(),
		RPDisplayName: "cortex-mcp",
		RPOrigins:     []string{u.Scheme + "://" + u.Host},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		},
	})
	if err != nil {
		return nil, err
	}
	return &passkeys{store: store, wa: wa, cer: newCeremonies(store.now), login: login, logger: logger}, nil
}

// refuseTooMany answers a request the login limiter refused.
func refuseTooMany(w http.ResponseWriter, d time.Duration) {
	w.Header().Set("Retry-After", retryAfter(d))
	oauthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "too many attempts")
}

// beginLogin is POST /login/passkey/begin?id=... with the CSRF token in the
// csrfHeader header. Begin and finish are each charged to the source's
// bucket (admitPasskey), never to the global login bucket: a passkey cannot
// be guessed, so the global budget only has to bound guessable codes.
func (p *passkeys) beginLogin(w http.ResponseWriter, r *http.Request) {
	a, err := p.login.pendingWithCSRF(r, r.URL.Query().Get("id"), r.Header.Get(csrfHeader))
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "sign-in request not valid in this browser")
		return
	}
	if d, ok := p.login.admitPasskey(r); !ok {
		refuseTooMany(w, d)
		return
	}
	if n, err := p.store.passkeyCount(); err != nil || n == 0 {
		oauthError(w, http.StatusBadRequest, "invalid_request", "no passkey is registered")
		return
	}
	assertion, sess, err := p.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		p.logger.Error("passkey login could not start", "err", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "passkey login could not start")
		return
	}
	if !p.cer.put("login:"+a.ID, sess) {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "too many passkey ceremonies in progress")
		return
	}
	writeJSON(w, http.StatusOK, assertion)
}

// finishLogin is POST /login/passkey/finish?id=... with the CSRF token in
// the csrfHeader header and the assertion as the body. The ceremony is
// keyed by the auth request, which pendingWithCSRF has tied to this
// browser, so an assertion only completes the request it was begun for.
func (p *passkeys) finishLogin(w http.ResponseWriter, r *http.Request) {
	a, err := p.login.pendingWithCSRF(r, r.URL.Query().Get("id"), r.Header.Get(csrfHeader))
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "sign-in request not valid in this browser")
		return
	}
	// Charged before the ceremony is taken, so a refused finish leaves it
	// open for a retry.
	if d, ok := p.login.admitPasskey(r); !ok {
		refuseTooMany(w, d)
		return
	}
	sess, ok := p.cer.take("login:" + a.ID)
	if !ok {
		oauthError(w, http.StatusBadRequest, "invalid_request", "the passkey prompt expired; try again")
		return
	}
	body, ok := readBody(w, r, maxCredentialBytes)
	if !ok {
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "the passkey response is not valid")
		return
	}
	owner, err := p.store.ownerUser()
	if err != nil {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "the owner is not set up")
		return
	}
	handler := func(_, userHandle []byte) (webauthn.User, error) {
		if subtle.ConstantTimeCompare(userHandle, owner.id) != 1 {
			return nil, errors.New("unknown user handle")
		}
		return owner, nil
	}
	_, cred, err := p.wa.ValidatePasskeyLogin(handler, sess, parsed)
	if err != nil {
		p.logger.Warn("passkey login failed", "err", err)
		oauthError(w, http.StatusUnauthorized, "access_denied", "passkey not accepted")
		return
	}
	// The library flags a counter that did not grow (both zero is allowed:
	// many synced passkeys never count). The stored counter is left as it
	// was, so the genuine authenticator keeps working.
	if cred.Authenticator.CloneWarning {
		p.logger.Warn("passkey refused: its signature counter did not increase, the authenticator may be cloned",
			"client_id", a.ClientID)
		oauthError(w, http.StatusUnauthorized, "access_denied", "passkey not accepted")
		return
	}
	if err := p.store.updatePasskey(cred); errors.Is(err, errCounterNotIncreased) {
		p.logger.Warn("passkey refused: another login already recorded this signature counter, the authenticator may be cloned",
			"client_id", a.ClientID)
		oauthError(w, http.StatusUnauthorized, "access_denied", "passkey not accepted")
		return
	} else if err != nil {
		p.logger.Error("passkey update failed", "err", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "sign-in failed")
		return
	}
	// A passkey is a stronger factor than TOTP: proving it clears the TOTP
	// failure count and with it the lock.
	if err := p.store.loginSucceeded(); err != nil {
		p.logger.Error("login bookkeeping failed", "err", err)
	}
	if err := p.store.completeAuthRequest(a.ID, "hwk"); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "sign-in request not valid")
		return
	}
	p.logger.Info("connection approved", "client_id", a.ClientID, "amr", "hwk")
	writeJSON(w, http.StatusOK, map[string]string{"redirect": p.login.callbackURL(a.ID)})
}

// enrollPage is GET /enroll. The page reads the token from the URL fragment
// (never sent to the server or a proxy log), asks for a TOTP code, and runs
// the registration ceremony.
func (p *passkeys) enrollPage(w http.ResponseWriter, _ *http.Request) { renderEnroll(w) }

// beginEnroll is POST /enroll/begin with {"token", "code"}. The token is
// looked up first (a cheap check of a 256-bit secret), so a request without
// a live link is refused before any rate-limit bucket is charged and never
// counts a TOTP failure. Only then is the TOTP check charged like a login
// attempt (admit), and a wrong code never burns the link; the link is
// consumed by startEnrollment, which is the gate.
func (p *passkeys) beginEnroll(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
		Code  string `json:"code"`
	}
	body, ok := readBody(w, r, maxEnrollBodyBytes)
	if !ok {
		return
	}
	if json.Unmarshal(body, &in) != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "the request is not valid JSON")
		return
	}
	expired := "this enrollment link is not valid or has expired; run cortex-mcp setup -passkey for a new one"
	if ok, err := p.store.enrollmentValid(in.Token); err != nil || !ok {
		oauthError(w, http.StatusBadRequest, "invalid_request", expired)
		return
	}
	if d, ok := p.login.admit(r); !ok {
		refuseTooMany(w, d)
		return
	}
	if err := p.store.verifyTOTP(in.Code); err != nil {
		desc := "authenticator code not accepted"
		if errors.Is(err, errTOTPLocked) || errors.Is(err, errTOTPJustLocked) {
			desc = "authenticator codes are locked after too many failures; log in with a recovery code first"
		}
		oauthError(w, http.StatusUnauthorized, "access_denied", desc)
		return
	}
	key, creation, err := p.startEnrollment(in.Token)
	switch {
	case errors.Is(err, ErrNotFound):
		oauthError(w, http.StatusBadRequest, "invalid_request", expired)
		return
	case errors.Is(err, errCeremoniesFull):
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "too many passkey ceremonies in progress")
		return
	case err != nil:
		p.logger.Error("passkey registration could not start", "err", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "registration could not start")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"session": key, "options": creation})
}

var errCeremoniesFull = errors.New("too many passkey ceremonies in progress")

// startEnrollment consumes the enrollment link (a single-use DELETE) and
// only then opens a registration ceremony. Two requests racing on one link
// cannot both pass the DELETE, so at most one ceremony, and so at most one
// credential, comes from each link. It returns ErrNotFound when the link
// is gone.
func (p *passkeys) startEnrollment(token string) (string, *protocol.CredentialCreation, error) {
	if err := p.store.consumeEnrollment(token); err != nil {
		return "", nil, err
	}
	owner, err := p.store.ownerUser()
	if err != nil {
		return "", nil, err
	}
	creation, sess, err := p.wa.BeginRegistration(owner,
		webauthn.WithExclusions(webauthn.Credentials(owner.creds).CredentialDescriptors()))
	if err != nil {
		return "", nil, err
	}
	key := rand.Text()
	if !p.cer.put("enroll:"+key, sess) {
		return "", nil, errCeremoniesFull
	}
	return key, creation, nil
}

// finishEnroll is POST /enroll/finish with the ceremony key in the
// enrollSessionHeader header and the attestation as the body.
// The session key is a random value from startEnrollment, not a secret
// that outlives the ceremony: it is single use and expires in ceremonyTTL.
func (p *passkeys) finishEnroll(w http.ResponseWriter, r *http.Request) {
	sess, ok := p.cer.take("enroll:" + r.Header.Get(enrollSessionHeader))
	if !ok {
		oauthError(w, http.StatusBadRequest, "invalid_request", "the registration expired; run cortex-mcp setup -passkey for a new link")
		return
	}
	body, ok := readBody(w, r, maxCredentialBytes)
	if !ok {
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "the passkey response is not valid")
		return
	}
	owner, err := p.store.ownerUser()
	if err != nil {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "the owner is not set up")
		return
	}
	cred, err := p.wa.CreateCredential(owner, sess, parsed)
	if err != nil {
		p.logger.Warn("passkey registration refused", "err", err)
		oauthError(w, http.StatusBadRequest, "invalid_request", "the passkey was not accepted")
		return
	}
	switch err := p.store.addPasskey(cred); {
	case errors.Is(err, errPasskeyExists):
		oauthError(w, http.StatusConflict, "invalid_request", "this passkey is already registered")
		return
	case err != nil:
		p.logger.Error("passkey could not be stored", "err", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "the passkey could not be saved")
		return
	}
	p.logger.Info("passkey registered")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
