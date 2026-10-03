package oauth

import (
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/time/rate"
)

const (
	maxLoginFormBytes = 8 << 10

	// Login attempts (any factor): a global bucket of loginGlobalBurst
	// refilled every loginGlobalEvery (10 a minute), and in front of it a
	// bucket per source of loginPerIPBurst refilled every loginPerIPEvery
	// (2 a minute). After its burst a single source gets a fifth of the
	// global rate, so it cannot keep the owner out on its own. TOTP also
	// locks after maxTOTPFailures consecutive failures (owner.go).
	loginGlobalBurst = 10
	loginGlobalEvery = 6 * time.Second
	loginPerIPBurst  = 5
	loginPerIPEvery  = 30 * time.Second
)

var errBadLoginRequest = errors.New("sign-in request not valid")

// loginPages serves the login and consent page. It approves an auth request
// only for the browser that started it, with that request's CSRF token,
// after the owner proves a factor.
type loginPages struct {
	store   *Store
	base    string
	limit   *rate.Limiter // global, every login attempt, any factor
	perIP   *ipLimiter    // per source, in front of limit (admit)
	proxies trustedProxies
	logger  *slog.Logger

	passkeysEnabled bool // set by New when WebAuthn is available
}

func newLoginPages(store *Store, base string, logger *slog.Logger) *loginPages {
	return &loginPages{
		store: store, base: base, logger: logger,
		limit: rate.NewLimiter(rate.Every(loginGlobalEvery), loginGlobalBurst),
		perIP: newIPLimiter(loginPerIPEvery, loginPerIPBurst, ipLimiterSize),
	}
}

// admit charges one attempt at a guessable factor (a TOTP or recovery code,
// or the TOTP check of /enroll/begin): the source's bucket, then the global
// one (admitSource).
func (l *loginPages) admit(r *http.Request) (time.Duration, bool) {
	return admitSource(l.perIP, l.limit, l.proxies.clientIP(r))
}

// admitPasskey charges a passkey ceremony step to the source's bucket only.
// A passkey cannot be guessed, so these steps need no global budget, and
// keeping them off it means sources that spend the global code budget
// (TOTP guesses) cannot keep the owner from approving with a passkey. The
// ceremonies they open are bounded by maxCeremonies (webauthn.go).
func (l *loginPages) admitPasskey(r *http.Request) (time.Duration, bool) {
	return l.perIP.allow(l.proxies.clientIP(r))
}

func (l *loginPages) callbackURL(id string) string {
	return l.base + "/authorize/callback?id=" + url.QueryEscape(id)
}

// pending returns the auth request if it still waits for approval and r
// comes from the browser that started it.
func (l *loginPages) pending(r *http.Request, id string) (*authRequest, error) {
	a, err := l.store.authRequest(id)
	if err != nil || a.IsDone || !sameBrowser(r, a.Browser) {
		return nil, errBadLoginRequest
	}
	return a, nil
}

// pendingWithCSRF also checks the request's CSRF token, in constant time.
// An empty token never matches (a.CSRF is never empty, and the lengths
// differ).
func (l *loginPages) pendingWithCSRF(r *http.Request, id, csrf string) (*authRequest, error) {
	a, err := l.pending(r, id)
	if err != nil {
		return nil, err
	}
	if a.CSRF == "" || subtle.ConstantTimeCompare([]byte(csrf), []byte(a.CSRF)) != 1 {
		return nil, errBadLoginRequest
	}
	return a, nil
}

func (l *loginPages) invalid(w http.ResponseWriter) {
	renderMessage(w, http.StatusBadRequest, "Sign-in request not valid",
		"This sign-in request is not valid in this browser or has expired. Start the connection again from the assistant.")
}

func (l *loginPages) notSetUp(w http.ResponseWriter) {
	renderMessage(w, http.StatusServiceUnavailable, "Not set up", "This server is not set up yet. On the host, run: cortex-mcp setup")
}

func (l *loginPages) failed(w http.ResponseWriter, what string, err error) {
	l.logger.Error(what, "err", err)
	renderMessage(w, http.StatusInternalServerError, "Error", "The server could not complete the sign-in. Try again.")
}

// show is GET /login?id=...
func (l *loginPages) show(w http.ResponseWriter, r *http.Request) {
	ok, err := l.store.OwnerExists()
	if err != nil {
		l.failed(w, "owner lookup failed", err)
		return
	}
	if !ok {
		l.notSetUp(w)
		return
	}
	a, err := l.pending(r, r.URL.Query().Get("id"))
	if err != nil {
		l.invalid(w)
		return
	}
	l.render(w, a, http.StatusOK, "")
}

// render fills the page from the stored client and request. The name is
// passed through cleanName again (it was cleaned before storage) and every
// field is escaped by html/template.
func (l *loginPages) render(w http.ResponseWriter, a *authRequest, status int, msg string) {
	name, clientHost := "an unregistered client", ""
	if c, err := l.store.clientByID(a.ClientID); err == nil {
		name = cleanName(c.Name)
		if c.Kind == kindCIMD {
			if u, err := url.Parse(c.ID); err == nil {
				clientHost = u.Host
			}
		}
	}
	n, err := l.store.passkeyCount()
	if err != nil {
		l.logger.Error("passkey lookup failed", "err", err)
	}
	u, _ := url.Parse(a.RedirectURI) // validated by the library before the request was stored
	host := ""
	if u != nil {
		host = u.Host
	}
	renderLogin(w, status, loginData{ClientName: name, RedirectHost: host, ClientHost: clientHost, ID: a.ID, CSRF: a.CSRF, Passkey: l.passkeysEnabled && n > 0, Error: msg}, originOf(u))
}

// submit is POST /login with a TOTP or recovery code.
func (l *loginPages) submit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginFormBytes)
	if err := r.ParseForm(); err != nil {
		l.invalid(w)
		return
	}
	a, err := l.pendingWithCSRF(r, r.PostForm.Get("id"), r.PostForm.Get("csrf"))
	if err != nil {
		l.invalid(w)
		return
	}
	if d, ok := l.admit(r); !ok {
		w.Header().Set("Retry-After", retryAfter(d))
		l.render(w, a, http.StatusTooManyRequests, "Too many attempts. Wait a minute and try again.")
		return
	}
	method, err := l.store.verifyCode(r.PostForm.Get("code"))
	switch {
	case errors.Is(err, errTOTPJustLocked):
		l.logger.Warn("authenticator codes locked after too many failed attempts; a passkey or a recovery code unlocks them",
			"failures", maxTOTPFailures, "client_id", logClientID(a.ClientID))
		l.renderLocked(w, a)
		return
	case errors.Is(err, errTOTPLocked):
		l.logger.Info("login refused: authenticator codes are locked", "client_id", logClientID(a.ClientID))
		l.renderLocked(w, a)
		return
	case errors.Is(err, errBadCode):
		l.logger.Warn("login failed: code not accepted", "client_id", logClientID(a.ClientID))
		l.render(w, a, http.StatusUnauthorized, "Code not accepted.")
		return
	case errors.Is(err, ErrNotSetUp):
		l.notSetUp(w)
		return
	case err != nil:
		l.failed(w, "code check failed", err)
		return
	}
	if method == "recovery" {
		left, _ := l.store.recoveryCodesLeft()
		l.logger.Warn("login with a recovery code", "recovery_codes_left", left)
	}
	l.approve(w, r, a, "otp")
}

func (l *loginPages) renderLocked(w http.ResponseWriter, a *authRequest) {
	l.render(w, a, http.StatusUnauthorized, "Authenticator codes are locked after too many failed attempts. Use a passkey or a recovery code.")
}

// approve records the approval and sends the browser to the library's
// callback, which issues the code.
func (l *loginPages) approve(w http.ResponseWriter, r *http.Request, a *authRequest, amr string) {
	if err := l.store.completeAuthRequest(a.ID, amr); err != nil {
		l.invalid(w)
		return
	}
	l.logger.Info("connection approved", "client_id", logClientID(a.ClientID), "amr", amr)
	http.Redirect(w, r, l.callbackURL(a.ID), http.StatusSeeOther) // #nosec G710 -- our own issuer URL; the id is a stored auth request id, query-escaped
}

// deny is POST /login/deny: the request is dropped and the client is told
// access_denied (RFC 6749 section 4.1.2.1) with iss (RFC 9207).
func (l *loginPages) deny(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginFormBytes)
	if err := r.ParseForm(); err != nil {
		l.invalid(w)
		return
	}
	a, err := l.pendingWithCSRF(r, r.PostForm.Get("id"), r.PostForm.Get("csrf"))
	if err != nil {
		l.invalid(w)
		return
	}
	u, err := url.Parse(a.RedirectURI)
	if err != nil {
		l.invalid(w)
		return
	}
	if err := l.store.deleteAuthRequest(a.ID); err != nil {
		l.failed(w, "deny failed", err)
		return
	}
	q := u.Query()
	q.Set("error", "access_denied")
	q.Set("error_description", "the owner denied the request")
	if a.State != "" {
		q.Set("state", a.State)
	}
	q.Set("iss", l.base)
	u.RawQuery = q.Encode()
	l.logger.Info("connection denied", "client_id", logClientID(a.ClientID))
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

func (s *Store) passkeyCount() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM passkeys`).Scan(&n)
	return n, err
}
