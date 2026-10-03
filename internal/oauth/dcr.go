package oauth

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/time/rate"
)

const (
	maxRegistrationBytes = 16 << 10
	// maxUnusedDCR bounds the clients that never completed a login (no
	// grant). Registration is unauthenticated and claude.ai registers a new
	// client per connection, so this is the squatting surface; clients with
	// a grant are the owner's real connections and never count.
	maxUnusedDCR = 50
)

// registration is the part of an RFC 7591 request this server uses. Every
// other field is ignored: all clients are registered as public clients with
// the authorization_code and refresh_token grants, and the response says
// so, which RFC 7591 section 3.2.1 allows.
type registration struct {
	RedirectURIs []string `json:"redirect_uris"`
	ClientName   string   `json:"client_name"`
}

type regError struct{ code, desc string }

// parseRegistration validates an untrusted registration body. The returned
// descriptions are fixed text, safe to send back.
func parseRegistration(body []byte, a allowlist) (registration, *regError) {
	var r registration
	if err := json.Unmarshal(body, &r); err != nil {
		return registration{}, &regError{"invalid_client_metadata", "the body must be a JSON object of client metadata"}
	}
	if _, err := a.checkRedirectSet(r.RedirectURIs); err != nil {
		return registration{}, &regError{"invalid_redirect_uri", err.Error()}
	}
	r.ClientName = cleanName(r.ClientName)
	return r, nil
}

type registrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope"`
}

// registrar serves POST /register.
type registrar struct {
	store *Store
	allow allowlist
	limit *rate.Limiter
}

// newRegistrar allows 60 valid registrations an hour with a burst of 10.
// The ceiling is global, not per client address (behind a proxy the address
// is not trustworthy), so it is generous for the owner's few assistants
// reconnecting while still bounding how fast an attacker can churn the
// table. Only requests that pass validation are charged (see ServeHTTP), so
// junk cannot starve real registrations.
func newRegistrar(store *Store, allow allowlist) *registrar {
	return &registrar{store: store, allow: allow, limit: rate.NewLimiter(rate.Every(time.Minute), 10)}
}

func (g *registrar) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "Content-Type must be application/json")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRegistrationBytes))
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "the body is too large or unreadable")
		return
	}
	reg, rerr := parseRegistration(body, g.allow)
	if rerr != nil {
		oauthError(w, http.StatusBadRequest, rerr.code, rerr.desc)
		return
	}
	// Charge the limiter only now: invalid requests are rejected for free.
	res := g.limit.Reserve()
	if d := res.Delay(); !res.OK() || d > 0 {
		res.Cancel()
		secs := max(1, int(math.Ceil(d.Seconds())))
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		oauthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "too many registrations, try again later")
		return
	}
	now := g.store.now()
	row := clientRow{ID: rand.Text(), Kind: kindDCR, Name: reg.ClientName, RedirectURIs: reg.RedirectURIs, Created: now}
	switch err := g.store.registerDCR(row, maxUnusedDCR, authRequestTTL); {
	case errors.Is(err, errRegistryFull):
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "registration is temporarily unavailable, try again later")
		return
	case err != nil:
		oauthError(w, http.StatusInternalServerError, "server_error", "registration is unavailable")
		return
	}
	writeJSON(w, http.StatusCreated, registrationResponse{
		ClientID:                row.ID,
		ClientIDIssuedAt:        now.Unix(),
		ClientName:              row.Name,
		RedirectURIs:            row.RedirectURIs,
		TokenEndpointAuthMethod: "none",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		Scope:                   Scope,
	})
}
