package oauth

import (
	"crypto/rand"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

const (
	maxRegistrationBytes = 16 << 10
	// maxDCRClients bounds the table: registration is unauthenticated, and
	// claude.ai registers a new client for every connection.
	maxDCRClients = 500
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

// newRegistrar allows 20 registrations an hour with a burst of 5: enough
// for a few assistants reconnecting, too few to fill the table quickly.
func newRegistrar(store *Store, allow allowlist) *registrar {
	return &registrar{store: store, allow: allow, limit: rate.NewLimiter(rate.Every(3*time.Minute), 5)}
}

func (g *registrar) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !g.limit.Allow() {
		w.Header().Set("Retry-After", "180")
		oauthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "too many registrations, try again later")
		return
	}
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
	n, err := g.store.countClients(kindDCR)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "registration is unavailable")
		return
	}
	if n >= maxDCRClients {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "too many registered clients; the owner can remove unused ones with cortex-mcp clients revoke")
		return
	}
	now := g.store.now()
	row := clientRow{ID: rand.Text(), Kind: kindDCR, Name: reg.ClientName, RedirectURIs: reg.RedirectURIs, Created: now}
	if err := g.store.insertClient(row); err != nil {
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
