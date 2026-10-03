package oauth

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net/url"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// browserKey is the context key under which Service.authorize passes the
// hash of the browser cookie to CreateAuthRequest.
type browserKey struct{}

var (
	errAuthRequestNotFound = errors.New("authorization request not found or expired")
	errNotSupported        = errors.New("not supported by this server")
	errStorage             = errors.New("storage error")
)

// opStorage is the op.Storage the zitadel provider runs on. Errors returned
// to the library carry fixed text: it echoes some of them to the browser and
// logs them.
type opStorage struct {
	s        *Store
	base     string // the issuer, public_url without a trailing slash
	mcpURL   string // the protected resource: base + "/mcp"
	allow    allowlist
	resolver *cimdResolver
	signing  signingKey
	logger   *slog.Logger
}

// client is an op.Client: always public (PKCE, no secret), code flow with
// refresh tokens, scope vault.
type client struct {
	id        string
	redirects []string
	native    bool
	loginBase string
}

func (c *client) GetID() string                        { return c.id }
func (c *client) RedirectURIs() []string               { return c.redirects }
func (c *client) PostLogoutRedirectURIs() []string     { return nil }
func (c *client) AuthMethod() oidc.AuthMethod          { return oidc.AuthMethodNone }
func (c *client) AccessTokenType() op.AccessTokenType  { return op.AccessTokenTypeBearer }
func (c *client) IDTokenLifetime() time.Duration       { return 5 * time.Minute }
func (c *client) DevMode() bool                        { return false }
func (c *client) IsScopeAllowed(scope string) bool     { return scope == Scope }
func (c *client) IDTokenUserinfoClaimsAssertion() bool { return false }
func (c *client) ClockSkew() time.Duration             { return 0 }

// ApplicationType native lets the library accept any loopback port for a
// registered loopback redirect (RFC 8252); web means exact matching.
func (c *client) ApplicationType() op.ApplicationType {
	if c.native {
		return op.ApplicationTypeNative
	}
	return op.ApplicationTypeWeb
}

func (c *client) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}

func (c *client) GrantTypes() []oidc.GrantType {
	return []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken}
}

func (c *client) LoginURL(id string) string { return c.loginBase + "/login?id=" + url.QueryEscape(id) }

func (c *client) RestrictAdditionalIdTokenScopes() func([]string) []string     { return keepScopes }
func (c *client) RestrictAdditionalAccessTokenScopes() func([]string) []string { return keepScopes }

func keepScopes(s []string) []string { return s }

// GetClientByClientID loads a DCR client from the table or a CIMD client
// through the resolver, then re-applies the current redirect allowlist.
// An unknown, revoked, or unusable client is invalid_client (the library
// answers it with 401 at the token endpoint; a plain error would be a 500).
// The error is built per call: the library sets fields on the value it
// gets.
func errUnknownClient() error {
	return oidc.ErrInvalidClient().WithDescription("client not found")
}

func (o *opStorage) GetClientByClientID(ctx context.Context, id string) (op.Client, error) {
	var row clientRow
	var err error
	if isCIMDClientID(id) {
		row, err = o.resolver.resolve(ctx, id)
	} else if row, err = o.s.clientByID(id); err == nil && row.Kind != kindDCR {
		err = ErrNotFound
	}
	if err != nil {
		if !errors.Is(err, ErrNotFound) && !errors.Is(err, errCIMD) {
			o.logger.Error("client lookup failed", "err", err)
		}
		return nil, errUnknownClient()
	}
	var redirects []string
	for _, u := range row.RedirectURIs {
		if o.allow.allows(u) {
			redirects = append(redirects, u)
		}
	}
	if len(redirects) == 0 {
		return nil, errUnknownClient()
	}
	return &client{id: row.ID, redirects: redirects, native: isLoopbackRedirect(redirects[0]), loginBase: o.base}, nil
}

// validChallenge accepts exactly an S256 challenge: the base64url (no
// padding) encoding of a SHA-256 digest is 43 characters.
func validChallenge(c string) bool {
	if len(c) != 43 {
		return false
	}
	for _, r := range c {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// CreateAuthRequest runs after the library validated the client, redirect
// URI, scopes, and response type. It enforces what the library does not:
// S256 PKCE (the library accepts plain and a missing method), and the
// browser binding set by Service.authorize. An *oidc.Error here is
// redirected to the client with the iss parameter added.
func (o *opStorage) CreateAuthRequest(ctx context.Context, req *oidc.AuthRequest, _ string) (op.AuthRequest, error) {
	// The library's native-client check is looser than our allowlist (any
	// loopback address, either scheme, userinfo, fragments, escapes), so the
	// matcher runs again on the request's own URI. redirectDisabled keeps the
	// library from redirecting the error to the URI it rejects.
	if !o.allow.allows(req.RedirectURI) {
		return nil, oidc.ErrInvalidRequestRedirectURI().WithDescription("the redirect_uri is not allowed")
	}
	// Only now is the URI trusted enough for the library to redirect the
	// PKCE error to it.
	if req.CodeChallengeMethod != oidc.CodeChallengeMethodS256 || !validChallenge(req.CodeChallenge) {
		return nil, oidc.ErrInvalidRequest().WithDescription("PKCE with code_challenge_method=S256 is required")
	}
	browser, _ := ctx.Value(browserKey{}).(string)
	if browser == "" {
		return nil, oidc.ErrServerError().WithDescription("the request did not pass through the authorize handler")
	}
	if err := o.s.sweep(); err != nil {
		o.logger.Warn("sweep of expired OAuth state failed", "err", err)
	}
	a := &authRequest{
		ID: rand.Text(), ClientID: req.ClientID, RedirectURI: req.RedirectURI, State: req.State, Nonce: req.Nonce,
		Challenge: req.CodeChallenge, Scopes: grantedScopes(), Browser: browser, CSRF: rand.Text(), Family: rand.Text(),
		Created: o.s.now(), Source: sourceLabel(sourceFrom(ctx)),
	}
	if err := o.s.createAuthRequest(a); err != nil {
		if !errors.Is(err, ErrNotFound) {
			o.logger.Error("create auth request failed", "err", err)
		}
		return nil, errStorage
	}
	return a, nil
}

func (o *opStorage) AuthRequestByID(_ context.Context, id string) (op.AuthRequest, error) {
	a, err := o.s.authRequest(id)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			o.logger.Warn("auth request lookup failed", "err", err)
		}
		return nil, errAuthRequestNotFound
	}
	return a, nil
}

func (o *opStorage) AuthRequestByCode(_ context.Context, code string) (op.AuthRequest, error) {
	a, err := o.s.authRequestByCode(code)
	if err != nil {
		if !errors.Is(err, errInvalidCode) {
			o.logger.Warn("code redemption failed", "err", err)
		}
		return nil, errInvalidCode
	}
	return a, nil
}

func (o *opStorage) SaveAuthCode(_ context.Context, id, code string) error {
	if err := o.s.saveAuthCode(id, code); err != nil {
		o.logger.Warn("save auth code failed", "err", err)
		return errStorage
	}
	return nil
}

func (o *opStorage) DeleteAuthRequest(_ context.Context, id string) error {
	if err := o.s.deleteAuthRequest(id); err != nil {
		o.logger.Warn("delete auth request failed", "err", err)
		return errStorage
	}
	return nil
}

func (o *opStorage) SigningKey(context.Context) (op.SigningKey, error) { return o.signing, nil }

func (o *opStorage) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.ES256}, nil
}

func (o *opStorage) KeySet(context.Context) ([]op.Key, error) {
	return []op.Key{publicKey{kid: o.signing.kid, pub: &o.signing.priv.PublicKey}}, nil
}

// The OIDC-only parts of op.Storage. Their endpoints (userinfo,
// introspection, JWT profile grants) are not mounted; these answers make
// sure nothing works through them even if one were.

func (o *opStorage) AuthorizeClientIDSecret(context.Context, string, string) error {
	return errNotSupported
}

func (o *opStorage) SetUserinfoFromScopes(context.Context, *oidc.UserInfo, string, string, []string) error {
	return nil // called while minting the ID token; there are no user claims
}

func (o *opStorage) SetUserinfoFromToken(context.Context, *oidc.UserInfo, string, string, string) error {
	return errNotSupported
}

func (o *opStorage) SetIntrospectionFromToken(context.Context, *oidc.IntrospectionResponse, string, string, string) error {
	return errNotSupported
}

func (o *opStorage) GetPrivateClaimsFromScopes(context.Context, string, string, []string) (map[string]any, error) {
	return nil, nil
}

func (o *opStorage) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, errNotSupported
}

func (o *opStorage) ValidateJWTProfileScopes(context.Context, string, []string) ([]string, error) {
	return nil, errNotSupported
}

func (o *opStorage) Health(ctx context.Context) error {
	if err := o.s.db.PingContext(ctx); err != nil {
		o.logger.Warn("health check failed", "err", err)
		return errStorage
	}
	return nil
}
