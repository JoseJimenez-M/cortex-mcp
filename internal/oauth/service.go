package oauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/time/rate"
)

const (
	maxFormBytes        = 64 << 10
	maxAccessTokenBytes = 4096

	// /authorize is unauthenticated and every request may write a row or
	// trigger a metadata fetch. A source gets authorizePerIPBurst requests,
	// then one every authorizePerIPEvery (20 a minute). The global bucket
	// (authorizeGlobalBurst, then 10 a second) is only a CPU circuit
	// breaker: disk is bounded by the pending caps (maxPendingPerSource,
	// maxPendingAuthRequests) and fetches by the CIMD budgets, so it can be
	// wide enough that a handful of sources cannot empty it and lock the
	// owner out (it takes about 30 sources at their own rate).
	authorizePerIPBurst  = 20
	authorizePerIPEvery  = 3 * time.Second
	authorizeGlobalBurst = 600
	authorizeGlobalEvery = 100 * time.Millisecond

	// tokenSweepEvery is how often the token endpoint, which every connected
	// client keeps using, may run the sweep. It shares the last-sweep time
	// with the flow entry points (sweepEvery), so it adds a sweep only when
	// no new flow has started for a while.
	tokenSweepEvery = 5 * time.Minute

	// browserCookie binds an authorization to the browser that started it.
	// __Host- makes browsers refuse it unless it is Secure, host-only, and
	// Path=/. Browsers (and Go's cookie jar) treat localhost as secure.
	browserCookie    = "__Host-cortex-browser"
	browserCookieAge = 3600
)

// ErrInvalidToken means the presented OAuth access token is unknown,
// expired, revoked, or for another resource. Verify never says which.
var ErrInvalidToken = errors.New("invalid token")

// Options are the Service's dependencies.
type Options struct {
	DB                *sql.DB  // from authdb.Open, shared with the Bearer token store
	PublicURL         string   // config public_url; the issuer is this without a trailing slash
	RedirectAllowlist []string // config oauth.redirect_allowlist
	TrustedProxies    []string // config trusted_proxies: proxies whose X-Forwarded-For entry keys rate limits
	Logger            *slog.Logger
	Now               func() time.Time // nil means time.Now

	fetch func(context.Context, string) ([]byte, error) // tests only: replaces the CIMD fetcher
}

// Identity is an authenticated OAuth access token, for the resource server.
type Identity struct {
	UserID     string // "oauth:" + grant family: stable across refreshes, never a Bearer row id
	ClientID   string
	ClientName string
	Scopes     []string
	Expires    time.Time
}

// Service is the authorization server and the OAuth half of the resource
// server's token check.
type Service struct {
	store    *Store
	base     string
	mcpURL   string
	provider *op.Provider
	crypto   op.Crypto
	reg      *registrar
	login    *loginPages
	passkeys *passkeys // nil when public_url's host cannot be a relying party id
	op       *opStorage
	allow    allowlist
	logger   *slog.Logger
	proxies  trustedProxies

	authorizeLimit  *ipLimiter    // per source, in front of authorizeGlobal
	authorizeGlobal *rate.Limiter // every /authorize request
}

// New builds the service: keys are loaded (or created) from the database,
// and the zitadel provider is configured with our storage, AES-GCM-only
// token encryption (no legacy decrypter), and CORS off.
func New(o Options) (*Service, error) {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	base := strings.TrimSuffix(o.PublicURL, "/")
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("oauth: public_url %q is not a usable issuer", o.PublicURL)
	}
	allow, err := parseAllowlist(o.RedirectAllowlist)
	if err != nil {
		return nil, fmt.Errorf("oauth: %w", err)
	}
	proxies, err := parseTrustedProxies(o.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("oauth: %w", err)
	}
	store := NewStore(o.DB, o.Now)
	signing, cryptoKey, cryptoKID, err := store.loadKeys()
	if err != nil {
		return nil, fmt.Errorf("oauth: keys: %w", err)
	}
	fetch := o.fetch
	if fetch == nil {
		fetch = newSafeFetcher().fetch
	}
	s := &Service{
		store:  store,
		base:   base,
		mcpURL: base + "/mcp",
		crypto: op.NewAES256GCMCrypto(cryptoKey, cryptoKID),
		reg:    newRegistrar(store, allow),
		allow:  allow,
		logger: o.Logger,

		proxies:         proxies,
		authorizeLimit:  newIPLimiter(authorizePerIPEvery, authorizePerIPBurst, ipLimiterSize),
		authorizeGlobal: rate.NewLimiter(rate.Every(authorizeGlobalEvery), authorizeGlobalBurst),
	}
	s.reg.proxies, s.reg.logger = proxies, o.Logger
	s.login = newLoginPages(store, base, o.Logger)
	s.login.proxies = proxies
	if pk, err := newPasskeys(store, base, s.login, o.Logger); err != nil {
		o.Logger.Warn("passkeys are disabled: the public_url host cannot be a WebAuthn relying party id (use a DNS name such as localhost); TOTP and recovery codes still work", "err", err)
	} else {
		s.passkeys = pk
		s.login.passkeysEnabled = true
	}
	s.op = &opStorage{
		s: store, base: base, mcpURL: s.mcpURL, allow: allow,
		resolver: newCIMDResolver(store, allow, fetch, o.Logger), signing: signing, logger: o.Logger,
	}
	opts := []op.Option{op.WithCrypto(s.crypto), op.WithCORSOptions(nil)}
	if u.Scheme == "http" {
		opts = append(opts, op.WithAllowInsecure()) // config allows http only for loopback hosts
	}
	cfg := &op.Config{
		CryptoKey:             cryptoKey,
		CryptoKeyId:           cryptoKID,
		CodeMethodS256:        true,
		GrantTypeRefreshToken: true,
		SupportedScopes:       []string{Scope, oidc.ScopeOfflineAccess},
	}
	if s.provider, err = op.NewProvider(cfg, s.op, op.StaticIssuer(base), opts...); err != nil {
		return nil, fmt.Errorf("oauth: provider: %w", err)
	}
	return s, nil
}

// Store is the database side, for the CLI and tests.
func (s *Service) Store() *Store { return s.store }

// MCPURL is the protected resource: public_url + "/mcp".
func (s *Service) MCPURL() string { return s.mcpURL }

// ResourceMetadataURL goes in the WWW-Authenticate challenge of /mcp.
func (s *Service) ResourceMetadataURL() string {
	return s.base + "/.well-known/oauth-protected-resource/mcp"
}

// Register adds every OAuth route to mux. It is the only place OAuth routes
// are added (internal/oauth/AGENTS.md lists them); library routes not named
// here (userinfo, introspection, end_session, device authorization, the
// library's health checks) stay unreachable.
func (s *Service) Register(mux *http.ServeMux) {
	handle := func(pattern string, h http.Handler) { mux.Handle(pattern, secureHeaders(h)) }
	prm := jsonDoc(s.protectedResourceMetadata())
	asm := jsonDoc(s.authServerMetadata())
	handle("GET /.well-known/oauth-protected-resource", prm)
	handle("GET /.well-known/oauth-protected-resource/mcp", prm)
	handle("GET /.well-known/oauth-authorization-server", asm)
	handle("GET /.well-known/openid-configuration", asm)
	handle("/authorize", http.HandlerFunc(s.authorize)) // GET only; the handler answers 405 itself, with secureHeaders
	handle("GET /authorize/callback", http.HandlerFunc(s.callback))
	handle("POST /oauth/token", http.HandlerFunc(s.token))
	handle("POST /revoke", http.HandlerFunc(s.revoke))
	handle("GET /keys", s.provider)
	handle("POST /register", s.reg)
	handle("GET /login", http.HandlerFunc(s.login.show))
	handle("POST /login", http.HandlerFunc(s.login.submit))
	handle("POST /login/deny", http.HandlerFunc(s.login.deny))
	if s.passkeys != nil {
		handle("POST /login/passkey/begin", http.HandlerFunc(s.passkeys.beginLogin))
		handle("POST /login/passkey/finish", http.HandlerFunc(s.passkeys.finishLogin))
		handle("GET /enroll", http.HandlerFunc(s.passkeys.enrollPage))
		handle("POST /enroll/begin", http.HandlerFunc(s.passkeys.beginEnroll))
		handle("POST /enroll/finish", http.HandlerFunc(s.passkeys.finishEnroll))
	}
}

// protectedResourceMetadata is RFC 9728. offline_access is deliberately
// absent (MCP authorization draft): it belongs to the AS metadata only.
func (s *Service) protectedResourceMetadata() oauthex.ProtectedResourceMetadata {
	return oauthex.ProtectedResourceMetadata{
		Resource:               s.mcpURL,
		AuthorizationServers:   []string{s.base},
		ScopesSupported:        []string{Scope},
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "cortex-mcp",
	}
}

// asMetadata adds the two OIDC discovery fields some clients require when
// they read openid-configuration.
type asMetadata struct {
	oauthex.AuthServerMeta
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

// authServerMetadata is RFC 8414 with the MCP-relevant extensions. It is
// written here rather than taken from the library's discovery handler,
// which advertises plain PKCE, implicit response types, and endpoints that
// are not mounted.
func (s *Service) authServerMetadata() asMetadata {
	return asMetadata{
		AuthServerMeta: oauthex.AuthServerMeta{
			Issuer:                                     s.base,
			AuthorizationEndpoint:                      s.base + "/authorize",
			TokenEndpoint:                              s.base + "/oauth/token",
			JWKSURI:                                    s.base + "/keys",
			RegistrationEndpoint:                       s.base + "/register",
			ScopesSupported:                            []string{Scope, oidc.ScopeOfflineAccess},
			ResponseTypesSupported:                     []string{"code"},
			ResponseModesSupported:                     []string{"query"},
			GrantTypesSupported:                        []string{"authorization_code", "refresh_token"},
			TokenEndpointAuthMethodsSupported:          []string{"none"},
			RevocationEndpoint:                         s.base + "/revoke",
			RevocationEndpointAuthMethodsSupported:     []string{"none"},
			CodeChallengeMethodsSupported:              []string{"S256"},
			ClientIDMetadataDocumentSupported:          true,
			AuthorizationResponseIssParameterSupported: true,
		},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"ES256"},
	}
}

func jsonDoc(v any) http.Handler {
	body, err := json.Marshal(v)
	if err != nil {
		panic(err) // static documents built from constants; a failure is a programmer error at startup
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
}

// resourceOK accepts no resource (the MCP URL is the only resource, and
// every grant's audience is set to it) or exactly one that is the MCP URL
// byte for byte (RFC 8707). No trailing-slash or case leniency: the PRM
// advertises this exact string, so a client that sends anything else is
// asking for a different resource.
func (s *Service) resourceOK(vals []string) bool {
	switch len(vals) {
	case 0:
		return true
	case 1:
		return vals[0] == s.mcpURL
	default:
		return false
	}
}

// authorize wraps the library's /authorize. Refusals here are plain 400
// pages, never redirects: the redirect URI has not been validated yet.
//
// Only GET is served. Each authorization sets the browser cookie, keeping
// the value the browser sent (browserID). A cross-site POST, which any page
// the owner visits can submit, arrives without the SameSite=Lax cookie, so
// it would get a fresh value and overwrite the owner's binding mid-login.
// A cross-site top-level GET carries the cookie, so it keeps the binding.
func (s *Service) authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	src := s.proxies.clientIP(r)
	if d, ok := admitSource(s.authorizeLimit, s.authorizeGlobal, src); !ok {
		w.Header().Set("Retry-After", retryAfter(d))
		http.Error(w, "Too many sign-in requests. Wait a minute and start the connection again from the assistant.", http.StatusTooManyRequests)
		return
	}
	r = r.WithContext(withSource(r.Context(), src))
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)
		return
	}
	if !canonicalForm(r, authorizeParams) {
		http.Error(w, "invalid authorization request: a parameter is repeated or misspelled", http.StatusBadRequest)
		return
	}
	if msg, ok := s.preCheck(r); !ok {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(r.Form.Get("scope")) == "" {
		r.Form.Set("scope", Scope) // the library refuses an empty scope; vault is the only one
	}
	b := browserID(r)
	http.SetCookie(w, &http.Cookie{
		Name: browserCookie, Value: b, Path: "/", MaxAge: browserCookieAge,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	ctx := context.WithValue(r.Context(), browserKey{}, hashHex(b))
	s.provider.ServeHTTP(&issWriter{ResponseWriter: w, iss: s.base}, r.WithContext(ctx))
}

// browserID keeps a well-formed existing cookie, so several authorizations
// in one browser share it, or makes a new one.
func browserID(r *http.Request) string {
	if c, err := r.Cookie(browserCookie); err == nil && len(c.Value) == 26 && isBase32(c.Value) {
		return c.Value
	}
	return rand.Text()
}

func isBase32(s string) bool {
	for _, c := range s {
		if !(c >= 'A' && c <= 'Z' || c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}

// sameBrowser reports whether r carries the cookie whose hash is want.
func sameBrowser(r *http.Request, want string) bool {
	c, err := r.Cookie(browserCookie)
	if err != nil || want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(hashHex(c.Value)), []byte(want)) == 1
}

// callback wraps /authorize/callback: the code is only released to the
// browser that started the authorization.
func (s *Service) callback(w http.ResponseWriter, r *http.Request) {
	r = r.WithContext(withSource(r.Context(), s.proxies.clientIP(r)))
	a, err := s.store.authRequest(r.URL.Query().Get("id"))
	if err != nil || !sameBrowser(r, a.Browser) {
		http.Error(w, "This sign-in request is not valid in this browser or has expired. Start the connection again from the assistant.", http.StatusBadRequest)
		return
	}
	s.provider.ServeHTTP(&issWriter{ResponseWriter: w, iss: s.base}, r)
}

// token wraps /oauth/token: only the two grants this server issues, and
// the resource indicator if present.
func (s *Service) token(w http.ResponseWriter, r *http.Request) {
	if err := s.store.sweepAfter(tokenSweepEvery); err != nil {
		s.logger.Warn("sweep of expired OAuth state failed", "err", err)
	}
	r = r.WithContext(withSource(r.Context(), s.proxies.clientIP(r)))
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "the request body is not a valid form")
		return
	}
	if !canonicalForm(r, tokenParams) {
		oauthError(w, http.StatusBadRequest, "invalid_request", "a parameter is repeated or misspelled")
		return
	}
	switch r.Form.Get("grant_type") {
	case string(oidc.GrantTypeCode), string(oidc.GrantTypeRefreshToken):
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code and refresh_token are supported")
		return
	}
	if !s.resourceOK(r.Form["resource"]) {
		oauthError(w, http.StatusBadRequest, "invalid_target", "resource must be "+s.mcpURL)
		return
	}
	s.provider.ServeHTTP(w, r)
}

func (s *Service) revoke(w http.ResponseWriter, r *http.Request) {
	r = r.WithContext(withSource(r.Context(), s.proxies.clientIP(r)))
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "the request body is not a valid form")
		return
	}
	if !canonicalForm(r, revokeParams) {
		oauthError(w, http.StatusBadRequest, "invalid_request", "a parameter is repeated or misspelled")
		return
	}
	s.provider.ServeHTTP(w, r)
}

// Verify authenticates an OAuth access token for /mcp. Decryption only
// recovers the token id; everything that matters comes from the database
// (spec 6.2: never trust a decrypted payload alone).
func (s *Service) Verify(_ context.Context, token string) (Identity, error) {
	if token == "" || len(token) > maxAccessTokenBytes {
		return Identity{}, ErrInvalidToken
	}
	plain, err := s.crypto.Decrypt(token)
	if err != nil {
		return Identity{}, ErrInvalidToken
	}
	id, _, ok := strings.Cut(plain, ":")
	if !ok {
		return Identity{}, ErrInvalidToken
	}
	a, err := s.store.lookupAccess(id)
	if errors.Is(err, ErrNotFound) {
		return Identity{}, ErrInvalidToken
	}
	if err != nil {
		return Identity{}, err
	}
	if !s.store.now().Before(a.Expires) || !slices.Contains(a.Audience, s.mcpURL) {
		return Identity{}, ErrInvalidToken
	}
	return Identity{UserID: "oauth:" + a.Family, ClientID: a.ClientID, ClientName: a.ClientName, Scopes: a.Scopes, Expires: a.Expires}, nil
}
