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
)

const (
	maxFormBytes        = 64 << 10
	maxAccessTokenBytes = 4096
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
	}
	s.reg.proxies = proxies
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

func (s *Service) callbackURL(id string) string {
	return s.base + "/authorize/callback?id=" + url.QueryEscape(id)
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
	handle("/authorize", http.HandlerFunc(s.authorize))
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

// The parameters each library endpoint is allowed to see, in their only
// accepted spelling. The library's form decoder (zitadel/schema) matches
// keys with strings.EqualFold and walks the form map in random order, so
// "REDIRECT_URI" could override the "redirect_uri" our checks looked at.
// canonicalForm hands the library only these exact keys.
var (
	authorizeParams = []string{"client_id", "redirect_uri", "response_type", "response_mode", "scope", "state",
		"nonce", "prompt", "code_challenge", "code_challenge_method", "resource"}
	tokenParams  = []string{"grant_type", "code", "redirect_uri", "client_id", "code_verifier", "refresh_token", "scope", "resource"}
	revokeParams = []string{"token", "token_type_hint", "client_id"}
)

// canonicalForm replaces the parsed form of r with only the known keys,
// spelled exactly. It refuses a request with a key that case-folds to a
// known one without being it, or a known key given more than once (in the
// query, the body, or across both); resource is the one key RFC 8707 lets
// repeat, and resourceOK refuses more than one value itself. Other keys
// are dropped. The raw query and body are cleared, so nothing downstream
// can read the original values: the library's ParseForm is a no-op once
// Form and PostForm are set, and r.URL.Query() is empty.
func canonicalForm(r *http.Request, known []string) bool {
	clean := url.Values{}
	for k, v := range r.Form {
		if slices.Contains(known, k) {
			if len(v) > 1 && k != "resource" {
				return false
			}
			clean[k] = v
			continue
		}
		for _, n := range known {
			if strings.EqualFold(k, n) {
				return false
			}
		}
	}
	u := *r.URL
	u.RawQuery, u.ForceQuery = "", false
	r.URL, r.RequestURI = &u, u.RequestURI()
	r.Form, r.PostForm, r.MultipartForm = clean, clean, nil
	r.Body = http.NoBody
	return true
}

// preCheck runs before the library sees an authorization request. The
// library validates scope, prompt, and response_type after it accepted the
// redirect URI, and for a native client it accepts any loopback URI with
// the registered path (userinfo, 127.0.0.2, https, IPv4-mapped forms), then
// redirects its own errors there. Resolving the client and applying our
// allowlist first means no response of any kind is ever redirected to a
// URI the allowlist refuses. The messages are fixed text.
func (s *Service) preCheck(r *http.Request) (string, bool) {
	if r.Form.Get("response_type") != string(oidc.ResponseTypeCode) {
		return "unsupported response_type: only code is supported", false
	}
	if m := r.Form.Get("response_mode"); m != "" && m != string(oidc.ResponseModeQuery) {
		return "unsupported response_mode: only query is supported", false
	}
	if _, err := s.op.GetClientByClientID(r.Context(), r.Form.Get("client_id")); err != nil {
		return "unknown client: start the connection again from the assistant", false
	}
	if !s.allow.allows(r.Form.Get("redirect_uri")) {
		return "the redirect_uri is not allowed by this server", false
	}
	if !s.resourceOK(r.Form["resource"]) {
		return "invalid_target: resource must be " + s.mcpURL, false
	}
	return "", true
}

// authorize wraps the library's /authorize. Refusals here are plain 400
// pages, never redirects: the redirect URI has not been validated yet.
func (s *Service) authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
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

// issWriter adds the RFC 9207 iss parameter to every redirect that leaves
// this server (authorization responses, success or error). Redirects to our
// own pages (the login page) are left alone.
type issWriter struct {
	http.ResponseWriter
	iss   string
	wrote bool
}

func (w *issWriter) WriteHeader(code int) {
	if !w.wrote {
		w.wrote = true
		if code >= 300 && code < 400 {
			w.addIss()
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *issWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *issWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *issWriter) addIss() {
	loc := w.Header().Get("Location")
	if loc == "" || strings.HasPrefix(loc, "/") || loc == w.iss || strings.HasPrefix(loc, w.iss+"/") {
		return
	}
	// The client's query bytes are kept as they are (re-encoding would
	// reorder them and change escapes); only an existing iss pair is
	// dropped before ours is appended. Authorization responses here are
	// query mode only, but a fragment is kept after the query if present.
	rest, frag, hasFrag := strings.Cut(loc, "#")
	base, query, _ := strings.Cut(rest, "?")
	var pairs []string
	if query != "" {
		for _, p := range strings.Split(query, "&") {
			if k, _, _ := strings.Cut(p, "="); k != "iss" {
				pairs = append(pairs, p)
			}
		}
	}
	pairs = append(pairs, "iss="+url.QueryEscape(w.iss))
	loc = base + "?" + strings.Join(pairs, "&")
	if hasFrag {
		loc += "#" + frag
	}
	w.Header().Set("Location", loc)
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
