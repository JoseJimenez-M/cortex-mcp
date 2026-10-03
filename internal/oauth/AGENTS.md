# AGENTS.md: internal/oauth

*The OAuth 2.1 authorization server, owner login, and client registry. Security-critical: a bug here can
hand the vault to anyone on the internet. Read the root `AGENTS.md` first, then spec section 6.*

---

## Shape

- `Store` (store.go, owner.go, clients.go, grants.go) is every database operation on `auth.db`; the
  CLI uses it directly (`setup`, `unlock-totp`, `reset-auth`, `clients`).
- `Service` (service.go) is the HTTP side: it wraps `github.com/zitadel/oidc/v3/pkg/op` with
  `opStorage` (storage.go, grants.go) and adds our own handlers (`registrar`, `cimdResolver`,
  `loginPages`, `passkeys`).
- From this module, `internal/oauth` imports only `internal/config`.

## Routes (all public by protocol; invariant 7 names this list)

`GET /.well-known/oauth-protected-resource`, `GET /.well-known/oauth-protected-resource/mcp`,
`GET /.well-known/oauth-authorization-server`, `GET /.well-known/openid-configuration`,
`GET /authorize` (other methods get 405), `GET /authorize/callback`, `POST /oauth/token`, `POST /revoke`, `GET /keys`,
`POST /register`, `GET /login`, `POST /login`, `POST /login/deny`, `POST /login/passkey/begin`,
`POST /login/passkey/finish`, `GET /enroll`, `POST /enroll/begin`, `POST /enroll/finish`.
`Service.Register` is the only place routes are added; a new route is a design change.

## Rules for this package

- **The library is the protocol core, not the policy.** S256-only PKCE (`CreateAuthRequest`), the
  resource checks (`Service.authorize`, `Service.token`), the `iss` parameter (`issWriter`), refresh
  reuse detection (grants.go), the redirect allowlist (redirect.go), and browser binding (login.go,
  `Service.callback`) are ours. Never send a request to the provider without its wrapper, and never
  mount a library route that is not in the list above.
- **Every token lookup goes to the database.** `Service.Verify` decrypts only to learn the token id;
  expiry, audience, and client existence come from `access_tokens` joined with `grants` and
  `oauth_clients`. Never trust a decrypted payload alone (GHSA-j8gq-92xf-382c).
- **Concurrent refresh: the loser revokes the family, by design.** Two requests presenting the same
  refresh token race; the one that finds it already rotated revokes the whole family (RFC 9700) and
  gets `invalid_grant`. There is no grace window: the server cannot replay the winner's tokens to the
  loser, and a window would let an attacker holding a stolen family keep it alive. Each revocation logs
  `refresh token reuse: grant revoked` (client id, family id). Revisit only if those logs show real
  clients refreshing in parallel.
- **Secrets are stored hashed** (`hashToken`): refresh tokens, codes, recovery codes, enrollment tokens,
  browser cookies. Only the TOTP secret and the keys in `oauth_keys` are stored usable.
- **Errors that reach the library carry fixed text.** zitadel echoes some error strings to the browser
  and logs them through `slog.Default()`; never put a token, code, cookie, or client-supplied value in
  an error you hand to it.
- **One connection.** `auth.db` runs with `SetMaxOpenConns(1)`. Inside `Store.tx`, use only the
  `*sql.Tx`; touching `s.db` there blocks forever.
- **Untrusted input:** redirect URIs, DCR bodies, CIMD documents, client names, every form field and
  query parameter. Each parser has a fuzz target; names pass through `cleanName` before storage.
- **Redirect URIs are compared raw, never normalized.** The allowlist syntax lives in
  `config.CheckRedirectEntry` and the matcher applies the same character rules to incoming URIs
  (lowercase host, no trailing dot, no `%`, no userinfo, no fragment, no dot segments); a URI that
  would match only after normalizing is refused. Change the syntax and the matcher together, with
  `FuzzAllowlistEntry` as the guard.
- **Outbound HTTP happens only in cimd.go**, through `newSafeFetcher`. No other code here makes a
  network call.
- **Pages** set a nonce-based CSP with `frame-ancestors 'none'`, use `html/template`, and have no
  inline event handlers.
  Page scripts send the CSRF token in the `X-CSRF-Token` header (`csrfHeader`), never in a URL.
- **Rate limits are per source, then global** (`admitSource`, which gives the source's token back when
  the global bucket refuses). Code attempts on `/login` and the TOTP check of `/enroll/begin`
  (`loginPages.admit`, after the link is checked), `/register`, `/authorize`, and CIMD first fetches
  (the source reaches the resolver through the request context, `withSource`) charge a per-source
  bucket (`ipLimiter`, LRU-bounded at `ipLimiterSize`, IPv6 per /64) before the global one. Passkey
  begin and finish charge only the per-source login bucket (`admitPasskey`): passkeys cannot be
  guessed, and keeping them off the global bucket means TOTP guessing cannot block them;
  `maxCeremonies` is sized from the `/authorize` budget and the pending cap instead
  (`TestCeremonyCapExceedsTheLoginBudget`). The source is `trustedProxies.clientIP`: X-Forwarded-For is
  read only when the TCP peer is in config `trusted_proxies`, right-most untrusted entry first. Never
  key a limit on a header any other way.
- **Logs name a CIMD client by host only** (`logClientID`): the rest of the URL is chosen by whoever
  sends `/authorize`. Every log line with a client id goes through it.
- **Time:** use `Store.now`, never `time.Now`, so tests can expire things. The library uses real time
  for `expires_in`, so test clocks start at the real time and only move forward.

## Library behaviours we rely on (re-check on every zitadel/oidc bump)

1. An `*oidc.Error` returned by `CreateAuthRequest` is redirected to the already validated redirect URI
   (S256 enforcement relies on it). `ErrInvalidRequestRedirectURI` is flagged redirect-disabled and is
   rendered as an error page; the allowlist re-check in `CreateAuthRequest` relies on it, and runs
   before the PKCE check so no error is ever redirected to an unvetted URI.
   The library validates prompt and response_type only after accepting a native client's loopback URI
   loosely (userinfo, any loopback IP, https), and redirects those errors; `Service.preCheck` therefore
   resolves the client and applies the allowlist before the library runs.
2. The provider decodes `/authorize`, `/oauth/token`, and `/revoke` parameters from `r.Form` after our
   wrapper parsed it (the default scope relies on it), and its `ParseForm` is a no-op once `Form` and
   `PostForm` are set. Its decoder (zitadel/schema) matches keys case-insensitively (`strings.EqualFold`)
   and in map order, so a case variant could override a checked value: every OP endpoint that decodes goes
   through `canonicalForm`, which keeps only exact known keys, refuses case variants and repeats, and
   clears the raw query and body. `/authorize/callback` reads only `r.Form.Get("id")` (exact key, no decoder).
3. `op.WithCORSOptions(nil)` disables CORS entirely.
4. Refresh tokens are issued only when the stored scopes contain `offline_access` and the client lists
   the `refresh_token` grant.
5. Opaque access tokens are `Crypto.Encrypt(tokenID + ":" + subject)`; `/revoke` decrypts them the
   same way and passes the id to `RevokeToken`.
6. `AuthorizeCallback` requires `AuthRequest.Done()`; the code is `Crypto.Encrypt(authRequestID)`,
   handed to `SaveAuthCode`.
7. The token endpoint answers an `*oidc.Error` of type `invalid_client` with 401 and any non-oidc error
   with 500; `GetClientByClientID` returns a fresh `invalid_client` for a client that is gone
   (`TestRefreshByRevokedClientIsInvalidClient`).

The tests in this package and `internal/server/oauth_test.go` cover each one; run them on any bump.

## Tests a change here must have

1. A failing test first, at the narrowest level: a `Store` method, a handler through `httptest`, or the
   end-to-end flow in `internal/server/oauth_test.go`.
2. For anything a client controls: a negative test, and a fuzz target for parsers.
3. For tokens: expiry, revocation, and the effect on the whole family.
