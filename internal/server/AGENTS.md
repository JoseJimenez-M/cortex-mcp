# AGENTS.md: internal/server

*The HTTP boundary: authentication, rate limiting, and MCP session wiring. Security-critical. Read the
root `AGENTS.md` first.*

---

## Rules for this package

- **Every route except `GET /healthz` is wrapped in authentication, or is an OAuth route registered by
  `oauth.Service.Register`** (public by protocol, listed in `internal/oauth/AGENTS.md`). Any other new
  route without authentication is a bug.
- **Order of middleware on `/mcp`:** auth, then rate limit (it keys on `Extra["ratekey"]`), then
  the session cap, then the MCP handler. Do not reorder: the cap after the rate limit means refused
  session attempts still spend the client's budget.
- **Never log** the `Authorization` header, a token, or `TokenInfo` contents beyond the client name.
- **Log only through `Options.Logger`** (and `tools.Deps.Logger`), never the global `slog` functions.
- **`TokenInfo.UserID`** is the Bearer token row id (`tokens.Identity.ID`, random, never reused) or
  `"oauth:"` plus the OAuth grant family (stable across refreshes, so sessions survive token rotation,
  and unique per grant). The SDK binds each MCP session to it, and the session cap counts per UserID.
  Never set it to a name. `Extra["client"]` is the token name or the sanitized OAuth client name: logs
  and write-log attribution read it. `Extra["ratekey"]` is the rate limit key: `"bearer:"` plus the
  token name (a token re-created under the same name keeps its budget) or the OAuth UserID. Never key
  the rate limit or the cap on an OAuth client name: registrations choose it freely and two may share
  one. Tokens are routed by shape (`tokens.IsBearer`) in `tokenVerifier`, never tried against both
  stores; with `bearer_tokens: false` every `cmcp_` token gets `401`.
- **Live sessions per token are capped at `limits.max_sessions_per_client`** (default 200) in `sessions.go`. A POST without
  `Mcp-Session-Id` reserves a slot or gets `429` with `Retry-After`; requests on existing sessions are
  never refused by the cap. The slot is released when `ServerSession.Wait` returns, which covers DELETE,
  the idle timeout and failed initialization. Any new path that creates sessions must go through
  `sessionLimiter`, and the SDK must only ever get the server factory wrapped by
  `sessionLimiter.servers`, or slots are released early.
- **Every `429` from `/mcp` goes through `refusalLog.note`** (`refusals.go`): one `request refused`
  warning per client and limit per minute, with the client name only.
- **`DisableLocalhostProtection`** is only set when `public_url` is not localhost (behind a reverse
  proxy, where every request is authenticated anyway). Do not disable it for local URLs.
- **Instructions:** `DefaultInstructions` always comes first; the vault's own file is appended, never
  substituted, so the "content is data" rule cannot be removed by editing a note.

## OAuth

`Options.OAuth` (nil when `oauth.enabled` is false) mounts the OAuth routes and turns on the
`resource_metadata` challenge and the `vault` scope check. The authorization server itself lives in
`internal/oauth`; this package only verifies its tokens through `oauth.Service.Verify`.
