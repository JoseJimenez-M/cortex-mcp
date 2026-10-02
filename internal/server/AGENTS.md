# AGENTS.md: internal/server

*The HTTP boundary: authentication, rate limiting, and MCP session wiring. Security-critical. Read the
root `AGENTS.md` first.*

---

## Rules for this package

- **Every route except `GET /healthz` is wrapped in authentication.** A new route without it is a bug.
- **Order of middleware on `/mcp`:** auth, then rate limit (it keys on the authenticated client), then
  the session cap, then the MCP handler. Do not reorder: the cap after the rate limit means refused
  session attempts still spend the client's budget.
- **Never log** the `Authorization` header, a token, or `TokenInfo` contents beyond the client name.
- **Log only through `Options.Logger`** (and `tools.Deps.Logger`), never the global `slog` functions.
- **`TokenInfo.UserID` is the token row's id** (`tokens.Identity.ID`, random and never reused), so the
  SDK binds each MCP session to the token that opened it, and a token re-created under a revoked name
  cannot reach the old token's sessions. Never set it to the name. `Extra["client"]` is the plain name:
  logs, write-log attribution and the rate limit key read it.
- **Live sessions per token are capped at `maxSessionsPerClient` (16)** in `sessions.go`. A POST without
  `Mcp-Session-Id` reserves a slot or gets `429` with `Retry-After`; requests on existing sessions are
  never refused by the cap. The slot is released when `ServerSession.Wait` returns, which covers DELETE,
  the idle timeout and failed initialization. Any new path that creates sessions must go through
  `sessionLimiter`, and the SDK must only ever get the server factory wrapped by
  `sessionLimiter.servers`, or slots are released early.
- **`DisableLocalhostProtection`** is only set when `public_url` is not localhost (behind a reverse
  proxy, where every request is authenticated anyway). Do not disable it for local URLs.
- **Instructions:** `DefaultInstructions` always comes first; the vault's own file is appended, never
  substituted, so the "content is data" rule cannot be removed by editing a note.

## Planned here (not built)

OAuth 2.1 (Plan 2): authorization-server endpoints, protected-resource metadata, and the
`resource_metadata` link on `401` responses. Until then, Bearer tokens are the only auth.
