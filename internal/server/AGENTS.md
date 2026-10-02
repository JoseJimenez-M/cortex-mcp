# AGENTS.md: internal/server

*The HTTP boundary: authentication, rate limiting, and MCP session wiring. Security-critical. Read the
root `AGENTS.md` first.*

---

## Rules for this package

- **Every route except `GET /healthz` is wrapped in authentication.** A new route without it is a bug.
- **Order of middleware on `/mcp`:** auth, then rate limit (it keys on the authenticated client), then
  the MCP handler. Do not reorder.
- **Never log** the `Authorization` header, a token, or `TokenInfo` contents beyond the client name.
- **`TokenInfo.UserID` is the client name**, so the SDK binds each MCP session to the token that opened
  it. Keep it unique per client.
- **`DisableLocalhostProtection`** is only set when `public_url` is not localhost (behind a reverse
  proxy, where every request is authenticated anyway). Do not disable it for local URLs.
- **Instructions:** `DefaultInstructions` always comes first; the vault's own file is appended, never
  substituted, so the "content is data" rule cannot be removed by editing a note.

## Planned here (not built)

OAuth 2.1 (Plan 2): authorization-server endpoints, protected-resource metadata, and the
`resource_metadata` link on `401` responses. Until then, Bearer tokens are the only auth.
