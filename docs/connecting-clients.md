# Connecting clients

cortex-mcp serves one MCP endpoint, `<public_url>/mcp` (for example `https://mcp.example.com/mcp`), over
Streamable HTTP. A client authenticates in one of two ways:

- **OAuth 2.1**, for assistant apps and Claude Code: the app finds the server's OAuth metadata, opens
  the login page in a browser, and you approve the connection with a passkey, an authenticator code, or
  a recovery code. Needs `oauth.enabled: true` (the default) and `cortex-mcp setup` run once on the host.
- **A Bearer token**, for CLI agents, scripts, and machines without a browser: `cortex-mcp token create
  NAME` on the host prints a token once, and the client sends it as `Authorization: Bearer <token>`.
  Needs `bearer_tokens: true` (the default).

Paste the MCP URL exactly as shown, with no trailing slash: OAuth tokens are bound to this exact URL,
and `.../mcp/` is a different path that the server does not serve.

App menus change often; the steps below describe the apps as they were in October 2026.

## Before you approve any sign-in

Never approve a sign-in that you did not start yourself, just now, from your own assistant, even if
the redirect host is `claude.ai` or another app you use: anyone can start a sign-in for such an app and
send you the link, and approving it would connect their account to your vault.

The login page names the client, its redirect host, and, for a client metadata document, the host that
published it. The client name is chosen by whoever registered the client, so the redirect host is what
identifies it.

## Claude Code

With OAuth (Claude Code opens the login page in your browser and registers itself with a loopback
redirect URI):

```bash
claude mcp add --transport http cortex https://mcp.example.com/mcp
```

Or with a Bearer token, for machines without a browser:

```bash
claude mcp add --transport http cortex https://mcp.example.com/mcp \
  --header "Authorization: Bearer <token>"
```

## claude.ai

Web, desktop, and mobile share one connector: Settings, Connectors, Add custom connector, and paste the
MCP URL. claude.ai registers itself with a client ID metadata document or through `/register`; either
works.

## ChatGPT

Turn on developer mode, then add a connector (an MCP server) with the MCP URL and OAuth authentication.

## Meta Muse

Ask Muse, in a chat, to create a custom connector for your MCP server at the MCP URL, using OAuth.

In October 2026 Muse did not register itself: after creating the connector it showed a form (its
labels may appear in your account's language) with the server host, prefilled, and a required
**Client ID**, and no secret field. Register a client for it on your server and paste the id:

```bash
curl -sS -X POST https://mcp.example.com/register \
  -H 'Content-Type: application/json' \
  -d '{"client_name":"Meta Muse","redirect_uris":["https://agent.meta.ai/api/hatch/oauth/callback"]}'
```

The server answers `201 Created` with JSON like:

```json
{
  "client_id": "<client id>",
  "client_id_issued_at": 1790000000,
  "client_name": "Meta Muse",
  "redirect_uris": ["https://agent.meta.ai/api/hatch/oauth/callback"],
  "token_endpoint_auth_method": "none",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "vault"
}
```

Paste `client_id` into the form and save. Muse then opens the login page; approve it. If a form asks
for more, the values are: client secret empty (it is a public client using PKCE), authorization URL
`https://mcp.example.com/authorize`, token URL `https://mcp.example.com/oauth/token`, scopes
`vault offline_access`.

- The client id is not a secret.
- Register right before you connect. A client that never completes a sign-in is deleted after 24
  hours, and when 50 such clients exist the oldest one older than 10 minutes is evicted to make room
  (if none is old enough, `/register` answers 503 until one is). Once connected, the client is kept.
- `cortex-mcp clients revoke ID` deletes the client, and a Client ID from `/register` cannot be
  reused: the same id is refused from then on. To reconnect Muse after a revoke, register a new client
  with the command above and paste the new id into the connector.
- `/register` needs `Content-Type: application/json` and is rate limited per source address (5, then 1
  every 6 minutes). The redirect URI must be on `oauth.redirect_allowlist`; the Muse callback is there
  by default.
- Muse may open a new MCP session for each tool call and run calls in parallel. The defaults
  (`limits.requests_per_minute: 180`, `limits.max_sessions_per_client: 200`) allow for that. If Muse
  reports a rate limit, the server log has a `request refused` line saying which limit it hit; see
  [configuration](configuration.md).

## Other MCP clients

Any client that speaks Streamable HTTP and supports either a custom `Authorization` header or OAuth can
connect.

**With a Bearer token:** send `Authorization: Bearer <token>` on every request to `/mcp`.

**With OAuth**, the server implements the MCP authorization spec (revision 2025-11-25):

- **Discovery.** An unauthenticated request to `/mcp` gets `401` with
  `WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp", scope="vault"`.
  Protected resource metadata (RFC 9728) is at `/.well-known/oauth-protected-resource` and that
  path-specific variant; authorization server metadata (RFC 8414) is at
  `/.well-known/oauth-authorization-server` and `/.well-known/openid-configuration`.
- **Registration.** Either `POST /register` (RFC 7591; JSON body up to 16 KiB; only `client_name` and
  `redirect_uris` are used) or a client ID metadata document: the `client_id` is the https URL of a JSON
  document, which the server fetches on port 443 from a public address, without following redirects,
  within 5 seconds and 64 KiB. A client has 1 to 10 redirect URIs, all on `oauth.redirect_allowlist`,
  and all loopback or all https.
- **Public clients only.** Every client uses `token_endpoint_auth_method: none` and PKCE.
- **Authorization code flow** with PKCE `S256` (`plain` and a missing challenge are refused);
  `/authorize` accepts GET only. The `resource` parameter, when sent, must be the MCP URL byte for byte;
  omitted, it defaults to it. Every authorization response carries `iss`.
- **Tokens.** Every grant gets the scopes `vault offline_access`. Access tokens last 1 hour; refresh
  tokens last 30 days and rotate on every use. Presenting an already used refresh token revokes the
  connection, so a client must store each new refresh token before using it.
- **Redirect URIs.** Native apps use a loopback redirect (`http://127.0.0.1:<port>/...`,
  `http://localhost:<port>/...`, or `http://[::1]:<port>/...`), allowed by the `loopback` entry. A
  web-based client needs its https callback added to `oauth.redirect_allowlist`; a list in the config
  replaces the defaults, so keep the entries you still need.
- **No CORS.** A client that calls the token endpoint from JavaScript in a browser page cannot connect;
  supported clients call it from a server or a native app.

## Managing connections

- `cortex-mcp clients list` shows Bearer tokens and OAuth clients, one per line, with each OAuth
  client's redirect hosts.
- `cortex-mcp clients revoke ID` ends one connection: an OAuth client with all its tokens, or a Bearer
  token. Revoking one never affects the others. The OAuth client itself is deleted, and what happens
  next depends on how it registered:
  - A client registered through `/register` (Meta Muse, for example) cannot use its id again: the id
    is refused from then on. To reconnect, register again and give the app the new id.
  - A client that uses a client ID metadata document (claude.ai, for example) is created again the
    next time the app connects, since its id is the URL of that document. The connection still needs
    your approval on the login page, like a first connection.
- Each write is labelled in `state_dir/writes.log` with the client that made it: a Bearer token's name,
  or the name an OAuth app registered.
