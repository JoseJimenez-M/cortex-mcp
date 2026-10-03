# cortex-mcp

A self-hosted [MCP](https://modelcontextprotocol.io) server that lets AI assistants read and write one
Markdown vault (an Obsidian vault or any folder of `.md` files) over Streamable HTTP. The vault is the
durable memory; the assistant behind it is replaceable.

## Status

Pre-release. Implemented: the core server (vault library, twelve tools, rate limiting, write log), Bearer
tokens for CLI agents and scripts, and OAuth 2.1 for assistant apps (claude.ai, ChatGPT, Meta Muse,
Claude Code), with an owner login by passkey, TOTP, or recovery code. Release tooling and the licence
file are planned (plan 3).

## Features

Twelve tools. All paths are vault-relative and use `/`.

| Tool | What it does |
|------|--------------|
| `read_note` | Returns a note's content, modified time, and a `version`. |
| `list` | Lists the notes and subfolders of a folder, optionally recursive (at most 500 entries). |
| `search` | Case-insensitive text search; returns paths, line numbers, and snippets. |
| `search_tag` | Finds notes by tag, from frontmatter `tags` or inline `#tag`. |
| `backlinks` | Finds notes that link to a note by wikilink or Markdown link. |
| `recent` | Lists notes modified in the last 1–365 days, with the clients that changed them. |
| `create_note` | Creates a note; fails if it exists. |
| `append` | Adds text at the end of a note or of one section; needs no version. |
| `replace_section` | Replaces one section's body; needs the `version` from `read_note`. |
| `update_frontmatter` | Sets or removes frontmatter keys, body untouched; needs the `version`. |
| `move_note` | Moves or renames a note (also restores one from `.trash`); reports notes still linking to the old path, does not rewrite links. |
| `delete_note` | Moves a note to `.trash/`. Nothing is ever permanently deleted. |

The read tools are annotated read-only; the write tools are annotated with whether they are destructive
or idempotent so clients can ask for confirmation appropriately.

There is no shell, no git, and no hard delete. Guarded edits use a per-note version, so a stale edit
fails with `note_changed` instead of overwriting a newer one. Every write is appended to
`state_dir/writes.log` with the client name of the token that made it.

If `instructions_file` is set, its content is sent to every assistant on connect. Tools can read that
file but never change, move, or delete it.

## Security model

- All file access goes through `os.Root` in `internal/vault`; every path is cleaned and confined to the
  vault. The vault never follows symbolic links: a path that is or passes through one is refused.
  Paths over 1024 bytes, or with a segment over 255 bytes, are refused.
- `.git`, `.obsidian`, and `.cortex-mcp` are off limits at any depth. `.trash` is receive-only
  (`delete_note` writes there; reads and moves out are allowed). `deny` adds more, and each entry also
  protects the same path below `.trash/` (`delete_note` keeps the folder path). Obsidian's own trash
  flattens paths, which no entry can match: if you use `deny`, consider adding `.trash` to it.
- The `instructions_file` is read-only for tools: an assistant cannot rewrite the rules that every other
  assistant receives.
- Writes are atomic (temp file, fsync, rename) and serialized per note. Writes are refused with
  `disk_low` while the vault's filesystem has less than 1 GiB free (Linux and macOS), so a looping
  assistant cannot fill a shared disk; the rate limit bounds requests, not bytes.
- Every route except `GET /healthz` and the OAuth endpoints requires a token: a Bearer token from
  `token create` or an OAuth access token. Bearer tokens and OAuth refresh tokens are stored only as
  hashes in `state_dir/auth.db`; OAuth access tokens are opaque and always looked up there (expiry,
  audience, and the client's existence come from the database, never from the token alone). Requests
  are rate limited per client: per Bearer token name, or per OAuth connection, never per OAuth client
  name (any registration can choose any name).
- OAuth follows the MCP authorization spec (2025-11-25): PKCE with S256 only, the token bound to this
  server's `/mcp` URL (RFC 8707), the `iss` parameter on every authorization response (RFC 9207), access
  tokens valid 1 hour, refresh tokens valid 30 days and rotated on every use. Presenting a used refresh
  token, or a used authorization code, revokes that whole connection; a client that retries a lost
  refresh response must reconnect. An authorization code works once, including a failed exchange (a
  wrong PKCE verifier spends it).
- Clients register through `/register` (RFC 7591) or a client ID metadata document, and only with
  redirect URIs on `oauth.redirect_allowlist` (by default claude.ai, ChatGPT, Meta Muse, and loopback for
  native apps). Redirect URIs are compared exactly, never normalized. Metadata documents are fetched
  over https on port 443 only, never from private, loopback, or other non-public addresses, without
  following redirects, within 5 seconds and 64 KiB, at most 10 new fetches a minute (and 3, then 2 a
  minute, per source address; documents on the host of an allowlisted redirect, such as claude.ai, have
  a separate budget of 5, then 1 every 10 seconds), and cached for 1 hour. Redirect URIs in a document that are not on the
  allowlist are dropped and the rest kept. If the document host is briefly unreachable, a client that
  already has a connection keeps working from the cache for up to 24 hours; a well-formed document
  that is refused (no allowed redirect URI left, a different client id, a confidential client) ends it
  at once. Logs name a metadata document client by its host only.
- `/authorize` accepts GET only, and every request is rate limited per source address (20, then 1
  every 3 seconds) and globally (600, then 10 a second, a guard against CPU exhaustion). `state` may be
  at most 2048 bytes and `nonce` 512. At most 10 sign-in requests per source address, and 200 overall,
  wait for approval at once; beyond 200 the oldest waiting request of the address holding the most is
  dropped, so yours survives unless about 200 addresses each hold one (an approved request is never
  dropped).
- These limits keep a single source, or a few, from locking you out. Many sources together still can
  delay a sign-in (never grant one): about 30 can keep `/authorize` refusing, 5 can keep the global
  code budget empty (passkeys keep working), and 3 to 6 can keep the registration or metadata document
  budgets empty.
- `/register` is rate limited per source address (5, then 1 every 6 minutes) and globally (10, then 1 a
  minute). At most 50 registered clients that never completed a login are kept; when full, the oldest
  one older than 10 minutes is evicted. Clients with a connection never count and are never evicted.
- The login page is bound to the browser that started the authorization (a `Secure`, `HttpOnly`,
  `SameSite=Lax` cookie), carries a per-request CSRF token, cannot be framed (CSP `frame-ancestors
  'none'` with a per-page nonce), and names the client, its redirect host, and (for metadata documents)
  the host that published it. Attempts with a code (authenticator or recovery code, and the code on the
  passkey registration page) are limited per source address (5, then 2 a minute) and globally (10 a
  minute). Passkey sign-in steps draw only on the same per-source budget: a passkey cannot be guessed,
  so a few sources spending the global code budget cannot keep you from approving with a passkey. When
  the global budget refuses a request, the source's own budget is not charged.
- The owner logs in with a passkey (WebAuthn, user verification required, signature counter checked for
  cloned authenticators), a TOTP code (a time step is accepted once), or one of ten single-use recovery
  codes. After 50 consecutive wrong TOTP codes the TOTP factor locks until a passkey or recovery code
  login, or `cortex-mcp unlock-totp` on the host. Passkeys need a DNS name in `public_url` (`localhost`
  works); with an IP address the server logs a warning and offers TOTP and recovery codes only.
- Recovery codes, refresh tokens, authorization codes, enrollment links, and browser cookies are stored
  only as hashes. The TOTP secret and the OAuth signing and encryption keys are stored usable in
  `auth.db`, which is why `state_dir` is kept out of the vault.
- An MCP session is bound to the credential that opened it: a Bearer token's row (after `token revoke`,
  a new token created with the same name cannot use the old token's sessions) or an OAuth connection
  (stable across refreshes, so a session survives token rotation).
- Each token can hold at most 16 live sessions (normal clients use 1 or 2). Opening one more gets
  `429 Too Many Requests` with `Retry-After`; a slot frees when a client ends its session or the session
  times out.
- `state_dir` must not be inside the vault and must not be a shared directory such as `/tmp`.
- Sessions with no client POST for 30 minutes are closed. The instructions file is re-read at most every
  5 seconds.
- The default `listen` is `127.0.0.1:8080`. `serve` warns when `public_url` is https and `listen` is not
  loopback, because the plain HTTP port would then bypass the TLS proxy (in a container, `:8080` is
  expected).
- Tool errors are short stable codes; host paths and internals never reach the client. Note content is
  treated as data and never interpreted by the server.
- Notes are written with mode 0644 filtered by the umask. For a private vault, keep the vault root at
  0700 or run the service with `UMask=0077`.
- Assistants can write anything a note may contain, including code blocks that Obsidian plugins execute
  (`dataviewjs`, Templater). If those plugins are enabled, that code runs in your Obsidian with its
  permissions the next time you open the note. Review assistant-written notes, or keep such plugins off.
- Linux on ext4 (case-sensitive) is the supported target. On case-insensitive filesystems, name folding
  has documented limits: Unicode normalization (NFC vs NFD) is not folded, and NTFS case rules (such as
  the Turkish dotless i) differ from the Unicode simple folding the server uses, so two spellings the
  filesystem treats as one name may not match a `deny` entry.

## Quick start

Requires Go (see `go.mod` for the version).

```bash
go build -o bin/cortex-mcp ./cmd/cortex-mcp
cp config.example.yaml config.yaml          # set vault, state_dir, public_url
./bin/cortex-mcp setup -config config.yaml               # the owner, for OAuth apps
./bin/cortex-mcp token create -config config.yaml my-laptop  # optional: a Bearer token
./bin/cortex-mcp serve -config config.yaml
```

Commands:

```
cortex-mcp serve [-config path]
cortex-mcp setup [-config path] [-passkey | -force]
cortex-mcp unlock-totp [-config path]
cortex-mcp reset-auth [-config path] [-yes]
cortex-mcp clients list [-config path]
cortex-mcp clients revoke [-config path] ID
cortex-mcp token create [-config path] NAME
cortex-mcp token list [-config path]
cortex-mcp token revoke [-config path] NAME
cortex-mcp version
```

Flags go before `NAME`. The config path defaults to `$CORTEX_MCP_CONFIG`, then
`/etc/cortex-mcp/config.yaml`. `token create` prints the secret once on stdout; store it then, it
cannot be shown again. `serve` logs JSON to stderr and shuts down cleanly on SIGINT or SIGTERM (a second
signal exits at once). `GET /healthz` answers `ok` without authentication; the MCP endpoint is `/mcp`.

`setup` creates the owner who approves OAuth connections and prints three factors once: a TOTP URI for an
authenticator app (and the secret, to type by hand), ten recovery codes, and a link to register a passkey
(open it within 10 minutes while the server runs; it works once and asks for a current TOTP code). Keep
the factors in different places, for example the passkey in a password manager, TOTP in an authenticator
app, and the recovery codes offline, so losing one never locks you out. `setup` refuses to run twice:
`setup -passkey` prints a new passkey link (to add another passkey), and `setup -force` replaces every
factor at once (the old passkeys, authenticator entry, and recovery codes stop working, and approvals
they gave that have not yet become a connection are dropped; connected clients stay connected).
`unlock-totp` clears the TOTP lock after too many wrong codes. `reset-auth -yes` is the last resort: it
deletes the owner's factors and disconnects every OAuth client (Bearer tokens stay); without `-yes` it
asks you to type `reset`. `clients list` shows Bearer tokens and OAuth clients, one tab-separated line
each, with the redirect hosts of every OAuth client; `clients revoke ID` removes one of either kind (an
OAuth client's name is also accepted when exactly one client has it).

Every command works while `serve` is running: they share `auth.db`, and the server reads owner and
client state from it on each request.

Every config key is documented in [`config.example.yaml`](config.example.yaml). Invalid values fail at
startup with a message naming the key.

## Behind a reverse proxy

The server speaks plain HTTP. For anything beyond localhost, keep the default `listen: 127.0.0.1:8080`
and terminate TLS in a reverse proxy. Set `public_url` to the public https URL. A generic Caddy example:

```
mcp.example.com {
    reverse_proxy 127.0.0.1:8080 {
        flush_interval -1
    }
}
```

`flush_interval -1` disables response buffering so streamed (SSE) responses reach the client at once.

The OAuth endpoints (`/authorize`, the login page, client registration, metadata document fetches)
are rate-limited per client address. Behind a proxy every
request comes from the proxy's address, so set `trusted_proxies` to the proxy's network; without it all
clients share one bucket per limiter, which is safe but coarser. The server then reads
`X-Forwarded-For` only from a TCP peer inside `trusted_proxies`, and takes the right-most entry that is
not itself a listed proxy, so list only proxies that append the address they received from (Caddy
does), and never a network that untrusted hosts can send from. Entries wider than /8 (IPv4) or /32
(IPv6) are refused.

### Caddy and cortex-mcp in Docker

With both containers on one Docker network, Caddy proxies to the service name and the server listens on
all interfaces inside its container (`listen: ":8080"`, with no published port). Find the network's
subnet and list it in `trusted_proxies`:

```bash
docker network inspect <network> --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}'
```

```yaml
listen: ":8080"
trusted_proxies: [172.18.0.0/16]   # the subnet printed above
```

This trusts every container on that network, not only Caddy (Vaultwarden or any other service you run
there too): any of them could set `X-Forwarded-For` and pick its own rate-limit bucket. That is
acceptable for containers you run yourself, since the global limits still cap them all; give
cortex-mcp and Caddy a network of their own if another container there is not trusted.

The Caddyfile then uses `reverse_proxy cortex-mcp:8080` with the same `flush_interval -1`. `serve` logs
a warning for the non-loopback `listen`, which is expected in a container. Run the owner commands inside
the container, for example `docker compose exec cortex-mcp /cortex-mcp setup -config
/config/config.yaml`; `reset-auth` there needs `-yes` or a TTY.

### Upgrading from a plan 1 binary

The first time this version opens `state_dir/auth.db` (`serve` or any command) it migrates the file
from schema version 2 to 3 (it adds the OAuth tables; Bearer tokens are kept). The plan 1 binary refuses a version 3 database, so a rollback
needs the old file. Stop the server and back up `auth.db` together with `auth.db-wal` and `auth.db-shm`
(when present) before upgrading, then start the new binary and run `setup`. The backup is a live
credential: putting it back brings back every Bearer token it holds, including any revoked since (and a
copy of a later `auth.db` also holds the TOTP secret and the OAuth keys in usable form). Keep it as
private as `state_dir`, and delete it once the upgrade is verified.

## Connect assistant apps (OAuth)

Run `cortex-mcp setup` once on the host and register a passkey with the link it prints. Then add the
server in the app with the MCP URL `https://mcp.example.com/mcp`, pasted exactly as shown: no trailing
slash (the token is bound to this exact URL, and `.../mcp/` is a different resource):

- **claude.ai** (web, desktop, and mobile): Settings, Connectors, Add custom connector, paste the URL.
  claude.ai registers itself with a client ID metadata document or through `/register`; either works.
- **ChatGPT**: turn on developer mode, then add a connector (an MCP server) with the URL and OAuth
  authentication.
- **Meta Muse**: add a custom connector from a chat, giving it the URL; it signs in with OAuth.

The app opens this server's login page: check the client name and the redirect host (and, for a client
metadata document, the host that published it), then approve with your passkey, an authenticator code,
or a recovery code. `cortex-mcp clients list` then shows the connection, and `cortex-mcp clients revoke
ID` ends it. Each app connection is labelled in `writes.log` with the name the app registered; the name
is chosen by the app, so the redirect host on the login page is what identifies it.

Never approve a sign-in that you did not start yourself, just now, from your own assistant, even if the
redirect host is `claude.ai` or another app you use: anyone can start a sign-in for such an app and send
you the link, and approving it would connect their account to your vault.

## Connect Claude Code

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

Any MCP client that supports Streamable HTTP and either OAuth or a custom `Authorization` header can
connect the same way.

## Development

Test-driven: write the failing test first, then the minimum code. Read `AGENTS.md` before changing
anything; it lists the invariants and the package layout.

```bash
go test -race ./...
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@2026.2.1 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
go run github.com/securego/gosec/v2/cmd/gosec@v2.29.0 ./...
```

The design is in [`docs/specs/2026-10-01-cortex-mcp-design.md`](docs/specs/2026-10-01-cortex-mcp-design.md).

## Licence

Source-available under PolyForm Noncommercial 1.0.0. Commercial use requires a license: contact
jimenez331375@gmail.com. The `LICENSE` file itself is added in plan 3.
