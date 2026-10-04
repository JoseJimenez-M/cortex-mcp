# Security

cortex-mcp gives AI assistants read and write access to private notes over the internet. This page
states what it protects, against whom, how, what it deliberately does not do, and the limits that
remain. To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## What is protected

- **The vault:** the notes, and the paths outside it on the same host.
- **The auth state** in `state_dir/auth.db`: the owner's TOTP secret, the OAuth signing and encryption
  keys (stored usable), and hashes of Bearer tokens, refresh tokens, authorization codes, recovery
  codes, enrollment links, and browser cookies.
- **The write log** (`state_dir/writes.log`): which client changed which note, and when.

## Threat model

| Adversary | What they can do | What stops them |
|-----------|------------------|-----------------|
| Anyone on the internet, with no credential | Reach `GET /healthz` and the OAuth endpoints | Every other route needs a token; OAuth needs the owner's approval with a passkey, TOTP, or recovery code |
| Someone holding a leaked token | Act as that client until it is revoked or expires | Revocation (`clients revoke`, `token revoke`), 1-hour OAuth access tokens, per-client rate limits, the write log |
| A connected assistant that misbehaves, or that a note or web page manipulated (prompt injection) | Use the twelve tools with its token | Path confinement, protected paths, no permanent delete, a read-only instructions file, versioned edits, rate and size limits, the disk floor, the write log |
| A phishing link to a real sign-in, or a malicious OAuth client registration | Ask the owner to approve a connection | The redirect allowlist, a login page that names the client and its redirect host and is bound to the browser that started the sign-in, CSRF tokens, attempt limits |
| Hosts on the reverse proxy's network | Send requests that look proxied | `X-Forwarded-For` is read only from `trusted_proxies`, and only for the OAuth rate limits |
| Many source addresses at once | Delay a sign-in (never grant one) | Per-source and global limits; see [Residual limits](#residual-limits) |

Out of the model: an attacker with root or the service user on the host, a compromised owner device or
authenticator, and a malicious operator. Those already have the vault.

## Defences

### Vault access

- All file access goes through `os.Root` in `internal/vault`; every path is cleaned and confined to the
  vault. The vault never follows symbolic links: a path that is or passes through one is refused. Paths
  over 1024 bytes, or with a segment over 255 bytes, are refused.
- `.git`, `.obsidian`, `.cortex-mcp`, and Syncthing's `.stversions` and `.stfolder` are off limits at
  any depth. `.trash` is receive-only
  (`delete_note` writes there; reads and moves out are allowed). `deny` adds more, and each entry also
  protects the same path below `.trash/` (`delete_note` keeps the folder path). Obsidian's own trash
  flattens paths, which no entry can match: if you use `deny`, consider adding `.trash` to it.
- The `instructions_file` is read-only for tools: an assistant cannot rewrite the rules that every other
  assistant receives.
- Writes are atomic (temp file, fsync, rename) and serialized per note. Guarded edits need the
  `version` from the last read, so a stale edit fails with `note_changed` instead of overwriting a newer
  one. Nothing is ever permanently deleted: `delete_note` moves a note to `.trash/`.
- Writes are refused with `disk_low` while the vault's filesystem has less than 1 GiB free (Linux and
  macOS), so a looping assistant cannot fill a shared disk; the rate limit bounds requests, not bytes.
  Notes over 8 MiB are not read, and frontmatter over 64 KiB is not decoded.

### Tokens and sessions

- Every route except `GET /healthz` and the OAuth endpoints requires a token: a Bearer token from
  `token create` or an OAuth access token. Bearer tokens and OAuth refresh tokens are stored only as
  hashes in `state_dir/auth.db`; OAuth access tokens are opaque and always looked up there (expiry,
  audience, and the client's existence come from the database, never from the token alone).
- Requests are rate limited per client: per Bearer token name, or per OAuth connection, never per OAuth
  client name (any registration can choose any name).
- An MCP session is bound to the credential that opened it: a Bearer token's row (after `token revoke`,
  a new token created with the same name cannot use the old token's sessions) or an OAuth connection
  (stable across refreshes, so a session survives token rotation).
- Each token can hold at most `limits.max_sessions_per_client` live sessions (default 200; clients
  that reuse a session use 1 or 2, clients that open one per tool call use one per call). Opening one
  more gets `429 Too Many Requests` with `Retry-After`; a slot frees when a client ends its session or
  the session times out. Sessions with no client POST for 30 minutes are closed.
- Every `429` from `/mcp` is logged as `request refused`, with the limit (`rate` or `sessions`) and the
  client name, at most once per client and limit per minute (the next line counts the ones left out).
  The token and the `Authorization` header are never logged.

### OAuth

- OAuth follows the MCP authorization spec (2025-11-25): PKCE with S256 only, the token bound to this
  server's `/mcp` URL (RFC 8707), the `iss` parameter on every authorization response (RFC 9207),
  access tokens valid 1 hour, refresh tokens valid 30 days and rotated on every use. Presenting a used
  refresh token, or a used authorization code, revokes that whole connection; a client that retries a
  lost refresh response must reconnect. An authorization code works once, including a failed exchange
  (a wrong PKCE verifier spends it).
- Clients register through `/register` (RFC 7591) or a client ID metadata document, and only with
  redirect URIs on `oauth.redirect_allowlist` (by default claude.ai, ChatGPT, Meta Muse, and loopback for
  native apps). Redirect URIs are compared exactly, never normalized.
- Metadata documents are fetched over https on port 443 only, never from private, loopback, or other
  non-public addresses, without following redirects, within 5 seconds and 64 KiB, at most 10 new
  fetches a minute (and 3, then 2 a minute, per source address; documents on the host of an allowlisted
  redirect, such as claude.ai, have a separate budget of 5, then 1 every 10 seconds, and fall back to
  the general one when it is empty), and cached for 1 hour. Redirect URIs in a document that are not on
  the allowlist are dropped and the rest kept. If the document host is briefly unreachable, a client
  that already has a connection keeps working from the cache for up to 24 hours; a well-formed document
  that is refused (no allowed redirect URI left, a different client id, a confidential client) ends it
  at once. Logs name a metadata document client by its host only. This fetch is the server's only
  outbound network call.
- `/authorize` accepts GET only, and every request is rate limited per source address (20, then 1
  every 3 seconds) and globally (600, then 10 a second, a guard against CPU exhaustion). `state` may be
  at most 2048 bytes and `nonce` 512. At most 10 sign-in requests per source address, and 200 overall,
  wait for approval at once; beyond 200 the oldest waiting request of the address holding the most is
  dropped (an approved request is never dropped).
- `/register` is rate limited per source address (5, then 1 every 6 minutes) and globally (10, then 1 a
  minute). At most 50 registered clients that never completed a login are kept; when full, the oldest
  one older than 10 minutes is evicted (if none is old enough, registration answers 503), and a client
  that never completes a login is deleted after 24 hours. Clients with a connection never count and
  are never evicted.
- No endpoint sends CORS headers.

### The owner login

- The login page is bound to the browser that started the authorization (a `Secure`, `HttpOnly`,
  `SameSite=Lax` cookie), carries a per-request CSRF token, cannot be framed (CSP `frame-ancestors
  'none'` with a per-page nonce), and names the client, its redirect host, and (for metadata documents)
  the host that published it.
- Attempts with a code (authenticator or recovery code, and the code on the passkey registration page)
  are limited per source address (5, then 2 a minute) and globally (10 a minute). Passkey sign-in steps
  draw only on the same per-source budget: a passkey cannot be guessed, so a few sources spending the
  global code budget cannot keep the owner from approving with a passkey. When the global budget
  refuses a request, the source's own budget is not charged.
- The owner logs in with a passkey (WebAuthn, user verification required, signature counter checked for
  cloned authenticators), a TOTP code (a time step is accepted once), or one of ten single-use recovery
  codes. After 50 consecutive wrong TOTP codes the TOTP factor locks until a passkey or recovery code
  login, or `cortex-mcp unlock-totp` on the host. Passkeys need a DNS name in `public_url` (`localhost`
  works); with an IP address the server logs a warning and offers TOTP and recovery codes only.
- The owner exists only after `cortex-mcp setup` on the host; nothing on the web can create or reset
  it. The passkey enrollment link carries its token in the URL fragment (never sent to proxies), works
  once, lasts 10 minutes, and also asks for a current TOTP code.
- Recovery codes, refresh tokens, authorization codes, enrollment links, and browser cookies are stored
  only as hashes. The TOTP secret and the OAuth signing and encryption keys are stored usable in
  `auth.db`, which is why `state_dir` is kept out of the vault.

### Host and network

- `state_dir` must not be inside the vault and must not be a shared directory such as `/tmp`; the
  server keeps it at 0700 and its files at 0600 (Linux and macOS).
- The default `listen` is `127.0.0.1:8080`. `serve` warns when `public_url` is https and `listen` is
  not loopback, because the plain HTTP port would then bypass the TLS proxy (in a container, `:8080` is
  expected).
- `X-Forwarded-For` is read only when the TCP peer is in `trusted_proxies` (each entry at least /8 for
  IPv4 or /32 for IPv6), and only to key the OAuth rate limits; no other forwarded header is read.

### Errors and logs

- Tool errors are short stable codes; host paths and internals never reach the client (anything
  unexpected becomes `internal_error`). Note content is treated as data and never interpreted by the
  server.
- No token, secret, hash, or `Authorization` header appears in a log line or an error message. Reads
  are not logged; every write is, with the client that made it.

### Releases

- Release binaries are built with `CGO_ENABLED=0` and `-trimpath`. The checksum file of every release
  and the container image are signed keylessly with cosign by the release workflow, recorded in the
  public Rekor log, and ship SBOMs (SPDX per archive, and a BuildKit attestation in the image).
  [Installing](install.md#verifying-a-download) shows how to verify them.
- The image is distroless and static (no shell, no package manager) and runs as a non-root user.
- CI actions are pinned by commit SHA, the base image by digest, and Dependabot proposes the bumps.
  The release job runs only for tags on `main` and holds only the permissions it needs.

## Deliberate non-features

These are left out on purpose; asking for them is asking for a design change.

- **No shell, no `os/exec`, no git operations, no hard delete**, and no network calls from tool code.
- **One owner.** No user accounts, no multi-tenant vaults, no web sign-up. The owner and every factor
  are created from the host's console.
- **One scope**, `vault`, which grants all twelve tools. No per-client folder scopes yet.
- **No persistent owner browser session**: every connection is approved on its own.
- **No CORS** on any endpoint, and no browser-only OAuth clients.
- **No TLS in the server**: a reverse proxy terminates it.
- **No link rewriting** on `move_note`: it reports the notes that still link to the old path.
- **No read logging**: reads change nothing and would make the log large.
- **No key rotation command**: the OAuth signing and encryption keys are created on first start and stay
  in `auth.db`; `reset-auth` clears the owner and every client but keeps them. Editing `auth.db` by
  hand to replace them is not supported.

## Residual limits

Known and accepted for a single-owner server:

- **Many sources together can delay a sign-in, never grant one.** About 30 source addresses each
  spending their own rate can keep `/authorize` refusing, 5 can keep the global code budget empty
  (passkeys keep working), 6 the registration budget, 5 the metadata document budget, and 8 both
  metadata document budgets together. 200 sources holding one pending request each evict the owner's
  pending request (the owner starts again), and 1024 passkey begins within the owner's ceremony evict
  it. Buckets are kept for at most 4096 sources, and an IPv6 /48 counts as one address.
- **Trusted proxy networks are trusted whole.** With Caddy in Docker, every container on that network
  can choose its own rate-limit bucket.
- **A retried refresh ends the connection.** A client that lost a refresh response and retries with the
  old refresh token gets the whole connection revoked (RFC 9700 reuse detection), and must reconnect.
- **Secrets at rest.** The TOTP secret and OAuth keys are stored usable in `auth.db`. A backup of
  `auth.db` is a live credential: restoring it brings back every Bearer token it holds, including any
  revoked since. Keep backups as private as `state_dir`.
- **Notes are written with mode 0644 filtered by the umask.** For a private vault, keep the vault root
  at 0700 or run the service with `UMask=0077`.
- **Assistant-written code can run in your editor.** Assistants can write anything a note may contain,
  including code blocks that Obsidian plugins execute (`dataviewjs`, Templater). If those plugins are
  enabled, that code runs in your Obsidian with its permissions the next time you open the note. Review
  assistant-written notes, or keep such plugins off.
- **Case-insensitive filesystems.** Linux on ext4 (case-sensitive) is the supported target. On
  case-insensitive filesystems, name folding has documented limits: Unicode normalization (NFC versus
  NFD) is not folded, and NTFS case rules (such as the Turkish dotless i) differ from the Unicode simple
  folding the server uses, so two spellings the filesystem treats as one name may not match a `deny`
  entry.
- **Platforms.** On Windows the disk floor and the `state_dir` permission checks do not apply, and the
  test suite runs only on Linux.

## Operator checklist

- Run `setup`, register a passkey, and keep the three factors in different places.
- Keep `listen` on loopback behind a TLS proxy (or `:8080` in a container with no published port).
- Set `trusted_proxies` to the proxy's address or its own network, nothing wider.
- Keep `state_dir` private, outside the vault, and out of any sync or backup that others can read.
- Review `cortex-mcp clients list` now and then, and revoke what you do not recognize.
- Never approve a sign-in you did not start yourself, just now.
- Verify release signatures before installing or upgrading, and pin the image by digest.
