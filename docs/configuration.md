# Configuration

cortex-mcp reads one YAML file. [`config.example.yaml`](../config.example.yaml) is a complete,
commented example; this page lists every key with its default and the exact validation rules.

## Where the file is read from

The `-config path` flag of every command, else the `CORTEX_MCP_CONFIG` environment variable, else
`/etc/cortex-mcp/config.yaml`.

## How the file is read

- At most 1 MiB, one YAML document, and a mapping at the top level.
- Unknown keys are rejected, so a misspelled key fails instead of being ignored.
- A key that is missing keeps its default; `vault`, `state_dir`, and `public_url` have none and are
  required.
- Every invalid value is reported at startup in one message that names each key. Values that fail to
  decode are shown as `<value>`, so a secret pasted by mistake never reaches a log.
- No value is secret. Secrets (owner factors, OAuth keys, token hashes) live only in `state_dir`.

## Summary

| Key | Default | Rule |
|-----|---------|------|
| `vault` | none (required) | absolute path |
| `state_dir` | none (required) | absolute path, not the vault or inside it |
| `public_url` | none (required) | canonical https URL, host and optional port only |
| `listen` | `127.0.0.1:8080` | `host:port` |
| `trusted_proxies` | `[]` | up to 32 CIDR networks |
| `instructions_file` | not set | vault-relative `.md` file |
| `deny` | `[]` | vault-relative paths |
| `bearer_tokens` | `true` | `false` needs `oauth.enabled: true` |
| `oauth.enabled` | `true` | |
| `oauth.redirect_allowlist` | five entries (below) | 1 to 32 entries while OAuth is on |
| `limits.max_write_bytes` | `1048576` | 1 to 8388608 |
| `limits.requests_per_minute` | `180` | 1 to 6000 |
| `limits.max_sessions_per_client` | `200` | 1 to 2000 |
| `logs.max_size_mb` | `5` | 1 to 1024 |
| `logs.keep` | `3` | 1 to 100 |

## Keys

### `vault`

The folder of Markdown notes to serve. Must be an absolute path. Paths in the config are compared as
written (after cleaning `.` and `..`); symbolic links are not resolved, so write the real path.

### `state_dir`

Where `auth.db` (owner factors, OAuth state, hashed Bearer tokens, with its `-wal` and `-shm` side files)
and `writes.log` (with its rotated copies) live. Must be an absolute path, and must not be the vault or
inside it, so secrets never sync or get committed along with the notes. On Linux and macOS it must also
be a dedicated directory: the server refuses a shared one (sticky bit or world-writable, such as `/tmp`)
and sets the directory to 0700 and its files to 0600. On Windows those permission checks do not apply.

### `public_url`

The URL clients use to reach the server, for example `https://mcp.example.com`. The MCP endpoint is
this URL plus `/mcp`, and the OAuth issuer is this URL; both are compared byte for byte, so the value
must already be canonical:

- `https`, or `http` only for `localhost` (any case) and loopback IPs (127.0.0.0/8, `::1`).
- Lowercase scheme and host, no trailing dot on the host, and an internationalized name in its
  punycode form (`xn--...`): the URL must be ASCII, with no percent sign.
- No default port (`:443` for https, `:80` for http), no empty port, and a port, when present, from 1
  to 65535 without leading zeros.
- No credentials, path (a single trailing `/` is accepted), query, or fragment.

Passkeys need a DNS name here (`localhost` works). With an IP address the server logs a warning and
offers TOTP and recovery codes only.

### `listen`

The address to bind, `host:port`, with the port a plain number from 1 to 65535 (no sign, no leading
zeros). The default `127.0.0.1:8080` accepts connections only from the same host, for a reverse proxy
there that terminates TLS. In a container use `:8080`, so the container runtime's network can reach it.
`serve` logs a warning when `public_url` is https and `listen` is not a loopback address, because the
plain HTTP port would then be reachable without the TLS proxy (expected in a container).

### `trusted_proxies`

Reverse proxy networks whose `X-Forwarded-For` header is believed when the OAuth endpoints
(`/authorize`, the login page, client registration, client metadata document fetches) rate-limit per
client address. Empty (the default): the TCP peer is the client and the header is ignored. When the peer
is inside a listed network, the client is the right-most `X-Forwarded-For` entry that is not itself in a
listed network, so list only proxies that append or set the address they received the request from.
Never list a network that untrusted hosts can send from: they could choose the address their limits are
keyed on.

Each entry is a network in CIDR form with its host bits zero (`172.18.0.0/16`; one address is
`172.18.0.2/32`). Refused: `/0`; anything wider than /8 for IPv4 or /32 for IPv6; IPv4-mapped IPv6
networks (write the plain IPv4 form). At most 32 entries. When `public_url` is https, OAuth is on, and
this list is empty, `serve` logs a warning that all clients share one rate-limit bucket. See
[Behind a reverse proxy](install.md#behind-a-reverse-proxy) for Caddy and nginx values.

### `instructions_file`

Optional. A `.md` file inside the vault (vault-relative, extension in any case) whose content is sent to
every assistant as part of the MCP server instructions when it connects, after a short built-in text
about treating note content as data. Content beyond 64 KiB is cut and marked as truncated. If the file
cannot be read, the built-in text alone is sent and a warning is logged. The file is re-read at most
every 5 seconds, and an edit reaches new sessions without a restart (open sessions keep what they
started with). Tools can read it but never change, move, or delete it. The path must stay inside the
vault and must not contain control or format characters, a backslash, or a path segment that starts or
ends with whitespace.

### `deny`

Extra vault-relative files or folders that no tool may read or write. Each entry must be non-empty,
valid UTF-8, relative (no leading `/`), free of `..` segments, control and format characters, and
backslashes, without a path segment that starts or ends with whitespace, and must not name the vault
root itself (for example `.` or `./`). Matching ignores case, segment by segment.

Always protected, at any depth, whatever `deny` says: `.git`, `.obsidian`, `.cortex-mcp`, and Syncthing's `.stversions` and `.stfolder` (old copies of notes kept by
Syncthing's file versioning, which searches would mix with the current notes, and which Syncthing
never syncs back). `.trash`
is receive-only: `delete_note` moves notes there, and notes can be read and moved out, but nothing else
writes there. An entry also protects the same path below `.trash/`, because `delete_note` keeps the
folder path there. Obsidian's own trash flattens paths, which no entry can match: if you use `deny`,
consider adding `.trash` too.

### `bearer_tokens`

`true` (the default) accepts Bearer tokens created with `cortex-mcp token create`, for clients that
cannot run a browser login. `false` means OAuth only: config validation refuses it unless
`oauth.enabled` is `true`, and `serve` refuses to start until the owner has run `cortex-mcp setup`, so
there is always a way to authenticate.

### `oauth`

The built-in OAuth 2.1 authorization server that assistant apps use to connect.

#### `oauth.enabled`

`true` by default. Nobody can log in until the owner runs `cortex-mcp setup` on the host, which is the
only step that creates secrets. `false` removes every OAuth endpoint and the `resource_metadata` link in
the `401` challenge.

#### `oauth.redirect_allowlist`

The redirect URIs a client may register, through `/register` or a client metadata document. Default:

```yaml
redirect_allowlist:
  - https://claude.ai/api/mcp/auth_callback
  - https://chatgpt.com/connector_platform_oauth_redirect
  - https://chatgpt.com/connector/oauth/*
  - https://agent.meta.ai/api/hatch/oauth/callback
  - loopback
```

A list in the file replaces the defaults entirely, so copy the defaults you still need. While
`oauth.enabled` is true the list must not be empty; at most 32 entries. Each entry is one of:

- `loopback`: any `http` redirect to `localhost`, `127.0.0.1`, or `[::1]` on any port, for native
  clients such as Claude Code. Only those three hosts count.
- An exact https URL, compared as a raw string with no normalization.
- An https URL ending in `/*`, which matches exactly one more path segment: 1 to 128 characters from
  letters, digits, `.`, `_`, `~`, and `-`, not starting with a dot.

Rules for an https entry: at most 512 bytes of printable ASCII without spaces; scheme `https`; a host
of lowercase letters, digits, hyphens, and dots, with no trailing dot, that is a domain name (not an IP
address, and not `localhost`: use `loopback`); an optional port from 1 to 65535 without leading zeros; a
path starting with `/` without `.` or `..` segments; no credentials, query, fragment, backslash, or
percent-encoding; and `*` only as the last character, right after a `/`.

The allowlist is checked again every time a client is used, so removing an entry affects already
registered clients at once. A client registers 1 to 10 redirect URIs, all loopback or all https.

### `limits`

#### `limits.max_write_bytes`

The largest content one write may carry, in bytes. Default `1048576` (1 MiB); from 1 to `8388608`
(8 MiB, the largest note the vault reads back). Requests to `/mcp` may be up to twice this plus 64 KiB
(JSON escaping can double the content), which matters for a proxy body limit.

#### `limits.requests_per_minute`

Requests to `/mcp` per minute for each client: per Bearer token, or per OAuth connection. Default `180`;
from 1 to 6000. A short burst of a sixth of the value (30 at the default) is allowed. Some hosted
assistants (ChatGPT, Meta Muse) open a new session for each tool call, which costs about four requests
(initialize, initialized, tools/list, the call), and may run calls in parallel.

#### `limits.max_sessions_per_client`

Live MCP sessions each client may hold: per Bearer token, or per OAuth connection. Default `200`; from 1
to 2000. A request that would open one more gets `429` with `Retry-After: 60`, and open sessions keep
working. A session ends when the client sends `DELETE` or after 30 minutes without a request. Clients
that reuse their session hold 1 or 2; a client that opens a session per tool call and never ends it
holds one per call for 30 minutes, so for it this is the number of calls per 30 minutes. An idle session
uses about 25 KiB of memory.

### `logs`

Rotation of `state_dir/writes.log`, which records one line per write (time, client, tool, path,
result).

#### `logs.max_size_mb`

The size in MB at which the log rotates. Default `5`; from 1 to 1024.

#### `logs.keep`

How many rotated files are kept. Default `3`; from 1 to 100.

## Fixed values

These are not configurable. They are listed so nobody looks for a key that does not exist.

| What | Value |
|------|-------|
| Free disk below which every write is refused (`disk_low`, Linux and macOS) | 1 GiB |
| Largest note read (`note_too_large`) | 8 MiB |
| Largest frontmatter block decoded | 64 KiB |
| Longest path; longest path segment | 1024 bytes; 255 bytes |
| Live MCP sessions per token or OAuth connection | 16 |
| Idle MCP session timeout | 30 minutes |
| OAuth access token; refresh token; authorization code | 1 hour; 30 days (rotated on use); 60 seconds |
| Pending sign-in request; passkey enrollment link | 10 minutes; 10 minutes |
| Consecutive wrong TOTP codes before the TOTP factor locks | 50 |
