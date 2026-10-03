# cortex-mcp

A self-hosted [MCP](https://modelcontextprotocol.io) server that lets AI assistants read and write one
Markdown vault (an Obsidian vault or any folder of `.md` files) over Streamable HTTP. The vault is the
durable memory; the assistant behind it is replaceable.

## Status

Pre-release. Plan 1 (the core server) is implemented: the vault library, the twelve tools, Bearer-token
authentication, rate limiting, the write log, and the `serve` and `token` commands. OAuth 2.1 (needed
for apps such as claude.ai and ChatGPT), `setup`, and `reset-auth` are planned and not built. Until then
the only way to authenticate is a Bearer token, so `bearer_tokens: false` is refused at startup.

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
- Every route except `GET /healthz` requires a Bearer token. Tokens are random, shown once, and stored
  only as hashes in `state_dir/auth.db`. Requests are rate limited per client.
- An MCP session is bound to the token that opened it, not to the token's name: after `token revoke`, a
  new token created with the same name cannot use the old token's sessions.
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
./bin/cortex-mcp token create -config config.yaml my-laptop
./bin/cortex-mcp serve -config config.yaml
```

Commands:

```
cortex-mcp serve [-config path]
cortex-mcp token create [-config path] NAME
cortex-mcp token list [-config path]
cortex-mcp token revoke [-config path] NAME
cortex-mcp version
```

Flags go before `NAME`. The config path defaults to `$CORTEX_MCP_CONFIG`, then
`/etc/cortex-mcp/config.yaml`. `token create` prints the secret once on stdout; store it then, it
cannot be shown again. `serve` logs JSON to stderr and shuts down cleanly on SIGINT or SIGTERM (a second
signal exits at once). `GET /healthz` answers `ok` without authentication; the MCP endpoint is `/mcp`.

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

The login page and client registration are rate-limited per client address. Behind a proxy every
request comes from the proxy's address, so set `trusted_proxies` to the proxy's network (in a Docker
deployment, the subnet of the network Caddy shares with the server); without it all clients share one
bucket per limiter, which is safe but coarser.

## Connect Claude Code

```bash
claude mcp add --transport http cortex https://mcp.example.com/mcp \
  --header "Authorization: Bearer <token>"
```

Any MCP client that supports Streamable HTTP and a custom `Authorization` header can connect the same way.

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
