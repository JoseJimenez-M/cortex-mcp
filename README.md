# cortex-mcp

A self-hosted [MCP](https://modelcontextprotocol.io) server that lets AI assistants read and write one
Markdown vault (an Obsidian vault or any folder of `.md` files) over Streamable HTTP. The vault is the
durable memory; the assistant behind it is replaceable.

## Status

Pre-release. Implemented: the core server (vault library, twelve tools, rate limiting, write log), Bearer
tokens for CLI agents and scripts, OAuth 2.1 for assistant apps (claude.ai, ChatGPT, Meta Muse, Claude
Code) with an owner login by passkey, TOTP, or recovery code, and the release tooling: a version tag
builds signed binaries for Linux, macOS, and Windows and a signed multi-arch container image, with
SBOMs ([releasing](docs/releasing.md)). No release has been published yet; until one is, build from
source.

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

## Security in brief

- All file access is confined to the vault through `os.Root`; symbolic links are never followed;
  `.git`, `.obsidian`, and `.cortex-mcp` are off limits, and `.trash` is receive-only.
- Tool code runs no shell, no git, and no network calls. The server's only outbound request fetches
  OAuth client metadata documents, never from private or loopback addresses.
- Every route except `GET /healthz` and the OAuth endpoints needs a token (a Bearer token or an OAuth
  access token). Secrets are stored as hashes, and OAuth follows the MCP authorization spec
  (2025-11-25): PKCE S256, tokens bound to this server's `/mcp` URL, rotating refresh tokens with reuse
  detection.
- Each connection is approved by the owner on a login page bound to the browser that started it, with a
  passkey, an authenticator code, or a recovery code; redirect URIs are limited to an allowlist.
- Requests are rate limited per client and per source address; writes are atomic, versioned, logged,
  and paused when the disk has less than 1 GiB free.
- Release binaries and images are signed keylessly with cosign and ship SBOMs.

The threat model, every defence with its limits, the deliberate non-features, and the residual risks
are in [docs/security.md](docs/security.md). Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).

## Install

- **Release binary or container image** (`ghcr.io/josejimenez-m/cortex-mcp`), with signature
  verification, a systemd unit, a Docker Compose example, and Caddy and nginx examples:
  [docs/install.md](docs/install.md).
- **Every configuration key**, default, and limit: [docs/configuration.md](docs/configuration.md); the
  commented example is [`config.example.yaml`](config.example.yaml).
- **Connecting** Claude Code, claude.ai, ChatGPT, Meta Muse, and other MCP clients:
  [docs/connecting-clients.md](docs/connecting-clients.md).
- **Releasing and upgrading**: [docs/releasing.md](docs/releasing.md).

### Quick start from source

Requires Go (see `go.mod` for the version).

```bash
go build -o bin/cortex-mcp ./cmd/cortex-mcp
cp config.example.yaml config.yaml          # set vault, state_dir, public_url
./bin/cortex-mcp setup -config config.yaml               # the owner, for OAuth apps
./bin/cortex-mcp token create -config config.yaml my-laptop  # optional: a Bearer token
./bin/cortex-mcp serve -config config.yaml
```

`setup` prints three factors once (a TOTP URI, ten recovery codes, and a passkey link to open within
10 minutes while the server runs); keep them in different places. `token create` prints its token once.
For anything beyond localhost, put a TLS reverse proxy in front: see
[docs/install.md](docs/install.md#behind-a-reverse-proxy).

## Commands

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

Flags go before `NAME` and `ID`. The config path defaults to `$CORTEX_MCP_CONFIG`, then
`/etc/cortex-mcp/config.yaml`. `GET /healthz` answers `ok` without authentication; the MCP endpoint is
`/mcp`. What each command does, including `setup -force` and `reset-auth`, is in
[docs/install.md](docs/install.md#commands).

## Documentation

| Guide | Contents |
|-------|----------|
| [docs/install.md](docs/install.md) | Requirements, binary or image, verifying downloads, reverse proxy, first-time setup, commands |
| [docs/configuration.md](docs/configuration.md) | Every key, default, and validation rule; fixed limits |
| [docs/connecting-clients.md](docs/connecting-clients.md) | Claude Code, claude.ai, ChatGPT, Meta Muse, generic MCP clients |
| [docs/security.md](docs/security.md) | Threat model, defences, deliberate non-features, residual limits |
| [docs/releasing.md](docs/releasing.md) | Cutting and verifying a release, upgrading an installation |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contributor licence agreement, workflow, gates |
| [SECURITY.md](SECURITY.md) | Reporting vulnerabilities, supported versions, scope |

The design is in [`docs/specs/2026-10-01-cortex-mcp-design.md`](docs/specs/2026-10-01-cortex-mcp-design.md).

## Development

Test-driven: write the failing test first, then the minimum code. Read `AGENTS.md` before changing
anything; it lists the invariants and the package layout. Contributions need the agreement in
[CONTRIBUTING.md](CONTRIBUTING.md).

```bash
go test -race ./...
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@2026.2.1 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
go run github.com/securego/gosec/v2/cmd/gosec@v2.29.0 ./...
```

## Licence

Source-available under PolyForm Noncommercial 1.0.0. Commercial use (companies, paid services, resale, including modified versions) requires a separate licence: contact jimenez331375@gmail.com.

The full terms are in [`LICENSE`](LICENSE). This is not an OSI open source licence: personal,
research, hobby, and noncommercial organizational use is permitted, commercial use is not. The Go
standard library and modules built into the binary keep their own licences, reproduced in
[`THIRD_PARTY_NOTICES`](THIRD_PARTY_NOTICES). Contributions
are accepted under the contributor licence agreement in [`CONTRIBUTING.md`](CONTRIBUTING.md); security
reports go to [`SECURITY.md`](SECURITY.md).
