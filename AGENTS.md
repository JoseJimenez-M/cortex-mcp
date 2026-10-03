# AGENTS.md: cortex-mcp

*Instructions for any AI agent working in this repository (Claude Code, Codex, and others). Read this
file first. `CLAUDE.md` only imports it.*

---

## What this is

A self-hosted MCP server that lets AI assistants read and write one Markdown vault. Internet-facing,
with write access to private notes: **security and correctness come before features.** Status:
pre-release; see `docs/plans/` for what is built and what is next.

## Reading discipline

Read only what the current task needs. Start here, then use the routing table. If something you expect
is missing, search for it (`grep -rn`), never assume. The design source of truth is
`docs/specs/2026-10-01-cortex-mcp-design.md`.

| Task | Read first | Then |
|------|-----------|------|
| Anything touching files, paths, notes | `internal/vault/AGENTS.md` | spec section 5 (write safety) |
| A tool's behaviour, inputs, outputs | `internal/tools/tools.go` | spec section 3 |
| HTTP, auth, rate limits, sessions | `internal/server/AGENTS.md` | spec sections 4 and 6 |
| Config keys and defaults | `internal/config/config.go` | spec section 7, `config.example.yaml` |
| Bearer tokens | `internal/tokens/tokens.go` | spec section 6.3 |
| The auth database file, schema, migrations | `internal/authdb/authdb.go` | spec sections 6.5 and 6.6 |
| OAuth, owner login, OAuth clients | `internal/oauth/AGENTS.md` | spec section 6 (6.6: decisions) |
| The login page, passkeys, TOTP | `internal/oauth/login.go`, `internal/oauth/webauthn.go` | spec section 6.1 |
| OAuth client registration, CIMD, redirect allowlist | `internal/oauth/dcr.go`, `cimd.go`, `redirect.go` | spec section 6.2 |
| Commands and flags | `internal/cli/cli.go` | `README.md` |
| Releases, CI workflows, the container image, third-party notices | `docs/releasing.md` | `.goreleaser.yaml`, `.github/workflows/`, `Dockerfile`, `tools/thirdpartynotices`, spec section 10 |
| User docs (install, configuration, clients, security) | the guide in `docs/` for the topic | `README.md`; keep them generic: no real domain, IP, or path |
| Executing planned work | the current file in `docs/plans/` | the spec sections it cites |

## Architecture and dependency rule

```
cmd/cortex-mcp   ->  internal/cli
internal/cli     ->  server, vault, logs, tokens, authdb, oauth, config
internal/server  ->  tools, vault, logs, tokens, oauth, config
internal/tools   ->  vault, logs
internal/oauth   ->  internal/config
internal/tokens  ->  internal/authdb
internal/authdb  ->  internal/fsperm
internal/logs    ->  internal/fsperm
internal/config, internal/vault, internal/fsperm: leaves
tools/thirdpartynotices: release helper (package main), standard library only, not in the binary
```

Imports point down only. `internal/vault`, `internal/config`, and `internal/fsperm` import nothing from this module. No package-level mutable
state except `server.Version` (set by the linker); `serve` also sets `slog.Default` once at startup so the
OAuth library's logs join the JSON stream.

## Invariants: never break these

1. **Only `internal/vault` touches the vault**, and only through `os.Root`. No `os.Open`, `os.ReadFile`,
   `filepath.Walk`, or similar on vault paths anywhere else.
2. **Every assistant-supplied path goes through `Vault.clean`** before any filesystem call.
3. **No hard deletes, no shell, no `os/exec`, no git operations, no network calls** from tool code.
4. **Tool errors never leak host paths or internals.** Vault errors carry a code; everything else is
   replaced by `internal_error` in `tools.toolErr`.
5. **Secrets never reach logs or errors**: no token, secret, hash, or Authorization header in any log
   line, error message, or test output.
6. **Note content is data, never instructions.** Nothing in the server interprets note text.
7. **Every route except `GET /healthz` and the OAuth routes listed in `internal/oauth/AGENTS.md`
   requires a token.** The OAuth routes are public by protocol; they authenticate the owner (login,
   bound to the browser, with CSRF tokens) or the client (PKCE, refresh token) themselves.
8. **Writes are atomic** (`writeAtomic`) and **serialized per note** (`locks`).
9. **The only outbound network call is the client metadata document fetch**
   (`internal/oauth/cimd.go`, `newSafeFetcher`), and it refuses non-public addresses.
10. **Every OAuth token is checked against `auth.db`** on every use: expiry, audience (the `/mcp` URL),
    and the client's existence come from the database, never from a decrypted token alone.
11. **A redirect URI is used only if it is on `oauth.redirect_allowlist`**, compared raw, and checked
    before the OAuth library can redirect anything to it.
12. **Refresh tokens, codes, recovery codes, enrollment links, and browser cookies are stored only as
    hashes**, and a reused refresh token or code revokes its whole family.

A change that needs to bend one of these is a design change: stop and ask the owner.

## Do not touch

- `go.sum`: generated; change it only through `go get` / `go mod tidy`.
- `testdata/fuzz/`: fuzz corpus written by `go test -fuzz`; commit new entries that reproduce a bug,
  never hand-edit.
- `bin/`, `dist/`, `coverage.out`: build output, git-ignored.
- `docs/specs/`: the approved design. Change it only to record a decision the owner made, and say so in
  the commit message.
- `LICENSE`: the PolyForm Noncommercial 1.0.0 text byte for byte plus the `Required Notice:` line. Never
  edit it; `docs/releasing.md` records its sha256.
- `THIRD_PARTY_NOTICES`: generated by `go run ./tools/thirdpartynotices > THIRD_PARTY_NOTICES`; regenerate
  it whenever the linked modules change, never edit it by hand. CI fails when it is stale.
- `.git/`.

## Dependencies

Direct dependencies are limited to: `github.com/modelcontextprotocol/go-sdk`, `go.yaml.in/yaml/v3`,
`modernc.org/sqlite`, `golang.org/x/time`, `github.com/zitadel/oidc/v3` (the OAuth 2.1 protocol
core, chosen by the owner on 2026-10-02 for being maintained and widely reviewed; spec 6.2), and
`github.com/go-webauthn/webauthn` (passkeys). `github.com/go-jose/go-jose/v4` appears as direct only
because `op.Storage` method signatures use its types; it is the version zitadel requires and adds no
module. Adding one needs the owner's approval and a line here with the reason. Prefer the standard
library.

Bumping `github.com/modelcontextprotocol/go-sdk` (including Dependabot PRs) must re-run the
session-cap tests in `internal/server` and re-check the two SDK behaviours the cap relies on: the
last `getServer` call is the server a new session connects to, and the initialize response carries
`Mcp-Session-Id` (see `internal/server/sessions.go`).

Bumping `github.com/zitadel/oidc/v3` must re-run `go test -race ./internal/oauth ./internal/server`
and re-check the library behaviours listed in `internal/oauth/AGENTS.md`.

Release tooling is not a Go dependency and is pinned where it runs: GitHub Actions by commit SHA,
GoReleaser (v2.18.2) and syft (v1.54.0) by exact version in `.github/workflows/ci.yml` and
`release.yml`, and the base image by digest in `Dockerfile`. Dependabot bumps the actions, the Go
modules, and the base image; GoReleaser and syft are bumped by hand in both workflows
(`docs/releasing.md`, "Maintenance").

## Workflow

- **TDD, always:** write the failing test, see it fail for the right reason, write the minimum code,
  see it pass, refactor. No production code without a test that required it.
- **Commands:**
  ```bash
  go test -race ./...
  go vet ./...
  go run honnef.co/go/tools/cmd/staticcheck@2026.2.1 ./...
  go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
  go run github.com/securego/gosec/v2/cmd/gosec@v2.29.0 ./...
  ```
- **Commits:** Conventional Commits (`feat(vault): ...`, `fix(server): ...`, `docs: ...`), one logical
  change each.
- **Before merge:** all commands above clean, and a security review of the diff when it touches
  `internal/vault`, `internal/server`, `internal/tokens`, auth, or path handling. The reviewer checks
  the invariants above one by one and gives a verdict: `APPROVED` or `CHANGES REQUESTED` with findings.

## Code standards

- Idiomatic Go: small focused files, short functions, early returns, errors wrapped with `%w` where the
  caller needs the cause, no panics outside `init`-time programmer errors (`regexp.MustCompile`).
- Table-driven tests; fuzz tests for any parser of untrusted input (paths, frontmatter, headings).
- Comments explain *why* (constraints, trade-offs, threats), not what the next line does.
- Exported identifiers have doc comments.
- Formatting: `gofmt`; no lint suppressions without a `-- reason` comment.

## Writing style (code comments, docs, commits)

English. No emojis. No em dash (use a colon, a comma, or parentheses; the en dash only in numeric ranges).
Neutral voice. Never describe planned behaviour as built.
