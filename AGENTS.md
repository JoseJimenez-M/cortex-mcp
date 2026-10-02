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
| Commands and flags | `internal/cli/cli.go` | `README.md` |
| Executing planned work | the current file in `docs/plans/` | the spec sections it cites |

## Architecture and dependency rule

```
cmd/cortex-mcp  ->  internal/cli  ->  internal/server  ->  internal/tools  ->  internal/vault
                                         |                     |
                                         +-> internal/tokens   +-> internal/logs
                    internal/config  (used by cli and server)
                    internal/fsperm  (leaf: private dir/file modes, used by tokens and logs)
```

Imports point down only. `internal/vault`, `internal/config`, and `internal/fsperm` import nothing from this module. No package-level mutable
state except `server.Version` (set by the linker).

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
7. **Every route except `GET /healthz` requires authentication.**
8. **Writes are atomic** (`writeAtomic`) and **serialized per note** (`locks`).

A change that needs to bend one of these is a design change: stop and ask the owner.

## Do not touch

- `go.sum`: generated; change it only through `go get` / `go mod tidy`.
- `testdata/fuzz/`: fuzz corpus written by `go test -fuzz`; commit new entries that reproduce a bug,
  never hand-edit.
- `bin/`, `dist/`, `coverage.out`: build output, git-ignored.
- `docs/specs/`: the approved design. Change it only to record a decision the owner made, and say so in
  the commit message.
- `.git/`.

## Dependencies

Direct dependencies are limited to: `github.com/modelcontextprotocol/go-sdk`, `go.yaml.in/yaml/v3`,
`modernc.org/sqlite`, `golang.org/x/time`. Adding one needs the owner's approval and a line here with
the reason. Prefer the standard library.

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
