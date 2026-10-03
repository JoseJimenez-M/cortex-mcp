# Contributing to cortex-mcp

cortex-mcp is a small server that is internet-facing and writes to private notes, so every change is
reviewed for correctness and security before features. Thank you for reading this first.

## Before you start

- **Security problems are not issues.** Report them privately as described in [SECURITY.md](SECURITY.md).
- For anything beyond a small fix, open an issue first and describe the problem and the change you
  have in mind. The design is in [`docs/specs/2026-10-01-cortex-mcp-design.md`](docs/specs/2026-10-01-cortex-mcp-design.md);
  a change that bends one of its decisions needs agreement before any code.
- Read [`AGENTS.md`](AGENTS.md). It lists the package layout, the invariants every change must keep
  (for example: only `internal/vault` touches the vault, tool code runs no shell and makes no network
  calls, secrets never reach logs), and the files that are never edited by hand.
- A new dependency needs the maintainer's approval; the standard library is preferred.

## Contributor License Agreement

> **DRAFT for the owner to review.** The agreement below has not been reviewed by a lawyer or
> approved by the owner yet. Do not treat it as final: its wording, and whether it is required, may
> change before the first release.

Until the CLA is final, outside pull requests are not accepted.

cortex-mcp is source-available under the PolyForm Noncommercial License 1.0.0, and the author also
offers separate commercial licences. To keep both possible, every contribution is accepted under the
agreement below. Read it before you open a pull request.

> **cortex-mcp Contributor License Agreement, version 1**
>
> "You" are the person submitting a contribution. A "contribution" is any code, documentation, or other
> material you submit to the cortex-mcp repository to be included in it (a pull request, a patch, or a
> suggested change). "The author" is Jose Jimenez (https://github.com/JoseJimenez-M).
>
> 1. **Copyright licence.** You grant the author a perpetual, worldwide, non-exclusive, royalty-free,
>    irrevocable licence to use, copy, modify, distribute, and publicly display your contribution, and
>    to sublicense and relicense it under any terms, including the PolyForm Noncommercial License
>    1.0.0 and commercial licences.
> 2. **Patent licence.** You grant the author, and everyone who receives the software from the author,
>    a perpetual, worldwide, non-exclusive, royalty-free, irrevocable licence under any patent claims
>    you can license that your contribution, alone or combined with the software, would infringe.
> 3. **You keep your copyright.** This agreement is a licence, not a transfer of ownership.
> 4. **You have the right to contribute.** The contribution is your original work, or you have the
>    right to submit it under these terms. If your employer or anyone else could claim rights in it,
>    you have their written permission. You name, in the pull request, any part that comes from
>    someone else, with its licence.
> 5. **No obligation, no warranty.** The author does not have to use your contribution. You provide
>    it as is, without warranty of any kind.

To agree, put this line in the pull request description:

    I have read the cortex-mcp Contributor License Agreement, version 1, and I agree to it.

A pull request without that line is not merged.

## How to work

- **Test-driven, always.** Write the failing test, run it and see it fail for the right reason, write
  the minimum code that makes it pass, then refactor. No production code without a test that required
  it. Use table-driven tests, and a fuzz test for any parser of untrusted input.
- **Gates.** Every pull request must pass these commands, which CI also runs:

  ```bash
  go test -race ./...
  go vet ./...
  go run honnef.co/go/tools/cmd/staticcheck@2026.2.1 ./...
  go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
  go run github.com/securego/gosec/v2/cmd/gosec@v2.29.0 ./...
  ```

  CI also checks `gofmt`, `go mod tidy`, and that `THIRD_PARTY_NOTICES` is current (regenerate it with
  `go run ./tools/thirdpartynotices > THIRD_PARTY_NOTICES` after a dependency change), runs each fuzz
  target briefly, lints the workflows, and builds a release snapshot with GoReleaser.
- **Commits.** Conventional Commits (`feat(vault): ...`, `fix(server): ...`, `docs: ...`), one logical
  change each.
- **Style.** Idiomatic Go formatted with `gofmt`; comments explain why, not what. Docs, comments, and
  commit messages are in English, with no emojis and no em dashes.
- **Review.** A change to `internal/vault`, `internal/server`, `internal/tokens`, `internal/oauth`, or
  path handling gets a security review that checks the invariants in `AGENTS.md` one by one.
