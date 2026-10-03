---
type: guide
status: draft
created: 2026-10-03
updated: 2026-10-03
tags: [kind/repo, topic/dev]
---

# cortex-mcp Plan 3: Release (licence, signed builds, user docs) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** cortex-mcp can be published and installed by strangers: a verbatim PolyForm Noncommercial 1.0.0 `LICENSE`, a CLA and a security policy, version tags that build signed binaries and a signed multi-arch container image with SBOMs, and generic user docs (install, configuration, clients, security, releasing), with the two irreversible steps (making the repository public, pushing the first tag) left to the owner.

**Architecture:** GoReleaser v2 (`.goreleaser.yaml`, schema `version: 2`) builds the five binaries once, archives them with the licence and docs, writes `checksums.txt`, an SPDX SBOM per archive (syft), and a keyless cosign bundle for the checksum file, then builds and pushes the image to GHCR with `dockers_v2` (buildx, one push for both platforms, BuildKit SBOM attestation) from the same binaries and signs it by digest. `.github/workflows/release.yml` runs it on `v*` tags, only from a public repository and only for tags on `main`; `ci.yml` gains a job that lints the workflows, runs `goreleaser check`, and builds a full snapshot (binaries and images) on every pull request, so the release path is exercised before any tag exists. No Go code changes.

**Tech Stack:** Go 1.26 (toolchain go1.26.8), GoReleaser v2.18.2, syft v1.54.0, cosign v3 (from `sigstore/cosign-installer` v4.1.2, default v3.0.6), Docker buildx, `gcr.io/distroless/static-debian13:nonroot`, GitHub Actions, GHCR, actionlint v1.7.12, gitleaks v8.30.1 (local audit only).

Spec: [[Assistant/cortex-mcp/docs/specs/2026-10-01-cortex-mcp-design|design spec]] (sections 10 and 13 are binding; 6.6 feeds `docs/security.md`). Previous plans: `docs/plans/2026-10-02-plan-1-core-server.md`, `docs/plans/2026-10-02-plan-2-oauth.md`.

## Global Constraints

- Branch `plan-3-release`, created from `main` at `cae52e4`; module `github.com/JoseJimenez-M/cortex-mcp`. All commands run from `Assistant/cortex-mcp/`.
- **No change under `internal/` or `cmd/`, and none to `go.mod` or `go.sum`.** Direct Go dependencies stay exactly: go-sdk v1.8.0, yaml v3.0.5, sqlite v1.60.1, x/time v0.16.0, zitadel/oidc/v3 v3.51.11, go-webauthn/webauthn v0.18.2, go-jose/v4 v4.1.4. The only exception is a release-related bug that a test exposes: then stop, show Jose the failing test, and fix it test-first per `AGENTS.md`.
- `go test -race ./...` and every CI gate (`gofmt`, `go mod tidy`, vet, fuzz, staticcheck, govulncheck, gosec) stay green after every task.
- **Tool versions (exact):** GoReleaser `v2.18.2` (config `version: 2`); syft `v1.54.0`; cosign as installed by `sigstore/cosign-installer` v4.1.2 (its pinned default, `v3.0.6`, verified against a checksum inside the action); actionlint `v1.7.12` (`go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12`); gitleaks `v8.30.1` (`go run github.com/zricethezav/gitleaks/v8@v8.30.1`, local audit only, never in CI).
- **Actions, pinned by full commit SHA with the version as a comment** (tags dereferenced to commits on 2026-10-03):

  | Action | Version | Commit |
  |--------|---------|--------|
  | `actions/checkout` | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
  | `actions/setup-go` | v7.0.0 | `b7ad1dad31e06c5925ef5d2fc7ad053ef454303e` |
  | `docker/setup-buildx-action` | v4.4.1 | `f87e5991a6d7451dcb8d9637bfbc97413f497069` |
  | `docker/login-action` | v4.6.0 | `dbcb813823bdd20940b903addbd779551569679f` |
  | `sigstore/cosign-installer` | v4.1.2 | `6f9f17788090df1f26f669e9d70d6ae9567deba6` |
  | `anchore/sbom-action/download-syft` | v0.24.3 (annotated tag, dereferenced) | `66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c` |
  | `goreleaser/goreleaser-action` | v7.2.3 | `f06c13b6b1a9625abc9e6e439d9c05a8f2190e94` |

  `docker/setup-qemu-action` (v4.4.0, `99012661954931238ded8c8b007157a8430204e1`) was researched and is deliberately not used (decision 6).
- **Base image:** `gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3` (the multi-arch index digest; user `65532`).
- **Image:** `ghcr.io/josejimenez-m/cortex-mcp` (GHCR names are lowercase), platforms `linux/amd64` and `linux/arm64`, tags `vX.Y.Z` and `latest` (non-prerelease only).
- **Binaries:** linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64; `CGO_ENABLED=0`, `-trimpath`, ldflags `-s -w -X github.com/JoseJimenez-M/cortex-mcp/internal/server.Version=v{{ .Version }}`, so `cortex-mcp version` prints `cortex-mcp v0.1.0` for tag `v0.1.0`.
- **Signing identity** (what users verify): certificate identity `https://github.com/JoseJimenez-M/cortex-mcp/.github/workflows/release.yml@refs/tags/<tag>`, OIDC issuer `https://token.actions.githubusercontent.com`.
- **Workflow permissions:** `release.yml` sets `permissions: {}` at the top and grants per job only `contents: write`, `packages: write`, `id-token: write`; `ci.yml` keeps `contents: read`. No `${{ }}` expression built from event data inside any `run:` script.
- **Licence files:** `LICENSE` is the upstream text byte for byte (source sha256 `c0ea4a896d2c8c394b29f9427589996db826cd501c512279ff0ed3ef48fabbe5`) plus a blank line and `Required Notice: Copyright 2026 Jose Jimenez (https://github.com/JoseJimenez-M)`; the resulting file has sha256 `c7c5d8ecd956c65116c97ccdfb4a77c47b761570d548c57ab2176d9ce575b81b`. The README licence sentence is exactly: "Source-available under PolyForm Noncommercial 1.0.0. Commercial use (companies, paid services, resale, including modified versions) requires a separate licence: contact jimenez331375@gmail.com."
- **Docs are generic:** `mcp.example.com`, `/srv/...`, `/var/lib/cortex-mcp`, `172.18.0.0/16`; never the operator's real domain, IP, or paths. English, no emojis, no em dashes (the en dash only in numeric ranges), neutral voice, and never describe planned behaviour as built.
- **Owner gates:** Task 10 (making the repository public) and Task 11 (pushing `v0.1.0`) each contain a STOP step. Never perform those actions, change repository or package settings, or assume approval; wait for Jose's explicit "go" in chat. Everything else runs unattended.
- **Cortex code rule:** the code artifacts of this plan (`.goreleaser.yaml`, both workflows, `Dockerfile`, `dependabot.yml`) are shown here in full; approving this plan approves exactly that code. Any deviation found necessary while executing is shown to Jose with the reason and approved before it is committed.
- Every commit message ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Conventional Commits, one logical change each.
- Read `AGENTS.md` (root) before starting.

## Decisions this plan makes that the spec left open

1. **`dockers_v2`, not `dockers` plus `docker_manifests`.** GoReleaser 2.12 added `dockers_v2`, which builds every platform from the already-built binaries in one `docker buildx build --push` and will become the only `dockers` in GoReleaser v3. Because building and pushing are one step, release images are built in the publish phase; snapshots build one image per platform (`<tag>-amd64`, `<tag>-arm64`) and load them locally, which is what CI tests.
2. **Base image moves from `static-debian12` to `static-debian13`.** The distroless README no longer lists the debian12 images as updated; debian13 is the current base. It is pinned by digest, and Dependabot (new `docker` ecosystem entry) proposes digest bumps. Production picks the new base up on its first upgrade to a release image.
3. **`Dockerfile` takes the GoReleaser build context:** `COPY $TARGETPLATFORM/cortex-mcp` (BuildKit and Buildah set `TARGETPLATFORM`) plus `LICENSE` in the image. A manual build needs that layout; `docs/releasing.md` shows it.
4. **What is signed:** `checksums.txt` (keyless `cosign sign-blob --bundle`, one `checksums.txt.sigstore.json`), which lists every archive and every SBOM, so one signature covers all files; the image is signed by digest (`cosign sign <image>:<tag>@<digest>`). The BuildKit SBOM and provenance attestations live in the signed image index.
5. **Release only from a public repository and only for tags on `main`.** Keyless signing writes the repository name and workflow path to the public Rekor transparency log, and nobody outside a private repository could download or verify its release, so `release.yml` skips the job while the repository is private (`if: ${{ !github.event.repository.private }}`) and fails if the tagged commit is not an ancestor of `origin/main`.
6. **No QEMU.** The `Dockerfile` has no `RUN` step, so building the arm64 image on an amd64 runner executes nothing foreign; buildx only needs the arm64 base image layers.
7. **No `gomod.proxy`.** Building from the Go module proxy needs a public module; with the repository private today it would fail. It can be revisited after the repository is public.
8. **SBOM generation without `--enrich all`** (GoReleaser's default arguments): the SBOM is built from the binaries' embedded module information only, with no network lookups, so it is deterministic.
9. **GoReleaser and syft are pinned to exact versions** in the workflows' `with:` inputs. Dependabot does not bump those; `docs/releasing.md` lists the two places to edit.
10. **`latest` moves only for non-prerelease tags** (`v0.2.0-rc.1` is a GitHub prerelease and does not touch `latest`).
11. **CLA version 1** lives in `CONTRIBUTING.md`; a contributor agrees by putting one fixed line in the pull request description. The text below is a plain-language draft, not legal advice: Jose reviews its wording as part of approving this plan.
12. **No `windows/arm64` binary** (not in spec section 10 or the release brief) and **no separate build provenance attestation** (`actions/attest-build-provenance`): the cosign certificate already binds each artifact to this repository, workflow, and tag, and buildx attaches minimal provenance to the image.
13. **`setup-go` cache off in the release job** (`cache: false`), so a release never restores a module or build cache written by another run.
14. **The new user docs have no YAML frontmatter**, like `README.md`: they ship in release archives and render on GitHub, where frontmatter shows up as a table. The vault frontmatter rule keeps applying to `docs/specs/` and `docs/plans/`.

## File map

```
LICENSE                          create: PolyForm Noncommercial 1.0.0, verbatim, plus the Required Notice line
CONTRIBUTING.md                  create: CLA v1, TDD, gates, commit and style rules
SECURITY.md                      create: private reporting, supported versions, scope
docs/install.md                  create: requirements, binary or image, verification, reverse proxy, setup, commands
docs/configuration.md            create: every key, default, and validation limit (from internal/config/config.go)
docs/connecting-clients.md       create: Claude Code, claude.ai, ChatGPT, Meta Muse (Client ID via /register), generic clients
docs/security.md                 create: threat model, defences, deliberate non-features, residual limits
docs/releasing.md                create: tagging, what CI produces, verification, upgrading, manual image build, maintenance
Dockerfile                       modify: GoReleaser context layout, LICENSE, debian13 base pinned by digest
.github/dependabot.yml           modify: add the docker ecosystem
.goreleaser.yaml                 create: builds, archives, checksums, SBOMs, signing, dockers_v2, docker_signs
.github/workflows/ci.yml         modify: add the release-config job (actionlint, goreleaser check, snapshot)
.github/workflows/release.yml    create: tag-triggered release, least privilege
README.md                        modify: trimmed, points at docs/, exact licence sentence
AGENTS.md                        modify: routing rows, LICENSE in "Do not touch", release tooling pins
docs/specs/2026-10-01-cortex-mcp-design.md   modify: status header, section 10, section 13
docs/plans/2026-10-03-plan-3-release.md      modify: status at the end
```

## Doc checks used by several tasks

Each docs task ends with these three checks on the files it touched (set `FILES` to that list). Every check prints `ok: ...` when the files are clean; any other output is a failure to fix before committing.

```bash
LC_ALL=C.UTF-8 grep -nP '\x{2014}|[\x{1F000}-\x{1FAFF}\x{2600}-\x{27BF}\x{FE0F}]' $FILES && echo "FAIL: em dash or emoji" || echo "ok: no em dash or emoji"
grep -noE 'https?://[A-Za-z0-9.-]+' $FILES | grep -vE '://(mcp\.example\.com|localhost|127\.0\.0\.1|github\.com|ghcr\.io|raw\.githubusercontent\.com|polyformproject\.org|modelcontextprotocol\.io|claude\.ai|chatgpt\.com|agent\.meta\.ai|token\.actions\.githubusercontent\.com)$' && echo "FAIL: unexpected host" || echo "ok: hosts"
grep -noE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b|/home/' $FILES | grep -vE ':(127\.0\.0\.[0-9]+|172\.18\.0\.[0-9]+)$' && echo "FAIL: real-looking address or home path" || echo "ok: addresses"
```

---

### Task 1: Licence, contributor agreement, and security policy

**Files:**
- Create: `LICENSE`, `CONTRIBUTING.md`, `SECURITY.md`
- Modify: `README.md` (the `## Licence` section only; the rest of the README changes in Task 8)

**Interfaces:**
- Consumes: nothing.
- Produces: `LICENSE` at the repository root with sha256 `c7c5d8ecd956c65116c97ccdfb4a77c47b761570d548c57ab2176d9ce575b81b` (Task 4 copies it into the image, Task 5 into every archive, Task 7 documents the checksum); `SECURITY.md` and `CONTRIBUTING.md`, linked from the README in Task 8.

Why download instead of pasting: the licence must be the PolyForm text byte for byte. Fetching it from a pinned commit of the PolyForm project's own repository and checking a recorded sha256 proves that, which retyping cannot.

- [ ] **Step 1: Write the failing check**

```bash
echo "c7c5d8ecd956c65116c97ccdfb4a77c47b761570d548c57ab2176d9ce575b81b  LICENSE" | LC_ALL=C sha256sum --check
```
Expected: FAIL with `sha256sum: LICENSE: No such file or directory`.

- [ ] **Step 2: Create `LICENSE` from the pinned upstream file**

```bash
mkdir -p bin
curl -fsSL -o bin/polyform-noncommercial-1.0.0.md \
  https://raw.githubusercontent.com/polyformproject/polyform-licenses/9c032bcb6b44a68f90efddd1060cf71d4e6fd7ce/PolyForm-Noncommercial-1.0.0.md
echo "c0ea4a896d2c8c394b29f9427589996db826cd501c512279ff0ed3ef48fabbe5  bin/polyform-noncommercial-1.0.0.md" | LC_ALL=C sha256sum --check
{ cat bin/polyform-noncommercial-1.0.0.md; printf '\nRequired Notice: Copyright 2026 Jose Jimenez (https://github.com/JoseJimenez-M)\n'; } > LICENSE
rm bin/polyform-noncommercial-1.0.0.md
```
Expected: `bin/polyform-noncommercial-1.0.0.md: OK`. Commit `9c032bcb` is the last commit that touched the file in `polyformproject/polyform-licenses`; the same bytes are on its default branch `1.0.0`. If the download or the check fails, stop: never write the licence from memory.

- [ ] **Step 3: Run the check again**

```bash
echo "c7c5d8ecd956c65116c97ccdfb4a77c47b761570d548c57ab2176d9ce575b81b  LICENSE" | LC_ALL=C sha256sum --check
head -n 1 LICENSE
tail -n 1 LICENSE
```
Expected: `LICENSE: OK`, then `# PolyForm Noncommercial License 1.0.0`, then `Required Notice: Copyright 2026 Jose Jimenez (https://github.com/JoseJimenez-M)`.

- [ ] **Step 4: Create `CONTRIBUTING.md`**

````markdown
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

  CI also checks `gofmt` and `go mod tidy`, runs each fuzz target briefly, lints the workflows, and
  builds a release snapshot with GoReleaser.
- **Commits.** Conventional Commits (`feat(vault): ...`, `fix(server): ...`, `docs: ...`), one logical
  change each.
- **Style.** Idiomatic Go formatted with `gofmt`; comments explain why, not what. Docs, comments, and
  commit messages are in English, with no emojis and no em dashes.
- **Review.** A change to `internal/vault`, `internal/server`, `internal/tokens`, `internal/oauth`, or
  path handling gets a security review that checks the invariants in `AGENTS.md` one by one.
````

- [ ] **Step 5: Create `SECURITY.md`**

````markdown
# Security policy

cortex-mcp is an internet-facing server with write access to private notes. Security reports are
welcome and come before feature work.

## Reporting a vulnerability

Report privately, never in a public issue, pull request, or discussion:

1. Preferred: open a private report on GitHub from this repository's **Security** tab, **Report a
   vulnerability** (GitHub private vulnerability reporting). Only the maintainer sees it.
2. If that is not available to you, email jimenez331375@gmail.com with "cortex-mcp security" in the
   subject.

Include the version (`cortex-mcp version`, or the image tag and digest), your configuration with
anything private removed, the steps to reproduce, and what an attacker gains. Never include real tokens,
TOTP secrets, recovery codes, or `auth.db` files: if a secret is involved, revoke it and describe it.

What to expect: an acknowledgement within 7 days, a first assessment within 14 days, and a fix or a
mitigation plan agreed with you before anything is disclosed. This is a personal project maintained in
spare time, so these are targets, not guarantees. Fixed vulnerabilities are published as GitHub
security advisories that credit the reporter, unless you prefer otherwise.

## Supported versions

| Version | Supported |
|---------|-----------|
| The latest release | Yes |
| Older releases | No: upgrade to the latest release |
| Unreleased builds from `main` | Best effort |

Before version 1.0.0, fixes ship only in a new release; there are no backports.

## Scope

In scope:

- Anything that lets a client read or write outside the vault, reach a protected path (`.git`,
  `.obsidian`, `.cortex-mcp`, or a `deny` entry), change the instructions file, or delete a note for
  good.
- Authentication and authorization flaws: Bearer tokens, the OAuth 2.1 server (PKCE, the resource
  binding, the redirect allowlist, refresh token rotation, client registration, client metadata
  documents), the owner login (passkeys, TOTP, recovery codes), and MCP session binding.
- Secrets reaching logs, error messages, or the vault; host paths or internals reaching clients.
- The client metadata document fetcher reaching a non-public address (SSRF).
- A few requests causing large resource use (memory, disk, CPU) beyond the limits documented in
  [docs/security.md](docs/security.md).
- The integrity of release artifacts: checksums, signatures, SBOMs, and container images.

Out of scope:

- The residual limits documented in [docs/security.md](docs/security.md) (for example, many source
  addresses together delaying a sign-in), unless you show they are worse than described.
- Attacks that need shell access to the host, write access to `state_dir` or the config file, or a
  configuration the docs warn against (such as listing an untrusted network in `trusted_proxies`).
- Code that an assistant writes into a note and that an editor plugin later runs (for example
  Obsidian's `dataviewjs` or Templater): the server stores note content as data.
- Volumetric denial of service, and bugs in the assistant apps, reverse proxies, or other software
  that connects to the server.
````

- [ ] **Step 6: Replace the README licence section**

In `README.md`, replace the whole `## Licence` section (the heading and the two lines under it, from "Source-available under PolyForm Noncommercial 1.0.0. Commercial use requires a license" to "The `LICENSE` file itself is added in plan 3.") with:

```markdown
## Licence

Source-available under PolyForm Noncommercial 1.0.0. Commercial use (companies, paid services, resale, including modified versions) requires a separate licence: contact jimenez331375@gmail.com.

The full terms are in [`LICENSE`](LICENSE). This is not an OSI open source licence: personal,
research, hobby, and noncommercial organizational use is permitted, commercial use is not. Contributions
are accepted under the contributor licence agreement in [`CONTRIBUTING.md`](CONTRIBUTING.md); security
reports go to [`SECURITY.md`](SECURITY.md).
```

- [ ] **Step 7: Run the doc checks**

```bash
FILES="CONTRIBUTING.md SECURITY.md README.md"
LC_ALL=C.UTF-8 grep -nP '\x{2014}|[\x{1F000}-\x{1FAFF}\x{2600}-\x{27BF}\x{FE0F}]' $FILES && echo "FAIL: em dash or emoji" || echo "ok: no em dash or emoji"
grep -noE 'https?://[A-Za-z0-9.-]+' $FILES | grep -vE '://(mcp\.example\.com|localhost|127\.0\.0\.1|github\.com|ghcr\.io|raw\.githubusercontent\.com|polyformproject\.org|modelcontextprotocol\.io|claude\.ai|chatgpt\.com|agent\.meta\.ai|token\.actions\.githubusercontent\.com)$' && echo "FAIL: unexpected host" || echo "ok: hosts"
grep -noE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b|/home/' $FILES | grep -vE ':(127\.0\.0\.[0-9]+|172\.18\.0\.[0-9]+)$' && echo "FAIL: real-looking address or home path" || echo "ok: addresses"
grep -c 'Commercial use (companies, paid services, resale, including modified versions) requires a separate licence: contact jimenez331375@gmail.com.' README.md
```
Expected: `ok: no em dash or emoji`, `ok: hosts`, `ok: addresses`, `1`. (`LICENSE` is upstream text and is not run through these checks.)

- [ ] **Step 8: Commit**

```bash
git add LICENSE CONTRIBUTING.md SECURITY.md README.md
git commit -m "docs: add the PolyForm Noncommercial licence, CLA, and security policy

LICENSE is the upstream PolyForm Noncommercial 1.0.0 text byte for byte
(verified by sha256) plus the Required Notice line.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Install and configuration guides

**Files:**
- Create: `docs/install.md`, `docs/configuration.md`

**Interfaces:**
- Consumes: the release layout from Global Constraints (archive names, `checksums.txt`, `checksums.txt.sigstore.json`, image name, signing identity); the config rules in `internal/config/config.go` (read it; this task copies its limits).
- Produces: anchors other docs link to: `docs/install.md#verifying-a-download`, `docs/install.md#behind-a-reverse-proxy`, `docs/install.md#first-time-setup`, `docs/install.md#commands`, `docs/configuration.md` (one `###` heading per key, written as `` `key` `` or `` `block.key` ``).

The "test" for `docs/configuration.md` is a completeness check: every `yaml:"..."` tag in `internal/config/config.go` must appear in the doc as a code-formatted key. Write the check first and watch it fail.

- [ ] **Step 1: Write the failing completeness check**

```bash
for k in $(grep -o 'yaml:"[a-z_]*"' internal/config/config.go | cut -d'"' -f2 | sort -u); do
  grep -qE "\`([a-z_]+\.)?$k\`" docs/configuration.md 2>/dev/null || echo "missing: $k"
done
```
Expected: FAIL, one `missing:` line per key (17 lines: `bearer_tokens`, `deny`, `enabled`, `instructions_file`, `keep`, `limits`, `listen`, `logs`, `max_size_mb`, `max_write_bytes`, `oauth`, `public_url`, `redirect_allowlist`, `requests_per_minute`, `state_dir`, `trusted_proxies`, `vault`).

- [ ] **Step 2: Create `docs/configuration.md`**

````markdown
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
| `limits.requests_per_minute` | `60` | 1 to 6000 |
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
networks (write the plain IPv4 form). At most 32 entries. See
[Behind a reverse proxy](install.md#behind-a-reverse-proxy) for Caddy and nginx values.

### `instructions_file`

Optional. A `.md` file inside the vault (vault-relative, extension in any case) whose content is sent to
every assistant as the MCP server instructions when it connects. It is re-read at most every 5 seconds,
so edits reach new sessions without a restart. Tools can read it but never change, move, or delete it.
The path must stay inside the vault and must not contain control or format characters, a backslash, or
a path segment that starts or ends with whitespace.

### `deny`

Extra vault-relative files or folders that no tool may read or write. Each entry must be non-empty,
valid UTF-8, relative (no leading `/`), free of `..` segments, control and format characters, and
backslashes, without a path segment that starts or ends with whitespace, and must not name the vault
root itself (for example `.` or `./`).

Always protected, at any depth, whatever `deny` says: `.git`, `.obsidian`, and `.cortex-mcp`. `.trash`
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
  clients such as Claude Code.
- An exact https URL, compared as a raw string with no normalization.
- An https URL ending in `/*`, which matches exactly one more path segment.

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

Requests to `/mcp` per minute for each client: per Bearer token, or per OAuth connection. Default `60`;
from 1 to 6000.

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
````

- [ ] **Step 3: Run the completeness check**

```bash
for k in $(grep -o 'yaml:"[a-z_]*"' internal/config/config.go | cut -d'"' -f2 | sort -u); do
  grep -qE "\`([a-z_]+\.)?$k\`" docs/configuration.md 2>/dev/null || echo "missing: $k"
done; echo "check done"
```
Expected: only `check done`.

- [ ] **Step 4: Create `docs/install.md`**

````markdown
# Installing cortex-mcp

This guide covers what you need, the two ways to install (a release binary or the container image),
how to verify a download, running behind a reverse proxy, and the first-time setup. Every name,
address, and path here is an example: replace `mcp.example.com`, `/srv/vault`, `/var/lib/cortex-mcp`,
and the others with your own.

Releases are built from version tags and published on the GitHub Releases page of
`JoseJimenez-M/cortex-mcp`, with the container image at `ghcr.io/josejimenez-m/cortex-mcp`. Until a
release exists, build from source as shown in the [README](../README.md#quick-start-from-source).

## Requirements

- **Linux on amd64 or arm64**, on a case-sensitive filesystem such as ext4. This is the supported
  target and the one CI tests. Release binaries are also built for macOS (amd64, arm64) and Windows
  (amd64) from the same code, but the test suite runs only on Linux. On Windows the free-disk floor
  (writes pause below 1 GiB free) and the `state_dir` permission checks do not apply.
- **Little memory and disk:** one process using tens of MB of RAM, and an image of a few tens of MB.
  The state stays small: `auth.db` is a few KB plus OAuth rows, and the write log is rotated.
- **A reverse proxy that terminates TLS** (Caddy, nginx, or similar) for anything beyond your own
  machine. The server speaks plain HTTP and listens on `127.0.0.1:8080` by default.
- **A DNS name** for `public_url` if you want passkeys; WebAuthn needs one (`localhost` works for local
  tests). With an IP address the login page offers TOTP and recovery codes only.
- **Two folders:** the vault (any folder of `.md` files, such as an Obsidian vault) and a private state
  folder, which must not be the vault or inside it, so secrets never sync along with your notes.
- **To verify downloads:** [cosign](https://github.com/sigstore/cosign) v3, and `sha256sum` (Linux),
  `shasum` (macOS), or PowerShell's `Get-FileHash` (Windows).

## Option A: release binary

Each release has one archive per platform, `cortex-mcp_<version>_<os>_<arch>.tar.gz` (`.zip` for
Windows), holding the `cortex-mcp` binary, `LICENSE`, `README.md`, `config.example.yaml`, and these
docs. Next to them: `checksums.txt` (the SHA-256 of every file), its signature
`checksums.txt.sigstore.json`, and an SPDX SBOM per archive (`<archive>.sbom.json`).

On Linux, set `VERSION` to the release you install (without the leading `v`) and `ARCH` to `amd64` or
`arm64`:

```bash
VERSION=0.1.0
ARCH=amd64
BASE=https://github.com/JoseJimenez-M/cortex-mcp/releases/download/v${VERSION}
curl -fsSLO "${BASE}/cortex-mcp_${VERSION}_linux_${ARCH}.tar.gz"
curl -fsSLO "${BASE}/checksums.txt"
curl -fsSLO "${BASE}/checksums.txt.sigstore.json"
```

[Verify the download](#verifying-a-download) before going on. Then install the binary, create a
dedicated user, and give it a state folder and a config file:

```bash
mkdir "cortex-mcp-${VERSION}"
tar -xzf "cortex-mcp_${VERSION}_linux_${ARCH}.tar.gz" -C "cortex-mcp-${VERSION}"
sudo install -m 0755 "cortex-mcp-${VERSION}/cortex-mcp" /usr/local/bin/cortex-mcp
cortex-mcp version

sudo useradd --system --home-dir /var/lib/cortex-mcp --shell /usr/sbin/nologin cortex-mcp
sudo install -d -m 0700 -o cortex-mcp -g cortex-mcp /var/lib/cortex-mcp
sudo install -d -m 0755 /etc/cortex-mcp
sudo install -m 0644 "cortex-mcp-${VERSION}/config.example.yaml" /etc/cortex-mcp/config.yaml
```

Edit `/etc/cortex-mcp/config.yaml` (at least `vault: /srv/vault`, `state_dir: /var/lib/cortex-mcp`,
and `public_url`; see [configuration](configuration.md)), and give the `cortex-mcp` user write access
to the vault (make it the owner, or add it to the vault's group).

A systemd unit, `/etc/systemd/system/cortex-mcp.service`:

```ini
[Unit]
Description=cortex-mcp (MCP server for a Markdown vault)
After=network-online.target
Wants=network-online.target

[Service]
User=cortex-mcp
Group=cortex-mcp
ExecStart=/usr/local/bin/cortex-mcp serve
Restart=on-failure
# Notes are written 0644 filtered by the umask; 0077 keeps new notes private.
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadWritePaths=/srv/vault /var/lib/cortex-mcp
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
```

`ProtectSystem=strict` makes every path read-only except `ReadWritePaths`. If the vault lives under
`/home`, set `ProtectHome=false` and keep the vault in `ReadWritePaths`. `serve` reads
`/etc/cortex-mcp/config.yaml` by default and shuts down cleanly on SIGTERM.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cortex-mcp
curl -fsS http://127.0.0.1:8080/healthz        # prints: ok
```

Run the owner commands as the service user, so the files they create belong to it:
`sudo -u cortex-mcp cortex-mcp setup`.

**macOS:** the binaries are not notarized. After verifying the archive, remove the quarantine flag with
`xattr -d com.apple.quarantine cortex-mcp`.

**Windows:** unzip the archive, verify it, and run `cortex-mcp.exe serve -config C:\cortex-mcp\config.yaml`
(use Windows paths in the config). No service wrapper is shipped.

## Option B: container image

`ghcr.io/josejimenez-m/cortex-mcp` is a multi-arch image (linux/amd64, linux/arm64) built from the same
release binaries on a distroless static base: no shell, no package manager. Tags: `vX.Y.Z` for each
release, and `latest` for the newest release that is not a prerelease. It runs as uid 65532 unless you
set `user:`, and its default command is `serve -config /config/config.yaml`.

Pin the image by the digest you verified (see [Verifying a download](#verifying-a-download)). A
`compose.yaml`, with the reverse proxy on the same Docker network:

```yaml
services:
  cortex-mcp:
    image: ghcr.io/josejimenez-m/cortex-mcp:v0.1.0@sha256:<verified digest>
    restart: unless-stopped
    user: "1000:1000"          # the host owner of the vault and state folders
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    volumes:
      - /srv/vault:/data/vault
      - /srv/cortex-mcp/state:/data/state
      - /srv/cortex-mcp/config.yaml:/config/config.yaml:ro
    networks: [proxy]

networks:
  proxy:
    external: true
```

With `config.yaml`:

```yaml
vault: /data/vault
state_dir: /data/state
public_url: https://mcp.example.com
listen: ":8080"
trusted_proxies: [172.18.0.0/16]   # the subnet of the "proxy" network, see below
```

Create the state folder first, owned by the same uid, with `install -d -m 0700 -o 1000 -g 1000
/srv/cortex-mcp/state`. No port is published: the proxy reaches `cortex-mcp:8080` over the shared
network. `serve` logs a warning about the non-loopback `listen`, which is expected in a container.
Run the owner commands inside the container, for example
`docker compose exec cortex-mcp /cortex-mcp setup -config /config/config.yaml`; `reset-auth` there
needs `-yes` or a TTY.

## Verifying a download

Every release is signed in its GitHub Actions workflow with a short-lived Sigstore certificate (keyless
signing): the certificate names this repository's `release.yml` workflow and the tag, and the signature
is recorded in the public Rekor transparency log. Verifying it proves that the files were produced by
that workflow for that tag and have not changed since.

### Release archives

```bash
cosign verify-blob \
  --certificate-identity "https://github.com/JoseJimenez-M/cortex-mcp/.github/workflows/release.yml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle checksums.txt.sigstore.json \
  checksums.txt
sha256sum --check --ignore-missing checksums.txt
```

Expected: `Verified OK`, then `cortex-mcp_<version>_linux_<arch>.tar.gz: OK`. The SBOM files are listed
in `checksums.txt` too, so the same check covers any you download.

On macOS, check one archive with
`grep " cortex-mcp_${VERSION}_darwin_arm64.tar.gz\$" checksums.txt | shasum -a 256 --check`.
In PowerShell on Windows, after `cosign verify-blob` with the same flags:

```powershell
$file = "cortex-mcp_0.1.0_windows_amd64.zip"
$expected = (Select-String -Path checksums.txt -Pattern " $file$").Line.Split(" ")[0]
(Get-FileHash $file -Algorithm SHA256).Hash -eq $expected    # prints: True
```

### Container image

Resolve the tag to a digest once, verify that digest, and use it from then on, so the image you run is
the one you verified:

```bash
IMAGE=ghcr.io/josejimenez-m/cortex-mcp
DIGEST=$(docker buildx imagetools inspect "${IMAGE}:v${VERSION}" | awk '/^Digest:/ {print $2}')
cosign verify "${IMAGE}@${DIGEST}" \
  --certificate-identity "https://github.com/JoseJimenez-M/cortex-mcp/.github/workflows/release.yml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
echo "${IMAGE}:v${VERSION}@${DIGEST}"
```

Put the printed reference in `compose.yaml`. The image index also carries an SBOM attestation, covered
by the same signature:
`docker buildx imagetools inspect "${IMAGE}@${DIGEST}" --format '{{ json .SBOM }}'`.

## Behind a reverse proxy

The server speaks plain HTTP. For anything beyond localhost, keep the default `listen: 127.0.0.1:8080`
(or `:8080` in a container), terminate TLS in a reverse proxy, and set `public_url` to the public https
URL. The proxy must not buffer responses: streamed (SSE) responses have to reach the client at once.

The OAuth endpoints (`/authorize`, the login page, client registration, client metadata document
fetches) are rate-limited per client address. Behind a proxy every request comes from the proxy, so set
`trusted_proxies` to the proxy's address or network; without it all clients share one bucket per
limiter, which is safe but coarser. The server reads `X-Forwarded-For` only from a peer inside
`trusted_proxies` and takes the right-most entry that is not itself a listed proxy, so list only proxies
that append or set the address they received from (both examples below do), and never a network that
untrusted hosts can send from.

### Caddy on the same host

```
mcp.example.com {
    reverse_proxy 127.0.0.1:8080 {
        flush_interval -1
    }
}
```

`flush_interval -1` turns off response buffering. Caddy sets `X-Forwarded-For` itself. In the config:
`trusted_proxies: [127.0.0.1/32]` (add `::1/128` if Caddy connects over IPv6 loopback).

### Caddy and cortex-mcp in Docker

With both containers on one Docker network, Caddy proxies to the service name
(`reverse_proxy cortex-mcp:8080` with the same `flush_interval -1`), and cortex-mcp listens on all
interfaces inside its container (`listen: ":8080"`, no published port). Find the network's subnet and
list it in `trusted_proxies`:

```bash
docker network inspect <network> --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}'
```

```yaml
listen: ":8080"
trusted_proxies: [172.18.0.0/16]   # the subnet printed above
```

This trusts every container on that network, not only Caddy: any of them could set `X-Forwarded-For`
and pick its own rate-limit bucket. That is acceptable for containers you run yourself, since the global
limits still cap them all; give cortex-mcp and Caddy a network of their own if another container there
is not trusted.

### nginx on the same host

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name mcp.example.com;
    ssl_certificate     /etc/ssl/mcp.example.com/fullchain.pem;
    ssl_certificate_key /etc/ssl/mcp.example.com/privkey.pem;

    # Twice limits.max_write_bytes plus 64 KiB, rounded up (default 1 MiB writes).
    client_max_body_size 3m;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        # Replace, never append, the header: the server then sees exactly one address.
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 1h;
    }
}
```

With `trusted_proxies: [127.0.0.1/32]`. `proxy_buffering off` lets streamed responses through, and the
long `proxy_read_timeout` keeps an idle stream open (the server closes sessions idle for 30 minutes).
Raise `client_max_body_size` if you raise `limits.max_write_bytes`.

## First-time setup

1. **Configure.** Set `vault`, `state_dir`, and `public_url` (exactly the https URL clients will use,
   no path), plus `listen` and `trusted_proxies` for your proxy. Every key is in
   [configuration](configuration.md); invalid values fail at startup with a message naming the key.
2. **Create the owner.** Run `cortex-mcp setup`. It prints three factors once: a TOTP URI for an
   authenticator app (and the secret, to type by hand), ten recovery codes, and a link to register a
   passkey. Keep the factors in different places, for example the passkey in a password manager, TOTP
   in an authenticator app, and the recovery codes offline, so losing one never locks you out.
3. **Start the server** (`cortex-mcp serve`, the systemd unit, or `docker compose up -d`) and open the
   passkey link within 10 minutes. It works once and asks for a current TOTP code.
4. **Optional: a Bearer token** for a client without a browser: `cortex-mcp token create NAME` prints
   the token once on stdout. Store it then; it cannot be shown again.
5. **Check** that `https://mcp.example.com/healthz` answers `ok`.
6. **Connect your assistants**: see [connecting clients](connecting-clients.md).

To upgrade later, see [releasing](releasing.md#upgrading-an-installation).

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
`/etc/cortex-mcp/config.yaml`. `serve` logs JSON to stderr and shuts down cleanly on SIGINT or SIGTERM
(a second signal exits at once). `GET /healthz` answers `ok` without authentication; the MCP endpoint is
`/mcp`.

- `setup` refuses to run twice. `setup -passkey` prints a new passkey link (to add another passkey).
  `setup -force` replaces every factor at once: the old passkeys, authenticator entry, and recovery
  codes stop working, and approvals they gave that have not yet become a connection are dropped;
  connected clients stay connected.
- `unlock-totp` clears the TOTP lock after 50 consecutive wrong codes.
- `reset-auth -yes` is the last resort: it deletes the owner's factors and disconnects every OAuth
  client (Bearer tokens stay). Without `-yes` it asks you to type `reset`.
- `clients list` shows Bearer tokens and OAuth clients, one tab-separated line each, with the redirect
  hosts of every OAuth client. `clients revoke ID` removes one of either kind; an OAuth client's name is
  also accepted when exactly one client has it.
- `token create`, `token list`, and `token revoke` manage Bearer tokens by name.

Every command works while `serve` is running: they share `auth.db`, and the server reads owner and
client state from it on each request.
````

- [ ] **Step 5: Run the doc checks and the link check**

```bash
FILES="docs/install.md docs/configuration.md"
LC_ALL=C.UTF-8 grep -nP '\x{2014}|[\x{1F000}-\x{1FAFF}\x{2600}-\x{27BF}\x{FE0F}]' $FILES && echo "FAIL: em dash or emoji" || echo "ok: no em dash or emoji"
grep -noE 'https?://[A-Za-z0-9.-]+' $FILES | grep -vE '://(mcp\.example\.com|localhost|127\.0\.0\.1|github\.com|ghcr\.io|raw\.githubusercontent\.com|polyformproject\.org|modelcontextprotocol\.io|claude\.ai|chatgpt\.com|agent\.meta\.ai|token\.actions\.githubusercontent\.com)$' && echo "FAIL: unexpected host" || echo "ok: hosts"
grep -noE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b|/home/' $FILES | grep -vE ':(127\.0\.0\.[0-9]+|172\.18\.0\.[0-9]+)$' && echo "FAIL: real-looking address or home path" || echo "ok: addresses"
```
Expected: `ok: no em dash or emoji`, `ok: hosts`, `ok: addresses`. The `/home` mentions in `install.md` are the words "under `/home`" without a following path, which the third check does not match (it matches `/home/`); if it reports one, reword it. Links to `connecting-clients.md`, `releasing.md`, and the README anchor resolve once Tasks 3, 7, and 8 land; Task 9 checks every link.

- [ ] **Step 6: Commit**

```bash
git add docs/install.md docs/configuration.md
git commit -m "docs: install and configuration guides

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Client connection and security guides

**Files:**
- Create: `docs/connecting-clients.md`, `docs/security.md`

**Interfaces:**
- Consumes: the README sections "Security model", "Connect assistant apps (OAuth)", and "Connect Claude Code" (their facts move here; Task 8 trims the README); spec 6.6; `internal/oauth/dcr.go` (the registration request and response).
- Produces: `docs/connecting-clients.md#meta-muse`, `docs/security.md#residual-limits`, `docs/security.md#deliberate-non-features` (linked from the README in Task 8 and from `SECURITY.md`).

Every statement here is already true in the code and the current README; nothing new is promised. When in doubt, check the cited file before writing.

- [ ] **Step 1: Write the failing coverage check**

The security guide must carry every fact the README's "Security model" section holds today, because Task 8 removes that section. Check a set of distinctive phrases, one per README bullet:

```bash
for p in 'os.Root' '.trash' 'read-only for tools' 'disk_low' 'hashes in' 'RFC 8707' 'RFC 9207' 'redirect_allowlist' '64 KiB' '2048 bytes' '/48' '50 registered clients' 'frame-ancestors' 'signature counter' 'only as hashes' 'bound to the credential' '16 live sessions' '/tmp' '30 minutes' '127.0.0.1:8080' 'internal_error' 'UMask=0077' 'dataviewjs' 'ext4'; do
  grep -qF -- "$p" docs/security.md 2>/dev/null || echo "missing: $p"
done; echo "check done"
```
Expected: FAIL, 24 `missing:` lines before `check done`.

- [ ] **Step 2: Create `docs/security.md`**

````markdown
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
- `.git`, `.obsidian`, and `.cortex-mcp` are off limits at any depth. `.trash` is receive-only
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
- Each token can hold at most 16 live sessions (normal clients use 1 or 2). Opening one more gets
  `429 Too Many Requests` with `Retry-After`; a slot frees when a client ends its session or the
  session times out. Sessions with no client POST for 30 minutes are closed.

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
  one older than 10 minutes is evicted, and a client that never completes a login is deleted after 24
  hours. Clients with a connection never count and are never evicted.
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
- **No key rotation command**: the OAuth keys never leave `auth.db`; rotating them by hand (deleting the
  `oauth_keys` rows and restarting) invalidates every OAuth token.

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
````

- [ ] **Step 3: Run the coverage check**

```bash
for p in 'os.Root' '.trash' 'read-only for tools' 'disk_low' 'hashes in' 'RFC 8707' 'RFC 9207' 'redirect_allowlist' '64 KiB' '2048 bytes' '/48' '50 registered clients' 'frame-ancestors' 'signature counter' 'only as hashes' 'bound to the credential' '16 live sessions' '/tmp' '30 minutes' '127.0.0.1:8080' 'internal_error' 'UMask=0077' 'dataviewjs' 'ext4'; do
  grep -qF -- "$p" docs/security.md 2>/dev/null || echo "missing: $p"
done; echo "check done"
```
Expected: only `check done`.

- [ ] **Step 4: Create `docs/connecting-clients.md`**

````markdown
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
and `.../mcp/` is a different resource that the server refuses.

App menus change often; the steps below were checked in October 2026.

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
  hours, and when 50 such clients exist the oldest one older than 10 minutes is evicted to make room.
  Once connected, the client is kept.
- `cortex-mcp clients revoke ID` deletes the client: that id never works again. To reconnect, register
  a new one.
- `/register` is rate limited per source address (5, then 1 every 6 minutes). The redirect URI must be
  on `oauth.redirect_allowlist`; the Muse callback is there by default.

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
  token. Revoking one never affects the others.
- Each write is labelled in `state_dir/writes.log` with the client that made it: a Bearer token's name,
  or the name an OAuth app registered.
````

- [ ] **Step 5: Run the doc checks**

```bash
FILES="docs/connecting-clients.md docs/security.md"
LC_ALL=C.UTF-8 grep -nP '\x{2014}|[\x{1F000}-\x{1FAFF}\x{2600}-\x{27BF}\x{FE0F}]' $FILES && echo "FAIL: em dash or emoji" || echo "ok: no em dash or emoji"
grep -noE 'https?://[A-Za-z0-9.-]+' $FILES | grep -vE '://(mcp\.example\.com|localhost|127\.0\.0\.1|github\.com|ghcr\.io|raw\.githubusercontent\.com|polyformproject\.org|modelcontextprotocol\.io|claude\.ai|chatgpt\.com|agent\.meta\.ai|token\.actions\.githubusercontent\.com)$' && echo "FAIL: unexpected host" || echo "ok: hosts"
grep -noE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b|/home/' $FILES | grep -vE ':(127\.0\.0\.[0-9]+|172\.18\.0\.[0-9]+)$' && echo "FAIL: real-looking address or home path" || echo "ok: addresses"
```
Expected: `ok: no em dash or emoji`, `ok: hosts`, `ok: addresses`.

- [ ] **Step 6: Commit**

```bash
git add docs/connecting-clients.md docs/security.md
git commit -m "docs: client connection and security guides

Moves the README's security model into docs/security.md (threat model,
defences, deliberate non-features, residual limits) and documents the
Meta Muse Client ID step.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Container image built from the release binaries

**Files:**
- Modify: `Dockerfile`, `.github/dependabot.yml`

**Interfaces:**
- Consumes: `LICENSE` (Task 1).
- Produces: a `Dockerfile` whose build context is `<os>/<arch>/cortex-mcp` per platform plus `LICENSE` (exactly what GoReleaser `dockers_v2` builds in Task 5); the image runs as user `65532`, entrypoint `/cortex-mcp`, command `serve -config /config/config.yaml`, and holds `/LICENSE`.

The test is a real image build with the release context layout. Docker or Podman both work (same flags); the examples use `podman`, replace it with `docker` if that is what the host has.

- [ ] **Step 1: Build the release-style context and see the current Dockerfile fail**

```bash
mkdir -p bin/image/linux/amd64
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -X github.com/JoseJimenez-M/cortex-mcp/internal/server.Version=v0.0.0-imagecheck" \
  -o bin/image/linux/amd64/cortex-mcp ./cmd/cortex-mcp
cp LICENSE bin/image/
podman build --platform linux/amd64 -f Dockerfile -t cortex-mcp:imagecheck bin/image
```
Expected: FAIL at `COPY cortex-mcp /cortex-mcp` with a "no such file or directory" error (the current Dockerfile expects the binary at the context root).

- [ ] **Step 2: Replace `Dockerfile`**

```dockerfile
# Runtime-only image. GoReleaser (dockers_v2, see .goreleaser.yaml) builds it
# from the release binaries: the build context holds <os>/<arch>/cortex-mcp
# for each platform, which TARGETPLATFORM (set by BuildKit and Buildah)
# selects, plus LICENSE. The binary is static (CGO_ENABLED=0), so the image
# needs no shell or package manager and has nothing else to exploit.
# To build one by hand, see docs/releasing.md ("Building an image without
# GoReleaser"). The base is pinned by digest; Dependabot proposes updates.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
ARG TARGETPLATFORM
COPY LICENSE /LICENSE
COPY $TARGETPLATFORM/cortex-mcp /cortex-mcp
ENTRYPOINT ["/cortex-mcp"]
CMD ["serve", "-config", "/config/config.yaml"]
```

- [ ] **Step 3: Build again and check the image**

```bash
podman build --platform linux/amd64 -f Dockerfile -t cortex-mcp:imagecheck bin/image
podman run --rm cortex-mcp:imagecheck version
podman image inspect cortex-mcp:imagecheck --format '{{.Config.User}} {{.Config.Entrypoint}} {{.Config.Cmd}}'
cid=$(podman create cortex-mcp:imagecheck) && podman cp "$cid:/LICENSE" - | tar -xO | head -n 1; podman rm "$cid" >/dev/null
```
Expected: the build succeeds; then `cortex-mcp v0.0.0-imagecheck`; then `65532 [/cortex-mcp] [serve -config /config/config.yaml]`; then `# PolyForm Noncommercial License 1.0.0`.

- [ ] **Step 4: Let Dependabot propose base image updates**

Replace `.github/dependabot.yml` with:

```yaml
# Keeps the SHA-pinned actions, the Go modules, and the digest-pinned base
# image current. Pins by commit SHA or digest stop a moved tag from changing
# what CI runs or what the image contains; Dependabot proposes the bumps.
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
  - package-ecosystem: gomod
    directory: /
    schedule:
      interval: weekly
  - package-ecosystem: docker
    directory: /
    schedule:
      interval: weekly
```

- [ ] **Step 5: Clean up and commit**

```bash
podman rmi cortex-mcp:imagecheck
podman rmi gcr.io/distroless/static-debian13@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3 2>/dev/null || true
rm -rf bin/image
git add Dockerfile .github/dependabot.yml
git commit -m "build(image): build from the release binaries on distroless debian13

The Dockerfile now takes the GoReleaser dockers_v2 context (one binary per
platform under TARGETPLATFORM) and ships LICENSE. The base moves to
static-debian13, pinned by digest: the debian12 images are no longer listed
as updated by distroless. Dependabot now watches the base image.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: GoReleaser configuration and the release check in CI

**Files:**
- Create: `.goreleaser.yaml`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `Dockerfile` context layout (Task 4); `LICENSE`, `README.md`, `config.example.yaml`, `docs/*.md` (Tasks 1 to 3) as archive files; `server.Version` (`internal/server/server.go:30`, a `var` set by the linker).
- Produces: release file names used by the docs and Task 11: `cortex-mcp_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows), `<archive>.sbom.json`, `checksums.txt`, `checksums.txt.sigstore.json`; image `ghcr.io/josejimenez-m/cortex-mcp:<tag>` and `:latest`; a CI job `release-config`.

GoReleaser v2.18.2 needs Go 1.27 to build from source and this host's Go toolchain is pinned (`GOTOOLCHAIN=local`), so the local copy is the release binary, checked against the release's `checksums.txt`. It goes in `bin/tools/` (git-ignored) and is removed at the end. The local snapshot skips the image and SBOM steps (they need Docker buildx and syft); CI runs the full snapshot.

- [ ] **Step 1: Install GoReleaser v2.18.2 locally**

```bash
mkdir -p bin/tools
GR=https://github.com/goreleaser/goreleaser/releases/download/v2.18.2
curl -fsSL -o bin/tools/checksums.txt "$GR/checksums.txt"
curl -fsSL -o bin/tools/goreleaser_Linux_x86_64.tar.gz "$GR/goreleaser_Linux_x86_64.tar.gz"
(cd bin/tools && LC_ALL=C sha256sum --check --ignore-missing checksums.txt && tar -xzf goreleaser_Linux_x86_64.tar.gz goreleaser)
bin/tools/goreleaser --version | grep GitVersion
```
Expected: `goreleaser_Linux_x86_64.tar.gz: OK`, then a line containing `2.18.2`. On an arm64 host use `goreleaser_Linux_arm64.tar.gz`.

- [ ] **Step 2: Write the failing checks**

The version check is what proves the ldflags reach `server.Version`; a plain build prints `dev`:

```bash
go build -o bin/cortex-mcp ./cmd/cortex-mcp
out=$(bin/cortex-mcp version); echo "$out"
case "$out" in "cortex-mcp v"*-SNAPSHOT-*) echo "version ok" ;; *) echo "FAIL: version not set by the linker" ;; esac
bin/tools/goreleaser check
```
Expected: `cortex-mcp dev`, `FAIL: version not set by the linker`, and `goreleaser check` fails because no configuration file exists.

- [ ] **Step 3: Create `.goreleaser.yaml`**

```yaml
# GoReleaser configuration (schema version 2, GoReleaser v2.18.2).
# .github/workflows/release.yml runs "goreleaser release --clean" on v* tags;
# ci.yml runs "goreleaser check" and a snapshot on every pull request.
# docs/releasing.md explains what a release contains and how to verify it.
version: 2

project_name: cortex-mcp

builds:
  - id: cortex-mcp
    main: ./cmd/cortex-mcp
    binary: cortex-mcp
    env:
      - CGO_ENABLED=0
    goos: [linux, darwin, windows]
    goarch: [amd64, arm64]
    ignore:
      # Not a release target (spec section 10); nothing tests it.
      - goos: windows
        goarch: arm64
    flags:
      - -trimpath
    ldflags:
      - -s -w -X github.com/JoseJimenez-M/cortex-mcp/internal/server.Version=v{{ .Version }}
    # File times come from the commit, so rebuilding a tag gives the same bytes.
    mod_timestamp: "{{ .CommitTimestamp }}"

archives:
  - id: cortex-mcp
    ids: [cortex-mcp]
    formats: [tar.gz]
    format_overrides:
      - goos: windows
        formats: [zip]
    name_template: "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"
    files:
      - LICENSE
      - README.md
      - config.example.yaml
      - docs/*.md
    builds_info:
      mtime: "{{ .CommitDate }}"

checksum:
  name_template: checksums.txt
  algorithm: sha256

# One SPDX SBOM per archive, from the binaries' embedded module list only
# (no --enrich: no network lookups, the same input gives the same document).
sboms:
  - id: archives
    artifacts: archive
    args: ["$artifact", "--output", "spdx-json=$document"]

# Keyless signature of the checksum file, which lists every archive and SBOM.
# The certificate names this repository, release.yml, and the tag.
signs:
  - id: checksums
    cmd: cosign
    artifacts: checksum
    signature: "${artifact}.sigstore.json"
    args: ["sign-blob", "--bundle=${signature}", "${artifact}", "--yes"]
    output: true

# Multi-arch image from the binaries above, built and pushed in one buildx
# run during publish. Snapshots build one image per platform instead and load
# them locally ("<tag>-amd64", "<tag>-arm64"). sbom attaches a BuildKit SBOM
# attestation to the pushed index.
dockers_v2:
  - id: image
    ids: [cortex-mcp]
    dockerfile: Dockerfile
    images:
      - ghcr.io/josejimenez-m/cortex-mcp
    tags:
      - "{{ .Tag }}"
      - "{{ if not .Prerelease }}latest{{ end }}"
    platforms:
      - linux/amd64
      - linux/arm64
    extra_files:
      - LICENSE
    labels:
      org.opencontainers.image.title: cortex-mcp
      org.opencontainers.image.description: MCP server that lets AI assistants read and write one Markdown vault
      org.opencontainers.image.source: https://github.com/JoseJimenez-M/cortex-mcp
      org.opencontainers.image.licenses: PolyForm-Noncommercial-1.0.0
      org.opencontainers.image.version: "{{ .Version }}"
      org.opencontainers.image.revision: "{{ .FullCommit }}"
      org.opencontainers.image.created: "{{ .CommitDate }}"
    annotations:
      "index,manifest:org.opencontainers.image.description": MCP server that lets AI assistants read and write one Markdown vault
      "index,manifest:org.opencontainers.image.source": https://github.com/JoseJimenez-M/cortex-mcp
      "index,manifest:org.opencontainers.image.licenses": PolyForm-Noncommercial-1.0.0
      "index:org.opencontainers.image.base.name": "{{ .BaseImage }}"
      "index:org.opencontainers.image.base.digest": "{{ .BaseImageDigest }}"
    sbom: "true"

# Keyless signature of each pushed image, by digest.
docker_signs:
  - id: image
    cmd: cosign
    args: ["sign", "${artifact}@${digest}", "--yes"]
    output: true

release:
  prerelease: auto
  footer: |
    Verify before installing: see docs/install.md, "Verifying a download". checksums.txt is signed
    keylessly by this repository's release workflow (checksums.txt.sigstore.json), and the image
    ghcr.io/josejimenez-m/cortex-mcp is signed by digest.

changelog:
  sort: asc
  filters:
    exclude:
      - "^Merge "
```

- [ ] **Step 4: Run the checks against the new configuration**

```bash
bin/tools/goreleaser check
bin/tools/goreleaser release --snapshot --clean --skip=publish,sign,docker,sbom
ls dist/*.tar.gz dist/*.zip
grep -c '' dist/checksums.txt
bin=$(find dist -type f -name cortex-mcp -path '*linux_amd64*')
out=$("$bin" version); echo "$out"
case "$out" in "cortex-mcp v"*-SNAPSHOT-*) echo "version ok" ;; *) echo "FAIL: version not set by the linker" ;; esac
tar -tzf dist/cortex-mcp_*_linux_amd64.tar.gz | sort
```
Expected: `goreleaser check` prints `1 configuration file(s) validated` and no deprecation notice (fix any notice before going on); the snapshot ends with `release succeeded`; five archives (`darwin_amd64`, `darwin_arm64`, `linux_amd64`, `linux_arm64` as `.tar.gz`, `windows_amd64.zip`), named `cortex-mcp_0.0.0-SNAPSHOT-<commit>_<os>_<arch>`; `5` lines in `checksums.txt` (the SBOMs are skipped locally); `cortex-mcp v0.0.0-SNAPSHOT-<commit>` and `version ok`; the archive lists `LICENSE`, `README.md`, `config.example.yaml`, `cortex-mcp`, `docs/configuration.md`, `docs/connecting-clients.md`, `docs/install.md`, `docs/security.md`. If the snapshot version has a different shape (for example after a tag exists locally), adjust nothing in the config: the check only requires the `v` prefix and `-SNAPSHOT-`.

- [ ] **Step 5: Add the `release-config` job to CI**

Replace `.github/workflows/ci.yml` with (the `test` job is unchanged):

```yaml
name: ci

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version-file: go.mod
      - name: gofmt
        run: test -z "$(gofmt -l .)" || { gofmt -l .; exit 1; }
      - name: go mod tidy
        run: go mod tidy && git diff --exit-code go.mod go.sum
      - name: vet
        run: go vet ./...
      - name: test
        run: go test -race -coverprofile=coverage.out ./...
      - name: coverage
        run: go tool cover -func=coverage.out | tail -1
      - name: fuzz path validation
        run: go test -run='^$' -fuzz=FuzzCleanNeverEscapes -fuzztime=20s ./internal/vault
      - name: fuzz frontmatter split
        run: go test -run='^$' -fuzz=FuzzSplitFrontmatter -fuzztime=20s ./internal/vault
      - name: fuzz frontmatter parse
        run: go test -run='^$' -fuzz=FuzzParseFrontmatter -fuzztime=20s ./internal/vault
      - name: fuzz heading parser
        run: go test -run='^$' -fuzz=FuzzParseHeadings -fuzztime=20s ./internal/vault
      - name: fuzz frontmatter update
        run: go test -run='^$' -fuzz=FuzzSetFrontmatter -fuzztime=20s ./internal/vault
      - name: staticcheck
        run: go install honnef.co/go/tools/cmd/staticcheck@2026.2.1 && staticcheck ./...
      - name: govulncheck
        run: go install golang.org/x/vuln/cmd/govulncheck@v1.8.0 && govulncheck ./...
      - name: gosec
        run: go install github.com/securego/gosec/v2/cmd/gosec@v2.29.0 && gosec ./...

  # Exercises the release path before any tag exists: the workflows lint
  # clean, the GoReleaser config is valid, and a full snapshot (every binary,
  # archive, SBOM, and both images) builds. Nothing is signed or pushed.
  release-config:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0 # GoReleaser derives the version from tags and history
          persist-credentials: false
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version-file: go.mod
      - name: actionlint
        run: go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
      - uses: docker/setup-buildx-action@f87e5991a6d7451dcb8d9637bfbc97413f497069 # v4.4.1
      - uses: anchore/sbom-action/download-syft@66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c # v0.24.3
        with:
          syft-version: v1.54.0
      - uses: goreleaser/goreleaser-action@f06c13b6b1a9625abc9e6e439d9c05a8f2190e94 # v7.2.3
        with:
          version: v2.18.2
          install-only: true
      - name: goreleaser check
        run: goreleaser check
      - name: goreleaser snapshot
        run: goreleaser release --snapshot --clean --skip=publish,sign
      - name: snapshot contents
        run: |
          test "$(find dist -maxdepth 1 \( -name '*.tar.gz' -o -name '*.zip' \) | wc -l)" -eq 5
          test "$(find dist -maxdepth 1 -name '*.sbom.json' | wc -l)" -eq 5
          test "$(grep -c '' dist/checksums.txt)" -eq 10
      - name: snapshot binary reports its version
        run: |
          bin=$(find dist -type f -name cortex-mcp -path '*linux_amd64*')
          out=$("$bin" version)
          echo "$out"
          case "$out" in "cortex-mcp v"*-SNAPSHOT-*) ;; *) echo "version not set by the linker"; exit 1 ;; esac
      - name: snapshot image runs and carries the licence
        run: |
          img=$(docker image ls --format '{{.Repository}}:{{.Tag}}' ghcr.io/josejimenez-m/cortex-mcp | grep -- '-amd64$' | head -n 1)
          test -n "$img"
          docker run --rm "$img" version | grep -q '^cortex-mcp v'
          test "$(docker image inspect "$img" --format '{{.Config.User}}')" = 65532
          cid=$(docker create "$img")
          docker cp "$cid:/LICENSE" - | tar -xO | head -n 1 | grep -q '^# PolyForm Noncommercial License 1.0.0$'
          docker rm "$cid"
```

- [ ] **Step 6: Lint the workflow**

```bash
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
```
Expected: no output, exit code 0.

- [ ] **Step 7: Clean up and commit**

```bash
rm -rf dist bin/cortex-mcp
git add .goreleaser.yaml .github/workflows/ci.yml
git commit -m "build(release): GoReleaser config and a snapshot release check in CI

Five binaries with the version set by the linker, archives with the licence
and docs, checksums, an SPDX SBOM per archive, keyless cosign signing of the
checksum file and of the multi-arch GHCR image (dockers_v2). CI lints the
workflows, runs goreleaser check, and builds a full snapshot on every pull
request; nothing is signed or pushed there.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
Keep `bin/tools/goreleaser` until Task 9; it is removed there.

---

### Task 6: Release workflow on version tags

**Files:**
- Create: `.github/workflows/release.yml`

**Interfaces:**
- Consumes: `.goreleaser.yaml` (Task 5), which signs with `cosign` and needs `syft` and Docker buildx on the runner.
- Produces: the workflow path in the signing identity, `.github/workflows/release.yml`, so the certificate identity users verify is `https://github.com/JoseJimenez-M/cortex-mcp/.github/workflows/release.yml@refs/tags/<tag>`. Renaming this file changes that identity; `docs/install.md` and `docs/releasing.md` quote it.

Why each permission: `contents: write` creates the GitHub release and uploads its files; `packages: write` pushes to GHCR; `id-token: write` lets cosign get the GitHub OIDC token that Sigstore turns into the short-lived signing certificate. Nothing else is granted, and the top-level `permissions: {}` keeps any future job at zero unless it asks.

- [ ] **Step 1: Write the failing check**

```bash
test -f .github/workflows/release.yml && echo present || echo "FAIL: release workflow missing"
```
Expected: `FAIL: release workflow missing`.

- [ ] **Step 2: Create `.github/workflows/release.yml`**

```yaml
name: release

# Runs only when a version tag is pushed. docs/releasing.md describes the
# whole process; the owner pushes the tag.
on:
  push:
    tags: ["v*"]

permissions: {}

concurrency:
  group: release
  cancel-in-progress: false

jobs:
  release:
    # Keyless signing writes this repository's name and workflow path to the
    # public Rekor transparency log, and nobody outside a private repository
    # could download or verify its release: release only while public.
    if: ${{ !github.event.repository.private }}
    runs-on: ubuntu-latest
    timeout-minutes: 45
    permissions:
      contents: write # create the GitHub release and upload its files
      packages: write # push the image to ghcr.io
      id-token: write # GitHub OIDC token for keyless cosign signing
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0 # GoReleaser needs the tags and history
          persist-credentials: false
      - name: tag is on main
        run: git merge-base --is-ancestor "$GITHUB_SHA" origin/main
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version-file: go.mod
          cache: false # a release never restores a cache another run wrote
      - name: test
        run: go test -race ./...
      - uses: docker/setup-buildx-action@f87e5991a6d7451dcb8d9637bfbc97413f497069 # v4.4.1
      - uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2
      - uses: anchore/sbom-action/download-syft@66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c # v0.24.3
        with:
          syft-version: v1.54.0
      - uses: docker/login-action@dbcb813823bdd20940b903addbd779551569679f # v4.6.0
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: goreleaser/goreleaser-action@f06c13b6b1a9625abc9e6e439d9c05a8f2190e94 # v7.2.3
        with:
          version: v2.18.2
          args: release --clean
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

- [ ] **Step 3: Lint and re-check the GoReleaser config**

```bash
test -f .github/workflows/release.yml && echo present || echo "FAIL: release workflow missing"
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
bin/tools/goreleaser check
grep -nE 'uses: [^ ]+@[0-9a-f]{40} # v' .github/workflows/release.yml | wc -l
grep -nE 'uses: ' .github/workflows/release.yml | grep -vE '@[0-9a-f]{40} # v' || echo "ok: every action pinned by SHA"
```
Expected: `present`; no actionlint output; `1 configuration file(s) validated`; `7`; `ok: every action pinned by SHA`.

The workflow itself first runs when Jose pushes `v0.1.0` (Task 11). Until then, the `release-config` CI job is what proves the GoReleaser side works.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci(release): publish signed releases from v* tags

Runs GoReleaser on version tags with only contents, packages, and id-token
write permissions; skips while the repository is private and refuses tags
that are not on main. Every action is pinned by commit SHA.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Release process guide

**Files:**
- Create: `docs/releasing.md`

**Interfaces:**
- Consumes: `.goreleaser.yaml` (Task 5), `.github/workflows/release.yml` (Task 6), `Dockerfile` (Task 4), the LICENSE checksums (Task 1), the README's "Upgrading from a plan 1 binary" section (its facts move here; Task 8 removes it from the README).
- Produces: anchors `docs/releasing.md#upgrading-an-installation` (linked from `docs/install.md`) and `#building-an-image-without-goreleaser` (named in the `Dockerfile` comment).

- [ ] **Step 1: Write the failing check**

The guide must cover every release file and both owner prerequisites; check the distinctive strings:

```bash
for p in 'checksums.txt.sigstore.json' '.sbom.json' 'ghcr.io/josejimenez-m/cortex-mcp' 'release.yml@refs/tags/' 'Private vulnerability reporting' 'cannot be made private again' 'auth.db-wal' 'schema version 2 to 3' 'TARGETPLATFORM' 'c7c5d8ecd956c65116c97ccdfb4a77c47b761570d548c57ab2176d9ce575b81b' 'syft-version' 'Never move or'; do
  grep -qF -- "$p" docs/releasing.md 2>/dev/null || echo "missing: $p"
done; echo "check done"
```
Expected: FAIL, 12 `missing:` lines before `check done`.

- [ ] **Step 2: Create `docs/releasing.md`**

````markdown
# Releasing and upgrading

This page is for the maintainer cutting a release and for operators upgrading an installation. Every
release is built, signed, and published by GitHub Actions from a version tag; nothing is built or
signed on a personal machine.

## What a release contains

Pushing a tag `vX.Y.Z` runs `.github/workflows/release.yml`, which runs GoReleaser with
`.goreleaser.yaml`. It publishes:

| File or image | What it is |
|---------------|-----------|
| `cortex-mcp_X.Y.Z_linux_amd64.tar.gz`, `..._linux_arm64.tar.gz`, `..._darwin_amd64.tar.gz`, `..._darwin_arm64.tar.gz`, `..._windows_amd64.zip` | The static binary (`CGO_ENABLED=0`, `-trimpath`, version set by the linker) with `LICENSE`, `README.md`, `config.example.yaml`, and `docs/*.md` |
| `<archive>.sbom.json` | An SPDX SBOM per archive, made by syft from the binary's embedded module list |
| `checksums.txt` | The SHA-256 of every archive and SBOM |
| `checksums.txt.sigstore.json` | A keyless cosign signature bundle for `checksums.txt` |
| `ghcr.io/josejimenez-m/cortex-mcp:vX.Y.Z` (and `:latest` unless the tag is a prerelease) | A multi-arch image (linux/amd64, linux/arm64) from the same binaries on distroless static, signed by digest with cosign, with a BuildKit SBOM attestation in its index |

The signing certificate's identity is
`https://github.com/JoseJimenez-M/cortex-mcp/.github/workflows/release.yml@refs/tags/vX.Y.Z`, issued for
`https://token.actions.githubusercontent.com`. Every signature is recorded in the public Rekor
transparency log.

## One-time prerequisites (repository owner)

These are owner decisions and settings; they are not automated.

- **The repository is public.** The release job does not run while the repository is private
  (`if: ${{ !github.event.repository.private }}`): keyless signing records the repository and workflow
  names in the public Rekor log, and nobody outside a private repository could download or verify the
  release.
- **The GHCR package is public.** GHCR creates `ghcr.io/josejimenez-m/cortex-mcp` on the first push,
  linked to the repository through the `org.opencontainers.image.source` label. A package inherits
  private visibility while the repository is private; after the first release, check its visibility in
  the package settings and set it to public. A public package cannot be made private again.
- **Private vulnerability reporting** is enabled in the repository's security settings, so the
  process in `SECURITY.md` works.
- Optional: a tag ruleset that lets only the owner create `v*` tags.

## Versioning

Semantic versioning: `vMAJOR.MINOR.PATCH`. Before 1.0.0, a minor bump may change configuration or
behaviour; the release notes say how. A tag with a suffix (`v0.2.0-rc.1`) becomes a GitHub prerelease
and does not move the `latest` image tag.

## Cutting a release

1. Make sure `main` is green in CI. CI already runs `goreleaser check` and a full snapshot on every pull
   request (job `release-config`), so the configuration is known to build.
2. Tag the commit on `main` and push the tag:

   ```bash
   git switch main
   git pull --ff-only
   git tag -a v0.1.0 -m "cortex-mcp v0.1.0"
   git push origin v0.1.0
   ```

3. Watch the run: `gh run watch --exit-status $(gh run list --workflow release.yml --limit 1 --json databaseId --jq '.[0].databaseId')`.
   The job checks that the tag is on `main`, runs the tests, builds everything, publishes the GitHub
   release, pushes and signs the image.
4. Verify the published release as an operator would (next section), and edit the release notes if
   the generated changelog needs context (upgrade steps, breaking changes).

If a release run fails, fix the cause on `main` and release the next patch version. Never move or
re-push a published tag: anyone who verified the old one would see different content under the same
name.

## Verifying a release

With [cosign](https://github.com/sigstore/cosign) v3, for tag `vX.Y.Z`:

```bash
VERSION=X.Y.Z
gh release download "v${VERSION}" -R JoseJimenez-M/cortex-mcp -D "release-${VERSION}"
cd "release-${VERSION}"
cosign verify-blob \
  --certificate-identity "https://github.com/JoseJimenez-M/cortex-mcp/.github/workflows/release.yml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle checksums.txt.sigstore.json \
  checksums.txt
sha256sum --check checksums.txt

IMAGE=ghcr.io/josejimenez-m/cortex-mcp
DIGEST=$(docker buildx imagetools inspect "${IMAGE}:v${VERSION}" | awk '/^Digest:/ {print $2}')
cosign verify "${IMAGE}@${DIGEST}" \
  --certificate-identity "https://github.com/JoseJimenez-M/cortex-mcp/.github/workflows/release.yml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
docker buildx imagetools inspect "${IMAGE}@${DIGEST}" --format '{{ json .SBOM }}' | head -c 300
```

Expected: `Verified OK`; `OK` for every line of `checksums.txt`; a JSON verification result for the
image; and the start of the image's SPDX document. [Installing](install.md#verifying-a-download) shows
the same checks for a single archive.

The `LICENSE` file in every archive and image is the PolyForm Noncommercial 1.0.0 text from the
PolyForm project, byte for byte, plus the `Required Notice:` line; its SHA-256 is
`c7c5d8ecd956c65116c97ccdfb4a77c47b761570d548c57ab2176d9ce575b81b`, and the upstream file it starts
from (`polyformproject/polyform-licenses`, `PolyForm-Noncommercial-1.0.0.md`) has
`c0ea4a896d2c8c394b29f9427589996db826cd501c512279ff0ed3ef48fabbe5`.

## Upgrading an installation

Read the release notes first: they say when a version changes configuration or the state format.

1. **Verify** the new release ([Verifying a download](install.md#verifying-a-download)).
2. **Stop the server** (`systemctl stop cortex-mcp`, or `docker compose stop cortex-mcp`).
3. **Back up the state:** copy `state_dir/auth.db`, together with `auth.db-wal` and `auth.db-shm` when
   they exist, to a private place. The backup is a live credential: restoring it brings back every
   Bearer token it holds, including any revoked since, and it holds the TOTP secret and the OAuth keys
   in usable form. Keep it as private as `state_dir`, and delete it once the upgrade is verified.
4. **Replace the binary or the image:**
   - Binary: install the new `cortex-mcp` over the old one (`sudo install -m 0755 cortex-mcp
     /usr/local/bin/cortex-mcp`).
   - Image: change the `image:` line in `compose.yaml` to the new verified `vX.Y.Z@sha256:...`
     reference, then `docker compose pull cortex-mcp`.
5. **Start the server** and check `GET /healthz` and `cortex-mcp clients list`.

The first time a new version opens `auth.db` (`serve` or any command), it migrates the file to the
schema that version needs; an older binary refuses a newer schema ("auth database has schema version
N, this build supports up to M"). So a rollback needs the backup from step 3: stop the server, put the
old binary or image back, restore the backed-up files, and start again.

From a plan 1 build (before OAuth), the first open migrates the file from
schema version 2 to 3: it adds the OAuth tables and keeps the Bearer tokens. Then run `cortex-mcp setup`
to create the owner who approves OAuth connections.

## Building an image without GoReleaser

The `Dockerfile` expects the GoReleaser build context: one binary per platform at
`<os>/<arch>/cortex-mcp`, selected by `TARGETPLATFORM` (set by BuildKit and by Buildah/Podman), plus
`LICENSE`. To build an arm64 image by hand:

```bash
mkdir -p bin/image/linux/arm64
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath \
  -ldflags "-s -w -X github.com/JoseJimenez-M/cortex-mcp/internal/server.Version=$(git describe --tags --always --dirty)" \
  -o bin/image/linux/arm64/cortex-mcp ./cmd/cortex-mcp
cp LICENSE bin/image/
docker build --platform linux/arm64 -f Dockerfile -t cortex-mcp:local bin/image
```

The legacy Docker builder (`DOCKER_BUILDKIT=0`) does not set `TARGETPLATFORM` and cannot build this
file. Such an image is unsigned; prefer the release image.

## Maintenance

- **Dependabot** proposes weekly bumps for the SHA-pinned actions, the Go modules, and the base image
  digest in the `Dockerfile`. Review them like any change; CI runs the snapshot release on each.
- **GoReleaser and syft** are pinned by exact version in the workflows and are not bumped by
  Dependabot. To update them, change `version:` of `goreleaser/goreleaser-action` and `syft-version:`
  of `anchore/sbom-action/download-syft` in both `.github/workflows/ci.yml` and
  `.github/workflows/release.yml`, then let the `release-config` job prove the snapshot still builds.
- **cosign** comes from `sigstore/cosign-installer`, which installs the cosign version pinned (and
  checksum-verified) inside the action; a Dependabot bump of the installer bumps cosign.
- **Renaming `release.yml`** changes the signing identity that every verification command names;
  update `docs/install.md` and this page in the same change.
````

- [ ] **Step 3: Run the coverage check**

```bash
for p in 'checksums.txt.sigstore.json' '.sbom.json' 'ghcr.io/josejimenez-m/cortex-mcp' 'release.yml@refs/tags/' 'Private vulnerability reporting' 'cannot be made private again' 'auth.db-wal' 'schema version 2 to 3' 'TARGETPLATFORM' 'c7c5d8ecd956c65116c97ccdfb4a77c47b761570d548c57ab2176d9ce575b81b' 'syft-version' 'Never move or'; do
  grep -qF -- "$p" docs/releasing.md 2>/dev/null || echo "missing: $p"
done; echo "check done"
```
Expected: only `check done`.

- [ ] **Step 4: Run the doc checks**

```bash
FILES="docs/releasing.md"
LC_ALL=C.UTF-8 grep -nP '\x{2014}|[\x{1F000}-\x{1FAFF}\x{2600}-\x{27BF}\x{FE0F}]' $FILES && echo "FAIL: em dash or emoji" || echo "ok: no em dash or emoji"
grep -noE 'https?://[A-Za-z0-9.-]+' $FILES | grep -vE '://(mcp\.example\.com|localhost|127\.0\.0\.1|github\.com|ghcr\.io|raw\.githubusercontent\.com|polyformproject\.org|modelcontextprotocol\.io|claude\.ai|chatgpt\.com|agent\.meta\.ai|token\.actions\.githubusercontent\.com)$' && echo "FAIL: unexpected host" || echo "ok: hosts"
grep -noE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b|/home/' $FILES | grep -vE ':(127\.0\.0\.[0-9]+|172\.18\.0\.[0-9]+)$' && echo "FAIL: real-looking address or home path" || echo "ok: addresses"
```
Expected: `ok: no em dash or emoji`, `ok: hosts`, `ok: addresses`.

- [ ] **Step 5: Commit**

```bash
git add docs/releasing.md
git commit -m "docs: release process, verification, and upgrade guide

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: README, agent routing, and spec status

**Files:**
- Modify: `README.md` (whole file), `AGENTS.md`, `docs/specs/2026-10-01-cortex-mcp-design.md`

**Interfaces:**
- Consumes: every doc from Tasks 1 to 3 and 7 (the README links them), the release layout (Tasks 4 to 6).
- Produces: the README anchor `#quick-start-from-source` (linked from `docs/install.md`).

The README keeps what a first-time visitor needs (what it is, status, tools, security in brief, how to
install, commands, where the docs are, licence) and points to `docs/` for the rest. Nothing is lost:
the security model moved to `docs/security.md` (Task 3, with a coverage check), client setup to
`docs/connecting-clients.md`, reverse proxy and setup details to `docs/install.md`, and the plan 1
upgrade note to `docs/releasing.md`.

- [ ] **Step 1: Write the failing link check**

```bash
grep -oE '\]\(((docs/)?[A-Za-z0-9_.-]+\.md|LICENSE)(#[a-z0-9-]+)?\)' README.md | sed -E 's/^\]\(//; s/\)$//; s/#.*//' | sort -u | while read -r f; do test -f "$f" || echo "missing: $f"; done
for d in install configuration connecting-clients security releasing; do grep -q "docs/$d.md" README.md || echo "not linked: docs/$d.md"; done; echo "check done"
```
Expected: FAIL: `not linked:` lines for the five guides (the current README links none of them) before `check done`.

- [ ] **Step 2: Replace `README.md`**

````markdown
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
research, hobby, and noncommercial organizational use is permitted, commercial use is not. Contributions
are accepted under the contributor licence agreement in [`CONTRIBUTING.md`](CONTRIBUTING.md); security
reports go to [`SECURITY.md`](SECURITY.md).
````

- [ ] **Step 3: Run the link check and the doc checks**

```bash
grep -oE '\]\(((docs/)?[A-Za-z0-9_.-]+\.md|LICENSE)(#[a-z0-9-]+)?\)' README.md | sed -E 's/^\]\(//; s/\)$//; s/#.*//' | sort -u | while read -r f; do test -f "$f" || echo "missing: $f"; done
for d in install configuration connecting-clients security releasing; do grep -q "docs/$d.md" README.md || echo "not linked: docs/$d.md"; done; echo "check done"
FILES="README.md"
LC_ALL=C.UTF-8 grep -nP '\x{2014}|[\x{1F000}-\x{1FAFF}\x{2600}-\x{27BF}\x{FE0F}]' $FILES && echo "FAIL: em dash or emoji" || echo "ok: no em dash or emoji"
grep -noE 'https?://[A-Za-z0-9.-]+' $FILES | grep -vE '://(mcp\.example\.com|localhost|127\.0\.0\.1|github\.com|ghcr\.io|raw\.githubusercontent\.com|polyformproject\.org|modelcontextprotocol\.io|claude\.ai|chatgpt\.com|agent\.meta\.ai|token\.actions\.githubusercontent\.com)$' && echo "FAIL: unexpected host" || echo "ok: hosts"
grep -noE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b|/home/' $FILES | grep -vE ':(127\.0\.0\.[0-9]+|172\.18\.0\.[0-9]+)$' && echo "FAIL: real-looking address or home path" || echo "ok: addresses"
```
Expected: only `check done`, then `ok: no em dash or emoji`, `ok: hosts`, `ok: addresses`.

- [ ] **Step 4: Update `AGENTS.md`**

1. In the routing table, after the row `| Commands and flags | internal/cli/cli.go | README.md |`, add:
```markdown
| Releases, CI workflows, the container image | `docs/releasing.md` | `.goreleaser.yaml`, `.github/workflows/`, `Dockerfile`, spec section 10 |
| User docs (install, configuration, clients, security) | the guide in `docs/` for the topic | `README.md`; keep them generic: no real domain, IP, or path |
```
2. In "Do not touch", after the `docs/specs/` bullet, add:
```markdown
- `LICENSE`: the PolyForm Noncommercial 1.0.0 text byte for byte plus the `Required Notice:` line. Never
  edit it; `docs/releasing.md` records its sha256.
```
3. In "Dependencies", after the paragraph about bumping `github.com/zitadel/oidc/v3`, add:
```markdown
Release tooling is not a Go dependency and is pinned where it runs: GitHub Actions by commit SHA,
GoReleaser (v2.18.2) and syft (v1.54.0) by exact version in `.github/workflows/ci.yml` and
`release.yml`, and the base image by digest in `Dockerfile`. Dependabot bumps the actions, the Go
modules, and the base image; GoReleaser and syft are bumped by hand in both workflows
(`docs/releasing.md`, "Maintenance").
```

- [ ] **Step 5: Update the spec (record the decisions approved with this plan)**

In `docs/specs/2026-10-01-cortex-mcp-design.md`:

1. Set the frontmatter `updated:` to the current date.
2. Replace the status paragraph (from "Status: design approved." to "are recorded in 6.6.") with:
```markdown
Status: design approved. Plan 1 (core server: vault, tools, Bearer auth, rate limit, write log, `serve`
and `token` commands), plan 2 (OAuth 2.1, `setup`, `unlock-totp`, `reset-auth`, `clients`), and plan 3
(the licence file, release tooling, and user docs of sections 10 and 13) are implemented. No release has
been published yet. Decisions taken while building plan 2 are recorded in 6.6, and those of plan 3 in
10 and 13.
```
3. In section 10, replace the paragraph that starts "**CI on every pull request:**" with:
```markdown
**CI on every pull request:** `gofmt`, `go mod tidy`, `go test -race ./...` with a coverage report, each
fuzz target for 20 s, `go vet`, `staticcheck`, `govulncheck`, `gosec`, and, for the release path,
`actionlint`, `goreleaser check`, and a full GoReleaser snapshot (every binary, archive, and SBOM, and
both images); the snapshot's amd64 binary and image must report the snapshot version. A failing gate
blocks merge.
```
4. In section 10, replace the paragraph that starts "**Releases:**" with:
```markdown
**Releases** (built with plan 3): GoReleaser v2 (`.goreleaser.yaml`) runs from
`.github/workflows/release.yml` on `v*` tags. It builds linux/amd64, linux/arm64, darwin/amd64,
darwin/arm64, and windows/amd64 binaries (`CGO_ENABLED=0`, `-trimpath`, `server.Version` set by the
linker), archives them (tar.gz, zip for Windows) with `LICENSE`, `README.md`, `config.example.yaml`, and
`docs/*.md`, writes `checksums.txt` and an SPDX SBOM per archive (syft), signs `checksums.txt` keylessly
with cosign (a `.sigstore.json` bundle; GitHub OIDC identity of `release.yml` at the tag), and pushes a
multi-arch image (linux/amd64, linux/arm64) to `ghcr.io/josejimenez-m/cortex-mcp` with `dockers_v2`,
built from the same binaries on `gcr.io/distroless/static-debian13:nonroot` pinned by digest, with a
BuildKit SBOM attestation, signed keylessly by digest. Decisions made with plan 3: the base moved from
debian12 to debian13 (distroless no longer lists debian12 as updated); the release job runs only while
the repository is public and only for tags on `main`, with `contents`, `packages`, and `id-token` write
and nothing else; every action is pinned by commit SHA and the base image by digest (Dependabot bumps
both); GoReleaser and syft are pinned by version; no QEMU (the image build runs no commands), no
windows/arm64 binary, no separate provenance attestation; `latest` moves only for non-prerelease tags.
Making the repository public and pushing the first tag are owner decisions, never automated.
```
5. In section 10, replace the paragraph that starts "**Docs (English), shipped with the code:**" with:
```markdown
**Docs (English), shipped with the code and in every release archive:** `README.md` (what, status,
security in brief, install pointers, commands, licence), `docs/install.md` (requirements, binary or
image, verifying signatures, systemd, Docker Compose, Caddy and nginx with `trusted_proxies`, `setup`,
commands), `docs/configuration.md` (every key, default, and limit), `docs/connecting-clients.md`
(Claude Code with OAuth or a Bearer token, claude.ai, ChatGPT, Meta Muse with a Client ID registered
through `/register`, generic MCP clients), `docs/security.md` (threat model, defences, deliberate
non-features, residual limits), `docs/releasing.md` (cutting and verifying a release, upgrading),
`CONTRIBUTING.md`, and `SECURITY.md`. Docs never contain any operator's real domain, IP, or paths.
```
6. At the end of section 13, add:
```markdown
Implemented with plan 3: `LICENSE` is the PolyForm Noncommercial 1.0.0 text, byte for byte from the
PolyForm project's repository (its sha256 is in `docs/releasing.md`), followed by
`Required Notice: Copyright 2026 Jose Jimenez (https://github.com/JoseJimenez-M)`; release archives and
the image include it. The README states: "Source-available under PolyForm Noncommercial 1.0.0.
Commercial use (companies, paid services, resale, including modified versions) requires a separate
licence: contact jimenez331375@gmail.com." `CONTRIBUTING.md` holds the CLA (version 1): contributors
grant the author a copyright licence that allows relicensing, commercial licences included, and a
patent licence, keep their copyright, and agree by a fixed line in the pull request description.
```

- [ ] **Step 6: Check the edited files and commit**

```bash
FILES="AGENTS.md docs/specs/2026-10-01-cortex-mcp-design.md"
LC_ALL=C.UTF-8 grep -nP '\x{2014}|[\x{1F000}-\x{1FAFF}\x{2600}-\x{27BF}\x{FE0F}]' $FILES && echo "FAIL: em dash or emoji" || echo "ok: no em dash or emoji"
grep -c 'Implemented with plan 3' docs/specs/2026-10-01-cortex-mcp-design.md
grep -c 'docs/releasing.md' AGENTS.md
git add README.md AGENTS.md docs/specs/2026-10-01-cortex-mcp-design.md
git commit -m "docs: point the README at the guides; record plan 3 in the spec

The README keeps the overview, tools, security in brief, quick start, and
commands, and links the new guides; nothing is lost (the security model is
in docs/security.md, setup and proxies in docs/install.md, clients in
docs/connecting-clients.md, the upgrade note in docs/releasing.md).
The spec changes record decisions Jose approved with the plan 3 review.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
Expected before the commit: `ok: no em dash or emoji`, `1`, and `3` (the routing row, the "Do not touch" bullet, and the Dependencies paragraph).

---

### Task 9: Final gates, pull request, review, and merge

**Files:**
- Modify: `docs/plans/2026-10-03-plan-3-release.md` (status line only, Step 6)

**Interfaces:** none (verification and integration).

- [ ] **Step 1: Run every local gate**

```bash
gofmt -l .
go mod tidy && git diff --exit-code go.mod go.sum
go vet ./...
go test -race ./...
go run honnef.co/go/tools/cmd/staticcheck@2026.2.1 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
go run github.com/securego/gosec/v2/cmd/gosec@v2.29.0 ./...
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
bin/tools/goreleaser check
git diff --stat origin/main -- internal cmd go.mod go.sum
```
Expected: no `gofmt` output; no diff from `go mod tidy`; vet, staticcheck, govulncheck, gosec, and actionlint clean; every test package `ok`; `1 configuration file(s) validated`; and an empty `git diff --stat` (this plan changes no Go code and no module file).

- [ ] **Step 2: Check every relative link in the new and changed docs**

```bash
for f in README.md CONTRIBUTING.md SECURITY.md docs/*.md; do
  dir=$(dirname "$f")
  grep -oE '\]\([^)#:]+\.(md|yaml)(#[a-z0-9-]+)?\)|\]\(LICENSE\)|\]\(\.\./SECURITY\.md\)' "$f" | sed -E 's/^\]\(//; s/\)$//; s/#.*//' | sort -u | while read -r l; do
    test -e "$dir/$l" || echo "$f: broken link $l"
  done
done; echo "links done"
```
Expected: only `links done`.

- [ ] **Step 3: Remove local tools and build output**

```bash
rm -rf bin/tools dist bin/image bin/cortex-mcp
git status --short
```
Expected: `git status --short` prints nothing (everything is committed; `bin/` and `dist/` are git-ignored).

- [ ] **Step 4: Push and open the pull request**

```bash
git push -u origin plan-3-release
gh pr create --base main --head plan-3-release --title "Plan 3: licence, signed releases, user docs" --body "$(cat <<'EOF'
Implements docs/plans/2026-10-03-plan-3-release.md (spec sections 10 and 13).

- LICENSE (PolyForm Noncommercial 1.0.0, verbatim, plus the Required Notice), CONTRIBUTING.md (CLA v1), SECURITY.md.
- GoReleaser v2 config: five binaries, archives, checksums, SPDX SBOMs, keyless cosign signing, multi-arch GHCR image (dockers_v2) signed by digest.
- release.yml on v* tags (public repository and tags on main only; contents, packages, id-token write).
- CI job release-config: actionlint, goreleaser check, full snapshot with binary and image checks.
- Dockerfile on distroless static-debian13 pinned by digest; Dependabot watches it.
- docs/install.md, configuration.md, connecting-clients.md, security.md, releasing.md; README trimmed to point at them.
- No change under internal/ or cmd/, and none to go.mod or go.sum.

Not done here (owner gates): making the repository public, pushing v0.1.0.

Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```
Expected: a PR URL. (The PR body has no emoji: the repository's writing rules forbid them.)

- [ ] **Step 5: Wait for CI and fix anything red**

```bash
gh pr checks --watch
```
Expected: `test` and `release-config` both pass. The `release-config` job is the first run of the full snapshot with Docker buildx and syft; if it fails, read the log (`gh run view --log-failed`), fix the cause in a new commit (a change to the code shown in this plan needs Jose's approval first, per Global Constraints), and push again.

- [ ] **Step 6: Security review, plan status, and merge**

Request a review of the whole branch diff (superpowers:requesting-code-review). The reviewer checks: every action pinned by full commit SHA with a matching version comment; `permissions: {}` at the top of `release.yml` and only `contents`, `packages`, `id-token` write on the job; no `${{ }}` built from event data inside `run:`; `persist-credentials: false` on both new checkouts; the private-repository guard and the `main` ancestry check; `LICENSE` matching sha256 `c7c5d8ecd956c65116c97ccdfb4a77c47b761570d548c57ab2176d9ce575b81b`; no operator data in any doc; and the docs' claims against the code they describe (config limits in `internal/config/config.go`, OAuth numbers in spec 6.6). Verdict: `APPROVED` or `CHANGES REQUESTED` with findings; fix and re-review until `APPROVED`.

Then set this plan's frontmatter to `status: active` and `updated:` to the current date (it becomes `done` in Task 11), commit, push, and merge:

```bash
git add docs/plans/2026-10-03-plan-3-release.md
git commit -m "docs: plan 3 implemented, release gates pending

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
gh pr checks --watch
gh pr merge --rebase --delete-branch
git switch main && git pull --ff-only
```
Expected: CI green again, the PR merged with its per-task commits on `main`, and the local `main` up to date. Making the repository public and tagging are not part of this task.

---

### Task 10: OWNER GATE (a): make the repository public

**Files:** none in the repository (a history audit, then a repository setting Jose changes himself).

**Interfaces:**
- Consumes: `main` after Task 9.
- Produces: a public repository with private vulnerability reporting enabled; Task 11 depends on it (the release job does not run while the repository is private).

Making the repository public exposes its whole git history, every branch, and every past CI log, and cannot be fully undone (forks and caches may keep copies). The audit below runs first; the decision is Jose's.

- [ ] **Step 1: Audit the whole history for secrets**

```bash
go run github.com/zricethezav/gitleaks/v8@v8.30.1 git --log-opts=--all --redact --no-banner \
  --report-format json --report-path bin/gitleaks.json .
jq -r '.[] | [.RuleID, .File, (.StartLine|tostring), .Commit[0:8]] | @tsv' bin/gitleaks.json
```
Expected: exit code 1 with exactly the four known false positives found on 2026-10-03, all `generic-api-key` matches on the architecture lines (`internal/tokens  ->  internal/authdb`):
```
generic-api-key	AGENTS.md	39	b77e6609
generic-api-key	AGENTS.md	37	1d60e14f
generic-api-key	docs/plans/2026-10-02-plan-2-oauth.md	635	3e5a7686
generic-api-key	docs/plans/2026-10-02-plan-2-oauth.md	8502	3e5a7686
```
Any other finding stops the gate: report it to Jose without printing the secret.

- [ ] **Step 2: Audit the history for operator data**

Ask Jose for the strings that must never be public (his real domain, server IP, home paths, other personal identifiers) if they are not already in his instructions for this session, then search every commit:

```bash
git log --all -p | grep -n -i -E '<pattern given by Jose>' | cut -c1-160
git log --all --format='%an <%ae>' | sort | uniq -c
```
Expected: no match for Jose's patterns. The author lines show `jimenez331375@gmail.com`, which is already the public contact address in the README; Jose confirms that is acceptable. `rm bin/gitleaks.json` afterwards.

- [ ] **Step 3: STOP. Ask Jose to make the repository public**

Send Jose this summary and wait for his explicit answer in chat. Do not change any setting yourself.

> Plan 3 is merged. The history audit found: <the gitleaks result> and <the operator-data result>.
> Making `JoseJimenez-M/cortex-mcp` public exposes all history, branches, and CI logs, and cannot be
> fully undone. If you agree, please, on GitHub: Settings, General, Danger Zone, Change visibility,
> Public; then Settings, Security (Advanced Security), enable Private vulnerability reporting.
> Optional: a tag ruleset so only you can create `v*` tags. Tell me when it is done, or what to
> change first.

- [ ] **Step 4: Confirm the result (read-only)**

After Jose says it is done:

```bash
gh api repos/JoseJimenez-M/cortex-mcp --jq '{private, visibility}'
gh api repos/JoseJimenez-M/cortex-mcp/private-vulnerability-reporting --jq .enabled
```
Expected: `{"private":false,"visibility":"public"}` and `true` (the second endpoint answers 404 while the repository is private). If either differs, tell Jose; do not retry the settings yourself.

---

### Task 11: OWNER GATE (b): the first release, `v0.1.0`

**Files:**
- Modify (after the release): `README.md` (Status), `docs/specs/2026-10-01-cortex-mcp-design.md` (status line), `docs/plans/2026-10-03-plan-3-release.md` (status), on a new branch `release-v0.1.0-status`; plus `docs/install.md` and `docs/releasing.md` only if Step 4 finds a difference in the signing identity.

**Interfaces:**
- Consumes: a public repository (Task 10) and `main` with this plan merged (Task 9).
- Produces: release `v0.1.0`, image `ghcr.io/josejimenez-m/cortex-mcp:v0.1.0` and `:latest`.

Pushing the tag publishes a GitHub release and a container image under Jose's name, writes the signing record to the public Rekor log, and cannot be taken back cleanly. The decision is Jose's.

- [ ] **Step 1: Pre-flight (read-only)**

```bash
git switch main && git pull --ff-only
gh api repos/JoseJimenez-M/cortex-mcp --jq .private
gh run list --branch main --workflow ci.yml --limit 1 --json conclusion,headSha --jq '.[0]'
git rev-parse HEAD
git tag --list 'v*'
```
Expected: `false`; the latest `ci` run on `main` has `"conclusion":"success"` and its `headSha` equals `HEAD`; no existing `v*` tag.

- [ ] **Step 2: STOP. Ask Jose to push the first tag**

Send Jose this message and wait for his explicit "go" (or for him to push the tag himself). Do not create or push any tag before that.

> Everything is ready for `v0.1.0` at commit `<HEAD sha>` (CI green). Pushing the tag will publish a
> GitHub release with five binaries, SBOMs, and signed checksums, push
> `ghcr.io/josejimenez-m/cortex-mcp:v0.1.0` and `:latest`, and record the signatures in the public Rekor
> log. The new GHCR package may start private; making it public afterwards is your call and cannot be
> reversed. Shall I run `git tag -a v0.1.0 -m "cortex-mcp v0.1.0" && git push origin v0.1.0`, or will
> you?

- [ ] **Step 3: Tag (only after Jose's "go") and watch the run**

```bash
git tag -a v0.1.0 -m "cortex-mcp v0.1.0"
git push origin v0.1.0
gh run watch --exit-status "$(gh run list --workflow release.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
```
Expected: the `release` job succeeds. If it fails, do not delete or move the tag: read `gh run view --log-failed`, report to Jose, fix on `main` through a pull request, and the next attempt is `v0.1.1` (with a new "go").

- [ ] **Step 4: Verify the release exactly as a user would**

Install cosign v3.1.3 into `bin/release-check` (git-ignored), checked against its release checksums. The directory is fixed so later steps find it even in a new shell:

```bash
T="$PWD/bin/release-check"
mkdir -p "$T"
CO=https://github.com/sigstore/cosign/releases/download/v3.1.3
curl -fsSL -o "$T/cosign_checksums.txt" "$CO/cosign_checksums.txt"
curl -fsSL -o "$T/cosign-linux-amd64" "$CO/cosign-linux-amd64"
(cd "$T" && LC_ALL=C sha256sum --check --ignore-missing cosign_checksums.txt) && chmod +x "$T/cosign-linux-amd64"
VERSION=0.1.0
gh release download "v${VERSION}" -R JoseJimenez-M/cortex-mcp -D "$T/release"
(cd "$T/release" && ls && "$T/cosign-linux-amd64" verify-blob \
  --certificate-identity "https://github.com/JoseJimenez-M/cortex-mcp/.github/workflows/release.yml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle checksums.txt.sigstore.json checksums.txt && LC_ALL=C sha256sum --check checksums.txt)
tar -xzf "$T/release/cortex-mcp_${VERSION}_linux_amd64.tar.gz" -C "$T" cortex-mcp LICENSE
"$T/cortex-mcp" version
LC_ALL=C sha256sum "$T/LICENSE"
```
Expected: `cosign-linux-amd64: OK`; the release lists 5 archives, 5 `.sbom.json` files, `checksums.txt`, and `checksums.txt.sigstore.json`; `Verified OK`; `OK` for all 10 checksum lines; `cortex-mcp v0.1.0`; the LICENSE sha256 `c7c5d8ecd956c65116c97ccdfb4a77c47b761570d548c57ab2176d9ce575b81b`.

If `verify-blob` fails only on the identity (for example a different letter case in the repository name inside the certificate), inspect the identity it reports, and correct the identity string in `docs/install.md` and `docs/releasing.md` in Step 7's pull request.

Keep `bin/release-check` for Step 6.

- [ ] **Step 5: GHCR package visibility (Jose's decision)**

```bash
gh api /users/JoseJimenez-M/packages/container/cortex-mcp --jq .visibility
```
If the call is refused for a missing `read:packages` scope, ask Jose to look at the package page instead; never change the token's scopes yourself. If it prints `private`, tell Jose: "The image package is private, so nobody else can pull or verify it. To publish it: the package page, Package settings, Danger Zone, Change visibility, Public. A public package cannot be made private again." Wait for his answer. If he keeps it private, Step 6 is his to run with his own registry login (never type or pass his credentials yourself); note that in the status update.

- [ ] **Step 6: Verify the image anonymously**

Once the package is public, no login is needed:

```bash
T="$PWD/bin/release-check"
VERSION=0.1.0
IMAGE=ghcr.io/josejimenez-m/cortex-mcp
DIGEST=$(skopeo inspect --no-creds --format '{{.Digest}}' "docker://${IMAGE}:v${VERSION}")
echo "$DIGEST"
"$T/cosign-linux-amd64" verify "${IMAGE}@${DIGEST}" \
  --certificate-identity "https://github.com/JoseJimenez-M/cortex-mcp/.github/workflows/release.yml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
podman run --rm "${IMAGE}@${DIGEST}" version
podman image rm "${IMAGE}@${DIGEST}"
rm -rf "$T"
```
Expected: a `sha256:` digest (the multi-arch index); a JSON verification result naming the identity above; `cortex-mcp v0.1.0`. With Docker instead of Podman, `docker buildx imagetools inspect "${IMAGE}@${DIGEST}" --format '{{ json .SBOM }}'` also shows the SBOM attestation. If `cosign verify` finds no signature although the release log shows `docker_signs` ran, report it to Jose as a finding (how GHCR stores cosign v3 signatures) instead of re-signing anything.

- [ ] **Step 7: Record the release in the docs**

On a new branch:

```bash
git switch -c release-v0.1.0-status
```

1. In `README.md`, replace the sentence "No release has been published yet; until one is, build from source." with: "The first release is `v0.1.0` (<date>): binaries on the GitHub Releases page and the image `ghcr.io/josejimenez-m/cortex-mcp`, both verifiable as shown in [docs/install.md](docs/install.md#verifying-a-download)." using the release date in `YYYY-MM-DD` form.
2. In `docs/install.md`, replace "Until a release exists, build from source as shown in the [README](../README.md#quick-start-from-source)." with "To build from source instead, see the [README](../README.md#quick-start-from-source)."
3. In the spec status paragraph, replace "No release has been published yet." with "`v0.1.0` was released on <date>."
4. If Step 4 found a different signing identity, correct it in `docs/install.md` and `docs/releasing.md`.
5. Set this plan's frontmatter `status: done` and `updated:` to the current date.

```bash
git add README.md docs/install.md docs/specs/2026-10-01-cortex-mcp-design.md docs/plans/2026-10-03-plan-3-release.md
git commit -m "docs: record the v0.1.0 release

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push -u origin release-v0.1.0-status
gh pr create --base main --head release-v0.1.0-status --title "docs: record the v0.1.0 release" --body "Records the first release in the README, install guide, spec, and plan 3 status.

Generated with [Claude Code](https://claude.com/claude-code)"
gh pr checks --watch && gh pr merge --rebase --delete-branch
```
Expected: CI green and the PR merged. Upgrading the production server to the release image is a separate step Jose runs (the operator steps are in `docs/releasing.md`, "Upgrading an installation"); it is not part of this plan.

---

## Out of scope for this plan

- Upgrading the production server to the signed GHCR image (Jose's deployment notes cover it; the generic steps are in `docs/releasing.md`).
- Homebrew, Scoop, Linux packages (deb, rpm), and a Windows service wrapper.
- macOS notarization and Windows Authenticode signing.
- Building from the Go module proxy (`gomod.proxy`), reproducible-build verification by third parties, and SLSA provenance beyond what buildx attaches.
- Any change to server behaviour, configuration keys, or Go dependencies.
