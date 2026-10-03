# Releasing and upgrading

This page is for the maintainer cutting a release and for operators upgrading an installation. Every
release is built, signed, and published by GitHub Actions from a version tag; nothing is built or
signed on a personal machine.

## What a release contains

Pushing a tag `vX.Y.Z` runs `.github/workflows/release.yml`, which runs GoReleaser with
`.goreleaser.yaml`. It publishes:

| File or image | What it is |
|---------------|-----------|
| `cortex-mcp_X.Y.Z_linux_amd64.tar.gz`, `..._linux_arm64.tar.gz`, `..._darwin_amd64.tar.gz`, `..._darwin_arm64.tar.gz`, `..._windows_amd64.zip` | The static binary (`CGO_ENABLED=0`, `-trimpath`, version set by the linker) with `LICENSE`, `THIRD_PARTY_NOTICES`, `README.md`, `config.example.yaml`, and `docs/*.md` |
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
   A `test` job runs the tests with a read-only token; only when they pass does the `release` job
   check that the tag is on `main`, build everything, publish the GitHub release, and push and sign
   the image.
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

`THIRD_PARTY_NOTICES`, next to it in every archive and image, reproduces the licence and notice files
of the Go standard library and of every module linked into a release binary (for any release target).
It is generated by `go run ./tools/thirdpartynotices > THIRD_PARTY_NOTICES` and committed; CI
regenerates it and fails when the committed file differs, and the snapshot checks that every archive
and the image carry that exact file.

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
`LICENSE` and `THIRD_PARTY_NOTICES`. To build an arm64 image by hand:

```bash
mkdir -p bin/image/linux/arm64
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath \
  -ldflags "-s -w -X github.com/JoseJimenez-M/cortex-mcp/internal/server.Version=$(git describe --tags --always --dirty)" \
  -o bin/image/linux/arm64/cortex-mcp ./cmd/cortex-mcp
cp LICENSE THIRD_PARTY_NOTICES bin/image/
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
- **BuildKit and the SBOM scanner** are pinned by version and index digest, not bumped by
  Dependabot: the `driver-opts: image=moby/buildkit:...` line of `docker/setup-buildx-action` in both
  workflows, and the `generator=docker.io/docker/buildkit-syft-scanner:...` flag in
  `.goreleaser.yaml`. To update one, take the version its stable tag points to (`buildx-stable-1`,
  `stable-1`), read the index digest with `docker buildx imagetools inspect <image>:<version>` (the
  `Digest:` line) or `skopeo inspect --raw docker://docker.io/<image>:<version> | sha256sum`, and
  update the version comment next to it. The scanner only runs on a real release (snapshots skip the
  attestation); the `release-config` job checks that its reference resolves.
- **Third-party notices.** Any change to the linked modules (a Dependabot Go bump included) makes
  CI fail until `THIRD_PARTY_NOTICES` is regenerated: run `go run ./tools/thirdpartynotices >
  THIRD_PARTY_NOTICES` and commit the result in the same pull request. It needs an official Go
  toolchain (some distribution packages of Go move `LICENSE` out of `GOROOT`; the command says so),
  and it fails on a module that ships no licence file, which then needs a look before it is shipped.
  The release targets it lists must match `builds` in `.goreleaser.yaml`.
- **cosign** comes from `sigstore/cosign-installer`, which installs the cosign version pinned (and
  checksum-verified) inside the action; a Dependabot bump of the installer bumps cosign.
- **Renaming `release.yml`** changes the signing identity that every verification command names;
  update `docs/install.md` and this page in the same change.
