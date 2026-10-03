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
Windows), holding the `cortex-mcp` binary, `LICENSE`, `THIRD_PARTY_NOTICES` (the licences of the Go
standard library and modules built into it), `README.md`, `config.example.yaml`, and these docs. Next
to them: `checksums.txt` (the SHA-256 of every file), its signature `checksums.txt.sigstore.json`, and
an SPDX SBOM per archive (`<archive>.sbom.json`).

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

Put the printed reference in `compose.yaml`. The image index also carries an SBOM attestation and a
build provenance attestation (added by buildx when it pushes), both covered by the same signature:
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
