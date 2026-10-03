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
