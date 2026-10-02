# AGENTS.md: internal/vault

*The only package that touches the filesystem. Security-critical: every bug here is a potential escape
from the vault or a lost note. Read the root `AGENTS.md` first.*

---

## Rules for this package

- **Every public method starts with `v.clean(rel, access, wantMD)`**, then works only on the cleaned,
  slash-separated path, converted with `filepath.FromSlash` at the `os.Root` call.
- **All filesystem calls go through `v.root`** (`os.Root`). Never `os.*` or `filepath.Walk*` with a host
  path: `os.Root` is what refuses symlinks that resolve outside the vault.
- **Writes only through `writeAtomic`**, and only while holding `v.locks.lock(...)` for every path
  involved. Read-modify-write goes through `modify`.
- **Guarded edits** (anything that replaces existing text) take a `version` and must fail with
  `CodeChanged` when it is stale. Additive edits (`Create`, `Append*`) are the only unguarded writes.
- **Errors:** return `errf(Code..., ...)` for anything the assistant can act on; map filesystem errors
  with `fsErr`. Messages use vault-relative paths only.
- **Symlinks are never followed.** Protection is checked on the lexical path, so a link inside the vault
  could alias a denied path. Call `v.noSymlinks(p)` right after `clean` in every method that touches an
  existing path (`read` and `Create` do; folder operations use `checkFolder`). Walks skip symlink entries.
  `os.Root` stays the second line of defence against links leaving the vault.
- **Protected paths** (`neverAccessible`, `trashDir`, `deny`, also matched below `.trash/`, and the
  `readOnly` instructions file for writes and moves) are enforced in `clean` and again by
  `hidden`/`visible` in walks. A new operation must respect both.
- **Every write checks the disk floor** (`v.checkDisk()`, `disk_low` below `minFreeBytes`) after path
  validation and before taking a lock.
- **Scans that do not need frontmatter read with `readContent`**, never `read`: decoding YAML per note
  is the expensive part of a walk. Frontmatter blocks over `maxFrontmatterBytes` are never decoded.
- **Name folding** goes through `fold`/`foldEq` (fold.go) everywhere, locks included. Unicode normalization (NFC vs NFD) is not folded: a known limit.

## Tests a new operation must have

1. Happy path on a real temp vault (`newTestVault`).
2. Path traversal (`../`, absolute, NUL) and protected folders rejected with the right code.
3. A symlink (pointing inside or outside the vault, as the file or as a parent folder) is refused with
   `CodeInvalidPath`, and walks skip it.
4. For writes: no `.cortex-tmp-*` file left behind; concurrent calls with `-race` keep every change.
5. A fuzz target if it parses untrusted text.
