# Support bundle

When a site can only carry files out, `tenkaictl support-bundle export`
collects what support needs to diagnose Tenkai, redacted by allowlist and
signed. It needs only Tenkai: no other product, control plane or network.

`--out` must name a new file; an existing file is never replaced.

```bash
tenkaictl support-bundle export --out support.json \
  --signing-key /etc/tenkai/support.seed --log-file /var/log/tenkai-server.log
```

## What the bundle holds

A `tenkai.support-bundle.v1` file holds:

- **Version and platform:** the Tenkai version, operating system and CPU
  architecture.
- **Configuration:** every `TENKAI_*` and `SEKAI_*` setting by name, as `set`
  or `unset`. Values are included only for an allowlist of numeric and
  boolean settings (intervals, thresholds, retention counts,
  `TENKAI_TLS_SYSTEM_ROOTS`), and only when the value is a plain number or
  word. No token, path, URL or host leaves.
- **Store:** read from a copy taken through SQLite's read-only backup path,
  so the live database is never opened for writing or migrated, and a
  missing one is never created. The database's own schema version (read
  before anything opens it) next to the version this Tenkai supports, whether the store reads, and how many
  environments and releases it holds. A store that cannot be opened or read
  is reported as `unreadable` without its detail, which could name the
  database path, and the rest of the bundle is still written.
- **Executor:** whether the executor guard is installed.
- **Recovery diagnostics:** the [ADR 0027](decisions/0027-recovery-diagnostic-bundle.md)
  diagnostic for each environment's latest plan. These carry environment
  names, plan and release identities, digests and findings, and no
  execution authority.
- **Log events:** with `--log-file`, the last 500 `tenkai.<event>` lines,
  each reduced to its leading allowlisted fields (`outcome`, `state`,
  `sequence`, counts and thresholds). Everything from the first other field
  on, such as free-text `detail`, is dropped, as is every other line.
- **Collection errors:** an environment that could not be read is named,
  without detail, and the rest of the bundle is still written.

The bundle is self-contained JSON, so a larger whole-stack support bundle can
embed it unchanged as one entry.

## Verify after transfer

Add the seed's public key to a trust-roots file, as for
[release signing](release-signing.md), then:

```bash
tenkaictl support-bundle verify support.json --trust-roots support-trust.toml
```

Verification needs only the file and the trust roots. It refuses a bundle
changed after signing, an unknown signer and an unsupported schema.
