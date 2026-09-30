# GitHub Release binaries

Published tags `vX.Y.Z` attach community (default-feature) hosts to the GitHub
Release. These files are packaging of Tenkai itself. They are not Catalog
releases, OCI artifacts, or `tenkai.release-signature.v1` envelopes.

The release workflow creates GitHub artifact attestations for every host and
`SHA256SUMS`. Verify an attestation before trusting a downloaded executable.
The workflow refuses to upload assets unless the live release tag still points
to the commit that triggered the workflow. Existing Release assets are replaced
only after that check succeeds.

Source `cargo build` remains valid. Hub Postgres hosts are not attached.

## Attached hosts

| Binary | Role |
| --- | --- |
| `tenkaictl` | Embedded CLI and remote management client |
| `tenkai-server` | Network control-plane host |
| `tenkai-runtime` | Pull-only environment runtime |
| `tenkai-runtime-guard` | Runtime process fence |
| `tenkai-executor-guard` | Local executor process fence |

Platforms: `linux-x86_64`, `darwin-aarch64`. Asset names are
`<binary>-<platform>`. The release also attaches `SHA256SUMS` and
`tenkai-http-v1.schema.json`, the HTTP API contract clients generate types
from (see `api/` in the repository).
The fixture and Postgres conformance harness stay source-built.

## Verify and install

Replace `vX.Y.Z` with the published tag. Checksums must match before the
binary is executed.

```bash
tag=vX.Y.Z
platform=linux-x86_64   # or darwin-aarch64
base="https://github.com/Sannrox/tenkai/releases/download/${tag}"

curl -fsSL -O "${base}/SHA256SUMS"
curl -fsSL -O "${base}/tenkaictl-${platform}"
gh attestation verify "tenkaictl-${platform}" \
  --repo Sannrox/tenkai \
  --signer-workflow Sannrox/tenkai/.github/workflows/release-binaries.yml \
  --source-ref "refs/tags/${tag}"
grep " tenkaictl-${platform}$" SHA256SUMS | sha256sum -c -
# macOS: grep " tenkaictl-${platform}$" SHA256SUMS | shasum -a 256 -c
chmod 0755 "tenkaictl-${platform}"
./tenkaictl-${platform} --version
```

That grep checks only the downloaded host. Download every asset you will run
and check each name the same way, or check the full `SHA256SUMS` file when
every listed file is present.

## Hub Postgres

Community assets are default-feature SQLite hosts. Tenant-mode hub binaries
still require:

```bash
cargo build --release --locked --features postgres --bin tenkai-server
```

Spoke and embedded CLI continue to refuse `TENKAI_POSTGRES_URL`.

## Packaging path

Tag `v[0-9]+.[0-9]+.[0-9]+` starts `.github/workflows/release-binaries.yml`.
That workflow builds the five hosts, names them with
`scripts/package-release-binaries.sh`, adds the HTTP API contract, writes
`SHA256SUMS`, and attests all twelve files before the upload job runs. The upload job checks that the live
tag resolves to the triggering commit. If the Release does not exist yet, the
workflow creates it; if it already exists, the workflow attaches or replaces
only the asset files and does not rewrite notes. A tag mismatch fails closed
before assets are uploaded.

Tags `v0.2.0`, `v0.3.0`, and `v0.3.1` predate this workflow and have no
attached hosts. Install those from source. First attached hosts: `v0.3.2`.
