# GitHub Release binaries

Published tags `vX.Y.Z` attach community (default-feature) hosts to the GitHub
Release. These files are packaging of Tenkai itself. They are not Catalog
releases, OCI artifacts, or `tenkai.release-signature.v1` envelopes.

The release workflow creates GitHub artifact attestations for every host and
`SHA256SUMS`. Verify an attestation before trusting a downloaded executable.
The workflow refuses to upload assets unless the live release tag still points
to the commit that triggered the workflow. Existing Release assets are replaced
only after that check succeeds.

Source `cargo build` remains valid.

## Attached hosts

| Binary | Role |
| --- | --- |
| `tenkaictl` | Embedded CLI and remote management client |
| `tenkai-server` | Community SQLite control-plane host; serves the pinned web console at `/ui/` |
| `tenkai-server-postgres` | Tenant-mode hub host built with `--features postgres,ui` |
| `tenkai-runtime` | Pull-only environment runtime |
| `tenkai-runtime-guard` | Runtime process fence |
| `tenkai-executor-guard` | Local executor process fence |

Platforms: `linux-x86_64`, `darwin-aarch64`. Community asset names are
`<binary>-<platform>`. The hub host is `tenkai-server-postgres-<platform>`
so it does not replace `tenkai-server-<platform>`. The release also attaches
`SHA256SUMS` and `tenkai-http-v1.schema.json`, the HTTP API contract clients
generate types from (see `api/` in the repository).
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

## Install a server host

`tenkai-server` runs shell-executor deploys under `tenkai-executor-guard`. It
finds a file named exactly `tenkai-executor-guard` beside its own binary or
one directory up, or the path in `TENKAI_EXECUTOR_GUARD`. A server host
therefore needs both assets, installed under their unsuffixed names:

```bash
for binary in tenkai-server tenkai-executor-guard; do
  curl -fsSL -O "${base}/${binary}-${platform}"
  gh attestation verify "${binary}-${platform}" \
    --repo Sannrox/tenkai \
    --signer-workflow Sannrox/tenkai/.github/workflows/release-binaries.yml \
    --source-ref "refs/tags/${tag}"
  grep " ${binary}-${platform}$" SHA256SUMS | sha256sum -c -
  sudo install -m 0755 "${binary}-${platform}" "/usr/local/bin/${binary}"
done
tenkai-server --help | grep -- --require-executor
```

At startup the server logs `tenkai-server warning: shell executor unavailable`
and leaves `shell_executor` out of `/readyz` capabilities when the guard is
missing; `--require-executor` refuses to start instead. `tenkaictl` guards its
own embedded applies and needs no separate guard. Run the server under a
supervisor as described in
[run tenkai-server](run-tenkai-server.md#install-a-server-host).

## Hub Postgres

Community assets are SQLite hosts built with feature `ui`, which embeds the
web console ([run tenkai-server](run-tenkai-server.md#open-the-web-console)).
Tenant-mode hub hosts are attached as `tenkai-server-postgres-<platform>`,
built with `--features postgres,ui`. That binary accepts `TENKAI_POSTGRES_URL`
for non-loopback hub URLs under the existing verified-TLS rule, serves the
pinned console at `/ui/`, and refuses to start as the community SQLite host
when `TENKAI_POSTGRES_URL` is unset or `--tenant-mode` is omitted.
`tenkai-server --help` reports `Compiled features: postgres, ui`.

Install the hub asset the same way as the community hosts, using the distinct
name:

```bash
curl -fsSL -O "${base}/tenkai-server-postgres-${platform}"
grep " tenkai-server-postgres-${platform}$" SHA256SUMS | sha256sum -c -
chmod 0755 "tenkai-server-postgres-${platform}"
./tenkai-server-postgres-${platform} --help
```

Source build when you need a hub host with the console:

```bash
cargo build --release --locked -p tenkai-server --features postgres,ui
```

Spoke and embedded CLI continue to refuse `TENKAI_POSTGRES_URL`.

## Packaging path

Tag `v[0-9]+.[0-9]+.[0-9]+` starts `.github/workflows/release-binaries.yml`.
That workflow builds the five community hosts with `--workspace --features tenkai-server/ui`, then
rebuilds `tenkai-server` with `-p tenkai-server --features postgres,ui` and names it
`tenkai-server-postgres-<platform>` with
`scripts/package-release-binaries.sh package-hub`. It adds the HTTP API
contract, writes `SHA256SUMS`, and attests every packaged file before the
upload job runs. The upload job checks that the live
tag resolves to the triggering commit. If the Release does not exist yet, the
workflow creates it; if it already exists, the workflow attaches or replaces
only the asset files and does not rewrite notes. A tag mismatch fails closed
before assets are uploaded.

Tags `v0.2.0`, `v0.3.0`, and `v0.3.1` predate this workflow and have no
attached hosts. Install those from source. First attached hosts: `v0.3.2`.

## Disconnected sites

A dark site cannot fetch GitHub Release attachments. Carry the same hosts
inside a signed [offline bundle](offline-bundles.md#host-binaries):
`hosts/<platform>/<name>`, `hosts/manifest.json`, and `hosts/SHA256SUMS`.
Verify them with the exporter trust roots received out of band, then install
with `tenkaictl upgrade install-hosts`. GitHub artifact attestations stay an
online check; the bundle signature is the offline one.

## Upgrade a server host

`tenkaictl self-upgrade` replaces a community SQLite server's binaries from
a signed bundle, with the bundle's host binaries verified as above (#678).
Run it on the server host. The service runs `<home>/current/tenkai-server`:

```text
<home>/versions/<digest>/tenkai-server, tenkai-executor-guard, tenkaictl
<home>/current  -> versions/<digest>
<home>/previous -> versions/<digest>
<home>/upgrade.json                 the last switch
<home>/backups/<ms>-<digest>.db     the store before that switch
```

```bash
# Changes nothing: verifies the hosts and runs the candidate's store check.
tenkaictl self-upgrade plan --home /opt/tenkai --bundle site.bundle.json \
  --trust-roots offline-trust.toml --env site-c --database /var/lib/tenkai/tenkai.db

# Backs up, switches, restarts, waits for readiness, rolls back if it fails.
tenkaictl self-upgrade apply --home /opt/tenkai --bundle site.bundle.json \
  --trust-roots offline-trust.toml --env site-c --database /var/lib/tenkai/tenkai.db \
  --ready-url http://127.0.0.1:8080/readyz -- systemctl restart tenkai-server
```

1. **Store check.** The candidate's own `tenkai-server --check-store`
   opens a private copy of the store. A binary that cannot open it, or a
   store newer than the binary, is refused before anything changes. `plan`
   and `apply` say when the candidate will migrate the schema.
   The check copies and migrates the whole store, so it may take up to
   `--check-timeout-secs` (default 1800).
2. **Backup and switch.** `apply` copies the store into `backups/`, records
   the switch, then repoints `current`.
3. **Readiness.** The arguments after `--` restart the service, without a
   shell. Then `apply` polls `--ready-url` until it answers 200 within
   `--ready-timeout-secs` (default 120) and confirms the switch. A restart
   command that fails counts as readiness that did not come. Without a
   restart command, `apply` stops after the switch, because the old server
   would still answer readiness. Restart the service yourself, then run
   `tenkaictl self-upgrade confirm --home <home> --ready-url <url>`.
4. **Automatic rollback.** When readiness does not come, `current` points
   back at the previous version and the service is restarted again. If the
   new version already migrated the store, the older binary cannot open it,
   and the store must not be replaced under a running server. `apply` then
   stops and says so. Stop the server, run
   `tenkaictl self-upgrade rollback --home <home> --restore-backup`, and
   start it. Restoring gives up what was written since the switch. The
   store is checked again after the rollback restart, so a candidate that
   migrated it while still starting is reported the same way. A restart
   command that runs longer than five minutes is killed and counts as
   failed.

`self-upgrade rollback` also rolls back a confirmed switch by hand. A switch
neither confirmed nor rolled back blocks the next one. An interrupted
rollback is finished by running it again. The backup is restored at most
once and only over a store the new version migrated, so a repeated rollback
never overwrites what the older server wrote since. One self-upgrade
command at a time holds a home.

The record, backup and links cover one host. With several server replicas,
upgrade one host at a time, with a schema both versions accept, as any
rolling deploy requires. PostgreSQL (tenant-mode) hubs are upgraded and
backed up by their operator; `--check-store` refuses them.
