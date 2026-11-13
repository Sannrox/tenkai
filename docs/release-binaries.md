# GitHub Release binaries

Published tags `vX.Y.Z` and release candidates `vX.Y.Z-rc.N` attach community
(default-feature) hosts to the GitHub Release. A candidate's Release is a
pre-release and is never marked latest. These files are packaging of Tenkai itself. They are not Catalog
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
| `tenkai-host-applier` | Root side of [privileged host releases](host-releases.md); `linux-x86_64` only |

Platforms: `linux-x86_64`, `darwin-aarch64`; `tenkai-host-applier` runs
under systemd and is published for `linux-x86_64` only. Community asset names
are `<binary>-<platform>`. The hub host is `tenkai-server-postgres-<platform>`
so it does not replace `tenkai-server-<platform>`. The release also attaches
`SHA256SUMS`, `install.sh` (the [install script](#install-with-one-command)),
the applier's systemd unit `tenkai-host-apply.service` (installed as
`tenkai-host-apply@.service`) and polkit rule `tenkai-host-apply.rules`, both
from `examples/host-applier-systemd/`,
`tenkai-http-v1.schema.json` (the HTTP API contract clients generate types
from, see `api/` in the repository), the `tenkai.cdx.json` SBOM, and the
`tenkai-release.json` family release manifest.
The fixture and Postgres conformance harness stay source-built.

## Supported Linux

`linux-x86_64` hosts need glibc 2.28 or newer on x86-64: RHEL 8 and 9 and
their rebuilds, Debian 10 and newer, Ubuntu 20.04 and newer, Amazon Linux
2023. Musl-only distributions are not supported. The hosts are built in a
glibc 2.28 image (`scripts/build-linux-release-hosts.sh`) rather than on the
CI runner, and stay dynamically linked so `TENKAI_SIGNER_MODULE` and
`TENKAI_RUNTIME_PKCS11_MODULE` can load the system's PKCS#11 module.

Every pull request builds the Linux hosts that way, refuses any that needs a
newer glibc (`scripts/package-release-binaries.sh check-glibc`), and runs
each one on RHEL 8, RHEL 9, Debian 12, and Ubuntu 22.04. The release
workflow checks the floor again before it writes `SHA256SUMS`. v0.6.0 and
earlier Linux hosts need glibc 2.39; build those from source on older
systems.

## Install with one command

Each Release attaches `install.sh`, a POSIX shell script that installs that
Release's hosts. Replace `vX.Y.Z` with the published tag, or use
`releases/latest/download/install.sh` for the latest Release:

```bash
# tenkaictl
curl -fsSL https://github.com/Sannrox/tenkai/releases/download/vX.Y.Z/install.sh | sh
# server host: tenkaictl, tenkai-server and tenkai-executor-guard side by side
curl -fsSL https://github.com/Sannrox/tenkai/releases/download/vX.Y.Z/install.sh | sudo sh -s -- --role server
# runtime host: tenkai-runtime and tenkai-runtime-guard
curl -fsSL https://github.com/Sannrox/tenkai/releases/download/vX.Y.Z/install.sh | sudo sh -s -- --role runtime
# server host that runs privileged host releases (linux-x86_64, as root)
curl -fsSL https://github.com/Sannrox/tenkai/releases/download/vX.Y.Z/install.sh | sudo sh -s -- --role server --with-host-applier
```

The script:

- installs the version it is attached to; `--version X.Y.Z` picks another;
- refuses an unsupported system: anything but `linux-x86_64` with glibc
  2.28 or newer and `darwin-aarch64`, including musl distributions such as
  Alpine;
- downloads `SHA256SUMS` and the role's hosts and checks every file before
  installing any. A checksum mismatch or a host missing from `SHA256SUMS`
  installs nothing;
- renames each host into `--prefix` (default `/usr/local/bin` as root,
  `~/.local/bin` otherwise) under its unsuffixed name;
- refuses a [self-upgrade home](#upgrade-a-server-host), or a host in the
  prefix that is a symbolic link, because a plain replace would skip
  self-upgrade's store check, backup, and rollback;
- with `--with-host-applier`, also installs the
  [host applier](host-releases.md#install) as root, owned by root, at fixed
  paths, and refuses when any of their directories, or one above them, is a
  symbolic link or writable by anyone but root. It starts nothing;
- `--role host-applier` installs only those applier files, never writes
  `--prefix` or `client.toml`, and does not refuse a self-upgrade home;
- with `--role server`, writes `/etc/tenkai/client.toml` (`target = "remote"`,
  loopback URL) and a root-only `/etc/tenkai/management.token` unless they
  already exist, so `sudo tenkaictl status --env <env>` talks to the server
  instead of an empty embedded store;
- prints the `gh attestation verify` command for each installed file.

`install.sh` is listed in `SHA256SUMS` and covered by the provenance
attestation, so it can be checked before it runs:

```bash
curl -fsSL -O https://github.com/Sannrox/tenkai/releases/download/vX.Y.Z/install.sh
gh attestation verify install.sh --repo Sannrox/tenkai \
  --signer-workflow Sannrox/tenkai/.github/workflows/release-binaries.yml \
  --source-ref refs/heads/main
sudo sh install.sh --role server
```

It writes no service unit for the server or runtime; run them under a supervisor as
described in [run tenkai-server](run-tenkai-server.md#install-a-server-host).
Re-running it replaces plain installs; upgrade a server installed into a
self-upgrade home with `tenkaictl self-upgrade` instead.

## Verify and install by hand

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
  --source-ref refs/heads/main
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
therefore needs both assets, installed under their unsuffixed names.
`install.sh --role server` does that; by hand:

```bash
for binary in tenkai-server tenkai-executor-guard; do
  curl -fsSL -O "${base}/${binary}-${platform}"
  gh attestation verify "${binary}-${platform}" \
    --repo Sannrox/tenkai \
    --signer-workflow Sannrox/tenkai/.github/workflows/release-binaries.yml \
    --source-ref refs/heads/main
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

A `v*` tag push starts `.github/workflows/release-dispatch.yml`, which only
runs `gh workflow run release-binaries.yml --ref main -f tag=<tag>`. The
release always uses main's workflow and tag verifier; a failed run is fixed
on main and re-run for the same tag. `release-binaries.yml` refuses a tagged
run that is not from main, checks out the tag, and runs main's
`scripts/verify-release-tag.sh verify-signed` against main's
`security/release-tag-fingerprints` (public key in
`security/release-tag-key.asc`): the tag must be annotated, signed by an
allowed key, resolve to a commit on main or the matching `release-*`
line, and equal the tagged commit's workspace version. Lightweight and
unsigned tags stop the workflow before anything is built. The tag's
CHANGELOG section must exist and carry its
`Gate flags:` line. Manifest `git_sha` is that tagged commit.

The workflow then builds the five community hosts with `--workspace --features tenkai-server/ui`
(Linux hosts inside the glibc 2.28 image, with `tenkai-host-applier`),
rebuilds `tenkai-server` with `-p tenkai-server --features postgres,ui` and names it
`tenkai-server-postgres-<platform>` with
`scripts/package-release-binaries.sh package-hub`. It adds the HTTP API
contract, and `install.sh` with the tag's version written in plus the
applier's unit and polkit rule
(`scripts/package-release-binaries.sh install-script`), refuses Linux hosts
above the glibc floor, and writes `SHA256SUMS`. `scripts/release-metadata.py` writes
`tenkai.cdx.json`, a CycloneDX 1.5 SBOM of the locked Cargo graph and the
pinned web console. A separate job validates it against the CycloneDX schema
and SPDX license expressions; the attest job regenerates it and requires the
validated digest. The attest job then creates:

- a provenance attestation for every host, the contract, `install.sh`, the
  applier unit and rule, `SHA256SUMS`, and the SBOM;
- an SBOM attestation for every file listed in `SHA256SUMS`;
- `tenkai-release.json`, the [family release manifest](family-release-manifests.md),
  and a provenance attestation for it.

The upload job checks that the live tag resolves to the tagged commit,
creates a draft GitHub Release whose body is the tag's `CHANGELOG.md`
section, attaches the assets, and publishes it: marked latest for a `vX.Y.Z` tag on `main`, as a pre-release
not marked latest for a tag that contains `-`, and never marked latest for a
tag on a `release-*` maintenance line. A rerun
resumes a draft. An already published Release is refused, not edited. A tag
mismatch fails closed before assets are uploaded. Pull requests build
the Linux hosts the same way, run them on older distributions, and run
`scripts/release-dry-run.sh --linux-hosts` instead, which writes the same
notes, SBOM, and manifest (macOS hosts are stubs) and never attests or
publishes. `workflow_dispatch` without a tag dry-runs that packaging path
on the dispatched ref.

Verify the SBOM and manifest like a host:

```bash
for asset in tenkai.cdx.json tenkai-release.json; do
  curl -fsSL -O "${base}/${asset}"
  gh attestation verify "$asset" \
    --repo Sannrox/tenkai \
    --signer-workflow Sannrox/tenkai/.github/workflows/release-binaries.yml \
    --source-ref refs/heads/main
done
gh attestation verify "tenkaictl-${platform}" --repo Sannrox/tenkai \
  --predicate-type https://cyclonedx.org/bom
```

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
Run it on the server host. Build a hosts-only bundle from verified GitHub
Release binaries; no product release is required:

```bash
tenkaictl bundle build \
  --hosts-dir tenkai-hosts \
  --host-tag v0.7.1 \
  --host-git-sha 0123456789abcdef0123456789abcdef01234567 \
  --host-workflow release \
  --env site-c \
  --out hosts.bundle.json \
  --signing-key exporter.seed \
  --trust-roots offline-trust.toml
```

The service runs `<home>/current/tenkai-server`:

```text
<home>/versions/<digest>/tenkai-server, tenkai-executor-guard, tenkaictl
<home>/current  -> versions/<digest>
<home>/previous -> versions/<digest>
<home>/upgrade.json                 the last switch
<home>/backups/<ms>-<digest>.db     the store before that switch
```

Catalog delivery of this host, including the web console, is the
`tenkai-server` product ([deliver Tenkai with Tenkai](deliver-tenkai.md)).

```bash
# Changes nothing: verifies the hosts and runs the candidate's store check.
tenkaictl self-upgrade plan --home /opt/tenkai --bundle site.bundle.json \
  --trust-roots offline-trust.toml --env site-c --database /var/lib/tenkai/tenkai.db

# Backs up, switches, restarts, waits for readiness, rolls back if it fails.
tenkaictl self-upgrade apply --home /opt/tenkai --bundle site.bundle.json \
  --trust-roots offline-trust.toml --env site-c --database /var/lib/tenkai/tenkai.db \
  --ready-url http://127.0.0.1:8080/readyz -- systemctl restart tenkai-server
```

A hosts-only bundle needs `tenkaictl` 0.8.0 or newer. A 0.7.x `tenkaictl`
refuses it with `bundle must contain releases and entries`. On a 0.7.x
host, verify the new `tenkaictl` from the same Release
([verify and install by hand](#verify-and-install-by-hand)), then run
`plan` and `apply` with that binary:

```bash
./tenkaictl-linux-x86_64 self-upgrade plan --home /opt/tenkai --bundle site.bundle.json \
  --trust-roots offline-trust.toml --env site-c --database /var/lib/tenkai/tenkai.db
./tenkaictl-linux-x86_64 self-upgrade apply --home /opt/tenkai --bundle site.bundle.json \
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

`self-upgrade` does not install the host applier. After the server is
ready, upgrade the applier, its unit and its rule as root (linux-x86_64):

```bash
curl -fsSL https://github.com/Sannrox/tenkai/releases/download/vX.Y.Z/install.sh \
  | sudo sh -s -- --role host-applier
```

That rename-installs the three files at the same paths as
`--with-host-applier` and leaves the self-upgrade home unchanged. Repeat it
to finish an interrupted upgrade. Restart the server afterwards so
`/readyz` lists the new `host_applier:<version>`. To roll the applier back
with the server, run `--role host-applier` for the previous release after
`self-upgrade rollback`, then restart. An applier on an older minor than
the server is named on `/readyz` and refuses to plan host steps until it is
upgraded; fencing and recovery still use the host executor.

Converting an existing install whose unit runs a packaged `tenkai-server` to
the `<home>/current` layout is a first install: run `self-upgrade apply`
without a restart command, point the unit at `<home>/current/tenkai-server`,
restart, then `self-upgrade confirm`. That first switch has nothing to roll
back to through `self-upgrade`; reverting the unit is the rollback.

Any other way of replacing the binary (a package, the install script, a
manual copy) relies on the server's own pre-migration copy: its first start
at a newer schema leaves `<db>.pre-v<found>.<ms>.<id>.db` beside the store,
or refuses to start. To roll back, stop the server, move the store and its `-wal` and
`-shm` files aside, copy the newest pre-migration copy over the store, and
start the previous binary
([pre-migration copy](operational-storage.md#pre-migration-copy)).

The record, backup and links cover one host. With several server replicas,
upgrade one host at a time, with a schema both versions accept, as any
rolling deploy requires. PostgreSQL (tenant-mode) hubs are upgraded and
backed up by their operator; `--check-store` refuses them.
