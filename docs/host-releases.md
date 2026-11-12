# Privileged host releases

A release that declares `executor = "host"` installs software on the host
itself, as root, while `tenkai-server` stays an unprivileged `tenkai` user
([ADR 0041](decisions/0041-per-release-executor-and-privileged-host-releases.md)).
The root side is `tenkai-host-applier`, run by the systemd template unit
`tenkai-host-apply@.service`. The server may only start and stop instances of
that unit. Everything it hands over is untrusted: the applier verifies the
release, the plan, and the approvals itself, against root-owned files, and
runs each approved step at most once.

This page covers the root side: what it checks, how to install it, and what
it records. [Run host releases](run-tenkai-server.md#run-host-releases)
covers the server side: planning, approvals, and configuration.

For the whole flow on a bare host, from installing Tenkai to a cluster it
installs and releases delivered into it, see
[bare host to cluster](bare-host.md).

## What one step does

For each host step the server writes a request into its spool directory and
runs `systemctl start tenkai-host-apply@<instance>.service`, which returns
once the applier exited; meanwhile the server keeps its environment lease
fresh, and stops the unit when it loses the lease or is itself stopped. The
applier then:

1. returns how this instance ended if it ever started, from its own records
   alone, and stops;
2. copies `request.json` into a fresh root-owned directory under
   `/run/tenkai-host/work/<instance>`, opening every path component relative
   to its parent with `O_NOFOLLOW` and refusing symbolic links, hard links,
   special files, and set-id bits;
3. verifies the copy: the instance name, the plan format, the step and its
   host action, a software manifest declaring `executor = "host"`, the
   release signature against `/etc/tenkai/release-trust-roots.toml` with
   offline revocation and the signer window at the signed time, the manifest
   digest against the signature and the step, and the approvals against the
   host approval policy;
4. only then copies the manifest's deploy inputs the same way and checks
   their digest against the signature and the step;
5. takes the product's lock and, in one critical section, settles the step
   that last changed the product's record, checks the expected generation,
   the source release, and downgrade approvals, and durably writes the
   advanced record and the instance's `started` record;
6. runs the signed command for the action (`deploy.install`,
   `deploy.uninstall`, or `deploy.health`) with `/bin/sh -c` in the copied
   workdir, with its own process group and a fixed environment;
7. stops anything the command left running, records the result, updates
   the product's record, and removes the copy.

A refusal before step 5 changes nothing and does not count as a start: the
server may start the same instance again once the reason is fixed, for
example after more approvals arrive. The reason is written to
`/var/lib/tenkai-host/instances/<instance>/refused.json`.

## The command

The command sees only this environment:

| Variable | Value |
| --- | --- |
| `PATH` | `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` |
| `LANG` | `C.UTF-8` |
| `HOME` | `/root` (hidden by the unit's `ProtectHome`) |
| `TENKAI_ENVIRONMENT` | the approved plan's environment |
| `TENKAI_PRODUCT`, `TENKAI_VERSION` | from the signed manifest |
| `TENKAI_RELEASE_DIGEST` | sha256 of the signed manifest |
| `TENKAI_HOST_ACTION` | `install`, `uninstall`, or `health` |
| `TENKAI_PLAN_ID` | the approved plan's id |
| `TENKAI_SECRETS_DIR` | only for a step that writes sealed values: `/var/lib/tenkai-host/secrets/<environment>/<instance>`, holding `<secret>/<key>` |
| `TENKAI_IDENTITY_DIR` | only for a release with a [workload certificate](manifest.md#workload-identity), on install and health: `/var/lib/tenkai-host/identity/<environment>/<instance>/current`, holding `cert.pem`, `key.pem`, `ca.pem` and `grant.json` |

Nothing the server supplies becomes an environment variable, an argument, or
a path the command interprets.

A step whose approved plan writes sealed values gets them from the
environment runtime, the only component that can open them (ADR 0048 §4).
The runtime spools each opened value with its ciphertext next to the request;
the spool must be memory-backed (tmpfs), or both the runtime and the applier
refuse the step. The applier binds every value to the approved step's slot
and ciphertext digest, then writes it, root-owned and mode 0600, to
`<secret>/<key>` under `TENKAI_SECRETS_DIR` before the command runs. A
service running as another user reads it through its service manager's
credential hand-off. A runtime host that writes sealed values needs swap
off or encrypted: the values sit in memory, and memory reaches disk only
through swap. Its working directory is the root-owned copy,
which is removed after the step.

A workload certificate travels the same way: the runtime issues it and
spools it with the sealed values. The applier accepts it only if the
approved step's issuer signed it for exactly the approved names and role,
it is valid now, and the key is its own; then it
writes the whole set into a new directory and switches the `current` link
to it with one rename. An interrupted write leaves the previous set. Each
open follows the link again, so a reader that opens `cert.pem` and then
`key.pem` across a switch can get a mixed pair. Read a consistent set by
resolving the link once per load (`realpath "$TENKAI_IDENTITY_DIR"`) and
opening every file from that directory. The previous set is kept until
the next write, so a directory resolved just before a switch stays
readable. A health step
issues nothing; its command gets `TENKAI_IDENTITY_DIR` for the set its
install wrote.

The applier also records the certificate it installed, without the key, in
`/var/lib/tenkai-host/identities/<key>.json`; an install of a release
without a certificate, or an uninstall, removes the record. The runtime
reads it to renew a `reload = "runtime"` certificate past two thirds of its
lifetime ([ADR 0046](decisions/0046-workload-identity-and-peer-policy.md)
§3). It spools `renewal.json` and the new certificate and key, with no
request or approvals, and starts the same unit. Under the product lock the
applier installs it only while the product is installed, the record still
holds the certificate the renewal replaces, and the new certificate proves
exactly the recorded grant, is valid now and matches its key. Otherwise it
records the refusal in `refused.json`, and the runtime retries on a later
pass. A renewal never writes a result or advances the generation.

During an issuer rotation
([ADR 0046](decisions/0046-workload-identity-and-peer-policy.md) §7) the
runtime spools, beside a certificate, the approved rotation plans it
verified. `ca.pem` may then hold the next or the previous issuer after the
granted one. The applier admits each such issuer only when a spooled plan
proves it under the applier's own approval policy, and only one generation
from the granted issuer. Once an approved issue plan replaced the recorded
issuer, a renewal may move the recorded grant to the issuer that replaced
it, with everything else unchanged. A plan the applier's policy does not
approve proves nothing, so the certificate is refused and names the issuer.

The applier kills the command's process group when its own timeout fires
(`timeout_seconds`) and when the unit is stopped (`systemctl stop` sends it
SIGTERM). Nothing the command starts outlives the step: the applier is the
child subreaper, so a process that detaches or double-forks reparents to it,
and it kills and reaps everything left before it records the result and
releases the product's lock. A process stuck in the kernel holds the lock
until it dies. If the applier itself dies mid-command, the step resolves as
`interrupted` only once the unit's control group, recorded when the step
started, holds nothing else; until then the product admits no step. Install
long-running services as their own systemd units.

## Approvals

Host steps are always attended. The server's own automatic approvals never
count, and the host approval policy refuses automatic and preflight signers.
The policy is evaluated only from what the root side can verify:

- `execute_plan` and `skip_gates` rules always apply, as if gates were
  skipped; `rollback` and `downgrade` rules apply when the plan has such a
  step;
- every rule applies whatever its `min_criticality`;
- a rule with `exclude_requester = true` is refused when the policy loads;
- approvals count once per key and once per identity, and a rule's `groups`
  restrict which signers count
  ([ADR 0037](decisions/0037-multi-party-plan-approval.md));
- an `install` whose target is not newer than the newest release ever applied
  for the product (also after an uninstall) needs the `downgrade` rule, or
  the `rollback` rule for a rollback step. Versions that are not semantic
  versions are never newer.

Without a rule for a purpose, one approval from a listed signer is enough.

## Applied state

For each environment and product the applier keeps a record in
`/var/lib/tenkai-host/records/<key>.json`: a generation, a state (`empty`,
`applied`, or `dirty` with the releases on either side), and the high-water
release. Each host step names the generation it expects; the number is part
of the approved plan.

- `install` and `uninstall` advance the generation before the command runs.
  Success sets `applied` or `empty`; anything else leaves `dirty`.
- `health` requires the current generation and an applied release, and
  changes nothing.
- A step's `from` must be the applied release, either side of a `dirty`
  pair, or nothing for `empty`.

Because every started install or uninstall advances the generation, an
approved plan that never ran can never run after another host step for that
product, including after a rollback (A, B, A). Two plans that expect the
same generation cannot both run.

Per instance, `/var/lib/tenkai-host/instances/<instance>/` holds
`started.json`, written before the command runs, and `result.json`, written
once after. An instance that started and has no result after a crash or a
reboot resolves as `interrupted` and is never run again; its product stays
`dirty`, and continuing takes a new approved plan for the current generation.
A failed host step is never restored automatically: returning to the
previous release is a rollback plan with its own approvals.

The server reads these records. It accepts a result only when its `instance`
is the unit it started and it names the step's environment, product, action,
and release; a missing or mismatched result is a failed step. Before it
starts a unit, the server returns an instance's existing result, so a retry
of the same step never starts it again.

## Known limit: recall

Catalog recall is server state the root side cannot see. A recalled host
release can still run while a plan that approves it is unexpired. Approval
expiry bounds that window; set `max_approval_ttl_ms` in the host approval
policy to cap it on the root side.

## Install

Every file below is owned by root and not writable by group or others; the
applier refuses configuration or trust it reads from anything else.

On `linux-x86_64`, the [install script](release-binaries.md#install-with-one-command)
does steps 1 and 5 from a GitHub Release, every file checked against its
`SHA256SUMS` first. A first install:

```bash
curl -fsSL https://github.com/Sannrox/tenkai/releases/download/vX.Y.Z/install.sh \
  | sudo sh -s -- --role server --with-host-applier
```

A server already in a [self-upgrade home](release-binaries.md#upgrade-a-server-host)
upgrades the applier after the server switch, without touching that home:

```bash
curl -fsSL https://github.com/Sannrox/tenkai/releases/download/vX.Y.Z/install.sh \
  | sudo sh -s -- --role host-applier
```

It installs the binary at `/usr/local/libexec/tenkai/tenkai-host-applier`
(mode 0755), the unit at `/etc/systemd/system/tenkai-host-apply@.service`,
and the rule at `/etc/polkit-1/rules.d/50-tenkai-host-apply.rules` (0644),
all owned by root, staged and checked in a root-only directory. It runs only
as root and refuses when one of those directories, or any directory above
them, is a symbolic link or writable by anyone but root. It
neither reloads systemd nor starts anything; continue with steps 2 to 4 and 6,
then `systemctl daemon-reload`.

By hand, or from a source build:

1. Install the binary where only root can write:

   ```bash
   install -o root -g root -m 0755 -D tenkai-host-applier \
     /usr/local/libexec/tenkai/tenkai-host-applier
   ```

2. Create the server's user and its spool directory:

   ```bash
   useradd --system --home-dir /var/lib/tenkai --create-home tenkai
   install -o tenkai -g tenkai -m 0750 -d /var/lib/tenkai/host-spool
   ```

3. Write `/etc/tenkai/host-applier.toml`:

   ```toml
   version = 1
   spool_dir = "/var/lib/tenkai/host-spool"
   timeout_seconds = 1800              # default 30 minutes
   max_artifact_bytes = 4294967296     # default 4 GiB per release
   max_artifact_entries = 100000       # default
   ```

4. Write the trust the applier verifies with, in `/etc/tenkai`:

   - `release-trust-roots.toml`: the release signers trusted for host
     releases, in the [release trust-root format](release-signing.md);
   - `host-approval-policy.toml`: the approvers and quorum for host steps;
   - optionally `key-revocations.json` with `key-revocation-trust-roots.toml`
     ([offline key revocation](decisions/0036-offline-key-revocation.md)). A
     list without its authorities fails closed.

   ```toml
   # /etc/tenkai/host-approval-policy.toml
   version = 1
   max_approval_ttl_ms = 86400000

   [[signers]]
   key_id = "sha256:..."
   identity = "alice@example.com"
   public_key = "<base64 Ed25519 public key>"
   groups = ["ops"]

   [[signers]]
   key_id = "sha256:..."
   identity = "bob@example.com"
   public_key = "<base64 Ed25519 public key>"
   groups = ["ops"]

   [[quorum]]
   purpose = "execute_plan"
   n = 2
   groups = ["ops"]
   ```

   Keep these keys away from the `tenkai` user: an approver whose private key
   the server can read is the server approving itself.

5. Install the unit and the polkit rule from
   [examples/host-applier-systemd](../examples/host-applier-systemd/), then reload systemd:

   ```bash
   install -m 0644 examples/host-applier-systemd/tenkai-host-apply@.service /etc/systemd/system/
   install -m 0644 examples/host-applier-systemd/tenkai-host-apply.rules \
     /etc/polkit-1/rules.d/50-tenkai-host-apply.rules
   systemctl daemon-reload
   ```

   The rule lets `tenkai` start and stop `tenkai-host-apply@<64 hex>.service`
   and refuses it every other systemd action. Do not add a sudoers entry.

6. Check the denial: `sudo -u tenkai systemctl restart
   tenkai-host-apply@<instance>.service` and starting any other unit as
   `tenkai` must fail.

The unit runs the applier with `NoNewPrivileges`, a bounded capability set
(file ownership and modes, switching to another user, process signals, and
binding low ports),
`ProtectHome`, a private `/tmp`, and its own journal identifier
(`journalctl -t tenkai-host-apply`). A release that loads kernel modules or
changes network or mount configuration needs a drop-in that widens
`CapabilityBoundingSet` for this unit.

## Exit status

`tenkai-host-applier run <instance>` prints the result record and exits `0`
when the step succeeded, `1` when it failed (also for a recorded failure of
an earlier start), and `2` when it refused before anything started.

## Request format

The server spools each step under `<spool_dir>/<instance>/`:

- `request.json`: a `tenkai.host-apply-request.v1` document with the
  executable `plan`, `step_id`, `action`, the signed `manifest` text, its
  release `signature`, and the plan `approvals`;
- `artifacts/`: the release workdir, with the manifest's deploy inputs at
  their declared relative paths.

The step in the plan carries `host = { action, expected_generation }`; for
`uninstall` and `health` its `from` equals its `to`. The instance name is
`tenkai::host_apply::instance_key(plan_digest, step_id, action)`: 64 lowercase
hex characters.
