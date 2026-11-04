# Privileged host releases

A release that declares `executor = "host"` installs software on the host
itself, as root, while `tenkai-server` stays an unprivileged `tenkai` user
([ADR 0041](decisions/0041-per-release-executor-and-privileged-host-releases.md)).
The root side is `tenkai-host-applier`, run by the systemd template unit
`tenkai-host-apply@.service`. The server may only start and stop instances of
that unit. Everything it hands over is untrusted: the applier verifies the
release, the plan, and the approvals itself, against root-owned files, and
runs each approved step at most once.

The server side that writes requests and starts the unit is
[#911](https://github.com/Sannrox/tenkai/issues/911). This page covers the
root side: what it checks, how to install it, and what it records.

## What one step does

For each host step the server writes a request into its spool directory and
runs `systemctl start --no-block tenkai-host-apply@<instance>.service`. The
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

Nothing the server supplies becomes an environment variable, an argument, or
a path the command interprets. Its working directory is the root-owned copy,
which is removed after the step.

The applier kills the command's process group when its own timeout fires
(`timeout_seconds`) and when the unit is stopped (`systemctl stop` sends it
SIGTERM). Nothing the command starts outlives the step: the applier is the
child subreaper, so a process that detaches or double-forks reparents to it,
and it kills and reaps everything left before it records the result and
releases the product's lock. A process stuck in the kernel holds the lock
until it dies. Install long-running services as their own systemd units.

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
is the unit it started; a missing or mismatched result is a failed step.

## Known limit: recall

Catalog recall is server state the root side cannot see. A recalled host
release can still run while a plan that approves it is unexpired. Approval
expiry bounds that window; set `max_approval_ttl_ms` in the host approval
policy to cap it on the root side.

## Install

Every file below is owned by root and not writable by group or others; the
applier refuses configuration or trust it reads from anything else.

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
(file ownership and modes, process signals, and binding low ports),
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
