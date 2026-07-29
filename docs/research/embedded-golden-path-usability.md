# Embedded golden-path usability exercise

Issue: [#187](https://github.com/Sannrox/tenkai/issues/187)

Date: 2026-07-29

Revision exercised: `b8afed3532875ed5787cfb691dac39f139b8778c`

## Decision output

The embedded `local` profile has enough independent evidence to remain the
default actively supported community path.

Three non-implementer participants completed the fresh-checkout workflow
without maintainer intervention:

- initialize isolated embedded state;
- publish, promote, subscribe, plan, and apply a synthetic `1.0.0`;
- inspect healthy status;
- upgrade successfully to `2.0.0`;
- apply a deliberately unhealthy `3.0.0` and observe automatic restoration of
  `2.0.0`;
- confirm the channel remains at `3.0.0` and status is therefore `behind`; and
- back up the operational database, restore it into a separate empty database,
  and verify the recovered Catalog and operational posture.

This exercise supplies no usability evidence for server, remote runtime,
PostgreSQL, tenant isolation, multi-replica, offline, or provider-dependent
profiles. Those capabilities retain only their existing conformance and
operational-drill evidence.

## Method

Each participant:

- used a separate fresh `git clone --no-local` of the same public revision;
- acted as a non-implementer and did not inspect implementation source;
- used README, linked operator documentation, and CLI help;
- created a uniquely named synthetic shell product and isolated database,
  runtime, backup, and restore paths;
- used only the existing local-only unsigned-release and unapproved-plan
  development bypasses;
- measured intentional commands and recorded documentation detours, errors,
  concepts learned, and maintainer interventions; and
- returned only sanitized observations. Temporary databases, backups, runtime
  files, credentials, keys, and local paths are not retained here.

The synthetic product had three immutable releases:

| Release | Behavior |
| --- | --- |
| `1.0.0` | Healthy initial install |
| `2.0.0` | Healthy upgrade |
| `3.0.0` | Install writes the new marker, then health deliberately fails so Tenkai must restore `2.0.0` |

## Aggregate result

| Evidence | Session 1 | Session 2 | Session 3 |
| --- | --- | --- | --- |
| Fresh clone and cold build | Pass | Pass | Pass |
| Init → publish → promote → subscribe | Pass | Pass | Pass |
| Plan → apply → status/inspect | Pass | Pass | Pass |
| Healthy `1.0.0` → `2.0.0` upgrade | Pass | Pass | Pass |
| Unhealthy `3.0.0` automatic rollback | Restored `2.0.0` | Restored `2.0.0` | Restored `2.0.0` |
| Post-rollback posture | deployed `2.0.0`, head `3.0.0`, `behind` | same | same |
| Backup → separate-database restore | Pass | Pass | Pass |
| Maintainer intervention | None | None | None |
| Unexpected workflow error | None | None | None |

All restored databases reported one synthetic product, three releases, three
plans, the local environment and subscription, deployed `2.0.0`, channel head
`3.0.0`, and `behind` posture. Participants separately verified that the
synthetic runtime marker contained `2.0.0` after rollback.

Two participants measured the deliberately unhealthy apply returning exit code
1. One participant saw the same terminal error text and correct rollback state
but recorded shell success. Because the other clean sessions did not reproduce
that exit status, this exercise does not establish an exit-code defect. Any
future golden-path automation should assert the exit code directly so a real
regression cannot be hidden by a timing wrapper or command-capture mistake.

## Timing

Cold Rust compilation dominated every session:

| Activity | Session 1 | Session 2 | Session 3 |
| --- | ---: | ---: | ---: |
| Fresh clone | 0.94s | not separately retained | 1.29s |
| `cargo build --bin tenkaictl` | ~28s | 53.85s | 51.72s |
| Init | 2.07s | 0.01s | 1.00s |
| Initial publish through apply | ~0.13s | ~0.20s | ~0.10s |
| Healthy-upgrade publish through apply | ~0.08s | ~0.06s | ~0.08s |
| Unhealthy-upgrade publish through rollback | ~0.12s | ~0.18s | ~0.09s |
| Backup, restore, and verification | ~0.04s | ~0.04s | ~0.04s |

Once built, the control-plane operations were consistently sub-second.

## Sanitized session records

### Session 1

Documentation:

1. README Quickstart.
2. README manifest and immutable-input guidance.
3. README embedded-state operations.
4. `docs/backup-restore.md`.
5. CLI help for explicit database selection during recovery.

Intentional command sequence:

```text
git clone --no-local <public-repository> <fresh-checkout>
cargo build --bin tenkaictl
tenkaictl init
tenkaictl publish <v1-manifest> --allow-unsigned-development
tenkaictl promote <product>@1.0.0 stable
tenkaictl env subscribe local <product>=stable
tenkaictl plan --env local
tenkaictl apply <plan-id> --allow-unapproved-development --development-reason <reason>
tenkaictl status
tenkaictl inspect
tenkaictl env inspect local

tenkaictl publish <v2-manifest> --allow-unsigned-development
tenkaictl promote <product>@2.0.0 stable
tenkaictl plan --env local
tenkaictl apply <plan-id> --allow-unapproved-development --development-reason <reason>

tenkaictl publish <unhealthy-v3-manifest> --allow-unsigned-development
tenkaictl promote <product>@3.0.0 stable
tenkaictl plan --env local
tenkaictl apply <plan-id> --allow-unapproved-development --development-reason <reason>
tenkaictl status
tenkaictl env inspect local

tenkaictl backup <sensitive-backup>
tenkaictl --database <recovery-database> restore <sensitive-backup>
tenkaictl --database <recovery-database> inspect
tenkaictl --database <recovery-database> env list
tenkaictl --database <recovery-database> status
```

Concepts learned:

- releases are immutable and environments follow product channels;
- planning and execution are separate;
- unsigned publication and unapproved apply are separate, reasoned local-only
  trust bypasses;
- rollback restores deployment state but intentionally does not rewrite the
  channel head; and
- operational backup excludes workload runtime data.

Errors and intervention:

- Expected unhealthy health failure and successful restoration.
- The participant recorded terminal error text but an anomalous success exit
  measurement; not reproduced by sessions 2 or 3.
- No maintainer intervention.

### Session 2

Documentation:

1. README Quickstart and manifest section.
2. README embedded-state operations.
3. `docs/backup-restore.md`.
4. CLI help.

The intentional command sequence matched session 1, with an explicit isolated
database argument on every operation. The participant also checked the
synthetic runtime marker after both the healthy upgrade and rollback.

Concepts learned:

- subscriptions target channels rather than versions;
- `plan` persists an executable identity that `apply` consumes;
- status, global inspect, and environment inspect serve different diagnostic
  depths;
- rollback may correctly leave a recovered environment `behind`; and
- recovery verification covers operational state while runtime content must be
  independently rehydrated or checked.

Errors and intervention:

- Expected unhealthy health command exited 1.
- Tenkai reported failed-install cleanup, restoration of `2.0.0`, and unchanged
  channel head.
- No accidental errors and no maintainer intervention.

### Session 3

Documentation:

1. README Quickstart.
2. README environment and state guidance.
3. Search from README to `docs/backup-restore.md`.
4. No troubleshooting documentation.

The intentional command sequence matched session 1. The participant verified
the Git revision and checked that no shared repository content was modified.

Concepts learned:

- promotion moves desired state while apply changes deployed state;
- immutable releases require a new version for upgrades;
- separate local trust bypasses preserve the production boundary;
- automatic rollback and channel position are deliberately independent; and
- restore requires a sole writer followed by inspect/list/status verification.

Errors and intervention:

- Expected unhealthy apply exited 1 and clearly reported cleanup and restore.
- No unexpected errors and no maintainer intervention.

## Recurring burdens

### 1. Plan-to-apply handoff — automate

All three participants identified manual copying of the long opaque plan ID as
the most error-prone repeated step.

Candidate directions:

- stable machine-readable shell guidance;
- `apply --latest --env <environment>` with strict environment, state, and
  executable-digest checks; or
- an explicit `plan --apply` operation that preserves the immutable plan and
  approval boundary.

This must not silently select an obsolete, blocked, approved-for-different-
content, or different-environment plan.

### 2. Synthetic rollback fixture — standardize

Two participants identified authoring three safe manifests, choosing external
runtime paths, and designing a deterministic unhealthy release as the largest
setup burden. The repository has examples and a provider-dependent replay
script, but not one copyable provider-free embedded fixture covering
healthy → healthy → unhealthy → restore.

Standardize one synthetic fixture in operator documentation. Do not add another
product mode or weaken signing, approval, fencing, health, rollback, or recovery
semantics.

### 3. Post-rollback next steps — integrate

Two participants explicitly identified the correct `behind` state as a point
where safe next actions are scattered across documentation. Preserve the
unchanged channel-head invariant, but integrate concise guidance:

- inspect failure and rollback evidence;
- re-promote the known-good release when appropriate;
- publish and promote a corrected immutable version; or
- intentionally remain behind while investigating.

## Bounded recommendation

Automate the plan-to-apply handoff first.

It recurred in all three sessions, affects every ordinary deployment rather
than only research setup, and can be improved without changing the product
model. Shape a narrow follow-up that exposes a shell-safe plan identity or an
explicit latest-plan apply selector with fail-closed environment, lifecycle,
approval, and executable-content binding.

Treat the synthetic fixture and post-rollback guidance as documentation
standardization opportunities, not new operating modes.

## Supported-profile evidence

| Profile or capability | Evidence from this exercise | Support conclusion |
| --- | --- | --- |
| Embedded host + SQLite + built-in `local` environment + single writer | Three complete independent sessions | Sufficient to remain the default actively supported community profile |
| Shell software executor with local development bypasses | Three complete independent sessions | Sufficient for the documented local learning path only |
| Automatic health rollback and operational backup/restore | Three complete independent sessions | Sufficient for the embedded local profile |
| Server + scoped remote runtimes | Not exercised | No new usability claim |
| PostgreSQL, tenancy, federated authentication, multi-replica | Not exercised | No new usability or support claim |
| Offline bundles or optional/required providers | Not exercised | No new usability or support claim |

The result supports a deliberately narrow default profile. It does not justify
advertising arbitrary capability combinations.
