# ADR 0041: Per-release software executor and privileged host releases

- Status: Accepted
- Date: 2026-11-04
- Issue: [#907](https://github.com/Sannrox/tenkai/issues/907)
- Owner: Tenkai maintainers
- Amended by: [ADR 0049](0049-removing-built-in-executor-instances.md)
  (§1 a product changes executor by an approved removal, then an install)
- Related: [software executor](../software-executor.md),
  [manifest](../manifest.md),
  [release signing](../release-signing.md),
  [software compatibility](../software-compatibility.md),
  [run tenkai-server](../run-tenkai-server.md)

## Context

A Tenkai process applies every software release with one executor, chosen by
`TENKAI_SOFTWARE_EXECUTOR`. Unset selects the shell executor (`deploy.install`
behind `tenkai-executor-guard`); a value selects Helm, native or in-process
Kubernetes, or the Docker host executor for everything that process executes.

That forces one executor per control plane. A single host that should run both
host-level products and a cluster cannot be delivered by one Tenkai: installing
a single-node Kubernetes distribution needs the shell executor, and the releases
that run in that cluster need `kubernetes-inprocess`. Operators work around it
with a second Tenkai, or with a custom executor program behind `tenkai-runtime`
that must re-implement the runtime protocol's fencing and idempotency. Kubernetes
descriptors also carry a placeholder `deploy.install` whose only job is to make
the shell executor refuse them.

Host-level installs need root. `tenkai-executor-guard` fences a deployment
command; it is not a privilege boundary, and it runs as the server's user. The
server must not run as root. Giving its user general root access, the way
membership of a container runtime's group grants access to its root daemon,
would make compromising that user equal to owning the host.

The target is: install only Tenkai on a bare host, then let Tenkai install the
cluster and everything delivered into it, from one control plane.

## Decision

### 1. A release declares its executor

The manifest gains one optional field:

```toml
[deploy]
executor = "kubernetes-inprocess"
```

Accepted values are the existing selector names: `shell`, `host`, `helm`,
`kubernetes` (aliases `k8s` and `native`), `kubernetes-inprocess`, and `docker`.
`host` is new (section 2). A declared `shell` runs the existing shell executor
as the server's user, and pins that choice so a non-shell process default can
never run the release. The field is part of the manifest, so it is covered by
the manifest digest and the release signature. Publication refuses an unknown
value.

When the field is absent, the process default applies exactly as today:
`TENKAI_SOFTWARE_EXECUTOR`, or the shell executor when that is unset. Existing
manifests and hosts keep their behavior.

The executor is resolved **per release content**, not per apply attempt. Today
one executor flows through `ExecutionOptions.software_executor` into the
step's adapters, and `restore_previous` re-activates the previous release with
the failing step's adapters. Under this decision every operation resolves the
executor of the release it acts on: activating the target uses the target's,
and removing or restoring the previous release uses the previous release's.
That covers apply, rollback, recovery, restart, and observation, including
`cluster_observe_executor`, which reads the variable directly today. The one
exception is `host` releases: they get no automatic restore, restart, or
periodic observation (section 2), and a failed host step leaves the step failed
until an approved rollback plan runs.

A product keeps one executor across its releases in an environment. A plan
whose target release resolves to a different executor than the currently
installed release of the same product is refused and names both. Moving a
product to another executor is an explicit remove of the old product followed
by an install of the new one; no in-place transition is defined. ADR 0049
makes that removal plannable for every built-in executor, not only `host`. A release
whose executor is not available in the process fails closed and names it; it
never falls back to another executor.

Packaging stays where each executor already reads it: `deploy.install` for
`shell` and `host`, `{workdir}/manifests/**` for the Kubernetes executors, the
chart root for Helm, `{workdir}/docker/host.json` for Docker. Releases that
declare a Kubernetes executor no longer need a placeholder `deploy.install`.

### 2. Privileged host releases run through a narrow systemd path

`executor = "host"` is the only value that runs with root. The server stays an
unprivileged `tenkai` user, with no sudo. Everything the server hands to the
root side is treated as untrusted; the root side relies only on what it can
verify itself.

**Entry point.** A root-owned template unit, `tenkai-host-apply@.service`, runs
a root-owned `tenkai-host-applier` binary with systemd sandboxing:
`NoNewPrivileges`, a bounded capability set, `ProtectHome`, a private `/tmp`,
and its own journal stream. A polkit rule lets the `tenkai` user `start` and
`stop` instances of that one template and nothing else: no other unit, no
other verb, no sudoers entry.

**Request.** For each host step the server writes a request into a spool
directory it owns: the executable plan in Tenkai's versioned plan encoding, the
signed release, the plan approval envelopes, the step id, and the step's action
(`install`, `uninstall`, or `health`). The server names the instance after a
digest of the plan digest, the step, and the action; the applier recomputes that
key from the verified request and refuses an instance whose name does not match.

**Verification before anything runs.** The applier:

1. copies the request and every release artifact into a fresh root-owned
   directory under `/run/tenkai-host/<instance>`, opening each source with
   `O_NOFOLLOW` and refusing links and special files, and from then on reads
   only that copy;
2. verifies the release signature against root-owned trust roots in
   `/etc/tenkai`, including offline revocation
   ([ADR 0036](0036-offline-key-revocation.md)) and signer validity windows
   ([ADR 0039](0039-signer-validity-windows.md)), using root-owned copies of
   that state;
3. checks that the signed manifest declares `executor = "host"` and that every
   copied artifact matches its signed digest;
4. recomputes the plan digest from the copied plan, finds the step, and checks
   that it names exactly this release, environment, and action. It then
   evaluates the approval envelopes ([ADR 0037](0037-multi-party-plan-approval.md))
   for that plan digest against a root-owned host approval policy in
   `/etc/tenkai`: the trusted approvers, the quorum, and the purposes it allows.
   It checks expiry and that purposes such as rollback and downgrade carry the
   approvals the policy requires. The root side uses only inputs it can verify:
   the plan, the envelopes, and its own record. Gates and the flag that skips
   them, the requester's identity, and product criticality are server state,
   so the host policy is evaluated at its strictest quorum as if gates were
   skipped, every rule applies regardless of criticality, and a host policy
   that uses requester exclusion is refused when it loads. As in ADR 0037,
   approvals count only when they are distinct by key and by trust-root
   principal, both read from the root-owned trust roots, and groups restrict
   which signers are eligible. An `uninstall` needs an approved plan that
   removes the product, like any other change;
5. refuses an instance it has already started, and returns the recorded result
   instead of running again.

Then, holding the per-environment, per-product lock (below) as one critical
section, it re-reads the applied-state record, requires the step's expected
generation to equal the record's, requires the step's source release to equal
the record's state at that generation (the `applied` release, either side of a
`dirty` pair, or nothing for `empty`), evaluates downgrade approvals against
the record's high-water release, durably writes the `started` record together
with the advanced generation and `dirty` state, and only then runs the command.
Two plans that expect the same generation therefore cannot both run.

**Applied-state record.** For each environment and product the applier keeps a
generation number, a state (`empty`, `applied(release)`, or `dirty(from, to)`),
and the high-water release: the newest release it ever applied for that
product. `empty` keeps the high-water release. Each host step in a plan names the generation it expects;
that number is part of the plan, so it is covered by the plan digest and the
approvals. The server reads the record to build the plan; only the applier
writes it.

- Starting an `install` or `uninstall` advances the generation and sets
  `dirty(from, to)` before the command runs. Success sets `applied(to)`, or
  `empty` after an `uninstall`. Failure or a crash leaves `dirty` at the new
  generation.
- `health` requires the current generation and changes nothing.
- Any approved step for the current generation may move on from `dirty`. A step
  whose target is not newer than the high-water release needs the rollback or
  downgrade approvals the host policy requires, also when the product is
  `empty` after an uninstall.

Because every applied or interrupted step advances the generation, an approved
plan that never ran can never run after any other host step for that product,
including after a rollback (A, B, A). A product can be uninstalled and installed
again, which is also how a product moves to another executor.

All of this state lives in persistent root-owned storage, `/var/lib/tenkai-host`:
the applied-state record, and per instance a `started` record written before the
command runs and a result record written after. An instance with a `started`
record but no result, after a crash or a reboot, resolves as interrupted and
failed and is never run again. Its product's record stays `dirty`, and
continuing takes a new approved plan for the current generation.

Only then does it run the copied release's command. It builds the command's
environment itself from a fixed allowlist plus values from the signed manifest;
nothing the server supplies becomes an environment variable, argv, or a path the
command interprets. Server-supplied identifiers are used only for lookup and
must equal the signed values.

**Fencing.** The applier holds a root-owned lock per environment and product in
`/run/tenkai-host`, so one host step per product runs at a time whatever the
server does. It enforces its own timeout and kills the command's process group
when it fires. The server cancels on lease loss with the allowed `stop`, which
the unit maps to the same kill. The result record (instance, release digest,
action, outcome, exit status, timestamps) is written to `/var/lib/tenkai-host`,
root-owned and readable but not writable by the `tenkai` user; the server accepts it only when it matches the instance it
started. A missing or mismatched result is a failed step. An instance is never
re-run once started, so a restart, a reboot, or a replayed request cannot run
the command twice.

**No automatic restore, restart, or periodic observation.** A host step
authorizes one release and one action, once. The applier therefore never runs an
unapproved restore of the release a failed step replaced, and reconcile does not
emit restart plans or periodic observation for host releases. A failed host step
stays failed, and returning to the previous release is a rollback plan with its
own approvals. A host release's `health` runs only as an approved step. Its
lasting health shows through what depends on it: in-cluster releases fail closed
while the cluster is down.

**Approvals for host steps are never the server's own.** Today the server can
auto-approve with a key it owns. Such keys are excluded from the host approval
policy, so every host step needs approval from a human or an external approver
whose key the `tenkai` user cannot read. Host releases, such as installing or
upgrading the cluster, are rare and high-impact, so they stay attended.

**What this buys.** A compromised `tenkai` user can only cause the root side to
run a release that a trusted signer signed for `host` execution, is not revoked
or outside its validity window, and appears in a plan whose quorum of approvals
satisfies the root-owned host policy for that exact action, and each such step
at most once, and only at the generation its record names. It cannot run
arbitrary commands, alter what runs, approve its own host steps, run an old plan
out of order, or uninstall a product without an approved plan.

**Known limit: recall.** Catalog recall is server state the root side cannot
see. A recalled host release can still run while a plan that approves it is
unexpired. Approval expiry bounds that window, and a signed recall statement the
applier can check is future work.

### 3. A cluster release hands Tenkai its own cluster identity

A host release that installs a cluster also creates a dedicated identity for
Tenkai in that cluster, and writes its kubeconfig to a path the `tenkai` user
can read. The operator sets that path once, when creating the environment, with
the existing command:

```bash
tenkaictl env cluster-config set <environment> /var/lib/tenkai/cluster/<environment>.kubeconfig
```

In-cluster releases run as that identity, never as host root. Kubeconfig
handling does not change: a path only, never bytes in the store, and no implicit
discovery.

### 4. Ordering needs no new concept

Before the cluster release has run, the kubeconfig at that path does not exist,
and the in-process executor already refuses an unreadable kubeconfig. In-cluster
releases therefore fail closed until the cluster exists, and reconcile's bounded
per-environment backoff converges them afterwards. No product dependency graph
is added.

Software compatibility is not used for this ordering. Its evidence is recorded
by the environment owner and must be fresh, and Tenkai deliberately does not
infer compatibility from a running process.

## Out of scope

- A dependency graph between products, or ordering beyond fail-closed retry.
- Arbitrary root commands, or any root path not bound to a signed `host`
  release.
- Inferring the executor from release content.
- Changes to kubeconfig storage or discovery.
- Provisioning the host itself (operating system, network, DNS).

## Consequences

- One Tenkai can deliver host-level and in-cluster releases on the same host,
  and a bare host needs only Tenkai installed by hand.
- For releases that declare `deploy.executor`, the executor is signed with the
  release, and an operator variable can no longer change how it executes.
  Releases without the field still follow the process default.
- A product cannot change executor in place; that takes a remove and an install.
- Hosts that use host releases install the template unit, the applier, the
  polkit rule, and root-owned trust roots. Hosts that do not are unchanged.
- Host releases cost a unit start, an artifact copy, and a second signature and
  approval verification per step.
- Host steps are always attended: they need human or external approvals under
  a root-owned policy, never the server's own auto-approval. They have no
  automatic restore; rollback is an approved plan.
- `TENKAI_SOFTWARE_EXECUTOR` remains, as the default for releases that declare
  nothing.

## Alternatives considered

- **Keep one executor per process.** Forces a second control plane or a custom
  runtime executor for every host that also runs a cluster.
- **Executor per environment.** Still one executor for everything in an
  environment, so a host that runs a cluster needs two environments for one
  machine, and the executor stays outside the signed release.
- **Infer the executor from release content.** Ambiguous: existing Kubernetes
  descriptors carry both a placeholder `deploy.install` and `manifests/`.
- **A root daemon on a group-owned socket.** One more long-running privileged
  process to secure and upgrade, and the usual trap that group membership equals
  root unless every request is re-verified, which the systemd path does anyway.
- **A sudoers allowlist for the applier.** Weaker confinement and auditing than a
  sandboxed unit, and easy to widen by accident.
- **Run the server as root.** Rejected outright.
- **Order through software compatibility.** Would need Tenkai to record its own
  evidence from running processes, which that contract excludes.
