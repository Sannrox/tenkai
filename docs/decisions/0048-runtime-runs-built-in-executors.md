# ADR 0048: The environment runtime runs the built-in executors

- Status: Accepted
- Date: 2026-11-09
- Amended: 2026-11-09 by [#1121](https://github.com/Sannrox/tenkai/issues/1121)
  (§1 mode switch, §3 release package, §5 no work-pull header; host releases
  on the runtime follow in [#1122](https://github.com/Sannrox/tenkai/issues/1122))
- Amended: 2026-11-09 by [#1050](https://github.com/Sannrox/tenkai/issues/1050)
  (§4 Secret name digest and cleanup timing; host sealed files follow in
  [#1125](https://github.com/Sannrox/tenkai/issues/1125))
- Amended: 2026-11-09 by [#1122](https://github.com/Sannrox/tenkai/issues/1122)
  (§1 host releases run, §2 the runtime reports the applier's records)
- Issue: [#1119](https://github.com/Sannrox/tenkai/issues/1119)
- Owner: Tenkai maintainers
- Amends: [ADR 0045](0045-sealed-secrets.md) §4 (who writes the target, host
  file owner, where a host value may sit before the write)
- Related: [ADR 0041](0041-per-release-executor-and-privileged-host-releases.md),
  [#1020](https://github.com/Sannrox/tenkai/issues/1020),
  [#1050](https://github.com/Sannrox/tenkai/issues/1050),
  [runtime protocol v1](../runtime-protocol-v1.md)

## Context

ADR 0045 §4 has the environment runtime open a sealed value and write it to
the target: an immutable Kubernetes Secret whose name the release receives as
`tenkai.secrets.<secret>.name`, or a 0600 file on the host.

The remote runtime cannot do that today, because it never applies anything
itself. It hands each step to an operator-supplied program
(`TENKAI_RUNTIME_EXECUTOR`) through `tenkai-runtime-guard`. That program
receives only non-secret arguments, and it has no way to receive a Secret
name or a value. The executors that can create Kubernetes objects and set
Helm values (`helm`, `kubernetes`, `kubernetes-inprocess`, `host`) live in
`tenkai-executor` and run only in `tenkai-server`.

So the component that holds the sealing key cannot write the target, and the
components that can write the target cannot hold the key. ADR 0041 already
names the related cost: operators write custom executor programs that must
re-implement the runtime protocol's fencing and idempotency.

The usual answer in delivery systems that seal values to an in-environment
agent is that the same agent both decrypts and deploys. It creates the Secret
itself and injects its name into the chart's values. This decision makes the
Tenkai runtime that agent.

## Decision

### 1. The runtime runs the built-in executors

`tenkai-runtime` links the built-in executors of ADR 0041 §1 and can run a
step in-process. `TENKAI_RUNTIME_EXECUTOR` selects one of two modes:

- **Program mode:** an absolute path. Every step runs through that operator
  program and `tenkai-runtime-guard`, as before this decision.
- **Built-in mode:** the value `builtin`. The runtime resolves each release's
  executor exactly as the server does: the declared `deploy.executor`, else
  `TENKAI_SOFTWARE_EXECUTOR`, else `shell`. A declared executor this runtime
  cannot run fails the step and names it.

The variable stays required, so a runtime never picks a mode by default, and
a step never falls back from one mode to the other. The runtime's claim
fencing, heartbeats, and completion ordering wrap the executor as they wrap
the guard. Each built-in executor keeps its existing idempotency, so a retry
after a crash re-applies the same release.

A `host` release runs through the runtime's own host applier, configured
as on a server (`TENKAI_HOST_SPOOL_DIR`); without one, the step fails and
names it.

### 2. Target access is the runtime host's own configuration

The runtime never uses a path or credential the server names. Its cluster
configuration file, its host-applier setup, and its Docker settings are local
runtime configuration, set on the runtime host. The environment record's
`cluster_config_path` keeps its meaning for steps the server executes and is
ignored by the runtime. A release whose executor the runtime is not
configured for fails closed and names the executor.

A runtime that runs `host` releases is installed like a server host under
ADR 0041 §2: the runtime's user may start only the applier template, and the
applier verifies every request itself.

The server plans a host step from the applier's applied-state record
(ADR 0041 §2), which lives on the runtime's host. The runtime reports every
record its applier keeps for the environment, each poll and after each
plan, and the server stores each as an immutable, read-only fact of the
environment. Planning uses the most advanced record of each product, so a
delayed report never moves a product back and reports need no lock. Once an environment reported,
its host steps are planned only from reported records; without a report, a
server plans them only from an applier of its own. A stale record cannot
cause a second run: the applier still requires the step's expected
generation and source release. The runtime builds the applier's request
from the claimed plan, the verified release, and the plan's approval
envelopes, which work delivery carries for every plan with a host step, and
runs the step under its claim as the server runs it under its lease. A
failed host step is never restored automatically.

### 3. The runtime verifies the release before it applies

Before it runs a built-in executor, the runtime verifies the signed release
against release-signing trust roots installed on the runtime host, including
offline revocation (ADR 0036) and signer windows (ADR 0039, ADR 0042). These
are the release signers, a separate set from the approvers its local approval
policy trusts (ADR 0045 §4); the runtime needs both, as the host applier does
(ADR 0041 §2). It pulls
artifacts only from the environment mirror and checks each one against its
signed digest. A server cannot make the runtime apply content no trusted
signer released.

The server hands the runtime a release package for each claimed step: the
signed manifest, its signature, the deploy inputs, and the executor request it
computed. The runtime checks the manifest against the plan step's digests and
names, rebuilds the deploy inputs under a work directory addressed by the
signed artifact digest, and checks them against that digest before any
executor runs.

### 4. Sealed values are written by the executor that applies the release

This replaces the writer in ADR 0045 §4. After the runtime's checks of ADR
0045 §4 succeed, it opens the value in memory and passes it to the executor
of the step's release, in-process.

- **Helm:** the executor creates the immutable Secret
  `<instance>-<secret>-<digest8>` in the instance's namespace, as ADR 0045 §4
  places it, then passes the name to the chart as
  `tenkai.secrets.<secret>.name`, next to the `tenkai.config.*` values. The
  Helm executor shells out to `helm` today and has no cluster client, so it
  gains one. The Secret write and every `helm` call it makes use the same
  explicit cluster configuration file and context from the runtime's
  configuration (§2): `helm` receives them as flags and never falls back to
  an ambient configuration, and both use the namespace `helm` installs into.
  Cleanup of older Tenkai-owned Secrets is unchanged from ADR 0045 §4.

  One Secret holds every key of one secret name, so `<digest8>` is the first
  8 hex characters of a digest over that secret's keys and their sealed
  digests. Cleanup runs once `helm upgrade --wait` succeeds, before the
  runtime's health check; it still keeps the previous Secret, so a failed
  health check that restores the previous release finds it. The runtime
  opens values with its file sealing key; a hardware-backed sealing key
  refuses sealed steps until the token can derive the shared secret.
- **Kubernetes descriptors (`kubernetes`, `kubernetes-inprocess`):** these
  have no values to carry a name. A sealed step for such a release is refused
  with a named reason until a descriptor substitution exists.
- **Host:** the applier runs as a separately started unit, so the value
  cannot stay in one process's memory. The runtime places it in the applier's
  request, in a 0600 file on a memory-backed run directory, and refuses the
  step if that directory is on persistent storage. It removes the file once
  the result is recorded, and at startup and before every retry it removes
  any request file it left behind.

  The applier verifies the request as in ADR 0041 §2. It also checks that the
  approved step names this instance, secret and key, and that the request's
  ciphertext digest equals the step's. It cannot open the value itself, so
  the runtime that can open it is trusted for its content, as it is for every
  other environment. A forged value can therefore land only in a slot an
  approved step names.

  The target path is never taken from the request. The applier derives it
  from a fixed root-owned base directory and the environment, instance,
  secret and key, each validated as a Tenkai identifier (no separators, no
  `..`), and the release's command receives that directory through the
  applier's own allowlisted environment. The applier writes the file through
  a temporary path and rename, then removes its own copy of the request.

  The target file is mode 0600 and owned by root. A service that runs as
  another user receives it through its service manager's credential hand-off,
  which reads it as root. This replaces "owned by the release's user", since
  no release declares a user; a run-as owner is a later, additive manifest
  field.

  For host releases this relaxes ADR 0045 §4's "only in the runtime's memory
  and in the target": the value may also sit in memory-backed request files.
  Like the runtime's own memory, those pages reach disk only through swap, so
  a runtime host that writes sealed host values needs swap off or encrypted,
  and the install guide says so.
- **`shell`, `docker`, and operator executor programs:** a sealed step is
  refused with a named reason. The plain value is never passed to a command
  or a program.

### 5. Rolling compatibility

Work pull is unchanged and carries no executor capabilities. A server offers
a built-in runtime every step, as it offers a program-mode runtime. A step
whose executor the runtime cannot run fails visibly on the runtime instead of
waiting for, or moving to, another runner: an environment has one runtime,
so there is nowhere else for the step to go.

A runtime in built-in mode fetches each step's release package from an
endpoint that older servers lack. Against such a server the step fails and
names the upgrade. Upgrade the servers before switching a runtime to
built-in mode. A program-mode runtime keeps its behavior against any server.

## Consequences

- One component holds the key and writes the target, so ADR 0045 can be
  delivered without passing a value or Secret name through a separate
  program.
- Operators no longer need a custom executor program for Helm, Kubernetes, or
  host releases on a remote runtime, and that program's fencing gaps go away
  for those releases.
- The runtime's trust boundary grows: it verifies releases as well as plans,
  so it needs release-signing trust roots installed next to its approval
  policy, and it holds cluster or host-applier access. Both were already true of the
  server, and both stay local to the environment.
- `tenkai-runtime` takes on `tenkai-executor` and its Kubernetes and Helm
  dependencies. Its build and binary size grow accordingly.
- Raw Kubernetes descriptors cannot read sealed values yet.
- A runtime in built-in mode does not report the observed runtime of what it
  applied; the server's read views show only what it applied itself.
- A hardware-backed runtime still needs its sealing key in hardware (ADR 0045
  §1), which needs a key-agreement operation in the hardware key path. Until
  that exists, such a runtime refuses sealed steps with a named reason.

## Alternatives considered

- **The runtime writes a secrets directory for the operator program.** The
  runtime unwraps into a private per-step directory and passes its path.
  Rejected: every operator program would re-implement Secret creation,
  immutability, cleanup, and name injection, which is the guarantee ADR 0045
  makes.
- **The runtime gains only a Kubernetes client for Secrets.** Rejected: the
  Secret name still could not reach the chart, because the operator program
  applies it.
- **Pass the value to the operator program.** Rejected: it breaks the
  program contract that arguments carry nothing secret, and the value would
  leave Tenkai's control.
- **Mutable, fixed-name Secrets.** Rejected for the reasons in ADR 0045:
  running pods would see a new value before their rollout, and rollback could
  not restore the old one.
- **Executor capabilities on work pull, so the server routes steps.**
  Rejected for now: with one runtime per environment there is no other
  runner to route to, and a visible failure on the runtime names the missing
  executor as clearly as a pending step would.
- **A new manifest field for the host file owner now.** Deferred: no release
  needs it yet, and it can be added without changing this decision.
