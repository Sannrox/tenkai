# ADR 0048: The environment runtime runs the built-in executors

- Status: Accepted
- Date: 2026-11-09
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

`tenkai-runtime` links the built-in executors of ADR 0041 §1 (`shell`,
`host`, `helm`, `kubernetes`, `kubernetes-inprocess`, `docker`) and can run a
step in-process. Runtime configuration enables the ones this runtime may run.
The runtime's claim fencing, heartbeats, and completion ordering wrap the
executor as they wrap the guard today. Each built-in executor keeps its
existing idempotency, so a retry after a crash re-applies the same release.

A runtime with no built-in executor enabled behaves exactly as today: every
step runs through its operator program. Once any is enabled, a release that
declares `deploy.executor` runs with that executor if it is enabled, and fails
closed naming it if not. A release without a declared executor uses the
runtime's default, which is exactly one of:

- an operator executor program (`TENKAI_RUNTIME_EXECUTOR`), run through
  `tenkai-runtime-guard` as today, or
- a built-in executor named by runtime configuration, as
  `TENKAI_SOFTWARE_EXECUTOR` does for the server.

A runtime configured with both refuses to start and names both. Once any
built-in executor is enabled, a release that declares an executor, `shell`
included, never runs through the program.

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

Work pull carries no capabilities today. A runtime with built-in executors
enabled sends them on work pull in an additive header, the way it already
sends its version: the enabled executors and its default (`program` or one
of them). A server resolves each step's executor for that runtime, the
declared one or else the default, and reads the header as follows:

- No header: the runtime is unchanged, and every step is offered as today.
  Sealed steps are never offered, since the program cannot write them.
- With the header: a step is offered only if its resolved executor is
  enabled, or is `program` because the release declares none and the
  runtime's default is `program`. A sealed step also needs a resolved executor that writes sealed
  values (`helm` or `host`) and the `sealed_secrets` capability (ADR 0045).
- A step held back this way stays pending, with the reason named in plan
  status.

A server that predates this decision ignores the header and offers every
step. A runtime then fails closed on a release whose executor it has not
enabled, so the plan fails visibly instead of running elsewhere. Upgrade the
servers before enabling built-in executors on a runtime. A runtime with none
enabled keeps today's behavior against any server.

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
- **A new manifest field for the host file owner now.** Deferred: no release
  needs it yet, and it can be added without changing this decision.
