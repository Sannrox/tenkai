# ADR 0041: Per-release software executor and privileged host releases

- Status: Accepted
- Date: 2026-11-04
- Issue: [#907](https://github.com/Sannrox/tenkai/issues/907)
- Owner: Tenkai maintainers
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

Values: `shell`, `host`, `helm`, `kubernetes`, `kubernetes-inprocess`,
`docker`. The field is part of the manifest, so it is covered by the manifest
digest and the release signature like every other field. Publication refuses an
unknown value.

When the field is absent, the process default applies exactly as today:
`TENKAI_SOFTWARE_EXECUTOR`, or the shell executor when that is unset. Existing
manifests and hosts keep their behavior. A process selects the executor per
release at plan, apply, rollback, recovery, and restart, in every place that
reads `selected_software_executor()` today. A release whose declared executor is
not available in the process fails closed and names the executor; it never
falls back to another one.

Packaging stays where each executor already reads it: `deploy.install` for
`shell` and `host`, `{workdir}/manifests/**` for the Kubernetes executors, the
chart root for Helm, `{workdir}/docker/host.json` for Docker. Releases that
declare a Kubernetes executor no longer need a placeholder `deploy.install`.

### 2. Privileged host releases run through a narrow systemd path

`executor = "host"` is the only value that runs with root. The server stays an
unprivileged `tenkai` user, with no sudo.

- A root-owned template unit, `tenkai-host-apply@.service`, runs a root-owned
  `tenkai-host-applier` binary with systemd sandboxing: `NoNewPrivileges`, a
  bounded capability set, `ProtectHome`, a private `/tmp`, and its own journal
  stream.
- A polkit rule lets the `tenkai` user start instances of that one template and
  nothing else. No other unit, no `systemctl` verb beyond start, no sudoers
  entry.
- For each host step the server writes a request (release id, manifest, release
  artifact paths, environment, product, fencing generation, idempotency key)
  into a spool directory it owns, and starts the instance named after the
  request id.
- The applier treats the request as untrusted. It re-verifies the release
  signature against root-owned trust roots in `/etc/tenkai`, checks that the
  signed manifest declares `executor = "host"`, and checks every artifact
  against the signed digests. Only then does it run the release's `install`,
  `uninstall`, or `health` command, under the same generation lock and
  idempotency key the shell executor uses. It writes a result record the server
  reads back; a missing or unreadable result is a failed step.

The property this buys: a compromised `tenkai` user can only cause releases that
a trusted root already signed for `host` execution to run, not arbitrary
commands. Rotating or removing a signer in the root-owned trust roots stops
future host releases without touching the server.

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
- The executor a release runs on is signed with the release; an operator
  variable can no longer silently change how a signed release executes.
- Hosts that use host releases install the template unit, the applier, the
  polkit rule, and root-owned trust roots. Hosts that do not are unchanged.
- Host releases cost a unit start per step and a second signature verification.
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
