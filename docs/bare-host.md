# Run a cluster on a bare host with one Tenkai

Install only Tenkai on a Linux host. Tenkai then installs a single-node
Kubernetes distribution as a privileged host release and delivers releases
into that cluster, from one control plane. `tenkai-server` runs as the
unprivileged `tenkai` user the whole time; only the root-side host applier
runs the cluster release, and only for plans a human approved
([ADR 0041](decisions/0041-per-release-executor-and-privileged-host-releases.md)).

The reference releases:

- [examples/bare-host-cluster](../examples/bare-host-cluster/): the cluster
  host release (`executor = "host"`). It downloads a pinned version of the
  distribution, refuses it unless its SHA-256 matches the pin, runs it as its
  own systemd unit, creates Tenkai's identity in the cluster, and writes that
  identity's kubeconfig to `/var/lib/tenkai/cluster/<environment>.kubeconfig`,
  readable by the `tenkai` user only. It also has `uninstall` and `health`
  commands.
- [examples/bare-host-app](../examples/bare-host-app/): an in-cluster
  release (`executor = "kubernetes-inprocess"`) with a Deployment and a
  Service under `manifests/`.

[`scripts/bare-host-drill.sh`](../scripts/bare-host-drill.sh) runs this whole
page on a throwaway host, and the `Bare-host drill` CI job runs it on every
change to this path.

## What you need

- A systemd Linux x86-64 host with glibc 2.28 or newer, polkit, and Python 3
  for the steps below. The host itself (operating system, network, DNS) is
  yours to provision.
- Network access to GitHub Releases, for Tenkai and for the distribution
  binary the cluster release downloads.
- Release signing and approver keys kept away from the `tenkai` user. An
  approver whose private key the server can read is the server approving
  itself, and the host applier is built to refuse that.

## 1. Install Tenkai

```bash
curl -fsSL -o install.sh https://github.com/Sannrox/tenkai/releases/download/vX.Y.Z/install.sh
# Check install.sh against the release's SHA256SUMS before running it.
sudo sh install.sh --role server --with-host-applier
```

This installs `tenkai-server`, `tenkaictl`, and `tenkai-executor-guard`, plus
the host applier, its systemd template unit, and its polkit rule, every file
checked against the release's `SHA256SUMS`. It also writes
`/etc/tenkai/client.toml` (`target = "remote"`, loopback URL) and a root-only
`/etc/tenkai/management.token`. It starts nothing.

## 2. Set up the host applier

Follow [privileged host releases](host-releases.md#install), steps 2 to 4 and
6: the `tenkai` user, its spool directory `/var/lib/tenkai/host-spool`,
`/etc/tenkai/host-applier.toml`, the release trust roots, and the host
approval policy that names the people who approve host steps. Then
`sudo systemctl daemon-reload`.

## 3. Create the environment and run the server

Create the environment and name its kubeconfig now, before the cluster
exists. The path is the one the cluster release writes:

```bash
sudo -u tenkai tenkaictl --database /var/lib/tenkai/tenkai.db init
sudo -u tenkai tenkaictl --database /var/lib/tenkai/tenkai.db env add edge
sudo -u tenkai tenkaictl --database /var/lib/tenkai/tenkai.db \
  env cluster-config set edge /var/lib/tenkai/cluster/edge.kubeconfig
```

The environment name is also the namespace in-cluster releases land in, so
it must be a valid namespace name. The cluster release refuses `tenkai-system`
and `kube-*`: those namespaces hold credentials Tenkai must not administer.

To let in-cluster releases converge without a person, give the environment an
[unattended approval policy](plan-approval.md#unattended-approval-policy)
with `mode = "auto"`. Host steps are never approved this way: the server
never approves a plan with a host step itself, and the host applier counts
only approvers from its own root-owned policy.

Run the server as the `tenkai` user, as in
[install a server host](run-tenkai-server.md#install-a-server-host), with the
host executor enabled ([run host releases](run-tenkai-server.md#run-host-releases)):

```bash
# /etc/tenkai/server.env, mode 0600, written as root. systemd EnvironmentFile
# does not expand command substitution: copy the contents of
# /etc/tenkai/management.token into the TENKAI_MANAGEMENT_TOKEN key. The
# tenkai user cannot read that root-only token file; sudo tenkaictl can.
TENKAI_RELEASE_TRUST_ROOTS=/etc/tenkai/release-trust-roots.toml
TENKAI_HOST_SPOOL_DIR=/var/lib/tenkai/host-spool
# With an unattended approval policy:
TENKAI_PLAN_APPROVAL_TRUST_ROOTS=/etc/tenkai/plan-approval-trust.toml
TENKAI_PLAN_APPROVAL_DIR=/var/lib/tenkai/approvals
```

Once the server is listening on loopback, status needs no extra flags:

```bash
sudo tenkaictl status --env edge
```

If this host has exactly one environment, `sudo tenkaictl status` is enough.
`tenkaictl` reads `/etc/tenkai/client.toml` (then
`$XDG_CONFIG_HOME/tenkai/client.toml`). Flags and environment variables
override both. The token stays in `token_file`; it is never in the config and
never on argv. A token file readable by group or others is refused.

From a workstation, do not copy the token off the host. Either run the CLI on
the host:

```bash
ssh -t user@host sudo tenkaictl status --env edge
```

or keep the token on the host and tunnel loopback, then sign in with OIDC on
the workstation (`tenkaictl login`) instead of a management token:

```bash
ssh -N -L 8080:127.0.0.1:8080 user@host
# workstation $XDG_CONFIG_HOME/tenkai/client.toml:
#   target = "remote"
#   server_url = "http://127.0.0.1:8080"
tenkaictl login
tenkaictl status --env edge
```

`/readyz` lists `host_executor:v1` once the host executor is usable.

## 4. Publish and subscribe

Sign both releases with your release key on a machine that holds it. Remote
`publish` uploads the manifest and the declared deploy inputs, covered by the
same digests the signature binds:

```bash
tenkaictl --target remote publish ./cluster/tenkai.toml \
  --signature ./cluster.sig.json --trust-roots /etc/tenkai/release-trust-roots.toml
tenkaictl --target remote publish ./app/tenkai.toml \
  --signature ./app.sig.json --trust-roots /etc/tenkai/release-trust-roots.toml
tenkaictl --target remote promote cluster@1.0.0 stable
tenkaictl --target remote promote app@1.0.0 stable
tenkaictl --target remote env subscribe edge cluster=stable --generation <generation>
tenkaictl --target remote env subscribe edge app=stable --generation <generation>
```

## 5. Approve the cluster plan

The next plan runs the cluster's `install` and `health` host steps first,
whatever the product names, then the in-cluster release. Reconcile leaves it
for a human: a plan with a host step is never approved by the server. Plan, approve with a key from the host
approval policy, and apply:

```bash
tenkaictl --target remote plan --env edge --generation <generation>
# On a machine that holds the approver key, sign the printed plan digest.
tenkaictl --target remote apply <plan-id> --approval approval.json --generation <generation>
```

The host applier verifies the release signature, the plan, and the approvals
against its root-owned trust, then runs `install` as root: the cluster comes
up as its own systemd unit and the kubeconfig appears. The approved `health`
step checks the node, and that the kubeconfig works with exactly the scope it
should have. Then the in-cluster release is applied as that identity.

There is no step after this. Until the kubeconfig exists, every attempt to
apply an in-cluster release in the environment fails closed, names the
missing file, and leaves the deployment as it was; reconcile retries with
its bounded backoff and converges once the cluster is up. After the host
release, in-cluster releases that declare contract requirements apply
providers before dependents and wait for Available between steps. Releases
with no edge keep name order. An undeclared Kubernetes readiness edge is a
missing contract; a cycle across releases is refused at planning. A plan that
would invert a contract edge to run the host release first is refused.

## Tenkai's identity in the cluster

The cluster release creates a service account `tenkai` in `tenkai-system` and
binds the built-in `admin` role to it in the environment's namespace only.
That covers every namespaced kind the in-process executor applies, Roles and
RoleBindings in that namespace included, and reading the namespace itself.
It grants nothing cluster-wide: no `cluster-admin`, no other namespace, no
nodes, no custom resource definitions. The account lives outside the
namespace it administers, so a release Tenkai applies cannot change Tenkai's
own credentials.

Namespace admin can create workloads, and a workload is a way onto the host.
Both namespaces therefore enforce the restricted
[Pod Security standard](https://kubernetes.io/docs/concepts/security/pod-security-standards/):
no privileged pods, host paths, or host namespaces, and containers run as
non-root. The `admin` role cannot change those labels. Without this, anyone
holding the `tenkai` user's kubeconfig could reach host root without an
approved host plan.

The `health` step fails if the namespaces do not enforce that standard, if
the identity can create namespaces, change its namespace, read secrets in
`tenkai-system`, or read nodes, or if the kubeconfig the `tenkai` user holds
is not the one `install` wrote. Root never loads that file: it is the
`tenkai` user's to change, and a kubeconfig can name commands to run.

The cluster keeps two cluster-wide services of the distribution that a
namespaced release cannot install itself: the service load balancer and the
local-path storage provisioner. A `LoadBalancer` Service in the environment's
namespace binds its ports on the host's addresses, which is how a release
serves traffic from outside. A PersistentVolumeClaim without a class gets a
volume from the default `local-path` StorageClass, a directory on the host
that only the provisioner creates; pods still cannot mount host paths
themselves. `health` fails when there is no default StorageClass. Those volumes live under the distribution's data directory, so uninstalling the cluster deletes them. Treat
namespace admin as the right to open host ports.

In-cluster releases run as that identity, never as host root. Releases that
need cluster-wide objects need a wider grant, made in the cluster release
where it is signed and reviewed.

## Upgrade, roll back, uninstall

Each is an approved plan; the host applier runs every host step at most once
and never restores a failed one on its own
([applied state](host-releases.md#applied-state)).

- **Upgrade:** publish a cluster release with a newer pin in `cluster.env`
  and a newer `product.version`, promote it, then plan, approve, and apply.
  Running pods keep running while the distribution restarts.
- **Roll back:** promote the previous release again, then plan, approve, and
  apply. The step is a downgrade, so it needs the `rollback` or `downgrade`
  approvals the host approval policy requires.
- **Uninstall:** `tenkaictl --target remote env unsubscribe edge cluster
  --generation <generation>`, then plan, approve, and apply. The `uninstall`
  command removes the kubeconfig first, then the cluster and all its state,
  including everything running in it. In-cluster releases of the environment
  fail closed from then on.

A failed host step stays failed until the next approved plan; see
[run host releases](run-tenkai-server.md#run-host-releases).

## Run the drill

```bash
# Against a published release:
scripts/bare-host-drill.sh --release-tag vX.Y.Z
# Against release assets built from a checkout (install.sh and SHA256SUMS included):
scripts/bare-host-drill.sh --dist DIR
```

It needs root through `sudo`, systemd, polkit, Python 3.11 or newer, and
network access to GitHub. It installs system software and a cluster, so run
it only on a throwaway host.
