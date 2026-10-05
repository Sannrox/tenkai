# tenkai

Tenkai (展開, "deployment") is a delivery control plane for software you ship
into many environments you do not fully control: customer VPCs, on-prem sites,
edge hosts, and air-gapped networks. You **publish** immutable releases,
**promote** them into channels, and **subscribe** environments to channels.
Tenkai computes the plan that converges each environment, executes it behind
health probes, and rolls back automatically on failure. Model routing configs
and other intelligence artifacts ship through the same path as services.

It is for teams that deliver one product to a fleet of heterogeneous or
disconnected environments and need per-environment channels, gates,
maintenance windows, signed releases, approvals, and an audit trail.

**Why not Flux, Argo CD, or a deploy script?** GitOps tools sync a git repo
into a connected cluster you own; a deploy script pushes whatever it is told
to. Tenkai keeps a catalog of immutable releases and lets each environment's
own constraints decide what it runs and when, including environments that are
only reachable by [offline bundle](docs/offline-bundles.md). The full
rationale is in [DESIGN.md](DESIGN.md).

## Try it in five minutes

Embedded mode is one `tenkaictl` binary with a local SQLite store: no server,
database, or network service. The example product only writes a file.

```bash
git clone https://github.com/Sannrox/tenkai && cd tenkai

# download the latest community host and check it against SHA256SUMS
platform=darwin-aarch64   # or linux-x86_64
base=https://github.com/Sannrox/tenkai/releases/latest/download
curl -fsSL -O "$base/SHA256SUMS" -O "$base/tenkaictl-$platform"
grep " tenkaictl-$platform\$" SHA256SUMS | shasum -a 256 -c -
chmod 0755 "tenkaictl-$platform" && mv "tenkaictl-$platform" tenkaictl

# initialize .tenkai-state/tenkai.db and the built-in local environment
./tenkaictl init

# publish an immutable release and promote it to a channel
export TENKAI_MANAGEMENT_TOKEN='replace-from-secret-store'
./tenkaictl publish examples/hello-local/tenkai.toml --allow-unsigned-development
./tenkaictl promote hello-local@0.1.0 stable

# subscribe this machine and converge
./tenkaictl env subscribe local hello-local=stable
./tenkaictl plan --env local
./tenkaictl apply <plan-id-from-previous-command> \
  --allow-unapproved-development \
  --development-reason "local quickstart"
./tenkaictl status
```

`--allow-unsigned-development` and `--allow-unapproved-development` are
development bypasses for the built-in `local` environment only. Every other
environment fails closed without [signed releases](docs/release-signing.md)
and [signed plan approvals](docs/plan-approval.md).

To verify build provenance with GitHub attestations, see
[GitHub Release binaries](docs/release-binaries.md). To build from source
instead, run `cargo build --bin tenkaictl` and use `./target/debug/tenkaictl`.
Hub Postgres hosts are the GitHub asset `tenkai-server-postgres-<platform>`,
built with `-p tenkai-server --features postgres,ui`. Source build uses the
same feature set.

## How it works

A **product** has immutable **releases**. Promoting a release moves a
**channel** to it. Each **environment** subscribes to one channel per product
and carries its own facts, constraints, maintenance windows, and trust policy.
Tenkai computes a **plan** that moves the environment to its channel heads,
applies it under a generation-fenced lease, probes health, and rolls back on
failure. Plans, deployments, leases, and audit records live in Tenkai's own
operational store, so Tenkai stays operable and recoverable without any
optional provider ([ADR 0001](docs/decisions/0001-standalone-core-and-service-evolution.md)).

The same contract runs three ways: embedded in `tenkaictl` (as in the
quickstart), as the networked `tenkai-server`, and with pull-only
`tenkai-runtime` processes inside environments the server cannot reach.

## Next steps

| I want to… | Read |
| --- | --- |
| Run Tenkai against a laptop Kubernetes cluster | [Local minikube dogfood](docs/local-dogfood-minikube.md) |
| Write a manifest for my product | [The manifest](docs/manifest.md) |
| Add environments, constraints, and maintenance windows | [Manage environments](docs/manage-environments.md) |
| Upgrade, roll back, or recover a product | [Upgrade and rollback](docs/upgrade-and-rollback.md) |
| Run the server or a remote environment runtime | [Run tenkai-server](docs/run-tenkai-server.md) |
| Ship from GitHub tags | [Deploy from GitHub](docs/deploy-from-github.md) |
| Sign releases and approve plans | [Release signing](docs/release-signing.md), [plan approval](docs/plan-approval.md) |
| Deliver to disconnected sites | [Offline bundles](docs/offline-bundles.md) |
| Back up and restore state | [Backup and restore](docs/backup-restore.md) |
| Look up a setting | [Environment variables](docs/environment-variables.md) |
| Understand the design | [DESIGN.md](DESIGN.md) and [architecture decisions](docs/decisions/README.md) |

Everything else is in the [documentation index](docs/README.md).

## Status

**v0 control-plane kernel**: the architecture program is complete and product
depth is still growing. See [capabilities and roadmap](docs/capabilities.md)
for what has shipped and what is next; work is tracked in GitHub Issues.

## Contributing

```bash
make test
make validate
make test-integration
make update
```

Contributor setup and pull-request flow live in
[CONTRIBUTING.md](CONTRIBUTING.md); agent workflow is [AGENTS.md](AGENTS.md).
