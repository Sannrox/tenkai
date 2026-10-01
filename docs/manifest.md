# The manifest (`tenkai.toml`)

A manifest describes one immutable release of one product: what to install,
how to check its health, and which gates it must pass. Publish it with
`tenkaictl publish <manifest>`.

```toml
[product]
name = "hello-local"
version = "0.1.0"

[deploy]
workdir = "."                    # relative to the manifest
install = "docker compose up -d" # any command; activates this release
uninstall = "docker compose down"
health = "curl -sf localhost:8080/healthz"  # exit 0 = healthy; failure rolls back
inputs = ["compose.yaml"]          # immutable files/directories used by these commands

[gate]
eval_suite = "my-suite"          # chisei eval suite; latest run must fully pass
```

This example shows every common field. The minimal working manifest used by the
quickstart is [`examples/hello-local/tenkai.toml`](../examples/hello-local/tenkai.toml).
Deploy commands run with a cleared environment; see
[environment variables](environment-variables.md#set-by-tenkai-for-deploy-commands)
for what they receive.

## Immutability

Releases are immutable: re-publishing the same version with different manifest
content or different declared deploy inputs is rejected — bump
`product.version`. Runtime state must live outside declared `inputs`.

## Signing

Release publication fails closed unless `--signature` and `--trust-roots` are
provided. Local development can opt into `--allow-unsigned-development`.
Inspect stored trust evidence or reverify signed content against current trust
roots with:

```bash
tenkaictl release inspect hello-local@0.1.0
tenkaictl release verify hello-local@0.1.0 \
  --trust-roots /etc/tenkai/release-trust.toml
```

The detached envelope and trust-root formats are documented in
[release signing](release-signing.md). Executing a plan separately requires a
signed approval bound to the exact plan and environment; see
[plan approval](plan-approval.md).

## Gates

If a release declares `gate.eval_suite`, `apply` blocks unless the suite's
latest eval run in chisei exists and every current case passed (fail closed).
The run's `config_ref` must match the content-bound reference shown in the
blocked-plan detail; it covers the manifest, immutable deploy inputs, and the
current suite definition, so stale evidence cannot authorize changed content.
`--skip-gates` is the current v0 break-glass action, and the bypass is recorded
on the Tenkai plan and audit record like any other apply. Under the standalone
architecture, a bypass must carry separately authorized, auditable override
evidence; inability to authorize the override fails closed. Migrated plans
preserve their original bypass evidence and version rather than gaining
implicit authorization.

An embedded apply with `[gate].eval_suite` fails closed locally unless a remote
provider host is explicitly configured; ungated solo deploys never open a
network connection. The evidence format is in
[evaluation gate evidence](evaluation-gate-evidence.md).

## Product kinds

Products are `software` by default (`product.kind`). Other kinds reuse the same publish, promote,
plan, apply, and rollback path:

| Kind | Page |
| --- | --- |
| `routing_config` | [below](#routing-configuration-products) |
| `model_runtime` | [model runtime](model-runtime.md) |
| `policy_bundle`, `eval_suite`, `agent_definition`, `prompt_package` | [staged products](staged-products.md) |
| `workshop_module` | [workshop modules](workshop-modules.md) |
| `worker_pool` | [worker pools](worker-pool.md) |

The portable subset other tools can emit is the
[delivery manifest profile](delivery-manifest-profile.md).

### Routing-configuration products

Tenkai can deliver a versioned model-routing document without sekai-chisei.
The manifest declares `product.kind = "routing_config"`, a JSON configuration,
and the providers admitted by that release:

```toml
[product]
name = "model-routing"
version = "1.0.0"
kind = "routing_config"

[routing]
config = "routing.json"
allowed_providers = ["local"]
```

The JSON contract is versioned and rejects unknown fields, invalid references,
duplicate routes, unsupported providers, and invalid weights before mutation.
The local executor publishes atomically, observes the resulting digest, and
uses the normal pinned-release plan path for rollback. See
[`examples/routing-local`](../examples/routing-local) and
[ADR 0002](decisions/0002-tenkai-owned-routing-configuration.md).

sekai-chisei may supply policy, evaluation, provenance, or an explicitly
configured adapter, but it is not required for standalone routing delivery and
does not own release, plan, apply, rollback, or recovery state.
