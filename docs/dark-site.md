# Dark-site local model and site-agent workers

A dark site needs one profile that imports a signed offline bundle, verifies
local weights, runs `model_runtime`, and runs a fixed set of site-agent
workers without cloud model callers. This profile is that packaging. It is
standalone: the only identity input is a local JWKS. Chisei is not required
to activate, refuse cloud routes, or roll back.

Worker claim admission stays with the plane. Tenkai owns the pool, drain,
health, and digest pins. See [worker pools](worker-pool.md) and
[offline bundles](offline-bundles.md).

## Profile

A version 1 TOML file:

```toml
version = 1

[model_runtime]
product = "qwen-coder"
version = "0.1.0"
digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[site_agent]
product = "site-agent-workers"
version = "1.0.0"
profile = "site-agent"
image_digest = "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
replicas = 2
drain_timeout_ms = 5000

[routing]
audience = "local"
model = "qwen-coder"
allowed_providers = ["local"]

[verifier]
jwks = "jwks.json"
```

`site_agent.profile` must be `site-agent` (the Shikigami serve profile).
`routing.allowed_providers` admits only `local`. Both digests are canonical
`sha256:` hex. The worker image digest sits beside the model digest in the
same file.

## Activate

After bundle import, bind the signed `stack/manifest.json` and write the
active profile beside environment runtime state. No origin pull:

```bash
tenkaictl dark-site activate \
  --profile examples/dark-site/profile.toml \
  --stack examples/dark-site/stack.json \
  --state .tenkai-state/runtime/local
```

The stack must name the model digest in `weights` and the worker image digest
in `images`. The JWKS file is resolved next to the profile. Activation fails
closed if either pin or the JWKS is missing.

While that activation is present, applying a `routing_config` that names a
non-local provider is refused and recorded on the activation
(`reason = cloud_route_refused`). Routing stays pinned to the local model
audience.

## Ready and rollback

```bash
tenkaictl dark-site ready --state .tenkai-state/runtime/local \
  --model-health healthy --ready-replicas 2
tenkaictl dark-site rollback --state .tenkai-state/runtime/local \
  --active-claims 1
```

Ready requires a healthy `model_runtime` and a converged site-agent pool.
A digest-pinned rollback of the worker image uses the existing pool drain:
in-flight claims make the decision `wait_drain` until `active_claims = 0` or
the profile drain timeout. Apply the previously pinned worker_pool and
model_runtime releases through the normal plan path.

See [`examples/dark-site`](../examples/dark-site).

A one- or two-node SQLite spoke uses the [spoke-standby profile](spoke-standby.md)
for writer loss. This page is the local model and site-agent packaging.
