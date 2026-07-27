# Local dogfood: minikube + embedded tenkaictl

Goal: prove Tenkai delivery on a **single Mac** without a remote control-plane
host, Postgres, or cloud spend.

| Piece | Choice |
| --- | --- |
| Control plane | Embedded `tenkaictl` + SQLite |
| Cluster | minikube (Docker driver) |
| Executor | `TENKAI_SOFTWARE_EXECUTOR=kubernetes` → `kubectl` |
| Product | [`examples/hello-minikube/`](../examples/hello-minikube/) |
| Script | [`scripts/dogfood-minikube.sh`](../scripts/dogfood-minikube.sh) |

Related contracts: [software executor](software-executor.md),
[release signing](release-signing.md), [plan approval](plan-approval.md),
[rollout waves](rollout-waves.md).

## Quick path

```bash
minikube start --driver=docker   # once
export TENKAI_SOFTWARE_EXECUTOR=kubernetes

# Default: unsigned install to built-in `local` only
./scripts/dogfood-minikube.sh

# Signed multi-env (local + stage) with tenkaictl dev signing (#149)
# Prefer a fresh DB if you already ran the unsigned path for 0.1.0:
#   rm -rf .tenkai-dogfood-minikube
TENKAI_DOGFOOD_MODE=signed-multi-env ./scripts/dogfood-minikube.sh

# Software canary cohort drill (designate → canary channel → policy → blocked
# promote → apply → stable promote). Prefer a fresh DB:
#   rm -rf .tenkai-dogfood-minikube
TENKAI_DOGFOOD_MODE=canary ./scripts/dogfood-minikube.sh
```

| Variable | Default | Purpose |
| --- | --- | --- |
| `TENKAI_DOGFOOD_MODE` | `local` | `local`, `signed-multi-env`, or `canary` |
| `TENKAI_DATABASE` | `.tenkai-dogfood-minikube/tenkai.db` | Embedded SQLite |
| `TENKAI_DEV_KEYS` | `.tenkai-dev-keys` | Dev-only Ed25519 seeds (gitignored) |
| `TENKAI_SOFTWARE_EXECUTOR` | forced to `kubernetes` by the script | Native kubectl apply |
| `TENKAI_KUBECTL_BIN` | `kubectl` on `PATH` | Override kubectl binary |

State and script artifacts under `.tenkai-dogfood-minikube/` are gitignored.
Development keys under `.tenkai-dev-keys/` are gitignored. **Not production KMS.**

The script exits non-zero if `minikube` or `kubectl` is missing, or if the
cluster is unreachable.

## Paths worth running

| Path | How | What you learn |
| --- | --- | --- |
| Happy install (`local`) | `./scripts/dogfood-minikube.sh` | publish → promote → plan → apply → `status` current |
| **Signed multi-env** | `TENKAI_DOGFOOD_MODE=signed-multi-env ./scripts/dogfood-minikube.sh` | signed publish; `stage` apply with plan approval only |
| **Software canary** | `TENKAI_DOGFOOD_MODE=canary ./scripts/dogfood-minikube.sh` | designate → canary channel → policy on stable → **blocked** promote without evidence → apply (no `--skip-gates`) → promote stable |
| Bad upgrade | manual (broken image) | auto-rollback; **phase=health/restore** diagnostics (#150) |
| Good upgrade | manual newer healthy version | cluster + Tenkai both current |
| Fleet / wave | included in signed mode; or `fleet status` / `wave run local,stage` | observe posture (waves do not apply; canary evidence still gates promotion) |

Manual command templates: [hello-minikube README](../examples/hello-minikube/README.md).

### Software canary cohort drill (#154)

Canary designation, promotion policy, and evidence gates are product features
(#7). The `model_runtime` path is documented in
[model-runtime canary](model-runtime.md#canary-promotion-evidence-model_runtime)
(#108). This dogfood mode exercises the **same gate for software** on
`hello-minikube` using the built-in `local` environment (unsigned development).

What the script proves:

1. `canary designate local` marks the cohort host.
2. Promote the release to the free **canary** channel first (policy does not
   block that channel).
3. `canary policy hello-minikube@0.1.0 stable --env local` requires complete
   evidence before wider promotion.
4. Promote to `stable` **without** a canary apply fails closed
   (`canary promotion blocked`).
5. Subscribe to `hello-minikube=canary`, plan, and apply **without**
   `--skip-gates` so outcomes record as gate-satisfied.
6. Promote to `stable` succeeds after a clean canary-cohort apply.
7. `wave run` only observes posture; it does not authorize channel promotion.

Prefer a fresh DB (`rm -rf .tenkai-dogfood-minikube`) if 0.1.0 was already
published on another path. Non-local canary cohort members still need signed
releases and plan approval (same trust rules as signed multi-env).

### Apply / health / restore diagnostics (#150)

Software k8s failures name the **phase** (`apply`, `health`, `restore`, or
`remove`), product@version, and environment/namespace, with credential-like
snippets redacted. Auto-rollback restores the previous **deployed** release;
**channel head is not rewritten** (status may show `behind` until you re-promote).

To force a health failure after a good install: publish a version with a
non-existent image tag, promote to `stable`, plan, and apply. Expect non-zero
exit and a `phase=health` (then often `phase=restore`) message without secrets.

### First-class dogfood signing (#149)

Prefer the **scripted** path above. Manual equivalent:

```bash
tenkaictl dev init-keys --dir .tenkai-dev-keys
tenkaictl dev sign-release examples/hello-minikube/tenkai.toml \
  --keys .tenkai-dev-keys \
  --signature .tenkai-dogfood-minikube/artifacts/rel.sig.json \
  --trust-roots .tenkai-dogfood-minikube/artifacts/rel-trust.toml
tenkaictl publish examples/hello-minikube/tenkai.toml \
  --signature .tenkai-dogfood-minikube/artifacts/rel.sig.json \
  --trust-roots .tenkai-dogfood-minikube/artifacts/rel-trust.toml

# after plan --env stage:
tenkaictl --database .tenkai-dogfood-minikube/tenkai.db dev sign-approval "$PLAN_ID" \
  --keys .tenkai-dev-keys \
  --approval .tenkai-dogfood-minikube/artifacts/approval.json \
  --trust-roots .tenkai-dogfood-minikube/artifacts/approval-trust.toml
tenkaictl --database .tenkai-dogfood-minikube/tenkai.db apply "$PLAN_ID" \
  --approval .tenkai-dogfood-minikube/artifacts/approval.json \
  --approval-trust-roots .tenkai-dogfood-minikube/artifacts/approval-trust.toml
```

Cargo examples `examples/dev_sign_*.rs` are **deprecated stubs**; use
`tenkaictl dev …`.

## Findings from Mac dogfood (v0.2)

These are intentional product rules, not minikube quirks:

1. **Unsigned development is `local`-only.**  
   `--allow-unsigned-development` is for the built-in `local` environment.
   Planning/applying the same release to `stage` (or any other name) fails closed
   until the release is signed and verified against trust roots.

2. **Non-local apply needs plan approval.**  
   `--allow-unapproved-development` is also restricted to `local`. For `stage`,
   use a detached `tenkai.plan-approval.v1` envelope and
   `--approval` / `--approval-trust-roots`.

3. **Rollback restores the environment, not the channel.**  
   After a failed upgrade, deployed version returns to the previous release while
   channel **head** may still point at the bad release (`behind`) until you
   re-promote a good version.

4. **Waves observe; they do not apply.**  
   `wave run` reports per-env posture. Channel promotion and canary evidence
   remain separate gates. Run `TENKAI_DOGFOOD_MODE=canary` to exercise the
   software promote gate on this path.

5. **Dev signing is not production KMS.**  
   Use `tenkaictl dev init-keys` / `sign-release` / `sign-approval` for laptop
   multi-env drills only; never treat `.tenkai-dev-keys` as production trust.

## Out of scope for this dogfood path

- Inventory fact probe → `env facts` automation
- Multi-replica `tenkai-server` + Postgres hub HA ([runbook](multi-replica-hub-runbook.md))
- OpenMetrics scrape on a hub process
- Remote GateProvider / outcome→priors intelligence loop
- In-process Kubernetes client (still kubectl argv)

Software canary cohort drill is in scope via `TENKAI_DOGFOOD_MODE=canary` (#154).
`model_runtime` canary remains documented under
[model-runtime](model-runtime.md#canary-promotion-evidence-model_runtime) (#108).
The items above remain optional later work; none are required to learn Tenkai’s
delivery core on a laptop.
