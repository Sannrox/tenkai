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
./scripts/dogfood-minikube.sh
```

State defaults to `.tenkai-dogfood-minikube/tenkai.db` (gitignored). Namespace
matches the environment name (`local`).

## Paths worth running

| Path | What you learn |
| --- | --- |
| Happy install | publish → promote → plan → apply → `status` current |
| Bad upgrade | non-existent image + `rollout status` health → **auto-rollback** to previous |
| Good upgrade | healthy newer version → cluster + Tenkai both current |
| Fleet / wave | second env + `fleet status` / `wave run local,stage` (observe posture) |
| Signed multi-env | non-`local` env requires **signed release** + **signed plan approval** |

Details and command templates: [hello-minikube README](../examples/hello-minikube/README.md).

### Apply / health / restore diagnostics (#150)

Software k8s failures name the **phase** (`apply`, `health`, or `restore`),
product@version, and environment/namespace, with credential-like snippets
redacted. Auto-rollback restores the previous **deployed** release; **channel
head is not rewritten** (status may show `behind` until you re-promote).

### First-class dogfood signing (#149)

```bash
tenkaictl dev init-keys --dir .tenkai-dev-keys
tenkaictl dev sign-release path/to/tenkai.toml \
  --keys .tenkai-dev-keys \
  --signature /tmp/rel.sig.json \
  --trust-roots /tmp/rel-trust.toml
tenkaictl publish path/to/tenkai.toml \
  --signature /tmp/rel.sig.json --trust-roots /tmp/rel-trust.toml

# after plan --env stage:
tenkaictl dev sign-approval "$PLAN_ID" \
  --keys .tenkai-dev-keys \
  --approval /tmp/approval.json \
  --trust-roots /tmp/approval-trust.toml
tenkaictl apply "$PLAN_ID" \
  --approval /tmp/approval.json \
  --approval-trust-roots /tmp/approval-trust.toml
```

Development keys only — not production KMS. Default keys dir: `.tenkai-dev-keys/`
(gitignored).

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
   remain separate gates.

5. **Dev signing is not production KMS.**  
   Use `tenkaictl dev init-keys` / `sign-release` / `sign-approval` for laptop
   multi-env drills only; never treat `.tenkai-dev-keys` as production trust.

## Out of scope for this dogfood path

- Multi-replica `tenkai-server` + Postgres hub HA ([runbook](multi-replica-hub-runbook.md))
- OpenMetrics scrape on a hub process
- Remote GateProvider / outcome→priors intelligence loop
- In-process Kubernetes client (still kubectl argv)

Those remain optional later work; none are required to learn Tenkai’s delivery
core on a laptop.
