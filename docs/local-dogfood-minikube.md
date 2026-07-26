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

5. **Dev signing helpers are not production KMS.**  
   `examples/dev_sign_release.rs` and `examples/dev_sign_plan_approval.rs`
   generate ephemeral keys (or seed env vars) for laptop dogfood only.

## Out of scope for this dogfood path

- Multi-replica `tenkai-server` + Postgres hub HA ([runbook](multi-replica-hub-runbook.md))
- OpenMetrics scrape on a hub process
- Remote GateProvider / outcome→priors intelligence loop
- In-process Kubernetes client (still kubectl argv)

Those remain optional later work; none are required to learn Tenkai’s delivery
core on a laptop.
