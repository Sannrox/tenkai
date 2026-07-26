# hello-minikube — local dogfood (no remote server)

Fully **on your machine**:

| Piece | What |
| --- | --- |
| Control plane | Embedded `tenkaictl` + SQLite |
| Cluster | minikube (Docker driver) |
| Apply path | `TENKAI_SOFTWARE_EXECUTOR=kubernetes` → `kubectl` |

No `tenkai-server`, no Postgres, no cloud.

## One-shot (unsigned, `local` only)

```bash
minikube start --driver=docker   # once
./scripts/dogfood-minikube.sh
kubectl -n local get deploy,pods
```

Unsigned releases **only** apply to the built-in `local` environment. That is
intentional trust policy, not a minikube limitation.

## Full dogfood paths exercised on a Mac

1. **Happy install** — publish → promote → plan → apply → `current`
2. **Bad upgrade + auto-rollback** — broken image / health fail → restore previous
3. **Good upgrade** — healthy newer version → `current`
4. **Signed multi-env** — `local` + `stage` with release signatures + plan approvals
5. **Fleet + wave** — `fleet status`, `wave run local,stage`

### Deliberate bad upgrade (rollback)

```bash
export TENKAI_SOFTWARE_EXECUTOR=kubernetes
export TENKAI_DATABASE=$PWD/.tenkai-dogfood-minikube/tenkai.db
# Publish a 0.x.y with a non-existent image tag, promote to stable, plan, apply.
# Expect: apply exits non-zero, ROLLBACK … restored <previous>, cluster back on good image.
# Channel head may still show the bad version (behind) until you re-promote a good release.
```

### Signed multi-env (stage needs signatures)

```bash
export TENKAI_DEV_SIGNING_SEED=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
export TENKAI_DEV_APPROVAL_SEED=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
export TENKAI_SOFTWARE_EXECUTOR=kubernetes
DB=$PWD/.tenkai-dogfood-minikube/tenkai.db
DOG=$PWD/.tenkai-dogfood-minikube

# 1) Sign + publish a release (dev helper, not production KMS)
cargo run --example dev_sign_release -- \
  path/to/tenkai.toml $DOG/trust.toml $DOG/rel.sig.json
./target/debug/tenkaictl --database $DB publish path/to/tenkai.toml \
  --signature $DOG/rel.sig.json --trust-roots $DOG/trust.toml
./target/debug/tenkaictl --database $DB promote hello-minikube@X.Y.Z stable

# 2) Env stage + plan
./target/debug/tenkaictl --database $DB env add stage
./target/debug/tenkaictl --database $DB env subscribe stage hello-minikube=stable
PLAN=$(./target/debug/tenkaictl --database $DB plan --env stage | sed -n 's/^plan id: //p')

# 3) Sign plan approval (non-local apply cannot use --allow-unapproved-development)
cargo run --example dev_sign_plan_approval -- \
  --database $DB --plan-id "$PLAN" \
  --trust-roots $DOG/approval-trust.toml --out $DOG/approval.json
./target/debug/tenkaictl --database $DB apply "$PLAN" \
  --approval $DOG/approval.json --approval-trust-roots $DOG/approval-trust.toml

./target/debug/tenkaictl --database $DB fleet status
./target/debug/tenkaictl --database $DB wave run local,stage
```

Dev helpers:

- `examples/dev_sign_release.rs` — trust roots + release signature
- `examples/dev_sign_plan_approval.rs` — plan-approval envelope

Keys are ephemeral unless you set the seed env vars (dogfood only).

## Tear down

```bash
kubectl delete ns local stage --ignore-not-found
minikube stop   # optional
rm -rf .tenkai-dogfood-minikube
```
