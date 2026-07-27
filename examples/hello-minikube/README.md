# hello-minikube — local dogfood (no remote server)

Fully **on your machine**:

| Piece | What |
| --- | --- |
| Control plane | Embedded `tenkaictl` + SQLite |
| Cluster | minikube (Docker driver) |
| Apply path | `TENKAI_SOFTWARE_EXECUTOR=kubernetes` → `kubectl` |

No `tenkai-server`, no Postgres, no cloud.

## One-shot scripts

```bash
minikube start --driver=docker   # once
export TENKAI_SOFTWARE_EXECUTOR=kubernetes

# Unsigned install to built-in `local` only
./scripts/dogfood-minikube.sh
kubectl -n local get deploy,pods

# Signed multi-env: local + stage (tenkaictl dev signing, no unapproved stage)
# Use a fresh DB if 0.1.0 was already published unsigned:
#   rm -rf .tenkai-dogfood-minikube
TENKAI_DOGFOOD_MODE=signed-multi-env ./scripts/dogfood-minikube.sh
kubectl -n stage get deploy,pods

# Software canary cohort: designate → canary channel → policy → blocked promote
# → apply (no --skip-gates) → promote stable (prefer a fresh DB)
TENKAI_DOGFOOD_MODE=canary ./scripts/dogfood-minikube.sh
```

| Mode | Env var | Trust |
| --- | --- | --- |
| `local` (default) | — | `--allow-unsigned-development` / unapproved apply on `local` only |
| `signed-multi-env` | `TENKAI_DOGFOOD_MODE=signed-multi-env` | signed publish + plan approval on `stage` |
| `canary` | `TENKAI_DOGFOOD_MODE=canary` | unsigned on `local`; canary evidence gates promote to `stable` |

Unsigned releases **only** apply to the built-in `local` environment. That is
intentional trust policy, not a minikube limitation.

Full ops notes: [`docs/local-dogfood-minikube.md`](../../docs/local-dogfood-minikube.md).

## Full dogfood paths exercised on a Mac

1. **Happy install** — script `local` mode → `current`
2. **Signed multi-env** — script `signed-multi-env` → `local` + `stage` current
3. **Software canary** — script `canary` → blocked promote without evidence, then
   stable promote after a clean canary-cohort apply (waves only observe)
4. **Bad upgrade + auto-rollback** — broken image / health fail → restore previous
   (expect `phase=health` / `phase=restore` in errors; channel may stay `behind`)
5. **Good upgrade** — healthy newer version → `current`
6. **Fleet + wave** — scripted in signed mode; or `fleet status` / `wave run local,stage`

### Deliberate bad upgrade (rollback + diagnostics)

```bash
export TENKAI_SOFTWARE_EXECUTOR=kubernetes
export TENKAI_DATABASE=$PWD/.tenkai-dogfood-minikube/tenkai.db
# Publish a 0.x.y with a non-existent image tag, promote to stable, plan, apply.
# Expect: apply exits non-zero, ROLLBACK … restored <previous>, cluster back on good image.
# Error text names phase=health (and often phase=restore) without secrets (#150).
# Channel head may still show the bad version (behind) until you re-promote a good release.
```

### Manual signed multi-env (same as script)

```bash
export TENKAI_SOFTWARE_EXECUTOR=kubernetes
DB=$PWD/.tenkai-dogfood-minikube/tenkai.db
BIN=./target/debug/tenkaictl
KEYS=.tenkai-dev-keys
ART=.tenkai-dogfood-minikube/artifacts
mkdir -p "$ART"

$BIN dev init-keys --dir $KEYS
$BIN dev sign-release examples/hello-minikube/tenkai.toml \
  --keys $KEYS --signature $ART/rel.sig.json --trust-roots $ART/rel-trust.toml
$BIN --database $DB publish examples/hello-minikube/tenkai.toml \
  --signature $ART/rel.sig.json --trust-roots $ART/rel-trust.toml
$BIN --database $DB promote hello-minikube@0.1.0 stable

$BIN --database $DB env add stage
$BIN --database $DB env subscribe local hello-minikube=stable
$BIN --database $DB env subscribe stage hello-minikube=stable
PLAN=$($BIN --database $DB plan --env stage | sed -n 's/^plan id: //p')

$BIN --database $DB dev sign-approval "$PLAN" \
  --keys $KEYS --approval $ART/approval.json --trust-roots $ART/approval-trust.toml
$BIN --database $DB apply "$PLAN" \
  --approval $ART/approval.json --approval-trust-roots $ART/approval-trust.toml

$BIN --database $DB fleet status
$BIN --database $DB wave run local,stage
```

`tenkaictl dev …` is development-only (not production KMS). Deprecated cargo
examples `examples/dev_sign_*.rs` are stubs only.

### Manual software canary (same as `TENKAI_DOGFOOD_MODE=canary`)

```bash
export TENKAI_SOFTWARE_EXECUTOR=kubernetes
DB=$PWD/.tenkai-dogfood-minikube/tenkai.db
BIN=./target/debug/tenkaictl
# Prefer: rm -rf .tenkai-dogfood-minikube
$BIN --database $DB init
$BIN --database $DB canary designate local
$BIN --database $DB publish examples/hello-minikube/tenkai.toml --allow-unsigned-development
$BIN --database $DB promote hello-minikube@0.1.0 canary
$BIN --database $DB canary policy hello-minikube@0.1.0 stable --env local
# Expect fail closed:
$BIN --database $DB promote hello-minikube@0.1.0 stable
$BIN --database $DB env subscribe local hello-minikube=canary
PLAN=$($BIN --database $DB plan --env local | sed -n 's/^plan id: //p')
# Do NOT pass --skip-gates (pass evidence needs GateOutcome::Satisfied)
$BIN --database $DB apply "$PLAN" \
  --allow-unapproved-development \
  --development-reason "local minikube software canary"
$BIN --database $DB promote hello-minikube@0.1.0 stable
$BIN --database $DB wave run local   # observes only; does not authorize promote
```

`model_runtime` canary is documented separately:
[`docs/model-runtime.md`](../../docs/model-runtime.md#canary-promotion-evidence-model_runtime).

## Tear down

```bash
kubectl delete ns local stage --ignore-not-found
minikube stop   # optional
rm -rf .tenkai-dogfood-minikube .tenkai-dev-keys
```
