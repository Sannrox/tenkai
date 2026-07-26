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
export TENKAI_SOFTWARE_EXECUTOR=kubernetes
DB=$PWD/.tenkai-dogfood-minikube/tenkai.db
BIN=./target/debug/tenkaictl
KEYS=.tenkai-dev-keys

$BIN dev init-keys --dir $KEYS
$BIN dev sign-release path/to/tenkai.toml \
  --keys $KEYS --signature /tmp/rel.sig.json --trust-roots /tmp/rel-trust.toml
$BIN --database $DB publish path/to/tenkai.toml \
  --signature /tmp/rel.sig.json --trust-roots /tmp/rel-trust.toml
$BIN --database $DB promote hello-minikube@X.Y.Z stable

$BIN --database $DB env add stage
$BIN --database $DB env subscribe stage hello-minikube=stable
PLAN=$($BIN --database $DB plan --env stage | sed -n 's/^plan id: //p')

$BIN --database $DB dev sign-approval "$PLAN" \
  --keys $KEYS --approval /tmp/approval.json --trust-roots /tmp/approval-trust.toml
$BIN --database $DB apply "$PLAN" \
  --approval /tmp/approval.json --approval-trust-roots /tmp/approval-trust.toml

$BIN --database $DB fleet status
$BIN --database $DB wave run local,stage
```

`tenkaictl dev …` is development-only (not production KMS). See also
`docs/local-dogfood-minikube.md`.

## Tear down

```bash
kubectl delete ns local stage --ignore-not-found
minikube stop   # optional
rm -rf .tenkai-dogfood-minikube
```
