# Software executor (Kubernetes via Helm)

Tenkai applies `product.kind = software` releases through a pluggable port so
cluster delivery does not require hard-linking a Kubernetes client into the core
crate.

Decision for the first reference: **Helm** (`helm upgrade --install` /
`helm uninstall`). Rationale: chart packaging is the common unit; argv-only
invocation (no shell); does not require Argo for Tenkai-owned plan/rollback;
Argo remains a valid future backend. Native clients are future work.

Source: `src/software_executor.rs`. Related: DESIGN executor notes, apply path
in `src/apply.rs`.

## Ports

| Type | Role |
| --- | --- |
| `SoftwareExecutor` | apply / remove / observe |
| `FakeSoftwareExecutor` | CI without cluster or helm |
| `HelmSoftwareExecutor` | Reference Helm path |

## Operator enablement

Default remains shell `deploy.install` / `deploy.uninstall`.

```bash
export TENKAI_SOFTWARE_EXECUTOR=helm
export TENKAI_HELM_BIN=/usr/local/bin/helm   # optional; default: helm on PATH

# Chart is the release workdir; namespace is the environment name
tenkaictl reconcile --once
```

| Variable | Meaning |
| --- | --- |
| `TENKAI_SOFTWARE_EXECUTOR=helm` | Use Helm instead of shell install |
| `TENKAI_SOFTWARE_EXECUTOR=fake` | Force fake executor (tests) |
| `TENKAI_HELM_BIN` | Path to helm binary |

Helm is invoked as:

```text
helm upgrade --install <product> <workdir> \
  --namespace <environment> --create-namespace --wait --timeout 5m \
  --set tenkai.version=<version> --set tenkai.releaseId=<release_id>
```

Product, version, and environment names must not contain path separators.

## Security

- No kubeconfig on CLI argv; use standard kubeconfig discovery for helm.
- Scope cluster credentials per environment outside Tenkai (operator responsibility).
- Do not store raw kubeconfig in operational SQLite.
- Failures leave Tenkai plan status failed; rollback remains Tenkai-authoritative.

## Tests

```bash
cargo test --locked software_executor
```

Default CI does not require a cluster or helm binary.
