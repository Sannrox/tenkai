# Environment variables

Operator settings read by the shipped binaries, grouped by the host that reads
them. Feature-specific settings are listed at the end with the page that
explains them. Secrets belong in the environment or a secret store, never on a
command line.

## Shared by the hosts

Read by `tenkaictl`, `tenkai-server`, or both.

| Variable | Default | Description |
| --- | --- | --- |
| `TENKAI_DATABASE` | `.tenkai-state/tenkai.db` | Embedded or server-owned operational SQLite database |
| `TENKAI_STATE_DIR` | `<workdir-parent>/.tenkai-state` | Immutable deploy-input snapshots and per-environment runtime directories; must be outside the source workdir |
| `TENKAI_PRINCIPAL` | `tenkai` (`local-operator` for embedded `env retire`) | Embedded audit principal or remote provider caller identity |
| `TENKAI_MANAGEMENT_TOKEN` | unset | Community management bearer for server management requests, remote CLI mode, and embedded `promote` / canary mutations including `canary repair` |
| `TENKAI_JWT_ASSERTION` | unset | Optional compact JWT for embedded `promote` / canary mutations including `canary repair`; requires `TENKAI_JWT_VERIFIER_CONFIG` |
| `TENKAI_JWT_VERIFIER_CONFIG` | unset | Filesystem path to a JWT trust TOML file for enterprise JWT verification |
| `TENKAI_OCI_STORE` | unset | Filesystem adapter root used to verify digest-bound OCI artifact references at publish and apply, and to load signed offline-bundle layers onto an environment mirror |
| `TENKAI_EXECUTOR_GUARD` | current `tenkaictl` binary | Optional explicit guard path for applications embedding the Tenkai library |
| `TENKAI_PLAN_APPROVAL_DIR` | unset | Directory of signed plan-approval envelopes |
| `TENKAI_PLAN_APPROVAL_TRUST_ROOTS` | unset | Trust-root file for plan-approval verification |
| `TENKAI_PLAN_PRIORS` | unset | Set `1` to enable advisory planner priors; see [plan priors](plan-priors.md) |

## `tenkai-server`

| Variable | Default | Description |
| --- | --- | --- |
| `TENKAI_LISTEN` | `127.0.0.1:8080` | Server listen address; must remain loopback behind a TLS proxy |
| `TENKAI_RUNTIME_TOKENS` | `{}` | JSON object mapping bearer secrets to one environment each |
| `TENKAI_ENVIRONMENT_MANAGEMENT_TOKENS` | `{}` | JSON object mapping environment-scoped management bearers to one environment each; distinct from the fleet management token and runtime tokens |
| `TENKAI_OIDC_CONFIG` | unset | Filesystem path to an OIDC trust TOML file; the server verifies OIDC access tokens sent as `Authorization: Bearer` and maps groups to grants ([configure server authentication](configure-server-authentication.md#oidc-access-tokens-468)). Mutually exclusive with `TENKAI_JWT_VERIFIER_CONFIG` |
| `TENKAI_POSTGRES_URL` | unset | Hub tenant-store URL only; embedded `tenkaictl` and spoke `tenkai-server` fail closed when it is set. Non-loopback hosts require verified TLS |
| `TENKAI_INSTANCE_ID` | random UUID per process | Replica identity used for multi-replica fencing; the server records it as `tenkai-server-<value>` |
| `TENKAI_ENABLE_METRICS` | `false` | Enable the Prometheus scrape endpoint (`--enable-metrics`) |

### Optional providers

| Variable | Default | Description |
| --- | --- | --- |
| `TENKAI_SEKAI_URL` | `http://127.0.0.1:$GRPC_PORT` | Optional provider endpoint used by the server host |
| `GRPC_PORT` | `50051` | Port used for the optional provider URL |
| `SEKAI_AUTH_TOKEN` | unset | Optional provider bearer token |
| `TENKAI_OUTCOME_PROVIDER` | `disabled` | Set to `chisei` to enable durable terminal-outcome export |
| `TENKAI_OUTCOME_PROVIDER_URL` | unset | Explicit Sekai endpoint used only with `tenkai-server --outcome-provider chisei` |
| `TENKAI_OUTCOME_NAMESPACE` | unset | Namespace authorized for terminal-outcome admission |
| `TENKAI_OUTCOME_PROVIDER_PRINCIPAL` | `tenkai.outcome` | Authenticated telemetry-writer principal for outcome admission |
| `TENKAI_OUTCOME_PROVIDER_TOKEN` | unset | Optional outcome-adapter bearer secret; environment-only and never persisted |
| `TENKAI_OUTCOME_PROVIDER_REGISTRATION` | unset | Required exact attestation of the administrator-registered Sekai producer and `tenkai.terminal_outcome.v1@1.0.0` schema when outcome export is enabled |

## `tenkai-runtime`

| Variable | Default | Description |
| --- | --- | --- |
| `TENKAI_SERVER_URL` | unset | Control-plane URL; also used by `tenkaictl --target remote` |
| `TENKAI_RUNTIME_ENVIRONMENT` | unset | The one environment assigned to an environment-runtime process |
| `TENKAI_RUNTIME_TOKEN` | unset | Runtime-only bearer secret; kept out of command-line arguments and executor state |
| `TENKAI_RUNTIME_EXECUTOR` | unset | Absolute path to the environment executor implementing the idempotency contract |
| `TENKAI_RUNTIME_INVENTORY` | enabled | Set `0`/`false`/`off`/`no` to disable runtime inventory reports |

## Software executors

| Variable | Default | Description |
| --- | --- | --- |
| `TENKAI_SOFTWARE_EXECUTOR` | unset | Host software adapter: `helm`, `kubernetes` (`k8s` / `native`), `kubernetes-inprocess`, or `fake`; unset keeps the shell install path ([software executors](software-executor.md)) |
| `TENKAI_HELM_BIN` | `helm` | Helm binary used by the Helm software executor |
| `TENKAI_KUBECTL_BIN` | `kubectl` | kubectl binary used by the native Kubernetes software executor |

## Telemetry

| Variable | Default | Description |
| --- | --- | --- |
| `TENKAI_OTEL_ENDPOINT` | unset | OTLP/HTTP collector root; unset leaves traces and metrics as a no-op ([telemetry](telemetry.md)) |
| `TENKAI_OPERATION_ID` | unset | Inbound delivery correlation identity copied onto allowlisted spans (`tenkaictl --operation-id`) |

## Feature-specific settings

| Variables | Page |
| --- | --- |
| `TENKAI_PLAN_PRIORS_FILE`, `TENKAI_PLAN_PRIORS_OUTCOME`, `TENKAI_PLAN_PRIORS_OUTCOME_FILE`, `TENKAI_PLAN_PRIORS_OUTCOME_REQUIRED` | [Plan priors](plan-priors.md) |
| `TENKAI_PACKAGE_MIGRATION_APPROVAL_TRUST_ROOTS` | [Package migrations](package-migrations.md) |
| `TENKAI_LLAMA_SERVER`, `TENKAI_USE_REAL_LLAMA` | [Model runtime](model-runtime.md) |
| `TENKAI_DEVELOPMENT_FIXTURE_PRINCIPALS` (server refuses to start when set without `--with-development-fixtures`) | [Development fixtures](development-fixtures.md) |

`TENKAI_DELIVERY_ADAPTER` and the `TENKAI_WORKER_*` variables are internal test
and worker-lifecycle plumbing, not operator settings.

## Set by Tenkai for deploy commands

Manifest `install`, `health`, and `uninstall` commands run with a cleared
environment. They inherit only `PATH`, `HOME`, `USER`, `LOGNAME`, `LANG`,
`LC_ALL`, `LC_CTYPE`, `TMPDIR`, `TMP`, `TEMP`, and `TZ`, and receive:

| Variable | Value |
| --- | --- |
| `TENKAI_ENVIRONMENT` | The environment being deployed |
| `TENKAI_PRODUCT` | The product being deployed |
| `COMPOSE_PROJECT_NAME` | `tenkai-<digest>`, stable per environment and product |
| `TENKAI_FENCING_GENERATION` | The current lease generation, for mutation commands |

Control-plane secrets are never passed to deploy commands.

## Scripts and tests only

These are read by repository scripts or opt-in tests, not by the shipped
binaries.

| Variable | Read by | Description |
| --- | --- | --- |
| `TENKAI_DOGFOOD_MODE` | `scripts/dogfood-minikube.sh` | `local`, `signed-multi-env`, or `canary` ([minikube dogfood](local-dogfood-minikube.md)) |
| `TENKAI_DEV_KEYS` | `scripts/dogfood-minikube.sh` | Directory of development-only Ed25519 seeds |
| `TENKAI_CLUSTER_CONFIG` | `tests/in_process_kubernetes_kind.rs` | Kubeconfig path for the kind in-process Kubernetes test |
| `TENKAI_GATE_URL`, `TENKAI_GATE_TOKEN` | `tests/two_environment_closure_drill.rs` | Remote gate endpoint for the library-only HTTP gate adapter ([provider contracts](provider-contracts.md#remote-gate-http-json-contract-113)) |
| `SEKAI_CHISEI_DIR`, `REPLAY_OUTPUT_DIR` | `scripts/capture-rollback-replay.sh` | Provider checkout and output directory for the replay capture |
