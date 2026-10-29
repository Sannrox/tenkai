# Environment variables

Operator settings read by the shipped binaries, grouped by the host that reads
them. Feature-specific settings are listed at the end with the page that
explains them. Secrets belong in the environment or a secret file, never on a
command line.

## Secret files

Every secret setting below (management and runtime tokens, the token maps,
`TENKAI_POSTGRES_URL`, `TENKAI_OUTCOME_PROVIDER_TOKEN`, `SEKAI_AUTH_TOKEN`,
`TENKAI_OIDC_CLIENT_SECRET`, `TENKAI_JWT_ASSERTION`, and the webhook secrets
named by `secret_env`) is read, in order, from:

1. the variable itself, `X`;
2. `X_FILE`, the path of a file holding the value;
3. `TENKAI_SECRET_DIR/X`, a file named after the setting in a secret
   directory.

Setting both `X` and `X_FILE` is refused. A secret file must be a regular file
owned by the user running Tenkai, with no group or world access (mode `0600`
or `0400`). Symlinks are followed, so a mounted secret volume works. One
trailing newline is dropped. Errors name the setting and path, never the value.

Webhook secrets are read again on every delivery, so a rotated file applies
without a restart. The other settings are read at startup; restart the
process after rotating them.

| Variable | Default | Description |
| --- | --- | --- |
| `TENKAI_SECRET_DIR` | unset | Directory holding one secret file per setting, named after it. |

## Shared by the hosts

Read by `tenkaictl`, `tenkai-server`, or both.

| Variable | Default | Description |
| --- | --- | --- |
| `TENKAI_DATABASE` | `.tenkai-state/tenkai.db` | Community SQLite path for embedded `tenkaictl` and community `tenkai-server`. Invalid with `--tenant-mode` or `TENKAI_POSTGRES_URL` |
| `TENKAI_HOST_WEBHOOKS` | unset | `tenkai-server` only: JSON list of webhook endpoints for host events (`backup.stale`, `clock.drift`, `trust.expiring`) ([operational events](deploy-webhooks.md#operational-events)) |
| `TENKAI_SMTP_SINKS` | unset | `tenkai-server` only: JSON list of SMTP digest sinks for operational events ([SMTP digests](deploy-webhooks.md#smtp-digests)) |
| `TENKAI_AUDIT_EXPORT_DIR` | unset | `tenkai-server` only: directory of the scheduled [audit export](audit-export.md) chain. Set with `TENKAI_AUDIT_SIGNING_KEY` |
| `TENKAI_AUDIT_SIGNING_KEY` | unset | Ed25519 seed file that signs audit exports |
| `TENKAI_AUDIT_EXPORT_INTERVAL_SECS` | `86400` | Seconds between scheduled audit exports |
| `TENKAI_AUDIT_TRUST_ROOTS` | unset | Trust roots for exports in the chain signed before an audit key rotation |
| `TENKAI_EXPORT_DIR` | unset | `tenkai-server` only: directory of exports created and downloaded over HTTP ([exports over HTTP](run-tenkai-server.md#exports-over-http)). Set with `TENKAI_EXPORT_SIGNING_KEY`. Refused in tenant mode |
| `TENKAI_EXPORT_SIGNING_KEY` | unset | Ed25519 seed file that signs support bundles and audit exports made over HTTP |
| `TENKAI_EXPORT_TRUST_ROOTS` | unset | Trust roots for audit exports made over HTTP and signed before an export key rotation |
| `TENKAI_EXPORT_RETENTION_DAYS` | unset | Days an export made over HTTP stays downloadable; unset keeps exports for good ([exports over HTTP](run-tenkai-server.md#exports-over-http)) |
| `TENKAI_IMPORT_SCANNER` | unset | Absolute path of a scanner run on every offline bundle import after signature verification and before any write ([offline bundles](offline-bundles.md#content-scanner)) |
| `TENKAI_IMPORT_SCANNER_TIMEOUT_SECS` | `600` | Seconds the import scanner may run before the import is refused |
| `TENKAI_IMPORT_SCANNER_SNAPSHOT_DIR` | the temp directory | Writable directory for the private copy of a bundle the scanner reads and the import then uses |
| `TENKAI_TIME_SOURCE` | unset | `tenkai-server` only: SNTP `host:port` for the runtime clock-drift check ([host preflight](host-preflight.md#keep-time-synchronized-after-install)) |
| `TENKAI_CLOCK_WARN_MS` | `1000` | Skew above which health reports `clock.state` as `warn` |
| `TENKAI_CLOCK_REFUSE_MS` | `30000` | Skew above which approvals, applies and runtime lease claims are refused |
| `TENKAI_CLOCK_CHECK_SECS` | `60` | Seconds between clock measurements |
| `TENKAI_CA_BUNDLE` | unset | PEM file of CA certificates every outbound TLS client trusts in addition to the built-in roots: registry and model downloads, OIDC, webhooks, telemetry, remote gates, the runtime agent, the remote CLI and its login, the gRPC outcome provider, the remote backend and PostgreSQL. Unreadable or empty fails closed. Kubernetes clients use their kubeconfig CA |
| `TENKAI_TLS_SYSTEM_ROOTS` | `true` | `false` drops the built-in and platform roots, so only `TENKAI_CA_BUNDLE` is trusted; requires the bundle. A remote HTTPS backend (`TENKAI_SEKAI_URL`) is refused with `false` until its client can drop its built-in roots |
| `TENKAI_BACKUP_DIR` | unset | `tenkai-server` only: directory for scheduled and on-demand backups ([backup and restore](backup-restore.md#server-mode-backups)). In tenant mode, the directory of recorded PostgreSQL backup evidence ([evidence](backup-restore.md#postgresql-backup-evidence)) |
| `TENKAI_BACKUP_INTERVAL_SECS` | `86400` | Seconds between scheduled backups; `0` takes backups only on demand |
| `TENKAI_BACKUP_RETAIN` | `7` | Backups kept; older ones are removed after each backup |
| `TENKAI_BACKUP_MAX_AGE_SECS` | twice the interval, else `172800` | Backup age after which health reports `backup.state` as `stale` |
| `TENKAI_BACKUP_SIGNING_KEY` | unset | Ed25519 seed file (32 bytes, mode 0600) that signs each backup manifest; `tenkaictl restore-drill --trust-roots` verifies it. Refused in tenant mode, as are the interval and retention |
| `TENKAI_IMPORT_STAGING_DIR` | unset | `tenkai-server` only: server-owned directory of staged offline bundles for `/v1/imports` ([offline bundles](offline-bundles.md#server-side-import)). Set with `TENKAI_BUNDLE_TRUST_ROOTS` |
| `TENKAI_BUNDLE_TRUST_ROOTS` | unset | Trust roots that must authenticate an exporter of a bundle imported through the server |
| `TENKAI_STATE_DIR` | `<workdir-parent>/.tenkai-state` | Immutable deploy-input snapshots and per-environment runtime directories; must be outside the source workdir |
| `TENKAI_PRINCIPAL` | `tenkai` (`local-operator` for embedded `env retire`) | Embedded audit principal or remote provider caller identity |
| `TENKAI_MANAGEMENT_TOKEN` | unset | Community management bearer for server management requests, remote CLI mode, and embedded `promote` / canary mutations including `canary repair`. When set, remote `tenkaictl` uses it instead of a saved OIDC login |
| `TENKAI_CLIENT_ID` | unset | Optional public OIDC client id for `tenkaictl login`; defaults to `GET /v1/auth/oidc` |
| `TENKAI_OIDC_CLIENT_ID` | unset | Optional OIDC client id for `tenkaictl login`, including `--client-credentials`; preferred over `TENKAI_CLIENT_ID`. CLI-only |
| `TENKAI_OIDC_CLIENT_SECRET` | unset | Confidential OIDC client secret for `tenkaictl login --client-credentials`. CLI-only; never passed on a command line, never stored in `tokens.json`, and never set on `tenkai-server` |
| `TENKAI_JWT_ASSERTION` | unset | Optional compact JWT for embedded `promote` / canary mutations including `canary repair`; requires `TENKAI_JWT_VERIFIER_CONFIG` |
| `TENKAI_JWT_VERIFIER_CONFIG` | unset | Filesystem path to a JWT trust TOML file for enterprise JWT verification. May be set together with `TENKAI_OIDC_CONFIG` when the issuers differ |
| `TENKAI_OCI_STORE` | unset | Filesystem adapter root used to verify digest-bound OCI artifact references at publish and apply, to load signed offline-bundle layers onto an environment mirror, and served read-only by `tenkaictl registry serve` ([seed registry](offline-bundles.md#seed-registry)) |
| `TENKAI_EXECUTOR_GUARD` | current `tenkaictl` binary | Optional explicit guard path for applications embedding the Tenkai library |
| `TENKAI_PLAN_APPROVAL_DIR` | unset | Directory of signed plan-approval envelopes |
| `TENKAI_PLAN_APPROVAL_TRUST_ROOTS` | unset | Trust-root file for plan-approval verification |
| `TENKAI_KEY_REVOCATIONS` | unset | Installed signed key revocation list, applied at startup; set with `TENKAI_KEY_REVOCATION_TRUST_ROOTS` ([key rollover](key-rollover.md)) |
| `TENKAI_KEY_REVOCATION_TRUST_ROOTS` | unset | Release-format trust roots naming the revocation authorities |
| `TENKAI_SIGNER_MODULE` | unset | PKCS#11 module path for the production content signer ([release signing](release-signing.md#production-signer)) |
| `TENKAI_SIGNER_TOKEN` | unset | PKCS#11 token label for the production content signer |
| `TENKAI_SIGNER_PIN` | unset | PKCS#11 user PIN for the production content signer (secret setting) |
| `TENKAI_SIGNER_KEY_LABEL` | `tenkai-signer` | PKCS#11 object label of the Ed25519 signing key pair |
| `TENKAI_SIGNER_KEY` | unset | Lab-only path of a 32-byte Ed25519 seed. A production profile refuses it |
| `TENKAI_PLAN_PRIORS` | unset | Set `1` to enable advisory planner priors; see [plan priors](plan-priors.md) |

## `tenkai-server`

| Variable | Default | Description |
| --- | --- | --- |
| `TENKAI_LISTEN` | `127.0.0.1:8080` | Server listen address; must remain loopback behind a TLS proxy |
| `TENKAI_RUNTIME_TOKENS` | `{}` | JSON object mapping bearer secrets to one environment each |
| `TENKAI_ENVIRONMENT_MANAGEMENT_TOKENS` | `{}` | JSON object mapping environment-scoped management bearers to one environment each; distinct from the fleet management token and runtime tokens |
| `TENKAI_OIDC_CONFIG` | unset | Filesystem path to an OIDC trust TOML file; the server verifies OIDC access tokens sent as `Authorization: Bearer` and maps groups to grants ([configure server authentication](configure-server-authentication.md#oidc-access-tokens-468)). May be set together with `TENKAI_JWT_VERIFIER_CONFIG` when the issuers differ |
| `TENKAI_POSTGRES_URL` | unset | Sole hub store URL for `--tenant-mode`. Invalid together with `TENKAI_DATABASE`. Embedded `tenkaictl` and spoke `tenkai-server` fail closed when it is set. Non-loopback hosts require verified TLS |
| `TENKAI_INSTANCE_ID` | random UUID per process | Replica identity used for multi-replica fencing; the server records it as `tenkai-server-<value>` |
| `TENKAI_TLS_CERT` | unset | `tenkai-server` only: PEM certificate chain for [native TLS](run-tenkai-server.md#native-tls); required for a non-loopback bind |
| `TENKAI_TLS_KEY` | unset | Secret setting: PEM private key for `TENKAI_TLS_CERT` (also `TENKAI_TLS_KEY_FILE` or the secret directory) |
| `TENKAI_TLS_CLIENT_CA` | unset | PEM CA bundle that verifies client certificates when presented |
| `TENKAI_TLS_REQUIRE_RUNTIME_CLIENT_CERT` | `false` | Refuse `/v1/runtime/*` without a verified client certificate, except enrollment; needs `TENKAI_TLS_CLIENT_CA` |
| `TENKAI_TRUST_WARNING_DAYS`, `TENKAI_TRUST_CRITICAL_DAYS` | `30`, `7` | `tenkai-server` only: certificate expiry thresholds of the [trust posture](run-tenkai-server.md#trust-posture) |
| `TENKAI_TRUST_CHANGE_EVENTS` | `false` | `tenkai-server` only: `true` appends a `trust_threshold_crossed` change event on `/v1/events` per certificate threshold crossing, and `trust/ok` on recovery. Enable only once every replica, and any rollback target, runs a release whose change-event readers skip unknown kinds (#775) ([trust posture](run-tenkai-server.md#trust-posture)) |
| `TENKAI_RUNNER_CA_CERT`, `TENKAI_RUNNER_CA_KEY` | unset | `tenkai-server` only: the [runner CA](run-tenkai-server.md#runner-certificates) (PEM files, set together) that issues and admits runner certificates; during rotation the certificate file lists the new CA first, then the old |
| `TENKAI_RUNTIME_CERTIFICATE_DIR` | unset | `tenkai-runtime`: keeps the runner key, certificate and CA; needs `TENKAI_RUNTIME_CREDENTIAL_FILE` |
| `TENKAI_RUNTIME_KEY_STORE` | `file` | `tenkai-runtime`: `file` writes `key.pem` in the certificate directory; `hardware` generates a non-exportable PKCS#11 key (TPM 2.0 on Linux) and writes only a locator ([attested runners](run-tenkai-server.md#attested-runners)) |
| `TENKAI_RUNTIME_PKCS11_MODULE` | TPM PKCS#11 if present | PKCS#11 module for `TENKAI_RUNTIME_KEY_STORE=hardware`; required unless a TPM 2.0 module is on the default Linux path |
| `TENKAI_RUNTIME_PKCS11_TOKEN` | unset | PKCS#11 token label for the hardware runner key |
| `TENKAI_RUNTIME_PKCS11_PIN` | unset | Secret setting: PIN for that token (`TENKAI_RUNTIME_PKCS11_PIN_FILE` or the secret directory) |
| `TENKAI_RUNTIME_PKCS11_KEY_LABEL` | `tenkai-runner` | PKCS#11 object label of the hardware runner key |
| `TENKAI_RUNTIME_PREFLIGHT_CONFIG` | unset | `tenkai-runtime`: host preflight config whose checks the agent runs and signs when its environment requires runner attestation; without it, attestation carries only the probed host facts ([attested runners](run-tenkai-server.md#attested-runners)) |
| `TENKAI_TLS_MIN_VERSION` | `1.3` | Lowest TLS version accepted: `1.3` or `1.2` |
| `TENKAI_ENABLE_METRICS` | `false` | Enable the Prometheus scrape endpoint (`--enable-metrics`) |
| `TENKAI_AGENT_ACTOR_POLICY` | `require_approval` | Mutations whose token `act` chain names an agent: `require_approval` allows only plans, which still need approval under the environment's policy; `forbid` refuses all ([auth request context](auth-request-context.md#delegated-calls-and-agent-actors)) |

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
| `TENKAI_RUNTIME_CREDENTIAL_FILE` | unset | Where an enrolled runtime keeps its own credential, owner-only; replaces `TENKAI_RUNTIME_TOKEN` ([enrolling a runtime](run-tenkai-server.md#enrolling-a-runtime)) |
| `TENKAI_RUNTIME_ENROLLMENT_TOKEN` | unset | Single-use token exchanged for that credential on first start; unused once the file exists |
| `TENKAI_RUNTIME_HOME` | unset | Where the runtime agent keeps its own versions, so Tenkai can upgrade and roll it back ([upgrading the runtime agent](run-tenkai-server.md#upgrading-the-runtime-agent)) |
| `TENKAI_RUNTIME_EXECUTOR` | unset | Absolute path to the environment executor implementing the idempotency contract |
| `TENKAI_RUNTIME_INVENTORY` | enabled | Set `0`/`false`/`off`/`no` to disable runtime inventory reports |

## Software executors

| Variable | Default | Description |
| --- | --- | --- |
| `TENKAI_SOFTWARE_EXECUTOR` | unset | Host software adapter: `helm`, `kubernetes` (`k8s` / `native`), `kubernetes-inprocess`, `docker`, or `fake`; unset keeps the shell install path ([software executors](software-executor.md)) |
| `TENKAI_HELM_BIN` | `helm` | Helm binary used by the Helm software executor |
| `TENKAI_KUBECTL_BIN` | `kubectl` | kubectl binary used by the native Kubernetes software executor |
| `TENKAI_DOCKER_BIN` | `docker` | Docker CLI used by the Docker host software executor |

## Telemetry

| Variable | Default | Description |
| --- | --- | --- |
| `TENKAI_OTEL_ENDPOINT` | unset | OTLP/HTTP collector root; unset leaves traces and metrics as a no-op ([telemetry](telemetry.md)) |
| `TENKAI_OPERATION_ID` | unset | Inbound delivery correlation identity copied onto allowlisted spans (`tenkaictl --operation-id`) |

## Feature-specific settings

| Variables | Page |
| --- | --- |
| Named webhook HMAC secrets (`secret_env` on `tenkaictl env webhooks set`, for example `TENKAI_WEBHOOK_SECRET`) | [Post-deploy webhooks](deploy-webhooks.md) |
| `TENKAI_PLAN_PRIORS_FILE`, `TENKAI_PLAN_PRIORS_OUTCOME`, `TENKAI_PLAN_PRIORS_OUTCOME_FILE`, `TENKAI_PLAN_PRIORS_OUTCOME_REQUIRED` | [Plan priors](plan-priors.md) |
| `TENKAI_PACKAGE_MIGRATION_APPROVAL_TRUST_ROOTS` | [Package migrations](package-migrations.md) |
| `TENKAI_LLAMA_SERVER`, `TENKAI_USE_REAL_LLAMA`, `TENKAI_MLX_SERVER`, `TENKAI_USE_REAL_MLX`, `TENKAI_MODEL_REGISTRY_TRUSTED_KEYS`, `TENKAI_MODEL_REGISTRY_URL` | [Model runtime](model-runtime.md) |
| `TENKAI_WEIGHT_CACHE` | [Offline bundles](offline-bundles.md) |
| `TENKAI_VLLM_IMAGE`, `TENKAI_VLLM_WEIGHTS_CLAIM`, `TENKAI_VLLM_WEIGHTS_ROOT`, `TENKAI_VLLM_SMOKE_BASE_URL` | [vLLM and TGI Kubernetes executor](vllm-kubernetes.md) |
| `TENKAI_TGI_IMAGE`, `TENKAI_TGI_WEIGHTS_CLAIM`, `TENKAI_TGI_WEIGHTS_ROOT`, `TENKAI_TGI_SMOKE_BASE_URL` | [vLLM and TGI Kubernetes executor](vllm-kubernetes.md) |
| `TENKAI_NIM_IMAGE`, `TENKAI_NIM_WEIGHTS_CLAIM`, `TENKAI_NIM_WEIGHTS_ROOT`, `TENKAI_NIM_SMOKE_BASE_URL`, `TENKAI_NIM_PULL_SECRET`, `TENKAI_NIM_NGC_API_KEY_SECRET` | [vLLM, TGI and NIM Kubernetes executor](vllm-kubernetes.md) |
| `TENKAI_DEVELOPMENT_FIXTURE_PRINCIPALS` (server refuses to start when set without `--with-development-fixtures`) | [Development fixtures](development-fixtures.md) |

The `TENKAI_WORKER_*` variables are internal worker-lifecycle plumbing, not
operator settings.

## Build time

| Variable | Default | Description |
| --- | --- | --- |
| `TENKAI_UI_BUNDLE` | unset | With `cargo build -p tenkai-server --features ui`, path to a local copy of the pinned console zip; skips the download but still enforces the checksum in `ui/console.pin` ([open the web console](run-tenkai-server.md#open-the-web-console)) |

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
| `TENKAI_CLUSTER_CONFIG` | `crates/tenkai-executor/tests/in_process_kubernetes_kind.rs`, `crates/tenkai-executor/tests/gpu_kubernetes_live.rs` | Kubeconfig path for ignored in-process Kubernetes tests |
| `TENKAI_VLLM_LIVE_TEST`, `TENKAI_VLLM_NAMESPACE`, `TENKAI_VLLM_MODEL_TAR`, `TENKAI_VLLM_NODE_SELECTOR`, `TENKAI_VLLM_TOLERATIONS`, and the same `TENKAI_TGI_*` and `TENKAI_NIM_*` names | `crates/tenkai-executor/tests/gpu_kubernetes_live.rs` | Opt-in GPU apply/rollback; namespace must already hold the weights claim |
| `TENKAI_MLX_SERVER` | `src/model_runtime/mlx.rs` (`mlx_operator_golden_path`) | Opt-in real `mlx_lm.server`; default CI uses `FakeMlxEngine` |
| `TENKAI_GATE_URL`, `TENKAI_GATE_TOKEN` | `crates/tenkaictl/tests/two_environment_closure_drill.rs` | Remote gate endpoint for the library-only HTTP gate adapter ([provider contracts](provider-contracts.md#remote-gate-http-json-contract-113)) |
| `SEKAI_CHISEI_DIR`, `REPLAY_OUTPUT_DIR` | `scripts/capture-rollback-replay.sh` | Provider checkout and output directory for the replay capture |
