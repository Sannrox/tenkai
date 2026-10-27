# Model runtime products

Tenkai can publish **model runtime** releases that describe which open-weight
model an environment should run, without becoming an inference engine.

Decision: [ADR 0007](decisions/0007-model-runtime-fleet-control-plane.md).  
Source: `src/model_runtime.rs`, `src/manifest.rs`.

## Manifest example

```toml
[product]
name = "qwen-coder"
version = "3.2.1"
kind = "model_runtime"

[model]
source = "hf://org/model/model-q4_k_m.gguf"   # or oci://registry/repo@sha256:…
revision = "9bcf…"             # hf://: the full 40-hex commit
format = "gguf"
quantization = "Q4_K_M"
artifact_digest = "sha256:…"   # 64 hex chars
license = "apache-2.0"
# registry_descriptor = "signed-descriptor.json"  # required for engine = "onnx"
# registry_attestation = "promotion-attestation.json"  # required to promote engine = "onnx"

[runtime]
engine = "llama.cpp"
port = 8080
context_length = 32768

[requirements]
architecture = ["arm64"]
memory_gib = 32
accelerator = ["apple-metal"]

[health]
endpoint = "http://127.0.0.1:8080/v1/models"
smoke_prompt = "Return exactly: OK"
max_startup_seconds = 300
```

Rules:

- No shell `deploy.install` / `uninstall` / `health` commands.
- No `deploy.inputs` weight files (use `model.artifact_digest`).
- No `[routing]` section (use a separate `routing_config` product).

## Lifecycle

Same as software and routing: publish → channel → subscribe → plan → apply →
health → rollback. The local reference executor stages the **descriptor** only.
Engine plugins that download multi-GB weights implement `ModelRuntimeExecutor`.

Apply selects the executor by `runtime.engine`. `llama.cpp` keeps the
reference executor. `mlx` is the Apple-silicon host-process executor next to
it (fake engine in CI; real `mlx_lm.server` behind `TENKAI_MLX_SERVER` /
`TENKAI_USE_REAL_MLX`). `onnx` uses the classical scoring executor: it verifies a
signed registry online descriptor (`model.registry_descriptor`) against
trusted registry keys, checks the artifact digest, applies declared
resources and health paths, and runs scoring through an injected engine port
(a fake engine in CI). Prediction summaries are exported to the descriptor
monitoring path. `vllm` uses the host-injected executor, only on an
environment that carries `cluster_config_path`; without a cluster
configuration or a host executor it fails closed, as does any unknown engine.
The host registers its factory at process start (`tenkai-executor` installs
the vLLM factory; serving image, weights claim, and the claim's host mount
come from `TENKAI_VLLM_IMAGE` / `TENKAI_VLLM_WEIGHTS_CLAIM` /
`TENKAI_VLLM_WEIGHTS_ROOT`). Model-runtime apply and
remove run under the executor guard: the environment fence is refreshed and
the mutation lock is held for the whole call.

## Separation from routing

| Product | Meaning |
| --- | --- |
| `model_runtime` | Which weights/engine/port this host should run |
| `routing_config` | Which logical routes point at which models |

Coordinate both with ordinary multi-step plans.

## Weight cache

`WeightCache` stores verified blobs under a content-addressed path outside
operational SQLite:

```text
<cache-root>/sha256/<64-hex>
```

Fetch schemes: `file://` (absolute), `http://`, `https://`, `hf://`, and
`oci://`. Digest mismatch never activates the model, and the partial download is
removed.

- `hf://<org>/<repo>/<file path>` downloads that file at `model.revision`, which
  must be the full 40-hex commit. Branch and tag names are refused at manifest
  validation. The cache resolves against `https://huggingface.co` unless the
  embedder calls `WeightCache::with_hub(endpoint, token)`; the token is never in
  a manifest and is redacted from `Debug`.
- On apply, `WeightCache::with_environment` applies the environment's policy.
  An `artifact_mirror.<hub host>` entry (`tenkaictl env artifact-mirror set
  <env> huggingface.co=<mirror>`) moves `hf://` resolution onto
  `https://<mirror>`; in an `isolated` environment a redirect that leaves the
  mirror is refused. An `isolated` environment without that mirror refuses
  `hf://` before any network attempt, naming the model and the missing mirror;
  blobs already in the cache, such as weights imported from an offline bundle,
  still resolve.
- `oci://<registry>/<repository>@sha256:<hex>` names a single-blob artifact of
  media type `application/vnd.tenkai.model.weights.v1`; the digest must equal
  `model.artifact_digest`. The cache pulls through
  `WeightCache::with_artifact_registry(registry, mirrors)`, rewritten onto the
  environment mirror like release artifacts; origin pull is refused. The blob is
  held in memory while it is written to the cache.
- `model_runtime::weight_artifact(&model)` returns the `oci://` reference so
  offline bundle export can carry the weights with
  `offline_bundle::insert_artifact_layers`.

Wire a cache into the local executor with
`LocalModelRuntimeExecutor::with_weight_cache(...)`.

Eviction: `WeightCache::evict(protected_digests, keep)` removes oldest
unprotected blobs until at most `keep` files remain. Active digests must be
passed in `protected` and are never deleted.

## Planner variant selection

Related hardware variants of a model are **published releases of the same
product name** (for example `qwen-coder@1.0.0` Q4 and `qwen-coder@1.1.0` Q8).
Each release declares `[requirements]` (`architecture`, `memory_gib`,
`accelerator`).

When planning a `model_runtime` subscription:

1. Environment capability facts (`architecture`, `memory_gib`, and
   `accelerator` when required) are read from the environment.
2. Candidates are published releases of that product at or below the channel
   head, optionally filtered by `constraint.version_range.<product>`.
3. A candidate fits when facts satisfy its requirements (architecture and
   accelerator membership; `memory_gib` ≥ requirement; GPU requirements below).
4. Plan selects the **highest semver** among feasible candidates.
5. `constraint.version_pin.<product>` forces that version and fails closed if
   it does not fit — no silent fallback.
6. If no candidate fits, plan creation fails closed with a named
   fact/requirement error (no unconstrained “latest”).

Selection never bypasses signing, approval, or deployable-trust checks.

### GPU requirements

A variant that needs GPUs declares `[requirements.gpu]`:

```toml
[requirements.gpu]
vendor = ["nvidia"]          # gpu_vendor; empty: any
families = ["hopper"]        # gpu_family; empty: any
vram_gib = 80                # gpu_vram_gib, per device
count = 1                    # gpu_count minimum (default 1)
tensor_parallel = 2          # needs gpu_count >= 2 (default 1)
driver_min = "535"           # gpu_driver_version, dotted numeric
runtime = "cuda"             # gpu_runtime: cuda or rocm
runtime_min = "12.1"         # gpu_runtime_version; needs runtime
```

Each field is checked against the Environment fact named in the comment. A
missing fact is unknown and never fits. Versions compare numerically per
component (`12.10` > `12.2`). A refusal names a stable reason code in the plan
error: `fact_missing`, `fact_invalid`, `fact_not_allowed`, or
`fact_below_minimum`. `gpu_model` is recorded for operators and is not matched.
Fractional sharing (MIG/MPS) and placement inside a cluster are out of scope.

```bash
tenkaictl env facts set gpu-a gpu_vendor=nvidia
tenkaictl env facts set gpu-a gpu_family=hopper
tenkaictl env facts set gpu-a gpu_vram_gib=80
tenkaictl env facts set gpu-a gpu_count=2
tenkaictl env facts set gpu-a gpu_driver_version=535.104.05
tenkaictl env facts set gpu-a gpu_runtime=cuda
tenkaictl env facts set gpu-a gpu_runtime_version=12.2
```

The local inventory probe does not detect GPUs yet; set these facts explicitly.

Populate facts with a local inventory probe (dry-run by default):

```bash
tenkaictl env facts probe local
tenkaictl env facts probe local --apply
```

Environment runtimes can also refresh admitted facts on each poll via
`POST /v1/runtime/environments/{env}/inventory` (provenance `runtime-probe`).
Disable with `tenkai-runtime --no-inventory-report` or
`TENKAI_RUNTIME_INVENTORY=0`. See `src/inventory.rs` and #136. Probes never
leave the host or invent unknown keys.

## Reference engine plugin (llama.cpp)

**Choice:** the reference plugin targets **llama.cpp** because manifests default
to `runtime.engine = "llama.cpp"`, health is plain HTTP on loopback, and a single
host can run without a GPU fleet control plane. `runtime.engine = "mlx"` is the
Apple-silicon sibling of this path. `vllm` and `tgi` serve on Kubernetes
([vLLM and TGI](vllm-kubernetes.md)). NVIDIA NIM remains a future plugin.

### Ports

| Type | Role |
| --- | --- |
| `InferenceEngineProcess` | start candidate / smoke / stop (no hard engine link) |
| `FakeInferenceEngine` | Deterministic CI lifecycle without a binary |
| `LlamaCppProcessLauncher` | Optional external `TENKAI_LLAMA_SERVER` / `llama-server` |
| `ReferenceLlamaCppExecutor` | verify weights → start → smoke → activate; retain previous |

### Happy path (one machine class)

1. Publish/promote a `model_runtime` release with loopback health
   (`http://127.0.0.1:<port>/…`).
2. Apply via Tenkai (embedded or runtime agent). The reference executor:
   - verifies weights when a `WeightCache` is configured;
   - starts a **candidate** generation on loopback only;
   - smoke-probes `[health]`;
   - on success, promotes the candidate to active and keeps the prior
     descriptor at `*.json.previous` for Tenkai rollback;
   - on smoke/start failure, stops the candidate and **leaves the previous
     active generation untouched**.
3. Rollback uses ordinary Tenkai plan/rollback paths against retained releases.

Default apply wiring uses `FakeInferenceEngine` so community software-only CI
never requires an inference binary. Operators enable the real process via env
(see golden path below). Manifest fields are passed as argv only (no shell).

## Classical ONNX scoring

Parent epic: [#651](https://github.com/Sannrox/tenkai/issues/651).  
Issues: [#727](https://github.com/Sannrox/tenkai/issues/727),
[#728](https://github.com/Sannrox/tenkai/issues/728);
registry attestation: [Sannrox/hinagata#39](https://github.com/Sannrox/hinagata/issues/39).

`runtime.engine = "onnx"` is the deploy path for classical models registered
with a signed online descriptor. The release carries the descriptor as
`model.registry_descriptor` (a relative JSON file, hashed with the other
immutable inputs) and, for channel promotion, a signed registry promotion
attestation as `model.registry_attestation`. Apply:

1. Verifies the signed descriptor and the embedded version manifest against
   the host's trusted registry keys (`TENKAI_MODEL_REGISTRY_TRUSTED_KEYS`).
2. Refuses a digest mismatch between the descriptor, the manifest, and
   `model.artifact_digest`, and verifies the weight bytes through
   `WeightCache`.
3. Starts a candidate scoring runtime through `OnnxScoringEngine` (CI uses
   `FakeOnnxEngine`) with the descriptor's resources and `/healthz` /
   `/readyz` health paths.
4. On smoke success, activates the candidate, retains the previous generation
   for ordinary Tenkai rollback, and exports a prediction summary to the
   descriptor monitoring path (`TENKAI_MODEL_REGISTRY_URL` when set).

Unknown keys, a tampered descriptor, or a missing workdir fail closed.

Channel promotion of an `onnx` release requires a valid
`hinagata.signed-attestation/v1` over `hinagata.promotion-attestation/v1`
matching the descriptor's namespace, model, version, and artifact digest,
signed by a trusted registry key. A missing file, an archived stage, or a
mismatched digest or version is refused with that named reason. Releases
that are not classical `onnx` model_runtime products are unchanged.

| Variable | Meaning |
| --- | --- |
| `TENKAI_MODEL_REGISTRY_TRUSTED_KEYS` | JSON file `{"keys":[{"key_id":"…","public_key":"<64 hex>"}]}` |
| `TENKAI_MODEL_REGISTRY_URL` | Optional base URL that receives `POST {path}` prediction summaries |

### Operator golden path (real llama.cpp)

One machine class: local host with loopback networking. The core crate still
does **not** link llama.cpp.

**Prerequisites**

- A `llama-server` (or equivalent) binary that accepts:
  `--host`, `--port`, `--model <weights-path>`
- Open-weight file on disk (or `file://` / `http(s)://` source for `WeightCache`)
- Health endpoint on loopback only, e.g. `http://127.0.0.1:8080/v1/models`

**Environment**

| Variable | Meaning |
| --- | --- |
| `TENKAI_LLAMA_SERVER` | Absolute or PATH path to the server binary (enables real engine) |
| `TENKAI_USE_REAL_LLAMA=1` | Use default binary name `llama-server` from `PATH` |

When neither is set, apply uses `FakeInferenceEngine` (CI-safe).

**Sequence (embedded)**

```bash
export TENKAI_LLAMA_SERVER=/usr/local/bin/llama-server   # or TENKAI_USE_REAL_LLAMA=1

# 1. Publish / promote a model_runtime with loopback health and file:// weights
export TENKAI_MANAGEMENT_TOKEN='replace-from-secret-store'
tenkaictl publish examples/model-runtime-local/tenkai.toml --allow-unsigned-development
tenkaictl eval-evidence trust --trust-roots eval-trust.toml
tenkaictl eval-evidence record evaluation-result.json
tenkaictl promote qwen-coder@0.1.0 stable
tenkaictl env subscribe local qwen-coder=stable   # if not already subscribed

# 2. Plan + apply (weights verify when cache is configured; smoke via HTTP).
#    `reconcile --once` also creates and executes a plan; the explicit path is:
tenkaictl plan --env local
tenkaictl apply <plan-id> \
  --allow-unapproved-development \
  --development-reason "local model_runtime"

# 3. On smoke failure the previous active generation remains; retry or rollback
#    with ordinary Tenkai plan/rollback — do not delete *.json.previous by hand.
```

**Security**

- Bind host is forced to loopback (`127.0.0.1` / `::1` / `localhost`).
- Process is spawned with argv only (no `sh -c`); never put credentials in the
  manifest.
- Do not expose the inference port beyond loopback in the reference path.

**Optional integration test**

```bash
# Requires a real binary; skipped in default CI
TENKAI_LLAMA_SERVER=/path/to/llama-server \
  cargo test --locked llama_cpp_operator_golden_path -- --ignored --nocapture
```

## Canary promotion evidence (model_runtime)

`model_runtime` uses the **same** canary promotion gate as software products
(#7). `wave run` and fleet status only observe posture. `wave execute` may
apply per-environment plans for a pinned release (ADR 0017); waves never
authorize a wider channel promotion.

Documented path (embedded; FakeInferenceEngine is fine for CI):

```bash
# 0. Init + canary host
tenkaictl init
tenkaictl canary designate local

# 1. Publish model_runtime and put it on a free "canary" channel first
tenkaictl publish examples/model-runtime-local/tenkai.toml --allow-unsigned-development
tenkaictl eval-evidence trust --trust-roots eval-trust.toml
tenkaictl eval-evidence record evaluation-result.json
tenkaictl promote qwen-coder@0.1.0 canary

# 2. Require complete canary evidence before promoting to stable
tenkaictl canary policy qwen-coder@0.1.0 stable --env local

# 3. Apply on the canary cohort (do NOT --skip-gates: pass evidence needs
#    GateOutcome::Satisfied). Unsigned apply is local-only; use signed
#    releases + plan approval for non-local canary environments.
tenkaictl env subscribe local qwen-coder=canary
tenkaictl env facts probe local --apply   # architecture / memory / accelerator
tenkaictl plan --env local
tenkaictl apply <plan-id> \
  --allow-unapproved-development \
  --development-reason "local model_runtime canary"

# 4. Wider promote succeeds only with complete passing evidence
tenkaictl promote qwen-coder@0.1.0 stable

# Missing, failed, or rolled-back canary outcomes block promote with an
# actionable error. `canary policy ... --reactivate` invalidates prior evidence.
```

Deterministic suite: `model_runtime_canary_evidence_gates_stable_promotion` in
`src/canary.rs` (missing blocks; passing permits; reactivate stale-blocks;
incomplete multi-env cohort blocks). Related: [rollout waves](rollout-waves.md),
[fleet status](server-diagnostics.md#fleet-status-operator-table).

Software products use the same canary gate. The minikube dogfood path exercises
it for `hello-minikube` via `TENKAI_DOGFOOD_MODE=canary` — see
[software canary cohort drill](local-dogfood-minikube.md#software-canary-cohort-drill-154).

## Ordered rollout with routing_config

When an environment runs both `model_runtime` and `routing_config`, plan
computation **orders** steps (it does not merge kinds):

| Direction | Order |
| --- | --- |
| Install / upgrade | `model_runtime` → `routing_config` |
| Downgrade / rollback | `routing_config` → `model_runtime` |

Unsafe orders are rejected (`validate_model_routing_rollout_order`). See
[examples/model-routing-rollout](../examples/model-routing-rollout/README.md).

## MLX on Apple silicon hosts

`runtime.engine = "mlx"` is the host-process executor for Apple silicon / edge
hosts. It reuses the llama.cpp lifecycle: `WeightCache` verifies weights, a
candidate binds loopback only, health plus a completion smoke must pass, then
the candidate activates and the previous generation is retained for ordinary
Tenkai rollback. A failed candidate is stopped and does not replace the
active generation.

Default apply wiring uses `FakeMlxEngine`, so community CI never needs an
Apple GPU or an MLX binary. Operators enable the real process via env.

`accelerator = ["apple-metal"]`. Do not declare `[requirements.gpu]` with
`cuda` or `rocm`; those facts are NVIDIA/AMD GPU inventory.

### Ports

| Type | Role |
| --- | --- |
| `FakeMlxEngine` | Deterministic CI lifecycle without a binary |
| `MlxLmServerLauncher` | Optional external `TENKAI_MLX_SERVER` / `mlx_lm.server` |
| `MlxHostExecutor` | verify weights → start → health and completion smoke → activate; retain previous |

### Environment

| Variable | Meaning |
| --- | --- |
| `TENKAI_MLX_SERVER` | Absolute or PATH path to the server binary (enables real engine) |
| `TENKAI_USE_REAL_MLX=1` | Use default binary name `mlx_lm.server` from `PATH` |
| `TENKAI_WEIGHT_CACHE` | Cache root for the verified `--model` path (default: a sidecar of the runtime state file) |

When neither server variable is set, apply uses `FakeMlxEngine` (CI-safe) and
does not fetch weights. Enabling the real engine always attaches a
`WeightCache` and passes the verified blob path as `--model`. The binary is
spawned with argv only (`--host`, `--port`, `--model <verified path>`); never
put credentials in the manifest. Bind host is forced to loopback. Completion
smoke uses the model id advertised at `/v1/models`.

**Optional integration test**

```bash
# Requires a real binary; skipped in default CI
TENKAI_MLX_SERVER=/path/to/mlx_lm.server \
  cargo test --locked mlx_operator_golden_path -- --ignored --nocapture
```

## vLLM on Kubernetes

`runtime.engine = "vllm"` uses the host-injected Kubernetes executor. Serving
image, weights claim, node selectors, tolerations, and the smoke base URL are
host configuration. See [vLLM Kubernetes executor](vllm-kubernetes.md).

## Model-release evidence

Two-way promotion evidence for a model identity (provider, model, profile
version, artifact digest, opaque serving endpoint) is defined in
[model-release evidence](model-release-evidence.md) ([ADR 0032](decisions/0032-model-release-evidence.md)).
Channel promotion requires a passing, fresh evaluation record for that
identity; missing, stale, or invalid results block `promote`. Install
signers and record the signed result with `tenkaictl eval-evidence`
([model-release evidence](model-release-evidence.md#channel-promotion)).

## Follow-on

- Peer/regional caches
- Additional engine plugins: NVIDIA NIM
  ([research](research/additional-model-serving-executors.md))
