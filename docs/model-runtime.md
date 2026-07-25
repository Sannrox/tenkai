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
source = "hf://org/model"
revision = "9bcf..."
format = "gguf"
quantization = "Q4_K_M"
artifact_digest = "sha256:…"   # 64 hex chars
license = "apache-2.0"

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

Supported fetch schemes today: `file://` (absolute), `http://`, `https://`.
`hf://` and `oci://` are reserved and fail closed until implemented. Digest
mismatch never activates the model.

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
   accelerator membership; `memory_gib` ≥ requirement).
4. Plan selects the **highest semver** among feasible candidates.
5. `constraint.version_pin.<product>` forces that version and fails closed if
   it does not fit — no silent fallback.
6. If no candidate fits, plan creation fails closed with a named
   fact/requirement error (no unconstrained “latest”).

Selection never bypasses signing, approval, or deployable-trust checks.

## Reference engine plugin (llama.cpp)

**Choice:** the reference plugin targets **llama.cpp** because manifests default
to `runtime.engine = "llama.cpp"`, health is plain HTTP on loopback, and a single
host can run without a GPU fleet control plane. MLX and other engines remain
future plugins implementing the same ports.

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
never requires an inference binary. Operators who install llama.cpp can inject
`LlamaCppProcessLauncher` (or set `TENKAI_LLAMA_SERVER`) in a host-specific
plugin build. Manifest fields are passed as argv only (no shell).

## Ordered rollout with routing_config

When an environment runs both `model_runtime` and `routing_config`, plan
computation **orders** steps (it does not merge kinds):

| Direction | Order |
| --- | --- |
| Install / upgrade | `model_runtime` → `routing_config` |
| Downgrade / rollback | `routing_config` → `model_runtime` |

Unsafe orders are rejected (`validate_model_routing_rollout_order`). See
[examples/model-routing-rollout](../examples/model-routing-rollout/README.md).

### Follow-on

- Peer/regional caches
- Additional engine plugins (MLX, vLLM, …)
