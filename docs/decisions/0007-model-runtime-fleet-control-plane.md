# ADR 0007: Open-weight model fleet control plane

- Status: Accepted
- Date: 2026-07-25
- Issue: [#48](https://github.com/Sannrox/tenkai/issues/48)
- Related: [#6](https://github.com/Sannrox/tenkai/issues/6) (ADR 0002)

## Context

Tenkai already delivers software and governed model-routing configuration through
immutable releases, channels, plans, health checks, and rollback. Routing says
which model name an environment should use. It does not manage model weights,
quantization, inference engines, or hardware placement.

Operators need a lifecycle control plane for open-weight models across fleets
(Mac metal, GPU servers, edge) without turning Tenkai into another inference
engine (MLX, llama.cpp, Ollama, vLLM, SGLang remain external).

## Decision

Tenkai is the **lifecycle control plane above** inference executors:

```
Tenkai
  ├─ decides which model_runtime version belongs where
  ├─ governs promotion and rollout
  ├─ verifies content-addressed weight digests and signatures
  ├─ coordinates install and routing product order
  ├─ evaluates health and quality gates
  └─ rolls back failures
Inference executor (plugin)
  └─ downloads, loads, serves the model
```

### Product kind

Add first-class `product.kind = "model_runtime"` with manifest sections:

- `[model]` — source locator, revision, format, quantization, `artifact_digest`, license  
- `[runtime]` — engine id, port, context length  
- `[requirements]` — architecture, memory, accelerators  
- `[health]` — endpoint, optional smoke prompt, max startup seconds  

Weight **bytes** stay out of Tenkai SQLite and out of `deploy.inputs`. The
Catalog stores the descriptor and digest; payloads live in external stores
(HF, OCI, object storage). Environment caches are content-addressed locally
by executors.

### Executor port

`ModelRuntimeExecutor` is provider-neutral (apply / remove / observe), matching
the routing executor pattern. The embedded `LocalModelRuntimeExecutor` stages
the validated descriptor atomically for development and conformance. Production
engine adapters (llama.cpp, MLX, …) implement the same port and perform download,
verify, start, smoke test, and switch.

### Out of this decision’s first delivery

Hardware inventory, planner variant selection, fleet waves/dashboards, full
weight-cache eviction policy, and concrete engine binaries are follow-on work.
Coordinated runtime+routing multi-product plans use existing ordered plan steps.

## Consequences

- Manifest and apply paths recognize `model_runtime` without shell install
  scripts for weight files.
- Future engine plugins share one contract; core does not hard-link engines.
- Routing (`routing_config`) and model runtimes remain distinct products that
  can be ordered in a plan.

## Alternatives

- **Embed weights in deploy.inputs:** rejected; blows up SQLite and release
  snapshots.
- **Make Tenkai an inference server:** rejected; duplicates specialized engines.
- **Opaque generic provider action only:** rejected; loses typed validation and
  digest identity for models.
