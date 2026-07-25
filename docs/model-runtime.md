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

## Follow-on (not in first delivery)

- Reference engine plugins (`tenkai-executor-llamacpp`, MLX, …)
- Planner constraints for hardware-class variant selection
- Peer/regional weight caches and eviction policy
