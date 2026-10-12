# Additional model serving executors (TGI, NVIDIA NIM, MLX)

Issue: [#586](https://github.com/Sannrox/tenkai/issues/586)

Date: 2026-10-12

Revision exercised: `9133b0a21c6242eef3461b125c6cdd3c43e70df7` (after #600–#602)

Conclusion: **implement MLX first**. TGI and NVIDIA NIM stay follow-on.

## Question and method

`model_runtime` already has a llama.cpp reference path and a vLLM Kubernetes
executor. This note compares Hugging Face Text Generation Inference (TGI),
NVIDIA NIM containers, and Apple MLX against the executor contract those two
paths share, then picks which plugin to build next.

Evidence is the tracked sources on this revision:

- `ModelRuntimeExecutor` apply / remove / observe (`src/model_runtime.rs`)
- Engine selection fail-closed on unknown ids (`select_model_runtime_executor`)
- Weight cache schemes and digest pinning (`WeightCache`)
- llama.cpp candidate → smoke → activate, loopback-only
  (`ReferenceLlamaCppExecutor`)
- vLLM candidate Deployment/Service, cache-mounted weights, host-configured
  image (`crates/tenkai-executor/src/vllm_model_runtime.rs`)
- Planner accelerator and GPU fit (`docs/model-runtime.md`, ADR 0007)

No GPU cluster, NGC entitlement, or Apple-silicon host was required. Default
CI stays engine-free.

## Shared contract

A new engine plugin is not a new product kind. It must keep:

| Obligation | What already exists |
| --- | --- |
| Port | `apply` returns the descriptor digest, `observe` reports it, `remove` frees the generation |
| Activation | Candidate must pass readiness and a completion smoke probe before traffic switches |
| Failure | A failed candidate is removed; the previous active generation stays serving |
| Rollback | Restore the retained previous generation through ordinary Tenkai plan/rollback |
| Weights | `WeightCache` verifies `file://`, `http(s)://`, `hf://`, or `oci://` by `artifact_digest`; payloads never enter operational SQLite |
| Identity | `runtime.engine` selects the plugin; unknown ids fail closed with a named error |
| Placement | Serving image, node selectors, entitlements, and binary paths are host configuration, never manifest fields |
| Guard | Apply and remove run under the executor fence and mutation lock |
| CI | Default `cargo test` needs no GPU, NGC key, or vendor binary |

vLLM already shows the Kubernetes shape: digest-pinned serving image, weights
claim mounted read-only, stable Service selector as the traffic switch.
llama.cpp already shows the host-process shape: argv-only spawn, loopback
health, fake engine in CI.

## Comparison

| Concern | TGI | NVIDIA NIM | MLX |
| --- | --- | --- | --- |
| Fleet class | NVIDIA GPU on Kubernetes, same class as vLLM | NVIDIA GPU on Kubernetes, NGC-entitled containers | Apple silicon / edge host process, same class as llama.cpp |
| Weight sourcing | Engine can download from the Hub at start. That fights digest pinning. Fit requires mounting the verified cache directory, as vLLM does with `directory+tar` | Many NIM images bake or pull weights from NGC. Baked payloads break `artifact_digest`. Fit requires a NIM that loads a digest-pinned cache mount, or refusal | mlx-lm loads local safetensors/gguf. Fit is `WeightCache` then `--model <verified path>`, like llama.cpp |
| Health / smoke | HTTP `/health` plus a generate or OpenAI-compatible completion | HTTP health on the NIM port plus a completion | HTTP or local OpenAI-compatible server (`mlx_lm.server`); loopback only, like llama.cpp |
| Accelerator facts | `accelerator = ["nvidia"]` plus `[requirements.gpu]` (vendor, vram, count). Planner fit already exists | Same NVIDIA GPU facts, plus driver/runtime mins (`cuda`) already validated | `accelerator = ["apple-metal"]` and `architecture = ["arm64"]` already appear in the model-runtime example. GPU vendor runtime enums are `cuda`/`rocm` only; MLX must not pretend to be CUDA |
| Licensing / entitlement | TGI server is Apache-2.0; model licenses stay on the descriptor. No extra credential hook | NGC login / entitlement is host secret, never a manifest field. Construction must fail closed when the entitlement is missing, the same way vLLM fails closed without `TENKAI_VLLM_IMAGE` | MLX is MIT. Model licenses stay on the descriptor. No entitlement plane |
| Host injection | New `runtime.engine = "tgi"` arm in `select_model_runtime_executor`, Kubernetes factory next to vLLM | `runtime.engine = "nim"`, Kubernetes factory, entitlement env | `runtime.engine = "mlx"`, host-process executor next to llama.cpp (fake process for CI) |
| Overlap with shipped work | High: second GPU Kubernetes engine | High on placement, extra entitlement surface | Low: covers the Mac-metal / edge side of ADR 0007 that vLLM does not |

Engine-managed Hub or NGC downloads are incompatible with the cache. Every
plugin that cannot load a digest-pinned `WeightCache` path is out of scope
until that engine grows a local-directory mode.

## Decision

Implement **MLX first**.

vLLM already serves the NVIDIA Kubernetes class. TGI would duplicate that
class. NIM adds NGC entitlement on top of the same class. MLX is the remaining
ADR 0007 machine class (Apple silicon / edge) and reuses the llama.cpp
host-process pattern: fake engine in default CI, real binary behind an env
flag, loopback smoke, retained previous generation.

Engine id: `mlx`. Unknown today; selection must keep failing closed until the
follow-up lands.

## Follow-up issues

Implementation is not this research PR. Each engine is its own issue so the
shared smoke/rollback tests land with that plugin:

1. [#614](https://github.com/Sannrox/tenkai/issues/614) MLX host-process
   executor (`runtime.engine = "mlx"`): fake CI engine, real `mlx_lm.server`
   behind an env flag, `WeightCache` path, loopback smoke, retain previous,
   select in `select_model_runtime_executor`.
2. [#615](https://github.com/Sannrox/tenkai/issues/615) TGI Kubernetes
   executor (`runtime.engine = "tgi"`): digest-pinned TGI image, cache-mounted
   weights, candidate → smoke → stable Service, vLLM-like host config. After
   #614.
3. [#616](https://github.com/Sannrox/tenkai/issues/616) NIM Kubernetes
   executor (`runtime.engine = "nim"`): digest-pinned NIM image that loads a
   cache mount, fail closed without host entitlement, same
   candidate/smoke/rollback contract. After #615.

Each follow-up must include deterministic apply / failed-candidate / rollback
coverage that default CI can run, and an ignored opt-in check only when a real
engine or GPU is required.
