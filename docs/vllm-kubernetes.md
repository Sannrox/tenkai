# vLLM Kubernetes executor

Tenkai's in-process Kubernetes adapter can serve `model_runtime` products with
`runtime.engine = "vllm"` on a GPU cluster. The core crate does not link vLLM;
`tenkai-executor` installs a host factory at process start.

Related: [model runtime](model-runtime.md), [ADR 0007](decisions/0007-model-runtime-fleet-control-plane.md).

## Minimal manifest

vLLM loads a model directory, so the pinned artifact is a tar of that
directory (`model.format = "directory+tar"`).

```toml
[product]
name = "tiny-llm"
version = "0.1.0"
kind = "model_runtime"

[model]
source = "oci://registry.example/models/tiny@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
revision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
format = "directory+tar"
quantization = "bf16"
artifact_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
license = "apache-2.0"

[runtime]
engine = "vllm"
port = 8000
context_length = 8192

[requirements]
architecture = ["x86_64"]
memory_gib = 32
accelerator = ["nvidia"]

[requirements.gpu]
vendor = ["nvidia"]
vram_gib = 24
count = 1

[health]
endpoint = "http://127.0.0.1:8000/v1/models"
smoke_prompt = "Return exactly: OK"
max_startup_seconds = 600
```

Rules:

- `runtime.engine` must be `vllm`. Other engines stay on the reference path.
- GPU requirements are mandatory for this executor.
- Serving image, placement, and the weights volume are host configuration,
  never manifest fields.

## Host configuration

The factory reads these from the host environment. Missing or empty values
fail closed with a named error.

| Variable | Meaning |
| --- | --- |
| `TENKAI_VLLM_IMAGE` | Digest-pinned serving image (`…@sha256:…`) |
| `TENKAI_VLLM_WEIGHTS_CLAIM` | PersistentVolumeClaim that holds the weight cache |
| `TENKAI_VLLM_WEIGHTS_ROOT` | Host mount of that claim; the executor writes verified weights here |
| `TENKAI_VLLM_SMOKE_BASE_URL` | Optional smoke URL template; default `http://{service}.{namespace}.svc:{port}` |

`TENKAI_CLUSTER_CONFIG` is the environment-scoped kubeconfig already required
for in-process Kubernetes apply. The executor never reads `KUBECONFIG`.

Placement is part of `VllmConfig` when a host constructs the executor
directly:

| Field | Meaning |
| --- | --- |
| `node_selector` | Node labels for GPU placement, for example `nvidia.com/gpu.product` |
| `tolerations` | Kubernetes toleration objects, typically `nvidia.com/gpu` Exists/NoSchedule |
| `weights_claim` | The claim mounted read-only on serving pods at `/weights` |

The cache root must be the host mount of `weights_claim`. Nothing copies
weights between volumes.

## Apply, readiness, smoke, rollback

Each descriptor generation is a candidate Deployment and Service.

1. Verify and unpack the digest-pinned weights into the claim.
2. Apply the candidate objects and wait until the Deployment is Available.
3. Smoke-probe a completion against the candidate Service (`/v1/completions`).
4. On success, the stable Service selects that generation. The previous
   generation stays deployed so rollback can re-select it.
5. On launch, readiness, or smoke failure, the candidate is removed. The
   active generation and the one retained for rollback are left unchanged.

Rollback re-selects the retained previous generation after confirming it is
still Available. A missing previous generation, or one that is no longer
Available, is refused. Ordinary Tenkai plan/rollback drives this path; do
not delete executor state files by hand.

## Optional GPU test

Default CI does not need a GPU. The test is `#[ignore]` and also requires
`TENKAI_VLLM_LIVE_TEST=1`. It applies a small model, waits for readiness
and smoke, rolls forward, forces a smoke/startup failure, and rolls back.

The weights PersistentVolumeClaim is namespace-scoped. Set
`TENKAI_VLLM_NAMESPACE` to the namespace that already contains
`TENKAI_VLLM_WEIGHTS_CLAIM`. The test does not create a random namespace or
copy the claim. Product names are unique per run so concurrent tests can share
that namespace.

The smoke URL must be reachable from the process that runs the test. The
in-cluster default only works when that process can resolve the Service
DNS; otherwise set `TENKAI_VLLM_SMOKE_BASE_URL` to a port-forward or other
reachable template that still contains `{service}` and `{port}`.

```bash
TENKAI_VLLM_LIVE_TEST=1 \
TENKAI_CLUSTER_CONFIG=/path/to/env.kubeconfig \
TENKAI_VLLM_NAMESPACE=gpu-serving \
TENKAI_VLLM_IMAGE='vllm/vllm-openai@sha256:…' \
TENKAI_VLLM_WEIGHTS_CLAIM=model-weights \
TENKAI_VLLM_WEIGHTS_ROOT=/mnt/model-weights \
TENKAI_VLLM_MODEL_TAR=/path/to/tiny-model.tar \
TENKAI_VLLM_NODE_SELECTOR='{"nvidia.com/gpu.product":"example"}' \
TENKAI_VLLM_TOLERATIONS='[{"key":"nvidia.com/gpu","operator":"Exists","effect":"NoSchedule"}]' \
TENKAI_VLLM_SMOKE_BASE_URL='http://{service}.{namespace}.svc:{port}' \
  cargo test -p tenkai-executor --locked vllm_live_gpu_apply_forward_smoke_fail_rollback -- --ignored --nocapture
```
