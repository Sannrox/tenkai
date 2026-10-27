# vLLM, TGI and NIM Kubernetes executor

Tenkai's in-process Kubernetes adapter can serve `model_runtime` products with
`runtime.engine = "vllm"`, `"tgi"` (Text Generation Inference) or `"nim"`
(NVIDIA NIM) on a GPU cluster. Both engines share one lifecycle: candidate,
readiness, smoke, switch, rollback. The core crate links neither;
`tenkai-executor` installs a host factory at process start.

Related: [model runtime](model-runtime.md), [ADR 0007](decisions/0007-model-runtime-fleet-control-plane.md).

## Minimal manifest

Both engines load a model directory, so the pinned artifact is a tar of that
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

- `runtime.engine` is `vllm`, `tgi` or `nim`. Either one needs an environment
  cluster configuration and the host factory, or selection fails closed.
- GPU requirements are mandatory for this executor.
- Serving image, placement, and the weights volume are host configuration,
  never manifest fields.

## Host configuration

The factory reads these from the host environment, with the prefix
`TENKAI_VLLM_` for vLLM, `TENKAI_TGI_` for TGI and `TENKAI_NIM_` for NIM. Missing or empty values
fail closed with a named error.

| Variable | Meaning |
| --- | --- |
| `<prefix>IMAGE` | Digest-pinned serving image (`…@sha256:…`) |
| `<prefix>WEIGHTS_CLAIM` | PersistentVolumeClaim that holds the weight cache |
| `<prefix>WEIGHTS_ROOT` | Host mount of that claim; the executor writes verified weights here |
| `<prefix>SMOKE_BASE_URL` | Optional smoke URL template; default `http://{service}.{namespace}.svc:{port}` |

| Engine | Server arguments | Smoke request |
| --- | --- | --- |
| `vllm` | `--model <dir> --served-model-name <product> --tensor-parallel-size <n> --max-model-len <context>` | `POST /v1/completions`, non-empty `choices[0].text` |
| `tgi` | `--model-id <dir> --num-shard <n> --max-total-tokens <context>`, `HF_HUB_OFFLINE=1` | `POST /generate`, non-empty `generated_text` |
| `nim` | Environment: `NIM_MODEL_NAME=<dir>`, `NIM_MANIFEST_ALLOW_UNSAFE=1`, `NIM_SERVED_MODEL_NAME`, `NIM_TENSOR_PARALLEL_SIZE`, `NIM_MAX_MODEL_LEN`, `HF_HUB_OFFLINE=1`; readiness `/v1/health/ready` | `POST /v1/completions`, non-empty `choices[0].text` |

NIM also needs an NGC entitlement, held on the host as Kubernetes Secret
names, never the key and never manifest data. Missing either one fails
executor construction closed:

| Variable | Meaning |
| --- | --- |
| `TENKAI_NIM_PULL_SECRET` | Image pull secret for the registry serving the NIM image |
| `TENKAI_NIM_NGC_API_KEY_SECRET` | Secret holding the key under `NGC_API_KEY`, passed to the container |

The model name is the mounted directory, so NIM loads the verified weights
rather than pulling or using baked ones. Model-specific NIM images accept a
local model only with `NIM_MANIFEST_ALLOW_UNSAFE=1`, which the executor sets;
the descriptor's digest-verified directory, not the image's built-in
profile, is what serves.

Weights always come from the verified cache mount; neither engine downloads
from a hub at start, and weights are never baked into the image.

`TENKAI_CLUSTER_CONFIG` is the environment-scoped kubeconfig already required
for in-process Kubernetes apply. The executor never reads `KUBECONFIG`.

Placement is part of `ServingConfig` when a host constructs the executor
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
3. Smoke-probe a completion against the candidate Service (see the table above).
4. On success, the stable Service selects that generation. The previous
   generation stays deployed so rollback can re-select it.
5. On launch, readiness, or smoke failure, the candidate is removed. The
   active generation and the one retained for rollback are left unchanged.

Rollback re-selects the retained previous generation after confirming it is
still Available. A missing previous generation, or one that is no longer
Available, is refused. Ordinary Tenkai plan/rollback drives this path; do
not delete executor state files by hand.

## Optional GPU test

Default CI does not need a GPU. Each engine has an `#[ignore]` test that also
requires `TENKAI_VLLM_LIVE_TEST=1`, `TENKAI_TGI_LIVE_TEST=1` or `TENKAI_NIM_LIVE_TEST=1`, and reads that
engine's prefix for the variables below. It applies a small model, waits for readiness
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

For TGI, use the `TENKAI_TGI_` variables and
`tgi_live_gpu_apply_forward_smoke_fail_rollback`. For NIM, use the
`TENKAI_NIM_` variables, including both entitlement Secrets, and
`nim_live_gpu_apply_forward_smoke_fail_rollback`. Default CI needs no GPU
and no NGC key.
