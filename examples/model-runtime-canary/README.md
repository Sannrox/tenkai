# model_runtime canary promotion (embedded)

Demonstrates the operator path where a `model_runtime` release is applied on a
canary environment before wider channel promotion. Full steps and fail-closed
rules: [docs/model-runtime.md](../../docs/model-runtime.md#canary-promotion-evidence-model_runtime).

Fixture product: reuse [../model-runtime-local/tenkai.toml](../model-runtime-local/tenkai.toml)
(or any `kind = "model_runtime"` manifest). Default CI uses
`FakeInferenceEngine` (no real llama binary).

```bash
tenkaictl init
tenkaictl canary designate local
tenkaictl publish ../model-runtime-local/tenkai.toml --allow-unsigned-development
tenkaictl promote qwen-coder@0.1.0 canary
tenkaictl canary policy qwen-coder@0.1.0 stable --env local
# plan/apply on local without --skip-gates, then:
tenkaictl promote qwen-coder@0.1.0 stable
```

Waves and fleet status observe posture only; they do not replace canary.
