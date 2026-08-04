# Staged product kinds (policy, eval suite, agent)

Three Catalog product kinds deliver **versioned JSON descriptors** through the
same publish → channel → plan → apply path as `routing_config`, without shell
install scripts as the primary path.

| Kind | Manifest section | Document | Apply effect |
| --- | --- | --- | --- |
| `policy_bundle` | `[policy].document` | allow/deny policy entries | Stage policy JSON for the environment |
| `eval_suite` | `[eval_suite_product].document` | suite_id + cases | Stage immutable eval contract |
| `agent_definition` | `[agent].document` | agent_id, runtime, entrypoint | Stage agent descriptor only |

Source: `src/staged_artifact.rs`, `src/manifest.rs`. Issues: #115, #116, #117.

The public kinds share one staging lifecycle but intentionally retain distinct
schema identities. The evidence and compatibility analysis are recorded in
[the consolidation research](research/staged-document-product-kinds.md).

## Non-goals

| Kind | Does **not** do |
| --- | --- |
| policy_bundle | Act as IdP / live policy engine UI |
| eval_suite | Run remote eval (see GateProvider / #113) |
| agent_definition | Schedule agent jobs (orchestration stays out of Tenkai) |

## Example: policy_bundle

```toml
[product]
name = "deploy-policy"
version = "1.0.0"
kind = "policy_bundle"

[policy]
document = "policy.json"
```

```json
{
  "version": 1,
  "policies": [
    { "id": "allow-deploy", "effect": "allow", "action": "deploy" }
  ]
}
```

```bash
tenkaictl publish path/to/tenkai.toml --allow-unsigned-development
tenkaictl promote deploy-policy@1.0.0 stable
tenkaictl env subscribe local deploy-policy=stable
tenkaictl plan --env local
# apply stages descriptor under env state; no secrets in documents
```

## eval_suite and gates

Publish an `eval_suite` product to pin a content-addressed suite definition.
Gate `[gate].eval_suite` continues to name the suite id for
`GetEvaluationGateEvidence` lookup; the Catalog release of the `eval_suite`
product is the versioned contract you promote and roll back. Remote evaluation
uses the server-owned Chisei projection described in
[Evaluation gate evidence](evaluation-gate-evidence.md).

## agent_definition

Stages `agent_id` / `runtime` / `entrypoint` only. Tenkai does not start agents
or run a multi-agent marketplace.
