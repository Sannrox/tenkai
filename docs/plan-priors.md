# Optional deployment-outcome priors

Planner priors are an **advisory** intelligence surface. When enabled, plan
creation may attach `prior_warnings` describing historical failure patterns
matched against the environment’s capability facts.

They never:

- hard-block planning or apply;
- change selected release versions or bypass pins;
- replace signing, approval, or canary evidence;
- open network connections.

Source: `src/plan_priors.rs`. Issue: #114.

## Enable

```bash
export TENKAI_PLAN_PRIORS=1
export TENKAI_PLAN_PRIORS_FILE=/path/to/priors.json
tenkaictl plan --env local
```

Default (unset): no behavior change.

## Prior file (`tenkai.plan-priors.v1`)

```json
{
  "schema": "tenkai.plan-priors.v1",
  "priors": [
    {
      "product": "api",
      "fact_key": "architecture",
      "fact_value": "x86_64",
      "note": "historical install failures on this architecture",
      "failure_count": 3
    }
  ]
}
```

When a plan step targets `api` and the environment fact `architecture=x86_64`,
the plan receives an advisory `prior_warnings` entry. Notes must not look like
secrets (`token=`, `password`, etc.) — load fails closed.

## Tenant mode

Prior files are host-local operator input. They must not embed foreign tenant
identifiers or credentials. Hard multi-tenant isolation of prior stores is a
follow-on; this delivery uses local files only.

## Follow-on (not this issue)

- Hard fail-closed priors as optional policy.
- Projection from OutcomeProvider / remote eval history.
