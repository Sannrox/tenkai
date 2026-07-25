# Ordered model_runtime then routing_config rollout

Coordinate open-weight model deployment with traffic routing using ordinary
Tenkai plan steps — no second control plane and no merged product kind.

## Happy path (forward)

1. **Publish** both products (`model_runtime` + `routing_config`) and promote
   them to the environment's channel(s).
2. **Subscribe** the environment to both channels.
3. **Plan / apply** — Tenkai orders steps so that:
   - `model_runtime` install/upgrade runs **first** (weights verify, candidate
     start, smoke via the reference engine plugin);
   - `routing_config` install/upgrade runs **second** (switch traffic only after
     the model generation is active).
4. **Observe** health and routes.
5. **Retain** prior model generations for Tenkai rollback (engine plugin keeps
   `*.json.previous`; Catalog retains prior releases).

## Rollback / retire

1. Plan a routing change that points away from the retiring model (or to the
   previous generation).
2. Plan model_runtime downgrade/rollback.
3. Tenkai orders reverse steps so **routing runs before model retire**, so
   traffic is never left pointing at a removed generation.

## Unsafe orders (rejected)

| Order | Why it fails |
| --- | --- |
| routing upgrade before model install | Traffic to a missing/unhealthy model |
| model downgrade before routing switch | Live routes still target the retiring model |

Source: `plan::validate_model_routing_rollout_order` /
`model_routing_rollout_rank` in `src/plan.rs`.

## Fixtures

- `model/tenkai.toml` — sample `model_runtime` product  
- `routing/tenkai.toml` + `routing.json` — sample `routing_config` product  

Use unsigned local publish for demos only (`--allow-unsigned-development`).
Production requires signed releases and the normal approval path.

Mid-sequence failure remains recoverable with Tenkai rollback/restore of the
last healthy generation; do not depend on `sekai-chisei` for recovery.
