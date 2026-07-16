# tenkai implementation plans

These files turn [the founding design](../../DESIGN.md) into executable work.
Each numbered plan owns exactly one task and should produce one reviewable
change. A plan may be implemented only when all of its `Depends on` entries
are complete.

The numbering is an identifier, not a requirement to execute every plan
serially. See [ROADMAP.md](ROADMAP.md) for parallel lanes and convergence
points.

## Plan index

| Plan | Single task | Depends on |
| --- | --- | --- |
| [00](00-plan-step-contract.md) | Make plans durable, immutable graph objects | — |
| [01](01-executor-interface.md) | Extract execution behind an executor interface | 00 |
| [02](02-public-api-compatibility.md) | Establish the public API compatibility contract | 00 |
| [03](03-constraint-model.md) | Add the generic constraint model and evaluator | 00 |
| [04](04-environment-facts.md) | Add typed environment facts and capabilities | 03 |
| [05](05-version-constraints.md) | Enforce environment version constraints | 03 |
| [06](06-product-dependencies.md) | Add product dependency declarations | 03 |
| [07](07-dependency-planner.md) | Produce dependency-ordered valid plans | 04, 05, 06 |
| [08](08-drift-detection.md) | Detect declared-versus-observed drift | 01, 04 |
| [09](09-reconciler.md) | Continuously reconcile environments | 02, 07, 08 |
| [10](10-maintenance-windows.md) | Enforce maintenance windows | 03, 04, 09 |
| [11](11-release-signing.md) | Verify signed releases at publication | — |
| [12](12-plan-approval-signing.md) | Require approved, signed plans for execution | 00, 02, 11 |
| [13](13-pull-agent.md) | Execute plans through a pull-based agent | 01, 02, 09, 12 |
| [14](14-intelligence-artifacts.md) | Deploy one intelligence-artifact product type | 01, 03, 12 |
| [15](15-canary-promotion.md) | Gate fleet promotion on canary outcomes | 09, 10 |
| [16](16-disconnected-bundles.md) | Export and import signed offline bundles | 11, 12, 13 |
| [17](17-fleet-rollout-waves.md) | Execute and observe fleet rollout waves | 09, 15 |
| [18](18-outcome-learning.md) | Feed deployment outcomes into planning priors | 15, 17 |

## Rules for changing the plans

- Keep one implementation outcome per file.
- Add a new numbered file when work can be reviewed or delivered separately.
- Never hide a new dependency in prose; update `Depends on` and the roadmap.
- Acceptance criteria describe observable behavior, not internal activity.
- A plan is complete only after its validation commands pass and its docs are
  consistent with the shipped behavior.
