# Software compatibility preflight: Apollo comparison

Issue: [#534](https://github.com/Sannrox/tenkai/issues/534)

Date: 2026-10-09

Conclusion: **adopt release-declared constraints checked against observed environment state before execution**. Use Apollo's separation of release metadata, environment observations, and plan eligibility. Tenkai's signed, content-bound evidence and fail-closed requirements remain authoritative.

## Primary-source findings

| Finding | Evidence | Consequence for Tenkai |
| --- | --- | --- |
| Releases declare dependencies rather than relying on operator-maintained upgrade scripts. | Apollo's [Product Release Dependencies Extension](https://www.palantir.com/docs/apollo/apollo-product-specification/product-dependencies/) declares product identity and inclusive lower/upper version bounds in release manifests; Apollo constructs a dependency graph and validates installed versions against all declared constraints. | Put the compatibility profile inside the signed release contract. Publish validates the declaration; plan and apply evaluate actual target observations. |
| Compatibility is checked in both directions. | [Plans and Constraints](https://www.palantir.com/docs/apollo/core/plans-and-constraints/#constraints) says a plan must preserve declared dependencies and that all dependent entities must satisfy their version constraint with the target release. | Check target requirements and retained installed components' requirements against the proposed final component set. Checking only the new release's outgoing requirements can break an existing dependent. |
| Evidence changes invalidate eligibility. | [Plan invalidation](https://www.palantir.com/docs/apollo/core/plans-and-constraints/) follows observed dependency/dependent state changes and requests new plans for neighboring entities. Agents continuously report state and poll for plans. | Reevaluate compatibility at apply and rollback before mutation, using current scoped observations. A passing plan-time report cannot authorize changed or stale evidence. |
| Version compatibility is declared, not inferred from health or version order. | The [dependency specification](https://www.palantir.com/docs/apollo/apollo-product-specification/product-dependencies/) defines bounded compatibility and rejects non-orderable versions. [Liveness and Readiness](https://www.palantir.com/docs/apollo/core/liveness-and-readiness/) separately describes process usability and readiness for traffic. | Keep compatibility distinct from health; document the exact contract major/minor rule. A version increase alone proves no semantic compatibility. |
| Incompatibility constraints protect coexistence regardless of installation order. | The [Product Release Incompatibilities Extension](https://www.palantir.com/docs/apollo/apollo-product-specification/product-incompatibilities/) says even a one-sided declaration prevents either product being installed alongside the incompatible other product. | Evaluate the resulting environment, including retained observations; do not make acceptance depend on component iteration order. |
| Catalog and observed environment state jointly determine eligible plans. | Apollo's [technical overview](https://www.palantir.com/docs/apollo/core/overview/) explicitly lists product dependencies and supported database schemas as catalog metadata; environment settings and current observed state provide the other inputs. | Treat schema bounds, runtime requirements, and immutable component identities as release declarations compared with environment-scoped facts and component evidence. |
| Apollo reports why work is blocked. | [Plans and Constraints](https://www.palantir.com/docs/apollo/core/plans-and-constraints/) exposes constraints and reasoning in the Activity view so operators can unblock a plan. | Return a deterministic typed report identifying the component or requirement, expected condition, and safe observed evidence without private payloads. |

## Contract guidance for issue #534

These are Tenkai design recommendations derived from the issue's requirements, not claims about Apollo's private implementation:

- Version the profile and include its complete declaration in the release content digest and signature verification. Record each component's identity and immutable revision or artifact digest. Reject duplicate identities and contradictory declarations during publish.
- Represent required/provided contracts explicitly. For a same-major minor-compatible rule, an observed provider must have the required major and at least the requested minor. Do not infer compatibility across majors. If exact matching is supported, make it an explicit rule rather than a special string convention.
- Compare required capabilities and facts with target-scoped observations. Require supported schema bounds and a compatible migration state; this preflight validates evidence and does not execute migrations.
- Bind dependency evidence to the exact release content digest, environment, and observation freshness. Reject missing, stale, ambiguous, changed-digest, and incompatible evidence before any deployment mutation. Define freshness against an explicit evaluation time, including future timestamps as invalid.
- Evaluate all components as a final set, sort report entries deterministically, and keep the report available through the same application contract in embedded CLI and remote API modes.
- Reuse the evaluator for planning, apply, and rollback, including the previous release's requirements. A rollback target's past successful deployment does not prove compatibility with today's schema and components.
- Keep existing specialized compatibility evaluators effective. A generic software profile must not become a bypass for a specialized product's stricter rules.

## Deliberate differences and evidence limits

Apollo's public docs allow dependency overrides and command-based break-glass constraint bypasses. Its artifact availability constraint distinguishes unavailable, available, and unchecked artifacts; unchecked artifacts do not block plans when the Hub cannot verify them. See [Plans and Constraints](https://www.palantir.com/docs/apollo/core/plans-and-constraints/). These exceptions must not be copied into #534's required fail-closed evidence contract. Any retained Tenkai bypass needs its own explicit authorization and durable audit evidence.

Apollo documents optional dependencies as absent-or-compatible, but warns that satisfying optional dependencies does not prove a valid deployment setup. Its dependency extension does not define those valid configurations, and its example comments mark bounds required while the prose calls them optional. Tenkai should specify required fields and permitted combinations explicitly instead of reproducing that ambiguity. See the [dependency specification](https://www.palantir.com/docs/apollo/apollo-product-specification/product-dependencies/).

The sources establish declaration-based dependency constraints, observed-state planning, database-schema metadata, and health separation. They do **not** establish Apollo's signature format, component digest binding, observation freshness algorithm, generic runtime-capability profile, or schema migration-state protocol. Those are requirements of #534, not verified Apollo behavior. The Apollo dependency version syntax also differs from ordinary semantic-version ranges; use Tenkai's documented contract-version rule rather than claiming syntax compatibility.

Sources were retrieved directly from Palantir's public Apollo documentation on the date above. No live service, cluster, or provider was needed.
