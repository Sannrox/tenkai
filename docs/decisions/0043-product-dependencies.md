# ADR 0043: Product dependencies in the environment graph

- Status: Proposed
- Date: 2026-11-06
- Issue: [#1003](https://github.com/Sannrox/tenkai/issues/1003)
- Owner: Tenkai maintainers
- Amends: [software compatibility](../software-compatibility.md) (profile v2)
- Related: [ADR 0040](0040-family-versioning-and-release-policy.md),
  [ADR 0016](0016-same-version-remediation.md),
  [#985](https://github.com/Sannrox/tenkai/issues/985)

## Context

Family products depend on each other at runtime. A platform product needs the
governance control plane at a minimum contract version. It can also use a
transform runner, a connector engine or an agent environment plane when one is
installed, and works without them. Tenkai cannot express either kind of
dependency well:

- **Evidence only.** The v1 compatibility profile declares `requires` and
  `provides`. A requirement on a provider in another release is satisfied only
  by an observation the environment owner records by hand, which expires
  within a day. An unmet requirement refuses the plan. Nothing waits for the
  provider to arrive.
- **Name order.** Releases in one environment apply in name order, and each
  waits for its workloads before the next starts (#985). A dependent that sorts
  before its provider cannot converge.
- **No optional dependencies.** A product learns which peers are installed from
  configuration an operator sets by hand. When that configuration is wrong, the
  product offers features that cannot work, or hides features that could.
- **Bundling.** To upgrade a dependency together with its dependent, product
  owners copy the dependency's workloads into their own release. The dependency
  then moves only when the dependent is released, not on its own cadence.

Tenkai already records which releases it deployed to each environment, and
already checks the profiles of installed releases when planning a candidate.
What is missing is using those records to satisfy requirements, order the
work, and wait instead of failing.

## Decision

### 1. A dependency is a contract requirement

Dependencies stay contract requirements in the signed compatibility profile.
A release depends on a contract, never on another product's name, so a
provider can be renamed, split or replaced without changing its dependents.

Profile `version = 2` accepts a table form per requirement:

```toml
[compatibility]
version = 2

[compatibility.components.api.requires]
"governance.enterprise-rpc" = "1.5.0"
"connector.capture" = { minimum = "0.1.0", optional = true }

[compatibility.components.api.provides]
"platform.customer-api" = "1.0.0"
```

The string form is a required dependency with that minimum. Version 1 profiles
keep their meaning.

Matching keeps the v1 rule for stable versions: the same major and at least the
minimum. Below `1.0`, a minor may break the surface (ADR 0040 §1), so the major
and minor must both match: `0.1.4` satisfies `0.1.0`, and `0.2.0` does not.
Contract versions stay stable semantic versions without suffixes.

### 2. Tenkai satisfies requirements from what it deployed

A requirement is satisfied by the `provides` of a release that Tenkai has
deployed in the same environment and whose last deployment succeeded. That
record is durable in the operational store, so every server instance reads the
same answer, and it does not expire.

Recorded observations remain for providers Tenkai does not install, such as a
managed database. They keep their current age and conflict rules. A contract
offered both by a deployed release and by an observation is ambiguous and
refused, as two providers are today.

### 3. Plans follow the dependency graph

Within one environment, a plan installs and upgrades providers before their
dependents, and removes dependents before their providers. Releases with no
edge between them keep name order, so plans stay deterministic. A cycle is
refused at publication when it is within one release, and at planning when it
spans releases; the refusal names the cycle.

This replaces the undocumented name-only order (#985) for releases that
declare dependencies.

### 4. Unmet dependencies hold, not fail

When a channel reconcile or promotion would deploy a release whose required
dependency is not satisfied in that environment, Tenkai records a durable hold
on that environment and release. The hold names the contract and the minimum.
It makes no change.

The hold is re-evaluated whenever the environment's deployed set changes, and
on every reconcile. Once the dependency is satisfied, the release continues
through the normal plan, approval and gate path; the hold never grants
execution authority. Evaluating a hold is idempotent, and a server that takes
over the environment lease continues from the stored hold.

An operator's explicit plan still refuses an unmet requirement, with the same
named reason. Optional requirements never hold.

### 5. Dependents are protected

A plan that removes, rolls back or upgrades a provider so that an installed
dependent's required contract is no longer satisfied is refused, naming the
dependent. Losing an optional provider is allowed, and the dependent is
re-rendered (section 6).

### 6. Dependents learn what is present

At apply, Tenkai gives each release that declares requirements a dependency
document: for each required or optional contract, the providing release and
the contract version, or `absent` for an optional contract with no provider.
The document is derived only from the stored deployment records, so it is the
same on every instance and on retry. The executor delivers it (a file for host
releases, a config object for in-cluster releases).

When the providers of a dependent's contracts change, the same plan re-renders
the dependent after the provider step, as a same-version remediation
(ADR 0016). The product reads the document instead of hand-set presence
configuration.

The document carries no endpoints or credentials. Discovery stays with the
products.

### 7. Producers declare, Tenkai checks

Tenkai does not infer requirements from a running process or a source tree.
Each producer generates its `requires` in its release workflow from the
dependency pins it builds with, and checks there that they agree. Tenkai
validates the profile at publication.

### 8. Trains and suites

Train profiles (ADR 0040 §3 and §11) still name the exact set tested together
for `stable`. Dependencies state what every environment must satisfy on every
channel. Admitting a train whose members do not satisfy each other's required
contracts is refused.

A product that bundles another product's workloads should depend on that
product's release instead. Existing bundles keep working; nothing forces the
split.

## Out of scope

- Choosing among candidate versions. Requirements have minimums only, so a
  hold plus graph order reaches the same result as a solver. A maximum bound
  needs a later record.
- Dependencies across environments.
- Endpoint and service discovery.
- Specialized product kinds (worker pools, models, prompt packages). They keep
  their own admission rules.

## Consequences

- Product owners stop bundling dependencies, and providers release on their
  own cadence. A platform can be upgraded only once the providers it requires
  are in place.
- An optional peer's presence becomes a fact Tenkai states, not configuration
  someone sets.
- Hand-recorded evidence is needed only for providers outside Tenkai.
- Servers older than profile v2 refuse a manifest that declares it. During a
  rolling server upgrade, publish v2 profiles only once every server and
  runtime that reads the catalog understands them.
- The hold is new durable state on the environment. It is visible in status
  and cleared by the deployed set changing, not by time.

## Alternatives considered

- **Keep evidence as the only source.** Rejected: hand-recorded, expiring
  evidence for releases Tenkai itself deployed is friction that operators will
  skip or fake.
- **Version ranges on product names.** Rejected: it couples dependents to a
  provider's name and packaging. Contracts already exist and survive renames.
- **A version solver.** Rejected for now: with minimum-only requirements it
  adds machinery without changing outcomes.
- **Bundle dependencies into suites.** Rejected as the default: it couples
  release cadences, and a dependency fix waits for every dependent.
- **Apply all objects first, then wait for all** (#985 option 3). Rejected as
  the answer: it fixes readiness deadlocks but not version order, and it does
  not tell a dependent which optional peers are present.
