# Software compatibility preflight

Software releases can declare a `[compatibility]` profile in `tenkai.toml`.
Version 1 and version 2 are valid. The complete profile is part of the manifest
digest and release signature. It describes component pins, required and provided
contracts, runtime capabilities, environment facts, and data-schema bounds.
Compatibility is checked before execution independently of process health and
ordinary evaluation gates.

Existing manifests without a profile retain their previous behavior. Specialized
product kinds keep their own admission rules and cannot declare this profile.
Adding a profile requires a new release version; changing published metadata
cannot reuse its signature or immutable version identity. Servers older than
profile v2 refuse a manifest that declares `version = 2`. Publish v2 once every
server that reads the catalog understands it.

## Declare the profile

```toml
[compatibility]
version = 1
max_evidence_age_ms = 60000
capabilities = ["containers"]

[compatibility.facts]
architecture = "arm64"

[compatibility.schema]
minimum = 2
maximum = 4
migration = "stable"

[compatibility.components.web.pin]
kind = "digest"
value = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[compatibility.components.web.requires]
database = "1.2.0"

[compatibility.components.database.pin]
kind = "revision"
value = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[compatibility.components.database.provides]
database = "1.3.0"
```

Version 2 accepts the same string form, which stays a required minimum, and a
table form that can mark a requirement optional:

```toml
[compatibility]
version = 2
max_evidence_age_ms = 60000

[compatibility.components.api.pin]
kind = "digest"
value = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[compatibility.components.api.requires]
database = "1.2.0"
"connector.capture" = { minimum = "0.1.0", optional = true }

[compatibility.components.api.provides]
"platform.customer-api" = "1.0.0"
```

An optional requirement with no provider is compatible. A provider that is
present is still version-checked, including when several providers make the
contract ambiguous. Quote dotted contract names so TOML treats them as a single
key.

Version 2 publication refuses a requirement cycle inside one release: a
component that requires a contract another component in the same profile
provides, including when a component requires a contract it provides itself.
The refusal names the components and the contracts on the cycle. Version 1
profiles with a satisfied self-requirement stay readable.

Component identities are unique within the environment's checked software graph.
A digest pin is a canonical lowercase SHA-256 digest. A revision is a complete
40- or 64-character hexadecimal source revision. Component pins identify the
candidate's constituent inputs, rather than a mutable image tag. The environment
owner is responsible for observing these inputs and the retained installed
components; Tenkai does not infer their compatibility from a running process.

Contract versions are stable semantic versions without prerelease or build
suffixes. A provider satisfies a requirement when its major matches and its
version is at least the declared minimum, including patch level. `1.3.0`
satisfies `1.2.0`; `2.0.0` and `1.1.0` are incompatible. Profile version 2 also
requires the minor to match below 1.0, because a 0.y minor may break the surface:
`0.1.4` satisfies `0.1.0`, and `0.2.0` is a different minor and is incompatible.
Version 1 keeps the same-major rule for 0.y contracts. Multiple providers of the
same required contract are ambiguous and refused even when their versions agree.

A required contract is also satisfied by the `provides` of a release whose last
deployment in the same environment succeeded. That record is durable in the
operational store and does not expire. Planning, apply, restart, and rollback
all use it. A contract offered both by a deployed release and by an observation,
or by several deployed releases, is ambiguous and refused. Hand-recorded
evidence remains for providers Tenkai does not install.

When reconcile (including the environment tick after a channel promotion) would
deploy a release whose required contract is not satisfied in that environment,
Tenkai records a durable hold on that environment and product, names the unmet
contract and minimum, and makes no change to that product. Other products still
plan. The hold is re-evaluated when the deployed set changes and on every
reconcile; once the contract is satisfied, the release continues through the
normal plan, approval, and gate path. The hold grants no execution authority.
An explicit `plan` still refuses an unmet required contract
(`missing_contract` or `incompatible_contract`). Optional requirements never
hold. Ambiguous contracts, stale or missing evidence, and other compatibility
failures still fail the tick.

The schema range is inclusive. Migration state is `stable` or `pending` and must
match exactly. Tenkai checks this declaration; it does not run migrations or
reverse them during rollback. Facts use the existing admitted environment fact
keys. Capabilities are explicit identifiers observed by the environment owner.

Version 1 and version 2 admit at most 128 components and 128 contracts per
component. Evidence age is between 1 millisecond and one day. Identifiers contain
only ASCII letters, digits, dots, underscores, or hyphens and are at most 128
bytes. Observations stay evidence version 1 with string minimums; optional is a
profile declaration.

## Record observations

The environment owner supplies a JSON observation bound to the exact target
release's manifest digest and environment. Components include the candidate
constituents. Do not re-state contracts Tenkai already deployed: those come
from the provider release's signed `provides`. `contracts` describes other
observed external providers. Required contracts from installed release profiles
are checked against deployed `provides` and the observation, so a candidate
cannot silently break a declared dependent. A plan that would remove, roll
back, or upgrade a provider so an installed remaining dependent's required
contract is no longer satisfied is refused, naming the dependent and the
contract. Losing an optional provider is allowed. A required contract that had
no matching deployed provider before the plan stays on observation rules. Reused component identities across
retained products are refused as ambiguous.

```json
{
  "version": 1,
  "environment": "local",
  "release_digest": "<64-character manifest SHA-256>",
  "observed_at_ms": 1790000000000,
  "components": {
    "web": {
      "pin": { "kind": "digest", "value": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
      "requires": { "database": "1.2.0" },
      "provides": {}
    }
  },
  "contracts": { "database": "1.3.0" },
  "capabilities": ["containers"],
  "schema_version": 3,
  "migration": "stable"
}
```

Replace the digest and timestamp with the actual release digest and observation
time. Do not repeat a deployed or component-provided contract in `contracts`,
since that would declare two providers.

```sh
tenkaictl env compatibility record local observation.json
tenkaictl env compatibility check local app@1.0.0
```

The same commands work with `--target remote`. The remote routes are:

| Request | Authority | Result |
| --- | --- | --- |
| `POST /v1/environments/{environment}/compatibility/evidence` | Management, scoped to the environment | JSON `null` after immutable recording |
| `GET /v1/environments/{environment}/compatibility/{product@version}` | Read, scoped to the environment | Versioned report, or `null` for a legacy release without a profile |

Runtime credentials cannot record management evidence. Tenant mode refuses these
routes until its catalog lifecycle supports the same isolation contract.
Observations contain only pins, contract versions, capability identifiers, schema
state, and timestamps. They must contain no credentials, command output, files,
or workdir paths. Each stored observation is content-addressed and immutable;
repeating identical evidence is idempotent and does not refresh its age. Recording
an observation does not change environment configuration or deployed versions.

## Dependency document

At apply and same-version restart, a software release that declares
cross-release requirements receives a version 1 JSON document derived only from
stored successful deployments (ADR 0043 §6). For each required or optional
contract the document names the providing product, its release version, and the
provided contract version, or `state: absent` for an optional contract with no
provider. Required contracts are never absent. A contract this release already
provides is omitted. The bytes are identical on every replica and on retry.
The document carries no endpoints, credentials, or instance names (instance
names are a later format).

```json
{
  "version": 1,
  "contracts": {
    "database": {
      "state": "present",
      "product": "postgres",
      "release": "1.3.0",
      "contract": "1.3.0"
    },
    "connector.capture": { "state": "absent" }
  }
}
```

When a plan changes the providers of an already-installed dependent, the same
plan re-renders that dependent after the provider step as `restart`. A
same-version restart is not a mixed-direction version change. Host releases are
never restarted (ADR 0041); they receive the file on install or upgrade. A
release with no cross-release requirements receives no document. Executors
deliver the document as described in [software executor](software-executor.md).

## Interpret refusal and refresh evidence

The newest observation for the exact environment and release is used. Conflicting
observations with the same newest timestamp fail closed. Missing, malformed,
stale, future-dated, mismatched, or ambiguous evidence cannot authorize execution.
A healthy process is still refused when its contract or pin is incompatible.

Reports contain a version, the target manifest digest, typed failure reasons
with requirement identifiers, and `satisfied_by` naming the deployed
`product@version` that satisfied each required contract. They omit observed
fact values, payloads, and private paths. CLI `check` prints the report and
exits unsuccessfully when any failure remains. Examples include
`missing_capability`, `component_changed`, `incompatible_contract`,
`unsupported_schema`, and `stale_evidence`.

Planning checks the target profile. A plan over several releases installs and
upgrades providers before dependents, removes dependents before providers, and
keeps name order among releases with no edge. Remove and downgrade order uses
the currently deployed contracts, including requirements the target drops. A
cycle across releases is refused at planning, naming the releases and
contracts. A plan that would invert a contract edge to satisfy host, agent, or
removal order is refused, naming the contract and the two releases. Apply checks current evidence again before
any executor mutation; a prior passing report grants no execution authority.
Pull-only runtime work dispatch and heartbeat renewal also recheck current
evidence. `--skip-gates` does not bypass compatibility. Plan signatures, approvals, fencing,
and artifact verification still apply normally.

Rollback checks the previous release against current observations and schema
state before removing the outgoing release or activating the previous one.
Automatic recovery and restart also check compatibility before activation. Keep
fresh evidence for rollback targets when preparing an upgrade; a historical
successful deployment does not prove that an older release fits today's schema.

The [compatibility preflight research](research/software-compatibility-preflight.md) records the
primary sources behind the dependency-graph approach and the stricter evidence
requirements specific to Tenkai.
