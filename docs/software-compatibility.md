# Software compatibility preflight

Software releases can declare a version 1 `[compatibility]` profile in
`tenkai.toml`. The complete profile is part of the manifest digest and release
signature. It describes component pins, required and provided contracts, runtime
capabilities, environment facts, and data-schema bounds. Compatibility is checked
before execution independently of process health and ordinary evaluation gates.

Existing manifests without a profile retain their previous behavior. Specialized
product kinds keep their own admission rules and cannot declare this profile.
Adding a profile requires a new release version; changing published metadata
cannot reuse its signature or immutable version identity.

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

Component identities are unique within the environment's checked software graph.
A digest pin is a canonical lowercase SHA-256 digest. A revision is a complete
40- or 64-character hexadecimal source revision. Component pins identify the
candidate's constituent inputs, rather than a mutable image tag. The environment
owner is responsible for observing these inputs and the retained installed
components; Tenkai does not infer their compatibility from a running process.

Contract versions are stable semantic versions without prerelease or build
suffixes. A provider satisfies a requirement when its major matches and its
version is at least the declared minimum, including patch level. Thus `1.3.0`
satisfies `1.2.0`, while `2.0.0` and `1.1.0` do not. Multiple providers of the
same required contract are ambiguous and refused even when their versions agree.

The schema range is inclusive. Migration state is `stable` or `pending` and must
match exactly. Tenkai checks this declaration; it does not run migrations or
reverse them during rollback. Facts use the existing admitted environment fact
keys. Capabilities are explicit identifiers observed by the environment owner.

Version 1 admits at most 128 components and 128 contracts per component.
Evidence age is between 1 millisecond and one day. Identifiers contain only
ASCII letters, digits, dots, underscores, or hyphens and are at most 128 bytes.

## Record observations

The environment owner supplies a JSON observation bound to the exact target
release's manifest digest and environment. Components include both the candidate
constituents and retained installed dependencies. Required and provided contracts
from installed release profiles are checked too, so a candidate cannot silently
break a declared dependent. Reused component identities across retained products
are refused as ambiguous.

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
    },
    "database": {
      "pin": { "kind": "revision", "value": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
      "requires": {},
      "provides": { "database": "1.3.0" }
    }
  },
  "contracts": {},
  "capabilities": ["containers"],
  "schema_version": 3,
  "migration": "stable"
}
```

Replace the digest and timestamp with the actual release digest and observation
time. `contracts` describes other observed external providers. Do not repeat a
component-provided contract there, since that would declare two providers.

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

## Interpret refusal and refresh evidence

The newest observation for the exact environment and release is used. Conflicting
observations with the same newest timestamp fail closed. Missing, malformed,
stale, future-dated, mismatched, or ambiguous evidence cannot authorize execution.
A healthy process is still refused when its contract or pin is incompatible.

Reports contain a version, the target manifest digest, and typed failure reasons
with requirement identifiers. They omit observed fact values, payloads, and
private paths. CLI `check` prints the report and exits unsuccessfully when any
failure remains. Examples include `missing_capability`, `component_changed`,
`incompatible_contract`, `unsupported_schema`, and `stale_evidence`.

Planning checks the target profile. Apply checks current evidence again before
any executor mutation; a prior passing report grants no execution authority.
Pull-only runtime work dispatch and heartbeat renewal also recheck current
evidence. `--skip-gates` does not bypass compatibility. Plan signatures, approvals, fencing,
and artifact verification still apply normally.

Rollback checks the previous release against current observations and schema
state before removing the outgoing release or activating the previous one.
Automatic recovery and restart also check compatibility before activation. Keep
fresh evidence for rollback targets when preparing an upgrade; a historical
successful deployment does not prove that an older release fits today's schema.

The [Apollo comparison](research/software-compatibility-preflight.md) records the
primary sources behind the dependency-graph approach and the stricter evidence
requirements specific to Tenkai.
