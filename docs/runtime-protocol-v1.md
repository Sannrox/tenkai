# Environment runtime protocol v1

The shipped host is pull-only HTTP on `tenkai-server`. An environment runtime
initiates every exchange; the server never pushes work into an environment.
There is no served gRPC `RuntimeService`.

| HTTP | Request | Result |
| --- | --- | --- |
| `GET /v1/runtime/environments/{environment}/work` | Bearer token and `x-tenkai-runtime-instance`; optional `x-tenkai-runtime-capabilities`. No body. | JSON `RuntimeWork` (`environment`, optional `plan`, optional `claim`, optional `approvals`, optional `issuer_candidate`) |
| `POST /v1/runtime/environments/{environment}/identity-issuer/candidate` | JSON `IssuerKey` (`generation`, `fingerprint`, `certificate`, `sealed_key`) | JSON `IssuerKey`: the candidate the server keeps ([below](#identity-issuer)); `409` when none was asked for |
| `POST /v1/runtime/environments/{environment}/complete` | JSON `RuntimeCompletion` (`plan_id`, `generation`, `succeeded`, `detail`, `receipts`) | `204` |
| `POST /v1/runtime/environments/{environment}/heartbeat` | JSON `RuntimeHeartbeat` (`plan_id`, `generation`) | JSON claim |
| `POST /v1/runtime/environments/{environment}/release` | JSON `RuntimeReleaseRequest` (`plan_id`, `generation`, `step_id`, optional `restore`). Renews the claim. | JSON `RuntimeRelease` (`manifest`, `signature`, `request`, `entries`) for a built-in runtime ([below](#release-package)); `412` naming why the step has none |
| `POST /v1/runtime/environments/{environment}/host-records` | JSON `RuntimeHostRecordsReport` (`records`: the host applier's applied-state records for the environment) | JSON `RuntimeHostRecordsResponse` (`stored`: products whose record was new) ([below](#host-records)) |
| `POST /v1/runtime/environments/{environment}/certificates` | JSON `RuntimeCertificatesReport` (`certificates`: each workload certificate its targets hold, with the last renewal attempt) | JSON `RuntimeCertificatesResponse` (`stored`: instances whose report was new) ([below](#workload-certificates)) |
| `POST /v1/runtime/environments/{environment}/inventory` | JSON `RuntimeInventoryReport` (`facts`, `source`) | JSON `RuntimeInventoryResponse` |
| `POST /v1/runtime/environments/{environment}/enroll` | No bearer. JSON `RuntimeEnrollRequest` (`token`: a single-use enrollment token; optional `csr`; optional `attestation`; optional `sealing_public_key`) | `201`, JSON `RuntimeEnrolled` (`environment`, `credential`, `credential_id`); `403` for an unknown, spent, expired or foreign token |
| `POST /v1/runtime/environments/{environment}/certificate` | Runner certificate (or, once it expired, the enrolled bearer) and `x-tenkai-runtime-instance`. JSON `RuntimeCertificateRequest` (`csr`; optional `attestation`; optional `sealing_public_key`) | JSON `RuntimeCertificate` (`certificate`, `ca`) ([runner certificates](run-tenkai-server.md#runner-certificates)) |

An environment that requires runner attestation (#675) answers an
enrollment or renewal without `attestation` with `428`, spending no token,
and a body that names the statement schemas it verifies, preferred first:

```json
{"error": "runner attestation required: attestation_missing",
 "accepted_schemas": ["tenkai.runner-attestation.v2", "tenkai.runner-attestation.v1"]}
```

The agent then repeats the request with an
[attestation](#runner-attestation-statement) in the first listed schema it
signs. A server of a release before 0.7.0 sends no `accepted_schemas`; an
agent then sends v1. An attestation in a schema the server does not verify,
in any JSON shape, is `403` `attestation_schema_unsupported` with the same
body. Other attestation refusals are `403` with a named reason
(`hardware_key_required` when the environment requires a hardware-backed
runner key and the statement names a file key), and a
work request (work, heartbeat, self-release, completion, inventory) admitted
by a bearer alone is `403` `attestation_requires_client_certificate`, and a
runtime inventory report contradicting an operator-declared fact is `409`
([attested runners](run-tenkai-server.md#attested-runners)). An agent sends
`attestation` only after a `428`, so agents and servers without it are
unchanged.

`sealing_public_key` is the runtime's HPKE DHKEM(P-256, HKDF-SHA256) public
key: standard-base64 of the uncompressed 65-byte P-256 point (ADR 0045).
The private half never leaves the runtime. A malformed key is refused
before an enrollment token is spent. A replica that predates the field
refuses it as an unknown field (`422`); the agent omits it and retries.
The server records the key against that enrolled runner and serves
unrevoked keys on
`GET /v1/environments/{environment}/recipient-keys` (read capability).
A runtime that has sent a key advertises the `sealed_secrets` capability.

`approvals` is the plan's approval envelopes (ADR 0037). The server includes
them only when a step writes a sealed secret, so a runtime that predates the
field keeps decoding idle work and ordinary plans. The runtime recomputes
the plan digest, finds the sealed step, and evaluates the envelopes against
a local approval policy installed with it (`TENKAI_RUNTIME_APPROVAL_POLICY`),
at the same strict quorum the host applier uses. Without that policy, or when
the envelopes bind different executable content, a sealed step is refused
with a named reason. Incomplete envelopes keep the claim and retry; they do
not fail the plan. Other steps are unchanged.

A step's `sealed` is a list: every non-remove step of an instance with
sealed values names each (`secret`, `key`, `digest`). The field is omitted
when empty, so plans without sealed values keep their digest.

### Runner attestation statement

`tenkai.runner-attestation.v2` is signed over the exact bytes the agent
sends. The `attestation` field of an enrollment or renewal is:

| Field | Value |
| --- | --- |
| `schema` | `tenkai.runner-attestation.v2` |
| `algorithm` | `ecdsa-p256-sha256`, the only one |
| `statement` | base64 (standard alphabet, padded) of the statement: a UTF-8 JSON object |
| `signature` | base64 (standard alphabet, padded) of an ASN.1 DER ECDSA P-256 SHA-256 signature, by the key of the request's CSR, over the ASCII domain `TENKAI-RUNNER-ATTESTATION-V2`, one `0x00` byte, then the decoded statement bytes |

The server verifies the signature over the bytes it received before it
parses them, so neither side's JSON formatting or field order is part of
the contract. The statement object has these fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `environment` | string | The environment of the request path |
| `checked_at` | integer | Unix milliseconds the evidence was taken; at most `max_age_ms` old and 60 s ahead of the server |
| `passed` | boolean | True only when every check passed |
| `checks` | array of `{check: string, passed: boolean, reason: string}` | Host preflight checks the agent ran; may be empty |
| `facts` | object of string to string | Probed host facts (the environment fact keys); a key may appear once |
| `key_fingerprint` | string | `sha256:<hex>` of the CSR key's DER SubjectPublicKeyInfo |
| `hardware_backed` | boolean | True when the key was generated in a hardware store |

A verifier ignores statement fields and check fields it does not know,
which the signature still covers. An added field must therefore be one an
older verifier can safely ignore; a field that changes what the statement
means needs a new schema. Fields of the `attestation` object other than
those above are ignored and unsigned. A repeated key in the statement or in
`facts` is malformed.

The evidence digest is `sha256:<hex>` of the decoded statement bytes as
sent. The issued runner certificate carries it in the private, non-critical
extension `2.25.15797326480183637975`: a DER `SEQUENCE` of two 32-byte
`OCTET STRING`s, the evidence digest and the key fingerprint, followed by
`BOOLEAN TRUE` when the key is hardware-backed.

`tenkai.runner-attestation.v1` is deprecated. Its `statement` is a JSON
object signed over the server's own re-encoding of it, it allows no added
field, and its evidence digest hashes the server's re-encoding of the whole
attestation. Servers of this release still verify it from agents of earlier
releases; a later release removes it.

The other endpoints take either a configured runtime token or an enrolled
credential as the bearer
([enrolling a runtime](run-tenkai-server.md#enrolling-a-runtime)). An agent may
send `x-tenkai-runtime-version`, which the
[runner registry](run-tenkai-server.md#runner-registry) shows.

Work pull does not accept supported versions and does not negotiate. The
capabilities are `workload_identity` and `peer_grants`, named
comma-separated in `x-tenkai-runtime-capabilities` ([below](#identity-issuer)). Completion covers the claimed plan in one request, not one proto
`CompleteStep` per step. Inventory is an admitted facts map, not a proto
`Observation`.

Operator publish, promote, plan, apply, and rollback are a different surface:
the authenticated HTTP [management lifecycle](management-lifecycle.md)
([ADR 0030](decisions/0030-remote-management-lifecycle.md)).
Transport authentication maps a principal to exactly one `environment_id`, and
the server rejects any request whose payload identity differs from that scope.
Each runtime process also presents a fresh instance identity. Authentication
remains token-based, while durable lease ownership binds both the authenticated
scope and that instance so overlapping processes cannot share one generation.

The HTTP host supplies the executor with a stable `<plan-id>:<step-id>`
idempotency key. Executors must durably claim that key before mutation and
return the previously recorded outcome after reconnect. This closes the
ambiguous interval where a runtime process can stop after the target changed
but before its receipt reached Tenkai.

Cancellation is advisory until observed by the runtime. Losing a lease is a
hard fence: the runtime must stop work, and a completion from that generation
is rejected.

### Release package

A runtime in built-in mode (`TENKAI_RUNTIME_EXECUTOR=builtin`, ADR 0048)
applies each claimed step itself. For every step it posts the plan id, claim
generation and step id to `/release`, and with `restore: true` asks for the
step's restore pin: the release a failed activation restores and a rollback
removes first. The server admits the release as it would before applying it
and answers with:

- `manifest`: the signed manifest text, and `signature`: its release
  signature envelope.
- `request`: the executor request the server computed (overlays, config
  digest, admitted environment-mirror pulls, dependency document). Its
  `workdir`, `cluster_config_path` and `secret_dir_path` are empty: the
  runtime fills them from its own configuration.
- `entries`: every deploy input, parents first, each a relative `path`, a
  `mode`, and base64 `contents` (absent for a directory).
- `sealed`: for a step that writes sealed secrets, each value the step
  names, in its order: `secret`, `key`, and the stored `sealed` value with
  every wrap. Omitted otherwise. A value changed since the plan was made is
  refused (`412`).

The runtime trusts none of it until it checks it: the manifest digest and
names against the plan step, the signature against its own release trust
roots (`TENKAI_RUNTIME_RELEASE_TRUST_ROOTS`), the request against the step,
the pulls against the manifest's artifacts, the rebuilt inputs against
the signed artifact digest, and each sealed value against the step's digest
before it opens the one wrapped for its own key. The runtime then runs the step as the server
would, including its recovery: a failed restart re-applies the current pin,
and a failed activation is cleaned up and the restore pin applied. An older
server answers `404`, and the runtime fails the
step naming the server upgrade.

A host step's package is its release: the runtime builds the applier's
request from the claimed plan, this release, and the plan's approval
envelopes, which work delivery carries for every plan with a host step.
Its restore pin has no package (`412`): host releases are never restored
automatically. A removal's package is the installed release, admitted as
the server admits a removal: a recalled release can still be removed, and
neither compatibility nor placement is checked. The runtime removes it
through the release's executor, or its `deploy.uninstall` for a `shell`
release (ADR 0049). A runtime asks for a non-host removal's package with
`removal: true`; without it the server answers `412`, because an older
runtime would install the release instead of removing it.

### Re-wrap steps

A step with `rewrap` (ADR 0045 §5) asks the runtime to wrap the data keys
of the instance's sealed values, as the step's `sealed` names them, for one
more recipient. Its release package carries the step's sealed values and
`rewrap_recipient`: that recipient's public key, which the runtime checks
against the step's fingerprint. The package has no manifest, inputs or
artifact pulls, so the server admits no release content for it, and the
runtime verifies nothing about the release and deploys nothing. A re-wrap
step has no restore pin (`412`). Its receipt carries `wraps`: for each value, `secret`, `key`, the
approved `digest`, and the new `wrap`. The server keeps them only for a
succeeded re-wrap step, for its recipient, and for a value at that digest.
`wraps` and `rewrap_recipient` are omitted when empty, so other receipts and
packages are unchanged.

A recovery re-wrap (ADR 0045 §7) also carries `rewrap.recovered`: wraps for
the step's recipient, each with `secret`, `key`, `digest` and `wrap`, that the
offline recovery key made. The runtime whose key is the recipient, and that
has no wrap of its own for a value, opens the value through the recovered
wrap for its slot and digest and returns a fresh wrap. Work with such a step
is handed only to that runtime; any other runtime polls idle. The recipient of a
re-wrap step may also be the environment's recovery key, so values sealed
before it was set get a wrap for it.
`recovered` is omitted when empty, so other steps keep their digest.

### Identity issuer

A built-in runtime with a sealing key names `workload_identity` in
`x-tenkai-runtime-capabilities` (ADR 0046 §2). A server that predates it
ignores the header. Only to such a runtime does the server:

- add `issuer_candidate` (`generation`) to idle work while
  `identity-issuer prepare` waits for a candidate. The runtime generates a CA
  key, seals it to its own sealing key only, and posts the fingerprint,
  certificate and sealed key. The server refuses a candidate with any wrap
  other than the poster's own unrevoked key, so it cannot add a recipient it
  controls. The first candidate for a generation is kept and returned to
  every later post, so a runtime whose key lost drops it, and a retry after a
  crash creates no second one. A candidate whose wrap a revocation dropped is
  replaced.
- hand out a plan with an issuer step, and only to a runtime whose key wraps
  the step's key. An older runtime polls idle instead.

A step with `issuer` names no product, instance or release, and has no
release package (`412`). Its `issuer.key` is the candidate. The runtime
verifies the plan against its local approval policy, opens the key, and
refuses it unless its public half has `issuer.key.fingerprint`. The server
then records the issuer as a compare-and-set on the previous generation, and
refuses the completion of a step whose generation is no longer the next. An
issuer step with `rewrap` wraps the recorded issuer key for
`issuer.recipient`, whose fingerprint `rewrap.fingerprint` names; its
receipt carries one wrap with `secret` `identity-issuer` and `key`
`generation-<n>`. `identity-issuer rewrap` plans this step on its own, apart
from `secret rewrap`: the runtime that opens the issuer key need not open
the sealed values. A lost issuer is rotated, not recovered.

Rotating an existing issuer (ADR 0046 §7) adds `issuer.phase` to the step:
`add` records `issuer.key` as the next issuer, `issue` makes the next
issuer current and keeps the replaced one as the previous issuer, and
`remove` names the previous issuer as `issuer.key` and stops trusting it.
Each is a compare-and-set, and a replay changes nothing. The server records
a remove step only once every deployed instance with a certificate
reported one from the current issuer, taken up as for the issue step. Running it opens
nothing and changes nothing on the runtime. The runtime keeps each key it
opens for an `add` or `issue` step, and every certificate it issues for a
Helm target carries the issuer one generation before and after the issuing
one in its trust bundle (`ca.pem`), after the issuing issuer. A certificate
whose bundle lacks one of them is renewed on the next pass. A host
certificate's bundle carries only the issuers an approved rotation plan the
runtime kept proves. The runtime spools those plans with the certificate,
and the host applier checks them against its own approval policy
([Host releases](host-releases.md)).

Work for a runtime that names `issuer_take_up`, idle or claimed, carries
`issuer_proofs`, each an approved rotation plan (`plan`) and its
`approvals`: the add plan while a next issuer waits, the issue plan
until the next issue step, and the remove plan once the replaced issuer is
removed, until the next issue step. A runtime that missed the promotion
reads the issue plan first and the remove plan after it. The issue step names that issuer in
`replaces`. The runtime trusts the add step's key, or the
issue step's `replaces` one generation below its key, only if its local
approval policy accepts the plan and the plan is of this environment with
that single step. A plan with `replaces` goes only to a runtime that names
`issuer_take_up`, and a plan with a `remove` step, or the remove plan's
proof, only to one that names `issuer_removal`. The server does not track
which runtimes name it: a runtime that does not keeps the removed issuer
in the bundles it writes, so approve a remove step only once every runtime
of the environment names `issuer_removal`. A runtime that verifies a remove plan drops its
issuer, and every generation below it, from the issuers it trusts and from
its kept proofs, never trusts them again, and renews each certificate whose
bundle still carries it. A replayed older plan changes nothing. It
refuses a remove plan for the issuer it issues from, or a later one. Running the issue step only keeps both issuers. The
server hands out the issue plan once it recorded the step; from then on a
runtime that can open the next issuer renews from it, and a certificate
granted by the replaced generation, whose issuer the runtime trusts,
renews from it with the same grant otherwise. A proof holds after its
approvals expire, as long as their signers are still in the runtime's
local policy and inside their validity window, so a runtime that joins
later still verifies it. The issue plan's proof also carries `current`,
the issuer as the server holds it now; the runtime uses it, for the wraps
re-wraps added since the plan, only when its generation, fingerprint and
certificate are the approved key's. Certificate reports carry `trust`, the bundle's issuer
fingerprints with the issuing one first (at most 4), and `restart_pending`
until every live pod of each restart-reload workload runs a template naming
the certificate and is ready;
both are omitted when empty. `observed_at` is when the runtime observed
the state, in Unix seconds; of two reports of one certificate the server
keeps the later observed, and a pending restart on a tie. A runtime sends
`trust`, `restart_pending` and `observed_at` only while the last work
response carried `x-tenkai-server-capabilities: certificate_observations`,
since an older server refuses them. The runtime
sends an unchanged state again every 5 minutes with a fresh `observed_at`;
a report not observed in a later second than the instance's last deployment does not count
toward take-up. The server plans the issue step only once
every instance with a certificate has taken up a bundle with the next
issuer. `phase` is omitted on the first
issuer's step and on a re-wrap, so they keep their digest. The server hands
a plan with a phase only to a runtime that also names `issuer_rotation`; an
older one, which cannot decode the field, polls idle.

A step with `identity` grants a workload certificate: `uri`, `dns_names`,
`certificate`, `reload`, `issuer_generation` and `issuer_fingerprint`, and
`peers` when its bindings give it any: `servers` (contract to the provider
identity it accepts) and `clients` (contract to the dependent identities it
accepts). The release package's dependency document must name exactly those
peers, or the runtime refuses the step; a grant without peers also
accepts no document. The server hands a plan whose grant
names peers only to a runtime that also names `peer_grants`, since an older
one cannot decode the field.
`restore_identity` grants the restore release's in the same shape, used
only when the step fails and the runtime restores. The plan digest covers
both. The server hands such a plan only to a runtime that
names `workload_identity` and whose key wraps the current issuer, and blocks
one whose issuer is no longer current. Its release package carries
`identity_issuer`, the current `IssuerKey`. The runtime recomputes the grant
from the signed manifest and that issuer and refuses the step on any
difference. The certificate and its key never appear in the receipt.
`identity`, `restore_identity` and `identity_issuer` are omitted when absent, so other steps
keep their digest.

### Host records

A built-in runtime with a host applier (`TENKAI_HOST_SPOOL_DIR`) posts every
applied-state record the applier keeps for its environment, each poll and
after each plan. The server stores each as an immutable, read-only fact of
the environment and plans host steps from the most advanced stored record of
each product (by generation, then by its latest start and that start's
result), so a delayed or concurrent report never moves a product back; a
product without one is planned from an empty record. Records of another
environment, or two of one product, refuse the report (`400`). Once an environment has reported, its host steps are planned only
from reported records; before that, only a server that runs an applier
itself plans them. A stale record makes the step refused by the applier's
generation check, never run. An older server answers `404`; the runtime
logs it and continues.

### Workload certificates

A built-in runtime with a sealing key renews workload certificates itself
([ADR 0046](decisions/0046-workload-identity-and-peer-policy.md) §3) and,
after a renewal pass whose result changed, posts each certificate its
targets hold: the instance, `not_before` and `not_after` (Unix seconds), and
`last_renewal`, the last attempt it audited (`at`, and `renewed` with the new
`not_after` or `failed` with a `reason` of at most 512 bytes). The server
stores each report as an immutable fact of the environment and keeps the
furthest one per instance (by `not_after`, then by the attempt's time), so a
delayed or repeated report never moves an instance back. `status` shows an
instance whose certificate is in its last sixth as near expiry, with the
expiry and the last failure. Reports of another environment, or two of one
instance, refuse the report (`400`). An older server answers `404`; the
runtime logs it and continues.

## Typed proto contract

`proto/tenkai/runtime/v1/runtime.proto` is a separate typed contract. Helpers
in `runtime_protocol` validate proto deliveries and compute
`delivery_plan_digest`. Those messages are not the HTTP JSON payloads and are
not served on the wire.

The runtime opens a proto session with all protocol major/minor pairs and
capabilities it supports. The server selects the highest mutually supported
minor in major version 1 and returns its required capabilities. A major
mismatch or missing capability fails negotiation. Before returning a plan,
both sides validate every step's required capability and version.

Within major version 1, senders may add fields and enum values, receivers
ignore unknown fields, and existing field numbers and meanings never change.
Fields are never reused. During a rolling upgrade, servers support the current
and previous minor; runtimes may be upgraded before or after servers. A
feature is delivered only after negotiation proves support. A major version
requires a parallel API package and an explicit migration window.

A proto delivery is immutable and scoped to one environment. Each step has an
attempt number and digest-only execution input. Its lease has an opaque ID and
a monotonically increasing generation. The runtime verifies that generation
immediately before mutation. Heartbeats renew only the exact `(lease_id,
generation)` pair. Completion under an older generation returns `STALE_LEASE`.
The plan digest uses the versioned canonical field sequence implemented by
`delivery_plan_digest`, not serialized protobuf bytes, so additive transport
fields do not change older digest contracts.
The server uses its own clock for lease authority; runtime completion
timestamps are audit metadata and are accepted only within five minutes of
server time and never after the active lease expiry.

The receipt ID is a deterministic digest of environment, plan, step, and
attempt. The result and result digest belong to the canonical receipt but not
its mutation identity. The server stores the first accepted receipt under that
identity atomically. Re-delivery, including a conflicting later result,
returns the first canonical receipt with `ALREADY_COMPLETED`; it must not
invoke the executor again. A plan cannot become successful until every step
has an accepted success receipt.

## Secrets and logging

Credentials belong to transport/runtime configuration.

The proto contract contains no credential, environment-variable, arbitrary
metadata, command-output, or free-form log field. Proto plans carry only
actions and content digests; proto receipts carry a result enum and digest.

HTTP `RuntimeCompletion` and `RuntimeStepReceipt` carry free-form `detail`
strings plus a success boolean. Those details persist into plan transitions
and terminal-outcome evidence. Runtimes must not put secrets, tokens,
command output, or credentials in `detail`. Implementations must log
identifiers, versions, result codes, and digests only, and must not
serialize authentication metadata into payloads, errors, tracing fields, or
logs.

## Compatibility checklist

- Authorize the path `environment` against the transport principal.
- Persist delivery and receipt idempotency keys atomically.
- Compare plan ID and generation on HTTP heartbeat and completion.
- Treat unknown HTTP JSON fields as unsupported, never as success. A
  signed runner attestation statement is the exception: its unknown fields
  are ignored and stay covered by its signature.
- Keep the proto `Negotiate` / `Pull` / `CompleteStep` / `Heartbeat` /
  `ReportObservation` surface distinct from the HTTP JSON types above.
- On the proto contract, negotiate versions and capabilities before accepting
  a delivery, and upgrade either side independently within the stated rolling
  window.
