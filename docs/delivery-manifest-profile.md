# Delivery-manifest profile v1

Profile id: `tenkai.delivery-manifest.v1` ([ADR 0021](decisions/0021-portable-delivery-manifest-profile.md)).

This is a public interoperability profile for delivery evidence. Tenkai remains
the operational owner of release, environment, plan, execution, rollback, and
recovery when it implements the profile. Independent verifiers reproduce
admission by calling the same content-bound functions; they do not reinterpret
unknown mandatory fields.

## Canonical bytes

| Object | Encoding | Fail-closed |
| --- | --- | --- |
| Signed release | `tenkai.release-signature.v1` ([release signing](release-signing.md)) | Digest mismatch, untrusted key, unknown fields. |
| Executable plan | `Plan::executable_digest` over immutable plan content | Lifecycle fields are excluded from identity. |
| Plan approval | `tenkai.plan-approval.v1` ([plan approval](plan-approval.md)) | Wrong plan, environment, expiry, or `skip_gates`. |
| Runtime receipt | Runtime completion + step receipts ([runtime protocol](runtime-protocol-v1.md)) | Stale fence, foreign environment, conflicting result. |
| Isolated archive | `tenkai.offline-bundle.v1` / `tenkai.offline-receipt.v1` ([ADR 0003](decisions/0003-canonical-offline-delivery-archives.md)) | Damaged media is discarded. |

Capability negotiation uses explicit required names. Unknown required
capabilities are denied. Unknown status or enum values are never success.

## Opaque ontology-package identity

An optional `ontology_package_ref` is a content-bound identity only:

- `sha256:` plus 64 lowercase hex digits, or
- a stable object id matching `[A-Za-z0-9:._/-]{1,256}` with no whitespace.

JSON payloads, privilege documents, reducers, and credential-like values fail
closed. The profile does not define ontology-package bytes.

## Exclusions

Reusable credentials, private keys, command output, arbitrary logs, ontology
payloads, governance policy languages, and agent-work state are not profile
fields.

## Conformance

`src/delivery_manifest.rs` admits fixtures through the shipped
`release_signing`, `plan_approval`, and `runtime_delivery` functions. Valid
fixtures must pass; altered manifest, plan, approval, and receipt fixtures
must fail. Recovery reconstructs progress from Tenkai-owned plan and receipt
state.
