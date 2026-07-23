# Plan approval format

Tenkai requires authorization bound to the exact executable plan immediately
before execution. Tenkai owns this contract so embedded operation does not
depend on sekai-chisei. An environment policy may require a sekai-chisei
decision, but its adapter supplies evidence through the same envelope used by
the built-in standalone policy.

The detached JSON envelope uses `schema: "tenkai.plan-approval.v1"`:

```json
{
  "schema": "tenkai.plan-approval.v1",
  "key_id": "sha256:<sha256-of-public-key>",
  "statement": {
    "plan_digest": "sha256:<digest>",
    "environment": "prod",
    "purpose": "execute_plan",
    "skip_gates": false,
    "issued_at": 1784800000000,
    "expires_at": 1784800300000,
    "policy_provider": "builtin",
    "policy_evidence_id": "decision-123",
    "policy_digest": "sha256:<digest>"
  },
  "signature": "<base64 Ed25519 signature>"
}
```

The canonical signed bytes are independent of JSON serialization. They begin
with `TENKAI-PLAN-APPROVAL-V1` and a NUL byte. The plan digest, environment,
and purpose follow as UTF-8 strings prefixed by unsigned 64-bit big-endian
lengths. The issue and expiry times follow as signed 64-bit big-endian
integers, then `skip_gates` as one byte (`0` or `1`). The provider name,
evidence id, and policy digest then use the same length-prefixed string
encoding. An approval for normal gated execution cannot authorize
`--skip-gates`; the bypass must be explicitly signed.

The plan digest is SHA-256 of Tenkai's versioned executable-plan encoding. It
includes the plan id, content id, environment, creation time, desired-state
inputs, and ordered executable steps. Lifecycle status and other mutable audit
fields are excluded.

Trust roots use the same strict Ed25519 key representation as release signing:

```toml
version = 1

[[signers]]
key_id = "sha256:<sha256-of-the-32-byte-public-key>"
identity = "deployment-approver@example.com"
public_key = "<base64-encoded-32-byte-Ed25519-public-key>"
```

Apply verifies the signature, exact plan and environment scope, purpose, issue
time, expiry, policy fields, and current trust membership before claiming the
execution lease. Removing a key therefore revokes every not-yet-executed
approval made by that key; adding a replacement key does not alter existing
envelopes. Unknown fields, duplicate roots, malformed values, and missing or
mismatched inputs fail closed.

```sh
tenkaictl apply <plan-id> \
  --approval approval.json \
  --approval-trust-roots plan-approvers.toml

tenkaictl approval inspect <plan-id>
```

Successful verification records immutable, credential-free evidence containing
the signer identity, key id, exact scope, validity interval, provider evidence
id, and policy digest. The detached signature and public key are not copied
into this operator-facing record.

The continuous reconciler leaves non-local plans in `awaiting_approval`. A
server operator can configure `TENKAI_PLAN_APPROVAL_DIR` and
`TENKAI_PLAN_APPROVAL_TRUST_ROOTS`; placing an envelope at
`$TENKAI_PLAN_APPROVAL_DIR/<plan-id>.json` lets the next tick revalidate and
execute that exact plan. Missing files, incomplete configuration, stale plans,
and invalid or expired approvals remain pending or fail closed.

For local development only, an operator may use:

```sh
tenkaictl apply <plan-id> \
  --allow-unapproved-development \
  --development-reason "exercise local executor"
```

This bypass is rejected for every environment except the built-in `local`
environment and is recorded with its reason and policy digest. It is never
inferred from provider absence.
