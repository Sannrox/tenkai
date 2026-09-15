# Preview environments

A preview environment is a short-lived, non-promotable `tenkai.environment`
bound to one content-addressed governance branch pin. It lets an operator plan
an unmerged branch of definitions without graduating that work onto a channel.

```json
{
  "contract": "tenkai.branch_pin.v1",
  "namespace": "acme",
  "branch_id": "types",
  "head_revision": "rev-1",
  "pin_digest": "sha256:..."
}
```

```sh
tenkaictl env preview review \
  --pin pin.json \
  --expires-at 2026-09-16T00:00:00Z
tenkaictl plan --env review
tenkaictl env inspect review
tenkaictl env close-preview review
```

Provision is an embedded `tenkaictl` mutation. The v1 remote management API
does not create or close preview environments.

The pin is Tenkai-owned identity after admission. Sekai-Chisei remains the
authority for branch membership, merge, and compatibility gates. Tenkai does
not import member payloads and does not recover from the branch service.

## Invariants

- `environment_kind=preview` is additive. Historical environments without the
  property stay ordinary channel subscribers.
- The same pin produces the same plan digest (`sha256:` of the canonical pin
  fields). Environment name is not part of that digest.
- Replaying the same name, pin, and expiry is idempotent. A different pin or
  expiry on an existing name fails closed. A torn-down name cannot be reused.
- Subscribe and any attempt to promote the preview environment onto a channel
  are refused. Catalog `promote` of a signed release onto a channel is
  unchanged and is not a preview graduation path.
- Expiry or recorded branch close tears the preview down and stores reason and
  timestamp on the environment object. Teardown never deletes the object and
  never mutates a non-preview environment, even if preview expiry properties
  are forged onto it.
- Planning a torn-down or expired preview fails closed. The reconciler tears
  down expired preview environments after in-flight apply recovery, never
  while a plan is still Busy or awaiting runtime.

Issue: [#379](https://github.com/Sannrox/tenkai/issues/379).
Related: [change-set closure pins](change-set-pin.md),
[workshop module delivery](workshop-modules.md).
