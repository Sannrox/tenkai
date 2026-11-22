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
tenkaictl --target remote env preview review \
  --pin pin.json \
  --expires-at 2026-09-16T00:00:00Z \
  --reason "review branch"
tenkaictl plan --env review
tenkaictl env inspect review
tenkaictl env close-preview review
tenkaictl --target remote env close-preview review
```

HTTP v1 create and close use the same provision and close rules as
embedded `tenkaictl`:

- `POST /v1/environments/preview` with the branch pin and an RFC 3339 expiry
- `POST /v1/environments/{environment}/close-preview`

An agent in the actor chain is refused on create and close. ADR 0034 is
unchanged.

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
  timestamp on the environment object. A preview with deployed instances first
  records status `closing` and plans `Remove` steps through its approval
  policy; it is `torn_down` only after those steps succeed. A preview that
  never deployed anything is marked `torn_down` immediately. Teardown never
  deletes the object and never mutates a non-preview environment, even if
  preview expiry properties are forged onto it. Existing `torn_down` previews
  have already dropped their deployment records; leftover workloads from
  those names stay a manual cleanup.
- Planning a torn-down or expired preview fails closed on snapshot planning,
  explicit `create_from_steps` (rollback/restart), and apply admission of a
  leftover Computed plan. A `closing` preview admits only `Remove` steps.
  The reconciler starts teardown after in-flight apply recovery, never while
  a plan is still Busy or awaiting runtime. Interrupted removal resumes on
  the next tick. Later ticks treat the retained torn-down object as terminal
  Current and do not re-plan or admit.

Issue: [#379](https://github.com/Sannrox/tenkai/issues/379).
Related: [change-set closure pins](change-set-pin.md),
[workshop module delivery](workshop-modules.md).
