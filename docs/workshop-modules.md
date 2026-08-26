# Workshop module delivery

`workshop_module` delivers one signed Workshop module through the existing
publish → promote → plan → apply path. Tenkai stores the delivery profile and
activation receipt. It does not render modules, migrate types, or change the
runtime.

See [ADR 0023](decisions/0023-workshop-module-delivery.md).

## Profile

```json
{
  "version": 1,
  "profile": "tenkai.workshop_module.v1",
  "module_id": "hello-workshop",
  "module_digest": "sha256:…",
  "type_compatibility": { "version": 1, "digests": ["sha256:…"] },
  "runtime_compatibility": { "version": 1, "digests": ["sha256:…"] }
}
```

The module payload remains in content-addressed storage. The profile binds
only digests.

Publication requires `[change_set_pin]` plus `--change-set-evidence`. The pin
must include:

- `workshop_module` / `module_id` / `module_digest`
- every `type_revision` digest from `type_compatibility`
- every `runtime` digest from `runtime_compatibility`

Missing evidence, unknown versions, unauthorized or recalled closures, and
digest mismatches fail before Catalog mutation.

## Observe, plan, apply

Record the environment's current type and runtime digests before the first
module plan:

```bash
tenkaictl env observe local \
  --type-digest sha256:… \
  --runtime-digest sha256:…
```

A mismatched or missing observation blocks planning and apply before the
module changes. Module-only apply leaves those observed digests unchanged
and writes one activation receipt. `tenkaictl env inspect` shows the tuple.

Restart and duplicate apply reuse the accepted receipt and do not activate
the module a second time.

## Rollback, recall, failed restore

- `tenkaictl rollback <product> --env <env>` restores the prior module
  receipt. Type and runtime observations stay as they were.
- Recalled module releases fail lookup and planning. Do not treat recall as a
  type or runtime change.
- If activation fails, Tenkai restores the prior module. If restore cannot
  prove the previous tuple, inspect reports recovery-required / unknown
  health. Reconcile the environment before the next module delivery.
- Recovery uses Tenkai receipts and retained descriptors. Ontology or
  governance availability is not required.

## Example

[examples/workshop-module](../examples/workshop-module/) contains a synthetic
signed-development fixture, compatibility pin, and rollout commands.
