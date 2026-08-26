# Workshop module fixture

Synthetic module-only delivery. The profile binds digests; it does not include
Workshop source.

```bash
tenkaictl init
tenkaictl publish examples/workshop-module/tenkai.toml \
  --allow-unsigned-development \
  --change-set-evidence examples/workshop-module/closure.json
tenkaictl promote hello-workshop@1.0.0 stable
tenkaictl env observe local \
  --type-digest sha256:2222222222222222222222222222222222222222222222222222222222222222 \
  --runtime-digest sha256:3333333333333333333333333333333333333333333333333333333333333333
tenkaictl env subscribe local hello-workshop=stable
tenkaictl plan --env local
tenkaictl apply <plan-id> --allow-unapproved-development \
  --development-reason "workshop module drill"
tenkaictl env inspect local
tenkaictl rollback hello-workshop --env local \
  --allow-unapproved-development \
  --development-reason "workshop module rollback"
```

A different `--type-digest` blocks planning before the module changes. Recalling
`hello-workshop@1.0.0` blocks later plans until another non-recalled head is
promoted. If restore cannot prove the prior tuple, inspect reports unknown
health and later module delivery stays blocked until `tenkaictl env reconcile`.
