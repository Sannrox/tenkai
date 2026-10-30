# Dark-site local model profile

Operator profile that pins a local `model_runtime` digest beside a
`site-agent` worker image, binds those pins to an offline stack index, and
refuses cloud model routes while active. See [dark-site.md](../../docs/dark-site.md).

Placeholder digests are schema examples only. Replace them with the bundle's
verified weight and worker-image digests before use.

```bash
tenkaictl dark-site validate --profile examples/dark-site/profile.toml
tenkaictl dark-site activate \
  --profile examples/dark-site/profile.toml \
  --stack examples/dark-site/stack.json \
  --state .tenkai-state/runtime/local
```
