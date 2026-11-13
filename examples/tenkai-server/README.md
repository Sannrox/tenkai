# tenkai-server catalog product

Signed catalog releases of the Tenkai control-plane host, including the web
console the `ui`-enabled binary serves at `/ui/`.

Pack verified host binaries next to this manifest, sign, publish, and deliver
through an environment runtime. The coordinating server refuses to apply
`tenkai-server` itself. In-place replacement of that host is
`tenkaictl self-upgrade`.

```bash
bash scripts/pack-tenkai-release.sh \
  --hosts-dir ./tenkai-hosts/linux-x86_64 \
  --version 0.9.0 \
  --out ./tenkai-server-0.9.0
tenkaictl dev sign-release ./tenkai-server-0.9.0/tenkai.toml --keys ./lab-keys \
  --signature ./tenkai-server-0.9.0/tenkai.sig.json \
  --trust-roots ./lab-trust.toml
```

Runbook: [`docs/deliver-tenkai.md`](../../docs/deliver-tenkai.md).
