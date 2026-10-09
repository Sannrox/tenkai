# hello-docker — Docker host executor

| Piece | What |
| --- | --- |
| Control plane | Embedded `tenkaictl` + SQLite |
| Runtime | Local Docker engine |
| Apply path | `TENKAI_SOFTWARE_EXECUTOR=docker` → Docker CLI |

`docker/host.json` is the immutable topology: two registry digest-pinned
containers, one network with a `database` alias, one named volume, a declared
command, a loopback port publication (`127.0.0.1:8080`), a health dependency,
and an `env_file` basename. Replace the placeholder references with real
`<repository>@sha256:` digests before a live apply; missing images are pulled. Secret values live in an environment-scoped directory, never in the
release or in Tenkai state:

```bash
export TENKAI_SOFTWARE_EXECUTOR=docker
tenkaictl env docker-secrets set local /var/lib/tenkai/local-secrets
```
