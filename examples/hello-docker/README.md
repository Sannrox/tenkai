# hello-docker — Docker host executor

| Piece | What |
| --- | --- |
| Control plane | Embedded `tenkaictl` + SQLite |
| Runtime | Local Docker engine |
| Apply path | `TENKAI_SOFTWARE_EXECUTOR=docker` → Docker CLI |

`docker/host.json` is the immutable topology: two digest-pinned containers, one
network, one named volume, a health dependency, and an `env_file` basename.
Replace the placeholder digests with images present on the host before a live
apply. Secret values live in an environment-scoped directory, never in the
release or in Tenkai state:

```bash
export TENKAI_SOFTWARE_EXECUTOR=docker
tenkaictl env docker-secrets set local /var/lib/tenkai/local-secrets
```
