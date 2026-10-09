# Publish a signed release from CI

Sample GitHub Actions workflow for a product repository. It is not a live
workflow in this Tenkai checkout. Copy `publish.yml` into the product repo
as `.github/workflows/publish.yml` and replace the placeholders.

The job authenticates as a machine principal with
`tenkaictl login --client-credentials`. It does not use the fleet
`TENKAI_MANAGEMENT_TOKEN`. Tenkai verifies the access token and never holds
the client secret.

## Server grant

Map the CI client's group (or role) to publish, optionally confined to one
channel:

```toml
[[grants.rules]]
value = "ci-publishers"
capabilities = ["publish"]
channels = ["stable"]
products = ["api"]
kind = "service"
```

See [configure server authentication](../../docs/configure-server-authentication.md#ci-client-credentials-login).

## Secrets on the runner

| Name | Use |
| --- | --- |
| `TENKAI_OIDC_CLIENT_SECRET` | Confidential OIDC client secret. Environment-only; never argv |
| `TENKAI_TRUST_ROOTS` | Public trust-root TOML for `--trust-roots` |
| `TENKAI_RELEASE_SEED` | 32-byte Ed25519 seed used by the product's signing step, not by `tenkai-server` |

`TENKAI_OIDC_CLIENT_ID`, `TENKAI_SERVER_URL`, and `TENKAI_PRODUCT` may be
variables. The detached signature `deploy/tenkai.sig.json` is produced before
publish (on the tag, as in [deploy from GitHub](../../docs/deploy-from-github.md),
or by a signing step that holds the seed). The server keeps only public trust
roots. Rotate by overlapping public keys, then removing the old key; see
[release signing](../../docs/release-signing.md). Do not use
`--allow-unsigned-development`. `tenkaictl dev sign-release` is laptop dogfood,
not the production signer.

## Idempotent re-run

The same version with the same signed manifest is a no-op (`already published`).
A changed manifest for the same version is rejected; bump `product.version`.
