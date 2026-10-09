# Deploy releases from GitHub

GitHub is the artifact source; Tenkai is the delivery plane. A new tag in the
product repository becomes publish → promote → apply, with the same gates,
health probes, and rollback as any other product. sekai-chisei is the first
product delivered this way and is used as the example below.

1. **The product repo owns its manifest**: for example `deploy/tenkai.toml` in
   sekai-chisei, pinning the container image tag that matches
   `product.version`. Keep its deploy commands self-contained (no repo
   checkout needed). See [the manifest](manifest.md).
2. **A release workflow publishes the image**: on tag `v*`, GitHub Actions
   builds and pushes `ghcr.io/<owner>/<repo>:<version>`. The tag also carries
   the detached release signature `deploy/tenkai.sig.json`; see
   [release signing](release-signing.md).
3. **Publish the manifest straight from the tag**, with no checkout:

```bash
release_signature=$(mktemp)
gh api "repos/Sannrox/sekai-chisei/contents/deploy/tenkai.sig.json?ref=v0.2.0" \
  --jq .content | base64 -d > "$release_signature"
gh api "repos/Sannrox/sekai-chisei/contents/deploy/tenkai.toml?ref=v0.2.0" \
  --jq .content | base64 -d | tenkaictl publish - \
    --signature "$release_signature" \
    --trust-roots /etc/tenkai/release-trust.toml
rm -f "$release_signature"
tenkaictl promote sekai-chisei@0.2.0 stable
tenkaictl plan --env local
# Apply needs a signed approval of that exact plan; see plan-approval.md.
tenkaictl apply <plan-id> \
  --approval approval.json \
  --approval-trust-roots /etc/tenkai/plan-approvers.toml
```

## Publish from CI without a fleet management token

A GitHub Actions job can authenticate as a machine principal with
`tenkaictl login --client-credentials` instead of `TENKAI_MANAGEMENT_TOKEN`.
The runner holds `TENKAI_OIDC_CLIENT_SECRET` as an environment-protected
secret. The Tenkai server still only verifies the access token.

Grant the CI client's group `capabilities = ["publish"]`, optional
`channels = ["stable"]`, and `kind = "service"`. See
[configure server authentication](configure-server-authentication.md#ci-client-credentials-login)
and the sample workflow in [examples/ci-publish](../examples/ci-publish/).

```bash
tenkaictl login --client-credentials
tenkaictl --target remote publish tenkai.toml \
  --signature tenkai.sig.json \
  --trust-roots "$TRUST_ROOTS"
tenkaictl --target remote promote "$PRODUCT@$VERSION" stable
```

Re-running the same job is safe: the same version with the same signed
manifest is a no-op (`already published`). A changed manifest for the same
version is rejected; bump `product.version`. Signing stays fail-closed; do
not pass `--allow-unsigned-development`.

Container executors are just shell commands in the manifest; Apple `container`
and Docker both work.

The instance Tenkai deploys should be a separate *workload* instance
(different ports and data) from the control-plane instance Tenkai talks to: the
control plane cannot safely restart its own backend mid-apply.
