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

A GitHub Actions job publishes with the `publish-release` step from this
repository. It authenticates as a machine principal with
`tenkaictl login --client-credentials`, never with `TENKAI_MANAGEMENT_TOKEN`,
and refuses to run when that token is set. The runner holds the client secret
as an environment-protected secret. The Tenkai server still only verifies the
access token. The step takes no signing key: sign the manifest first.

Grant the CI client's group `capabilities = ["publish"]`, optional
`channels = ["stable"]`, and `kind = "service"`. See
[configure server authentication](configure-server-authentication.md#ci-client-credentials-login)
and the sample workflow in [examples/ci-publish](../examples/ci-publish/).

```yaml
- id: tenkai
  uses: Sannrox/tenkai/.github/actions/publish-release@<tag or commit SHA>
  with:
    manifest: deploy/tenkai.rendered.toml
    signature: ${{ runner.temp }}/tenkai.sig.json
    trust-roots: ${{ runner.temp }}/release-trust.toml
    server-url: ${{ vars.TENKAI_SERVER_URL }}
    client-id: ${{ vars.TENKAI_OIDC_CLIENT_ID }}
    client-secret: ${{ secrets.TENKAI_OIDC_CLIENT_SECRET }}
    channel: stable        # optional; empty publishes only
    # tenkaictl: ./tenkaictl  # default: tenkaictl on PATH
```

The step's `release` output is the published `product@version`. Pin the step
to a Tenkai release tag or full commit SHA, and install a `tenkaictl` of the
same release.

Re-running the same job is safe: the same version with the same signed
manifest is a no-op, and promoting it again changes nothing. A changed
manifest for the same version fails the step; bump `product.version`. Signing stays fail-closed; do
not pass `--allow-unsigned-development`.

Container executors are just shell commands in the manifest; Apple `container`
and Docker both work.

The instance Tenkai deploys should be a separate *workload* instance
(different ports and data) from the control-plane instance Tenkai talks to: the
control plane cannot safely restart its own backend mid-apply.

Tenkai's own server and console follow the same rule, as the `tenkai-server`
catalog product. See [deliver Tenkai with Tenkai](deliver-tenkai.md).
