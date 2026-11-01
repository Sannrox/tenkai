# Family release manifests

A component's `v*` release workflow emits a family release manifest
(`tenkai.family-release-manifest.v1`, see the family versioning policy in
[ADR 0040](decisions/0040-family-versioning-and-release-policy.md)). Publish it
with the Catalog Release it describes:

```sh
tenkaictl publish tenkai.toml \
  --signature release.sig.json \
  --trust-roots release-trust.toml \
  --family-release kako-release.json \
  --family-release-signature kako-release.sig.json
```

The manifest is JSON with `schema`, `component`, `version`, `git_sha`, `tag`,
`binaries` and `images` (each `{name, digest}`), `attestations`, and
`gate_flags` (`breaking`, `migration`, `realm`). Admission requires:

- `component` and `version` equal the release's product name and version, and
  `tag`, when present, is `v<version>`;
- `git_sha` is a full lowercase SHA;
- every binary and image digest is `sha256:<64 lowercase hex>`;
- no image is a tag-only reference: an image name ending in `:latest`, an
  image without a valid digest, or a digest embedded in the name is refused;
- a release signature from the publication trust roots whose manifest digest
  is the SHA-256 of the manifest file and whose artifact digest is the SHA-256
  of the sorted `binary <name> <digest>` and `image <name> <digest>` lines.

The family release needs `--trust-roots` even for local development, so gate
flags never come from unsigned input. Publication stores the manifest digest
and gate flags on the release. Re-publishing the same release with a different
family manifest, or adding one to a release published without it, is refused:
releases are immutable.

## Gate flags hold channels

`tenkaictl promote <product>@<version> <channel>` sets a delivery hold on the
channel before moving its head when the release carries any gate flag. The
hold reason names the release and its flags; nothing reconciles from the
channel until a human clears the hold
(`tenkaictl channel hold <product> <channel> clear`; see
[manage environments](manage-environments.md)). A channel that
is already held keeps its existing hold. Releases without gate flags promote
as before.

`--family-release` is available with `--target embedded`, like the other
publication evidence.
