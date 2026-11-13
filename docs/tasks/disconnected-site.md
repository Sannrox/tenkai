# Deliver to a disconnected site

Goal: move signed releases to a site that cannot reach the catalog, then bind and receipt the isolated upgrade.

Build the archive on a connected host. The command is embedded-only. Signing keys stay in files.

```sh
tenkaictl bundle build \
  --release edge-app@1.0.0 \
  --env site-c \
  --out site-c.bundle.json \
  --signing-key exporter.seed \
  --trust-roots offline-trust.toml
```

Carry `site-c.bundle.json` and its companion chunk directory to the site. First install of an empty isolated environment:

```sh
tenkaictl upgrade install-bundle cutover site-c \
  --product edge-app \
  --version 1.0.0 \
  --channel stable \
  --bundle site-c.bundle.json \
  --trust-roots offline-trust.toml
```

A site that already has Tenkai binds the bundle, applies under the site's own policy, and returns a signed receipt. Conflicts fail closed.

```sh
tenkaictl upgrade bind-bundle cutover site-c \
  --bundle site-c.bundle.json \
  --trust-roots offline-trust.toml
tenkaictl upgrade import-receipt cutover site-c \
  --receipt site-c.receipt.json \
  --bundle site-c.bundle.json \
  --trust-roots offline-trust.toml
```

The runtime on the site still verifies the release and the approval before it applies. The connected control plane is not an authority over that apply.

Contract detail: [offline bundles](../offline-bundles.md), [connectivity upgrades](../connectivity-upgrades.md).
