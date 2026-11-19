# Security overview

Tenkai is built for environments where the delivery server is not trusted:
releases are signed, every change is approved and signed, and runtimes verify
what they apply. This page summarizes what that protects, how to check a
Tenkai download, how to report a vulnerability, and what is not protected.
The full analysis, with a link for every claim, is the
[threat model](threat-model.md).

## What is protected

- **Releases.** Only content signed by a trusted root is published.
  Runtimes in built-in mode and the root-side host applier check the
  signature, revocation and digests themselves before they apply
  ([threat model: compromised server](threat-model.md#against-a-compromised-server)).
- **Changes.** A plan runs only with signed approvals bound to its digest,
  environment and expiry, optionally from several distinct approvers
  ([plan approval](plan-approval.md)).
- **Secrets.** Sealed values are encrypted to the environment's runtimes;
  the server cannot read them or redirect them to another instance
  ([sealed secrets](manage-environments.md#sealed-secrets)).
- **Keys.** Keys can be rolled over without downtime and revoked fleet-wide,
  including offline; production signers use hardware tokens under dual
  control ([key rollover](key-rollover.md), [key ceremony](key-ceremony.md)).
- **Access.** Every management and runtime request is authenticated and
  scoped; runtime credentials
  cover one environment; agents can propose but not apply
  ([server authentication](configure-server-authentication.md),
  [agent actors](decisions/0034-agent-actor-mutations.md#decision)).
- **Audit.** Exports are a signed chain that verifies offline
  ([audit export](audit-export.md)).

## Verify a Tenkai download

Each release attaches `SHA256SUMS` and GitHub artifact attestations for every
host, package and the SBOM. Check both before running a binary:

```bash
gh attestation verify "tenkaictl-${platform}" \
  --repo Sannrox/tenkai \
  --signer-workflow Sannrox/tenkai/.github/workflows/release-binaries.yml \
  --source-ref refs/heads/main
grep " tenkaictl-${platform}$" SHA256SUMS | sha256sum -c -
```

- **Full steps.** Downloads and the macOS checksum command are in
  [verify and install by hand](release-binaries.md#verify-and-install-by-hand).
- **SBOM.** `tenkai.cdx.json` is a CycloneDX SBOM of the locked dependency
  graph, schema-validated before it is attested. Verify its attestation with
  `--predicate-type https://cyclonedx.org/bom`
  ([packaging path](release-binaries.md#packaging-path)).
- **Install script.** `install.sh` is listed in `SHA256SUMS` and attested;
  verify it the same way before running it
  ([install with one command](release-binaries.md#install-with-one-command)).
- **Disconnected sites.** Attestations need a network; verify the signed
  offline bundle instead
  ([disconnected sites](release-binaries.md#disconnected-sites)).

## Reproduce a release build

The Linux hosts build reproducibly: two builds of one commit package
byte-identical binaries. CI checks it on every change to dependencies, the
toolchain or release packaging. A second, cold build on another runner must
match the release dry run's hosts. To rebuild a release yourself, check out
its tag and run:

```bash
bash scripts/build-linux-release-hosts.sh --platform linux-x86_64 --out rebuilt
bash scripts/package-release-binaries.sh compare --out rebuilt --against downloaded
```

`downloaded` holds that release's `linux-x86_64` hosts, and `compare` names
any asset that differs. The build runs in a digest-pinned image with fixed
paths. The C toolchain is installed from the image's package repositories,
and the build log records its versions (`rpm -q gcc binutils glibc-devel`).
A rebuild long after a release can pick up a newer toolchain and differ for
that reason alone. The `darwin-aarch64` and `linux-aarch64` hosts are not
checked.

## Report a vulnerability

Report privately through
[GitHub private vulnerability reporting](https://github.com/Sannrox/tenkai/security/advisories/new).
Do not open a public Issue. The [security policy](../SECURITY.md) has what
to include and which versions receive fixes.

## Known limits

The most important ones; the full list is in the
[threat model](threat-model.md#known-limits).

- Outside sealed steps and host releases, a runtime trusts the server to
  choose among approved work.
- A runtime that hands steps to an operator program, rather than running the
  built-in executors, does not verify release signatures itself.
- A compromised server can delay work and withhold or delete sealed values,
  but cannot read or forge them.
- An executor that runs inside the server process has no protection from
  that server.
- An environment without a separate runtime cannot issue workload
  identities: the server host is never trusted to do it
  ([ADR 0046 §8](decisions/0046-workload-identity-and-peer-policy.md#8-environments-without-a-separate-runtime)).
- A recalled host release can run until its approval expires.
- Tenkai writes no network policy; products enforce peer identity
  themselves.

## Scope for an external review

A later external review should cover, in this order:

1. **Signature verification** in the catalog, runtime and host applier:
   release, approval, revocation, advisory and recall envelopes, canonical
   encoding, signer windows and clock handling.
2. **The server to runtime boundary:** enrollment, credential scope, lease
   fencing, release package checks and sealed-value handling.
3. **The root-side host applier:** request intake, file handling, approval
   checks and once-only execution.
4. **Authentication and tenant isolation** on the HTTP API: bearer, JWT and
   OIDC paths, tenant derivation, agent actor restrictions and error
   disclosure.
5. **The release pipeline:** tag signing, workflow permissions, pinned
   actions, attestation and SBOM generation.

Out of scope for that review: products Tenkai deploys, the network plugins
and clusters it targets, and optional providers.
