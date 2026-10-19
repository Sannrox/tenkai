# On-site key provider and ceremony

Air-gapped and customer-managed installs name the key provider in a deploy
profile, then run a ceremony that creates a customer root key reference and
per-tenant data-key ids. The root never leaves the provider. Evidence records
ids and custodians only. See sekai-chisei ADR 0113.

Signing-key rollover is a different key class. Use [key rollover](key-rollover.md).

## Deploy profile

A version 1 TOML file:

```toml
version = 1
class = "production"
[key_provider]
kind = "pkcs11"
```

`class` is `lab` or `production`. `kind` is `software`, `file`, `memory`,
`pkcs11`, `kmip`, or `cloud_kms`. Production refuses `software`, `file`, and
`memory`. Those exist for labs and CI.

The PKCS#11 adapter implements wrap, unwrap, KEK rotate, describe, and revoke
against a customer HSM. The KMIP adapter implements the same operations against
a KMIP endpoint. Describe returns provider kind, key ids, and the algorithm
name. It never returns key material. CI runs the PKCS#11 contract against a
software token and the KMIP contract against a loopback lab endpoint. A cloud
KMS adapter remains a follow-up slice. Ceremony against on-site adapters remains
a later slice.

## Distribution as releases

After the ceremony, components receive wrapped data keys and the provider
endpoint in release configuration (`tenkai.customer-key-release.v1`). Plaintext
keys never appear in that document, bundles, plans, or logs. Rotation and
revocation are the same document: a new wrapping KEK, or a revoked KEK id.
Preflight checks that every named component can unwrap. A revoked release fails
closed. This is a migration of on-disk release configuration (GATE:mig).

## Lab ceremony

```sh
tenkaictl keys ceremony \
  --profile lab-profile.toml \
  --signing-key ceremony.ed25519 \
  --custodian alice \
  --custodian bob \
  --tenant acme \
  --provider-dir /secure/lab-keys \
  --out key-ceremony.json
```

`lab-profile.toml` uses `class = "lab"` and `kind = "software"`. The software
provider writes owner-only files under `--provider-dir`. Tenant data keys are
wrapped with the root (AES-256-GCM) so deleting the root makes them unusable.
That directory is not a bundle, plan, or log path. The JSON at `--out` is
signed evidence: provider kind, root key id, per-tenant data-key ids,
custodians, and time. It does not contain key material.

## Dual-control

Two custodians attend the ceremony. Each is named with `--custodian`. One
person holds the ceremony signing seed; the other confirms the tenant list and
the provider kind before the command runs. The evidence is the record that
both were present.

## Escrow

File the signed evidence with the custodians' names. Escrow holds recovery
material the provider itself requires (HSM smart cards, KMIP credentials, or
the lab software directory), not copies of the root in Tenkai state. Tenkai
never exports the root.

## Key loss is data loss

Revoking or losing the customer root, or a tenant data key, makes wrapped data
unreadable. Restoring a key is a separate, audited ceremony. Restarting a host
does not recover a lost root. Write that down next to the escrow instructions.
