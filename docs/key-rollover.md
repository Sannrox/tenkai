# Key rollover and offline revocation

Tenkai verifies every signature locally against trust-root files, so
rollover and revocation work on an isolated fleet with no online check. See
[ADR 0036](decisions/0036-offline-key-revocation.md).

## Revoke a key fleet-wide

A revocation authority signs a `tenkai.key-revocations.v1` list of key ids.
Once a host installs the list, it refuses every signature by those keys:
releases, offline bundles, plan approvals (including automatic approvals),
package-migration approvals, model evaluation evidence, and host preflight. Trust-root files that still
list a revoked key keep loading, and only that key's signatures are refused.

Configure each host with both variables:

| Variable | Meaning |
| --- | --- |
| `TENKAI_KEY_REVOCATIONS` | Installed list. Read when `tenkaictl` or `tenkai-server` starts; replaced by imports |
| `TENKAI_KEY_REVOCATION_TRUST_ROOTS` | Release-format trust roots naming the revocation authorities |

Setting only one of them is an error. An installed list that fails to
verify stops the process.

```sh
# Offline, on the authority's workstation:
tenkaictl revocations sign \
  --signing-key /secure/revocation-authority.ed25519 \
  --sequence 7 \
  --revoke "sha256:<old release key>=rolled over 2026-10" \
  --revoke "sha256:<leaked exporter key>=exposed in a support bundle" \
  --out key-revocations.json

# On each host:
tenkaictl revocations import key-revocations.json
tenkaictl revocations show
```

The list can also travel inside an offline bundle as the
`trust/key-revocations.json` entry (`offline_bundle::insert_key_revocations`).
Binding or first-installing a bundle installs that list before it checks the
bundle's own signature, so a bundle signed by a key it revokes is refused.

Rules:

- Each new list needs a higher `sequence` and must keep every key the
  installed list revokes. A replayed or edited older list cannot un-revoke a
  key.
- An authority cannot revoke its own key. To retire an authority, add its
  successor to the authority trust roots, sign a list with the successor,
  then remove the old authority.
- `tenkai-server` applies the installed list at startup. After `revocations
  import` on a server host, restart its replicas one at a time. A bundle
  import applies the list in that process at once.

## Roll over a signing key without downtime

The pattern is the same for each key: overlap, switch, revoke, remove.

1. **Overlap.** Add the new public key to the trust-root file next to the
   old one, and distribute it (in bundles for isolated sites). Both keys now
   verify.
2. **Switch.** Sign everything new with the new key.
3. **Revoke.** When nothing still in flight needs the old key, sign a
   revocation list for it and import it everywhere. Its signatures are now
   refused even where the trust file still lists it.
4. **Remove.** Drop the old key from the trust-root file at the next routine
   distribution.

| Key | Trust-root file | Notes |
| --- | --- | --- |
| Release signing | `TENKAI_RELEASE_TRUST_ROOTS` | Releases already published under the old key stay recorded. Their deployable trust is re-checked at execution, so re-sign and republish any release you still need to deploy before revoking the key ([release signing](release-signing.md)) |
| Offline bundle exporter | Bundle import trust roots | Re-export bundles that have not been imported yet |
| Plan approval (human) | `TENKAI_PLAN_APPROVAL_TRUST_ROOTS` | Revocation refuses every not-yet-executed approval by that key, so re-approve pending plans ([plan approval](plan-approval.md)) |
| Automatic approval signer | `TENKAI_PLAN_APPROVAL_TRUST_ROOTS` and the policy's `auto_signer_key` | Point the policy at the new seed, keep both keys scoped to the environment while auto envelopes are reissued, then revoke the old key |
| Host preflight | `TENKAI_PLAN_APPROVAL_TRUST_ROOTS` (`preflight` scope) | Rerun `tenkaictl preflight` with the new seed before revoking the old one ([host preflight](host-preflight.md)) |
| JWT assertion keys | JWT verifier trust file | Overlap `[[keys]]` entries and restart; see [configure server authentication](configure-server-authentication.md) |

## Rotate a certificate authority

Tenkai trusts TLS through the system or configured CA bundles of its
clients and proxies, not through these signing keys. Rotate a CA with the
same overlap:

1. Add the new CA certificate to every trust bundle that validates server
   certificates (runtimes, `tenkaictl`, the reverse proxy, and the identity
   provider's clients), next to the old CA.
2. Reissue server certificates from the new CA and deploy them. Check them
   with host preflight's `[[certificates]]` rules before relying on them.
3. Remove the old CA from the trust bundles once no certificate it issued is
   still in use.

At no point does a client trust only a CA that has issued nothing yet, so
connections keep working through the rotation.
