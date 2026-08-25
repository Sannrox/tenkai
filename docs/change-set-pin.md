# Change-set closure pins

A Tenkai release may pin one accepted immutable change-set closure without
importing member payloads or taking over change-set publication.

```toml
[change_set_pin]
contract = "tenkai.change_set_pin.v1"
namespace = "acme"
branch_id = "types"
proposal_id = "prop-1"
base_digest = "sha256:..."
closure_digest = "sha256:..."
receipt_digest = "sha256:..."

[[change_set_pin.members]]
kind = "object_type"
id = "widget"
digest = "sha256:..."
```

```sh
tenkaictl publish tenkai.toml \
  --signature release.sig.json \
  --trust-roots release-trust.toml \
  --change-set-evidence closure.json
```

`closure.json` is `tenkai.change_set_publication_evidence.v1`. It must report
`status = "accepted"`, `authorized = true`, the same identities as the pin, and
the same member digest set. Unknown contracts, unknown member kinds, incomplete
closures, unaccepted or recalled status, unauthorized reads, and provider
unavailability fail before Catalog mutation.

`tenkaictl release inspect <product>@<version>` returns the stored pin
projection. Replaying the same pin and evidence is idempotent. Different
closure evidence for an existing release identity is an immutable conflict.

Planning, apply, rollback, recall, and recovery use the stored Catalog pin.
They do not require the change-set service to reconstruct Tenkai state.

Allowed member kinds for v1: `object_type`, `interface_type`,
`ontology_class`, `ontology_relation`, `link_type`, `action_type`, `control`.
Credentials, member documents, and unrestricted external records are excluded.
