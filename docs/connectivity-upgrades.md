# Connectivity-class upgrades

One Tenkai-owned upgrade carries a signed release and exact approved plan
across connected, intermittent, and isolated environments. Connectivity class
selects the adapter; it does not change identity, trust, or recovery. See
[ADR 0020](decisions/0020-connectivity-class-upgrade.md).

```bash
tenkaictl env add site-a
tenkaictl env connectivity site-a connected
tenkaictl env connectivity site-b intermittent
tenkaictl env connectivity site-c isolated
tenkaictl upgrade start fleet-1 --product edge-app --version 1.0.0 --channel stable --cohort site-a,site-b,site-c
tenkaictl upgrade advance fleet-1 --approval site-a.json --approval-trust-roots release-trust.toml
tenkaictl upgrade interrupt fleet-1 site-b
tenkaictl upgrade resume fleet-1 site-b
tenkaictl upgrade advance fleet-1 --approval site-b.json --approval-trust-roots release-trust.toml
tenkaictl upgrade bind-bundle fleet-1 site-c --bundle site-c.bundle.json --trust-roots offline-trust.toml
tenkaictl upgrade import-receipt fleet-1 site-c --receipt site-c.receipt.json --bundle site-c.bundle.json --trust-roots offline-trust.toml
tenkaictl upgrade advance fleet-1 --approval site-c.json --approval-trust-roots release-trust.toml
tenkaictl upgrade status fleet-1
tenkaictl upgrade rollback fleet-1 --allow-unapproved-development --development-reason drill
```

Isolated bind and import call ADR 0003 bundle and receipt verification inside the
upgrade coordinator. A well-formed digest string is not evidence; unknown
schemas, bad signatures, scope mismatch, unsuccessful receipts, and conflicting
receipts fail closed. The bound archive must name this upgrade's plan.
Upgrade rollback creates a fresh Tenkai rollback plan at apply time, so this
slice uses `--allow-unapproved-development` on the built-in `local`
environment rather than a pre-issued approval envelope.

Status values are `pending`, `interrupted`, `applied`, `conflicted`,
`rolled_back`, and `recovery_required`. Duplicate receipts are idempotent;
conflicting receipts cannot overwrite the first accepted result. Recovery uses
Tenkai state, content descriptors, and signed archives — never an optional
provider.
