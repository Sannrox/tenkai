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
tenkaictl upgrade advance fleet-1 --allow-unapproved-development --development-reason drill
tenkaictl upgrade interrupt fleet-1 site-b
tenkaictl upgrade resume fleet-1 site-b
tenkaictl upgrade bind-bundle fleet-1 site-c --digest sha256:...
tenkaictl upgrade import-receipt fleet-1 site-c --bundle-digest sha256:... --receipt-digest sha256:...
tenkaictl upgrade status fleet-1
tenkaictl upgrade rollback fleet-1 --allow-unapproved-development --development-reason drill
```

Status values are `pending`, `interrupted`, `applied`, `conflicted`,
`rolled_back`, and `recovery_required`. Duplicate receipts are idempotent;
conflicting receipts cannot overwrite the first accepted result. Recovery uses
Tenkai state, content descriptors, and signed archives — never an optional
provider.
