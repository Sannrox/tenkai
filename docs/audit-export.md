# Audit export

Security teams at isolated sites carry audit records out on media. Tenkai
exports them as signed files that chain to each other, so a missing
export, a reordered file or an edited record is detected offline.

## What an export holds

A `tenkai.audit-export.v1` file covers everything written since the
previous export. It lists, oldest first:

- **Audit records:** who performed which management action (for example
  `plan.approve.completed`, `environment.configure.set_fact.requested`), on
  which resource, and with what outcome.
- **Change events:** delivery transitions such as plans, applies, holds,
  receipts and rollbacks, with the environment they belong to.
- **Usage records:** Tenkai's own deployment activity in this period, as
  the documented `usage` record kind (`source` is `usage`). The actions
  are `environments.managed` (distinct environments on delivery change
  events), `plans.applied` (successful `plan_applied` events),
  `releases.deployed` (the same successful applies; catalog publish or
  promote is not a deployment), `executor.hours` and `runtime.hours`.
  Counts and millihours live in `outcome`. Millihours are 0 until Tenkai
  persists execution start and end; event spacing is not duration. Tenkai
  does not price, invoice or otherwise bill.

Entries carry identities, actions and outcomes only. No credential, token,
request body or payload is exported. Usage is derived from the change
entries of the same export, so the same period exported twice is
byte-identical. Tenkai does not import a usage export.

Exports are bounded by durable insertion cursors, not by time. Each export
starts at the audit and change cursors where the previous one ended. A record
that commits late, or under a clock that moved back, therefore lands in the
next export instead of falling between two. The period times (the previous
export's end and this export's time) are for reading. Each export carries a
sequence number and names the digest of the export before it. The statement
is signed with an Ed25519 seed.

## Export

On demand, against the embedded store:

```bash
tenkaictl audit export /var/lib/tenkai/audit --signing-key /etc/tenkai/audit.seed
```

This writes the next `audit-<sequence>.json` in the directory, covering
everything written since the newest export there (or since the beginning). The
existing chain in the directory must verify first, so a damaged or
incomplete directory is never continued. Pass `--trust-roots` for exports
there that were signed before a key rotation. If the operational store was
restored from a backup older than the chain, export refuses; start a new
chain in a new directory. The file is synced before it appears. An existing export is never
replaced.

On a schedule, `tenkai-server` does the same when `TENKAI_AUDIT_EXPORT_DIR`
and `TENKAI_AUDIT_SIGNING_KEY` are set, every
`TENKAI_AUDIT_EXPORT_INTERVAL_SECS` (default daily). After a key
rotation, point `TENKAI_AUDIT_TRUST_ROOTS` at roots that hold the earlier
key, so the existing chain still verifies. The seed file follows
the same rules as an approval-policy signer: 32 bytes, readable by the
owner only. Tenant-mode hubs refuse the setting, because tenant records
live in PostgreSQL.

## Verify

Add the seed's public key to a trust-roots file (`[[signers]]` with
`key_id`, `identity`, `public_key`, as for
[release signing](release-signing.md)), then:

```bash
tenkaictl audit verify audit-00000001.json audit-00000002.json --trust-roots audit-trust.toml
```

Verification needs only the files and the trust roots, so it works after
offline transfer. It refuses:

- a signature that does not verify, meaning the statement was changed;
- a gap between exports (records between them not covered);
- a missing or out-of-order export;
- an export that does not name its predecessor's digest;
- an entry outside its export's cursor range.

To verify a later run of files on its own, pass the digest of the export
before the first one with `--anchor`; `tenkaictl audit export` prints each
export's digest.
