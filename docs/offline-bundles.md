# Offline bundles and receipts

Tenkai uses the provider-independent contracts in ADR 0003 for disconnected
delivery. A bundle is a JSON archive whose signed root is canonical even when a
JSON producer changes field order. Payload entries are base64 encoded and each
has a signed SHA-256 digest, media type, canonical relative path, and byte size.

The v1 limits are 1,024 entries, 64 MiB per decoded entry, and 256 MiB across
decoded entries. Implementations must reject absolute paths, parent traversal,
backslashes, duplicate paths or identities, extra entries, invalid base64, and
content that differs from its signed digest or size. Producers sort entry
descriptors by path. Unknown schemas fail closed.

Bundle verification requires current Ed25519 trust roots, the configured tenant
and environment identities, and a time inside the signed validity interval.
Removing an exporter key prevents a not-yet-executed bundle from being trusted.
The archive may include signed release and plan-approval envelopes and bounded
provider evidence, but never bearer/session credentials, private keys,
environment variables, command output, arbitrary logs, or unrelated graph
data.

The offline runtime signs `tenkai.offline-receipt.v1` with a key authorized for
exactly its environment. Receipt import verifies the exact bundle root and
scope, then adapts it to the same application completion contract used by a
connected runtime. Deterministic step receipt identities make repeated import
idempotent; a different result under an accepted identity is a conflict.

Write exports to a temporary file on the destination filesystem, flush it, and
rename it into place. Interrupted or oversized exports are not bundles and may
be removed. Keep the source plan pending until a valid receipt imports. If
media is damaged or lost, create a new export; do not repair signed bytes.
Operational recovery uses Tenkai state plus the signed archive and receipt and
does not require Sekai Chisei.
