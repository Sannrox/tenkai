# Signed recall notices

A **recall notice** is a small signed file that tells an isolated spoke which
releases are recalled, before a fix bundle arrives. After import, planning of
those releases fails closed. Running workloads stay as they are until a
fix-forward wave is approved.

Trust matches the offline revocation list
([ADR 0036](decisions/0036-offline-key-revocation.md)): Ed25519, release-format
trust roots, and a revoked key is refused with no catalog write.

Related: [catalog contract](catalog-contract.md), [rollout waves](rollout-waves.md),
[ADR 0016](decisions/0016-same-version-remediation.md).

## Propose a recall and fix-forward wave

`tenkaictl remediate propose` takes an advisory id from the imported feed
([component inventory](catalog-contract.md)), recalls every matching release,
writes a signed notice, promotes the patched release, and admits a durable
stop-on-failure wave. The wave does not apply until signed plan approval
(or the documented local-development bypass) and `wave resume`.

```bash
tenkaictl remediate propose \
  --exposure TENKAI-2026-1 \
  --fix api@1.1.0 \
  --channel stable \
  --cohort canary,stage,prod \
  --signing-key notice.ed25519 \
  --notice-out notice.json
```

Carry `notice.json` by any medium. Optional `--wave-name` defaults to
`recall-<advisory-id>`. Use the existing apply emergency window when executing
the wave if a maintenance override is required.

When an environment sets `exposure.auto_recall_severity`, admitting a matching
advisory feed stamps the same catalog recall without that command. Default is
report only. The signed notice file and fix-forward wave still come from
`remediate propose`.

## Import on a spoke

```bash
tenkaictl remediate import-notice \
  --notice notice.json \
  --trust-roots notice-roots.toml
```

Import verifies the signature, refuses a revoked signer, then stamps catalog
recall. Named releases that are not in the catalog still get a recall claim, so
a later publish of that identity is not deployable. It prints which
environments still run a recalled release. Re-import of the same notice is
idempotent.

A notice whose digest does not match a catalog release that is already present
is refused and leaves state unchanged.

## Wire format

A signer serializes its statement once, signs those bytes, and sends them as
they are. Tenkai checks the signature over the received bytes before it
parses them, so the signer's JSON encoder, key order, and spacing are not
part of the contract. The notice file is:

```json
{
  "schema": "tenkai.recall-notice.v2",
  "key_id": "sha256:<64 lowercase hex>",
  "statement": "<base64 of the statement bytes>",
  "signature": "<base64 Ed25519 signature>"
}
```

- `statement` is the standard base64 alphabet with padding, of the UTF-8
  JSON statement bytes.
- The signed message is the 23 ASCII bytes `TENKAI-RECALL-NOTICE-V2` and
  one NUL byte (`0x00`), then the statement bytes. `signature` is the 64-byte
  Ed25519 (RFC 8032) signature over that message, standard base64 with
  padding.
- `key_id` is `sha256:` and the lowercase hex SHA-256 of the 32-byte public
  key. It must name a signer in `--trust-roots`, in the
  [trust-root format](release-signing.md), valid at `issued_at` and not
  revoked.
- The notice has exactly these four fields; any other is refused.

The statement is a JSON object:

| Field | Type | Rule |
| --- | --- | --- |
| `issued_at` | integer | Unix milliseconds; not more than five minutes after the import clock |
| `advisory_id` | string | required, no control characters |
| `reason` | string | required, no control characters |
| `recalled` | array | 1 to 4096 objects, each release once |
| `recalled[].release` | string | `<product>@<version>` |
| `recalled[].digest` | string | the release manifest digest, 64 lowercase hex, optionally prefixed `sha256:` |

A key may appear once per object. Fields Tenkai does not know are ignored
and stay covered by the signature. A field that changes what a recall means
needs a new schema id instead.

To sign without Tenkai, in any language:

```text
bytes     = utf8(json(statement))            # serialize once, keep the bytes
message   = "TENKAI-RECALL-NOTICE-V2" || 0x00 || bytes
signature = ed25519_sign(private_key, message)
notice    = {schema, key_id, statement: base64(bytes), signature: base64(signature)}
```

Tenkai stores an imported notice as the JSON of these four fields, so the
stored statement is the signer's own bytes and can be verified again. Its
object id is `tenkai:recall-notice:` and the SHA-256 of that JSON, so
importing the same notice twice is idempotent.

`tenkai.recall-notice.v1` is deprecated: its signature covered Tenkai's
re-encoding of the parsed statement, which no other encoder can reproduce.
This release still verifies v1 notices made by earlier releases, never
produces them, and keeps the stored form and object id of v1 notices already
imported. A later release removes v1. Releases before 0.7.0 refuse a v2
notice as malformed, so upgrade every `tenkaictl` that imports notices
before switching signers to v2.

## Fix-forward and rollback

Resume the admitted wave with the same approval flags as `wave execute`:

```bash
tenkaictl wave resume recall-TENKAI-2026-1 \
  --approval-dir ./approvals \
  --approval-trust-roots plan-approvers.toml
```

Completed environments are not repeated. Rollback onto recalled content still
requires `--allow-recalled-recovery --recovery-reason` inside the signed plan.
