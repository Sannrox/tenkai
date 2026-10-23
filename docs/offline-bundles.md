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
The archive may include signed release and plan-approval envelopes, bounded
provider evidence, and digest-bound artifact layers, but never bearer/session
credentials, private keys, environment variables, command output, arbitrary
logs, or unrelated graph data.

When a release names OCI artifacts, export fetches each digest from a live
registry and adds signed `oci-layers/<digest>` entries plus
`oci-layers/mirrors.json` load instructions. Those paths stay inside
`tenkai.offline-bundle.v1`; the statement schema does not change, so file-only
bundles remain valid. Identical digests share one payload entry. Import
verifies every layer against the signed instruction digest, names that digest
when bytes are missing or wrong, and stores the layer on the environment
mirror only. Origin pull is refused. A matching replay is a no-op, so an
interrupted import can resume. `TENKAI_OCI_STORE` is required to import
layers. A layer larger than the v1 entry limit cannot be bundled; re-export
after shrinking or splitting the release.

Model weights larger than those v1 JSON limits travel beside the archive in a
chunk store (`<bundle-stem>.chunks/`). The signed statement still uses
`tenkai.offline-bundle.v1`; `chunks/manifest.json` is a small JSON entry of
schema `tenkai.offline-chunk-manifest.v1` that lists per-chunk SHA-256
digests and sizes. Chunk files are raw bytes named by digest, not JSON
entries, so they do not count against the 64 MiB / 256 MiB caps. Export and
import copy one megabyte at a time, resume from the last verified chunk, and
refuse a corrupted or retargeted chunk before the weight cache blob is
replaced. File-only v1 bundles without a manifest still verify and import.
Isolated-bundle bind (`tenkaictl upgrade bind-bundle`) imports those chunks
into `TENKAI_WEIGHT_CACHE` from `<bundle-stem>.chunks/` beside the archive.
A chunked bundle without the archive path or that cache directory fails closed.

First install of a dark site uses the same archive schema. A signed
`stack/manifest.json` (`tenkai.offline-stack.v1`) lists the required product
images, model weights, schemas, and hub payload. `tenkaictl upgrade
install-bundle` verifies that index against the archive and companion chunk
store before it creates the isolated environment or writes the OCI store,
weight cache, or upgrade record. A bundle missing any required image, weight,
schema, or hub entry is refused with no mutation. An already published or
recalled catalog release is refused before import rather than bootstrapping
over existing catalog state. Every layer and chunk the
importer will consume must be named in that index. The archive also supplies
the catalog manifest (`releases/<product>@<version>/tenkai.toml`) plus its
release signature and trust roots used to bootstrap a fresh local pin.
Each catalog OCI artifact must appear in `stack/manifest.json` images and in
`oci-layers/mirrors.json` with the same registry, repository, digest, and
media type, plus the matching layer bytes. Catalog snapshots are written to
`TENKAI_STATE_DIR` or `./.tenkai-state` by passing that directory into
publication, not by mutating process environment.
Optional `file-modes.json` (`tenkai.offline-file-modes.v1`) may be a top-level
archive entry or sit beside `tenkai.toml` under `releases/<product>@<version>/`.
It restores signed filesystem modes for deploy inputs before the catalog digest
is checked. A catalog with `[change_set_pin]` must include matching
`change-set-evidence.json` beside `tenkai.toml` or as a top-level archive entry;
missing evidence is refused before import. The
upgrade binds the signed `plan_id`, plan digest, and approval digest
instead of inventing a local plan. Artifact layers are imported before that
catalog publication so digest-bound OCI artifacts verify against the local
store. Execution uses the host-local snapshot path while keeping the signed
plan identity. After
the first install, a second bundle of the same format updates the site
through the existing upgrade bind/receipt/advance path and rolls back with
`tenkaictl upgrade rollback`.

Rehearsal: `cargo test --locked incomplete_first_install_bundle_is_refused_before_mutation`
starts from an environment that does not exist, presents a signed bundle
without a stack index, and confirms the environment and upgrade record stay
absent. `cargo test --locked missing_stack_schema_is_refused_before_layer_import`
names a missing schema in an otherwise populated stack index and refuses
before any layer import. `cargo test --locked unnamed_chunk_artifact_is_refused_before_import`
refuses an extra chunk instruction that the stack index does not name.
`cargo test --locked first_install_rejects_non_executable_plan_before_mutation`
keeps the catalog, environment, and upgrade absent when the signed plan is
not executable. `cargo test --locked first_install_from_signed_bundle_bootstraps_catalog_and_authenticated_plan`
starts from an empty catalog, admits the signed release and plan from one
bundle, and leaves an isolated environment pending that plan.
`cargo test --locked first_install_rejects_recalled_release_before_mutation`
and `cargo test --locked first_install_rejects_mismatched_layer_reference_before_mutation`
keep OCI stores and catalog pins untouched when admission fails.
`cargo test --locked first_install_completes_channel_pin_for_existing_matching_release`
finishes an interrupted publish by pinning the matching isolated channel. Update and
rollback stay the three-class upgrade drill
(`connected_intermittent_and_isolated_complete_one_signed_upgrade`) plus
`rollback_uses_tenkai_owned_plan`.

Rehearsal: `cargo test --locked over_archive_limit_weight_stays_out_of_json_entries`
exports and imports a generated weight larger than the 256 MiB JSON archive
cap with process RSS well below artifact size. The 20 GiB model-scale run is
`cargo test --locked model_scale_weight_exports_and_imports -- --ignored`.
Results from the over-limit rehearsal are recorded with the crate tests;
the ignored 20 GiB run is operator evidence, not CI.

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

## Server-side import

`tenkai-server` can verify and import bundles itself, so an isolated site
needs no shell on the hub. Set `TENKAI_IMPORT_STAGING_DIR` to a directory the
server owns and `TENKAI_BUNDLE_TRUST_ROOTS` to the trust roots that must
authenticate the bundle exporter
([environment variables](environment-variables.md)). Operators place an
archive and its `<stem>.chunks/` store in the staging directory through
their transfer process. The server never accepts bundle bytes over HTTP.

- `GET /v1/imports/staged` lists the staged archives with size, target
  environment, plan, expiry, whether a chunk store sits beside them, and why
  a file is not a readable bundle.
- `POST /v1/imports` takes `{version, operation: "import", bundle, upgrade,
  environment, dry_run}`. `bundle` is a file name in the staging directory.
  Paths, hidden files and links are refused. The import binds the bundle to
  the isolated upgrade exactly as `tenkaictl upgrade bind-bundle` does, with
  the same verification: signature, validity interval, revocations, scope,
  plan and digests. With `dry_run` it also checks every layer and weight
  chunk it would import, the stores they need, and any revocation list it
  carries (verified, and it may not revoke the bundle's signer). It reports
  what the bind would do and writes no content and no revocations. A real
  import, like the CLI, installs a bundle's authenticated revocations before
  it trusts the bundle, even when the bundle is then refused.
- Every request is a job under `<staging>/imports/<id>.json`, readable at
  `GET /v1/imports/{id}`. The job records its state (`succeeded`, `failed`
  or `previewed` for a dry run) and the exact refusal, for example the
  missing layer digest or an expired interval. The id follows the bundle
  file, upgrade and environment, so retrying a failed or interrupted import
  continues it: layer import is a no-op for matching bytes, and chunked
  weights resume from the last verified chunk. One import runs at a time
  per host; a second request while one runs gets `409`.
- `GET /v1/content/inventory` lists, for each release, the layers and model
  weights it names. For each one it shows whether the host holds those bytes
  (`stored`) and their size: a layer under any registry path of
  `TENKAI_OCI_STORE`, or a weight in `TENKAI_WEIGHT_CACHE`. An environment
  still pulls a layer through its own mirror path. Files are found by their
  digest names and not re-hashed for the listing; import, apply and fetch
  verify the bytes. It also shows what
  references the release (channel heads and deployed versions), the
  referenced content that is missing, and the bytes each store uses.

Import needs the management capability. An environment-scoped credential
can import only for its own environment and cannot list the staging
directory. Tenant-mode hubs refuse import.
