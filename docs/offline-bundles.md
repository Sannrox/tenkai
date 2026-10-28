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

Bundle export signs the root through the same content signer as releases and
plan approvals. A production deploy profile refuses file-based signing keys;
see [release signing](release-signing.md#production-signer).

## Build

`tenkaictl bundle build` takes one or more published releases and writes one
signed v1 archive plus its companion chunk store. The same inputs produce
byte-identical checksum and SBOM manifests. The archive carries images by
digest, host binaries when `--hosts-dir` is set, release configs, public trust
roots, model weights, `checksums/manifest.json`
(`tenkai.offline-checksum-manifest.v1`), and `sbom/<component>.json`
(`tenkai.offline-sbom.v1`) per component. Those two manifests are ordinary
signed entries: the bundle signature covers them. A missing image, weight, or
schema fails the build and names the item. Private keys and credentials are
refused.

```bash
tenkaictl bundle build \
  --release edge-app@1.0.0 \
  --release weights@1.0.0 \
  --env site-c \
  --out site-c.bundle.json \
  --signing-key exporter.seed \
  --trust-roots offline-trust.toml \
  --hosts-dir tenkai-hosts \
  --host-tag v0.5.0 \
  --host-git-sha 0123456789abcdef0123456789abcdef01234567 \
  --host-workflow release
```

`--issued-at-unix-ms` pins the statement clock so two operator rebuilds can
match. `--out` must be a new path; an existing archive is refused. Chunk files
land in `site-c.bundle.chunks/` beside the archive. Images
are read from `TENKAI_OCI_STORE`; weights from `TENKAI_WEIGHT_CACHE`. The
command is embedded-only. The v1 envelope binds `plans/content.json` and
`approvals/content.json` as the signed release-set identity; those entries are
not an executable Plan. First install through `upgrade install-bundle` remains
#623.

Rehearsal: `cargo test --locked two_builds_of_the_same_inputs_produce_byte_identical_manifests`
builds the same release set twice and compares checksum and SBOM bytes.
`cargo test --locked sbom_and_checksum_are_covered_by_the_bundle_signature`
verifies the signed archive, then tampers an SBOM entry and confirms
verification fails. `cargo test --locked missing_image_fails_the_build_and_names_the_digest`,
`missing_weight_fails_the_build_and_names_the_digest`, and
`missing_schema_fails_the_build_and_names_the_path` refuse the build while
naming the missing item.

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
layers.

A layer larger than the v1 entry limit (64 MiB) travels in the chunk store
beside the archive instead (#684), next to model weights:

- **Index:** a signed `chunks/images.json` entry
  (`tenkai.offline-image-chunks.v1`) lists the layer's chunks by digest and
  size. Its `oci-layers/mirrors.json` instruction points at that entry.
- **Before any change:** first install, bind and preview verify every chunk
  and the reassembled digest. A tampered or missing chunk is refused, naming
  the image and the layer.
- **Import:** the layer is streamed from its chunks into the OCI store. The
  digest is checked before the blob becomes visible.
- **Older Tenkai:** it refuses such a bundle rather than skipping the layer,
  because the instruction's path is not the layer's own entry.
- **Unchanged:** bundles that carry only weights, and layers within the
  limit, are unchanged.

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

An image manifest or index in the bundle comes with every blob it
references (config and layers, or the listed manifests) in the same
repository: export follows a release's image manifests to them. Install and
bind refuse a bundle that misses one, naming the image and the digest, before
anything is stored.

## Delta bundles and content retention

A full bundle carries every layer and weight of a release, tens of GB for a
model stack. Once a site holds a release, the next one can travel as a
delta that carries only what that base release lacks (#635):

- **Export:** `insert_artifact_layers_delta` takes the base release
  (`<product>@<version>`) and the layer and weight digests it brought. Those
  layers are neither fetched nor carried; their `oci-layers/mirrors.json`
  instructions point at a signed `delta/base.json`
  (`tenkai.offline-delta-base.v1`), which names the base release and lists
  the digests. Base weights are left out of the chunk store.
- **Before any change:** bind, dry-run import and server-side import refuse
  a delta unless the base release is in the site's catalog and every listed
  layer (under the environment's mirror) and weight is held here with
  matching bytes. The refusal names the base release and the digest.
- **First install:** always needs a full bundle; a delta is refused. An
  update delta may keep `stack/manifest.json`; its base images and weights
  count as present once the base check passes.
- **Older Tenkai:** it refuses a delta rather than skipping layers, because
  an instruction's path is not the layer's own entry. Full bundles are
  unchanged.

The site keeps what rollback needs and nothing else.
`tenkaictl upgrade collect-content` lists the content it would remove;
`--apply` removes it. A release is kept while:

- a channel heads it;
- an environment has it deployed, or as its previous deployment (N-1), so
  `tenkaictl upgrade rollback` works from the local stores without media;
- an upgrade that has not succeeded or rolled back targets it.

Layers and weights that only unkept releases name are removed from
`TENKAI_OCI_STORE` and `TENKAI_WEIGHT_CACHE`, under every mirror path. An
image manifest keeps the blobs it references. Content no catalog release
names is left alone, since an interrupted import may have stored it before
its release was published. Collection holds an exclusive lock on this
host's stores and refuses while an import or apply runs; both wait for a
running collection. Channel heads and plans can still move: collection
refuses if they changed while it read them, and a release made live after
its content was collected fails closed at apply until its bundle is
imported again. Base image manifests a delta relies on must have every
blob they reference held here.

Rehearsal: `cargo test --locked delta_bundle_applies_offline_and_rollback_survives_collection`
imports N-1 from a full bundle, refuses the N delta against a store without
the base, imports and applies it, collects an older release's content while
keeping N-1, and rolls back to N-1 from the local store alone.

## Seed registry

A first dark-site install has no registry for executors to pull from. Tenkai
serves its own artifact store as one (#627):

1. Install with `tenkaictl upgrade install-bundle ... --seed-registry
   <host>:<port>`. Every image registry the bundle names is mirrored to that
   one name, and the layers are stored under it in `TENKAI_OCI_STORE`. Later
   bundles bind through the same mirror, so upgrades fill the same registry.
2. Run `tenkaictl registry serve --name <host>:<port> --listen <addr>
   --tls-cert <chain.pem> --tls-key <key.pem>` with `TENKAI_OCI_STORE` set.
   The certificate is issued for `<host>` by the site CA. Each executor host
   trusts that CA for the registry (for Docker,
   `/etc/docker/certs.d/<host>:<port>/ca.crt`).
3. Executors pull `<host>:<port>/<repository>@<digest>`, the mirror
   references Tenkai admits for each apply.

The registry is read-only and answers `GET` and `HEAD` by digest only. Tags,
pushes and deletes are refused, so it serves exactly what verified bundles
stored, and clients check every digest. It holds no state of its own: any
number of instances may serve one store, and `/v2/` answers 503 when an
instance cannot read it. It does not authenticate pulls; it serves only
release images, to the network it listens on.

Re-running the same install changes nothing in the graph. It imports the
layers and weights again, which stores only what is missing, so a store lost
or replaced since is refilled. A different bundle, release or seed registry
is refused.

`scripts/rehearse-seed-registry.sh` rehearses the pull side with Docker. A
fresh Docker daemon on a network with no route out pulls an image by digest
from the registry, trusting only a throwaway site CA. The digests must
match, a second pull must change nothing, and tag and origin pulls must fail.

## Host binaries

The archive may carry the Tenkai CLI, server, and executor hosts that GitHub
Releases otherwise attach online. They are ordinary v1 entries (they fit the
64 MiB limit) under `hosts/<platform>/<name>`, plus a signed
`hosts/manifest.json` (`tenkai.offline-host-binaries.v1`) and
`hosts/SHA256SUMS` in the GitHub Release checksum format. Each listed file
records its digest, size, and release provenance (tag, git sha, workflow).
The bundle signature covers those entries; verification uses the exporter
trust roots received out of band, the same roots as the rest of the archive.
A Tenkai without this index ignores the extra entries. A Tenkai that sees
the index refuses a missing role, a digest mismatch, or a checksum mismatch
before it writes a destination, and names the file.

```bash
tenkaictl upgrade install-hosts site-c \
  --bundle site-c.bundle.json \
  --trust-roots offline-trust.toml \
  --dest tenkai-hosts \
  --platform linux-x86_64
```

`--platform` is `linux-x86_64` or `darwin-aarch64`. Omit it to use this
process's packaged platform. The command writes unsuffixed
`tenkaictl`, `tenkai-server`, and `tenkai-executor-guard` after verification,
mode 0755. The installer sets that mode on the file before linking it. A
destination that already holds the signed bytes is left in place so a retry
can finish, and its mode is restored to 0755. A different file or a symlink
is refused; swapping a running host is a later operation. The command does
not open application storage. Bind and first-install of a product stack also
preflight the host index when it is present, so a tampered host file cannot
ride along with an otherwise valid stack.

Rehearsal: `cargo test --locked tampered_host_binary_is_refused_before_install_and_names_the_file`
tampers `hosts/linux-x86_64/tenkaictl` in a signed archive, presents the
exporter trust roots, and keeps the destination empty while naming that file.
`cargo test --locked offline_install_of_tenkai_hosts_from_signed_bundle`
installs both platforms' hosts from one archive onto one platform's
destination.

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

## Content scanner

Set `TENKAI_IMPORT_SCANNER` to the absolute path of a scanner executable to
scan incoming media before anything is unpacked. On `upgrade bind-bundle`,
`upgrade install-bundle` and server-side import (including dry runs), the
order is:

1. Tenkai checks the bundle signature against the current trust roots.
2. It copies the archive, and the chunks its signed manifest names (each
   bounded to its signed size), into a private snapshot, and runs the scanner with the snapshot
   archive and snapshot chunk store as its two arguments. The import then
   reads that same snapshot, so the bytes scanned are the bytes imported
   even if the staged files change. The snapshot archive is written from the
   bundle already verified in memory, so the staged file is not read again. The snapshot goes in
   `TENKAI_IMPORT_SCANNER_SNAPSHOT_DIR` (default: the temp directory), so
   the media may be read-only. It needs free space equal to the bundle and
   is removed afterwards. With a scanner, every weight must be in the
   scanned chunk store, even one already in the cache, and an interrupted
   weight import does not resume from its cached prefix.
3. Only then does it install revocations or write any layer, weight or
   record.

The scanner runs without a shell, with an empty environment except `PATH`,
and must finish within `TENKAI_IMPORT_SCANNER_TIMEOUT_SECS` (default 600),
including any process it leaves holding its output; on timeout its whole
process group is killed.
Exit 0 admits the import. Any other exit, a timeout or a launch failure
refuses it with the scanner's first output line, and nothing is changed.
An admitted scan is recorded with the isolated evidence of the upgrade
(`scan`: scanner, exit code, SHA-256 of its standard output and standard
error, first output line, time) and in
the server import job's preview.

## One-way transfer

Some sites accept media inbound only. No import step waits for a reply:
verification uses the trust roots and revocation lists carried with the
bundle, never a network call. Whether completion needs a return path
depends on where the upgrade record lives.

| Step | How | Direction |
| --- | --- | --- |
| Carry the archive, its `<stem>.chunks/` store, the exporter trust roots and, if used, the revocation authorities | Transfer media | Inbound only |
| First install of an empty isolated environment | `tenkaictl upgrade install-bundle` at the site | Inbound only |
| Bind an update bundle | `tenkaictl upgrade bind-bundle`, or `POST /v1/imports` on the site's server | Inbound only |
| Install bundled key revocations | Part of bind and install | Inbound only |
| Execute the bound plan | The site's offline runtime, which signs a `tenkai.offline-receipt.v1` for the environment | Inbound only |
| Record completion | `tenkaictl upgrade import-receipt`, then `tenkaictl upgrade advance`, on the Tenkai that holds the upgrade | Inbound only when that Tenkai is at the site (as after `install-bundle`); needs return when it is at the connected source |

`upgrade advance` leaves an isolated environment `interrupted` until a
signed receipt is imported. The receipt contract is ADR 0003. Tenkai
verifies and imports receipts; producing one is the offline runtime's job,
and `tenkaictl` has no command that runs a plan and signs a receipt today.

When the receipt must reach a connected source, it leaves on separate media.
Import is idempotent and a conflicting receipt cannot overwrite the first
accepted one, so it can be carried twice without harm. It must be imported
before the bundle expires: import re-verifies the bundle at the current
time, and an expired bundle refuses its receipts. Plan the bundle's validity
interval around the slowest expected return trip.

With no return path to the source:

- The site's own state is the record of what runs there.
- At the source, that environment stays `interrupted` with its plan pending.
  It never shows as applied without a signed receipt, which is intended:
  the source does not claim what it cannot verify.
- Do not re-export a bundle to prompt a reply. A different bundle for the
  same upgrade and environment is refused as a digest conflict. Ship the next
  release as a new upgrade.
- Keep the signed archive. With the site's own state, it is everything
  recovery needs there.

### Rehearsal: one-way first install

1. On the connected side, export the bundle and its chunk store for an
   environment that does not exist yet at the site, and copy the exporter
   trust roots beside it.
2. Carry them to a host with no route out, for example a Linux network
   namespace with only loopback (`unshare -n`), with `TENKAI_OCI_STORE` and
   `TENKAI_WEIGHT_CACHE` set.
3. Run `tenkaictl upgrade install-bundle` there. It must finish without any
   outbound attempt; a refusal names what is missing, for example a layer
   digest or a chunk.
4. Check `tenkaictl env inspect <env>` and `tenkaictl upgrade status <name>`:
   the environment exists, the content is in the local stores, and the
   upgrade waits on the signed plan carried in.
5. Execute the plan with the site's offline runtime and import its receipt at
   the site (`upgrade import-receipt`, then `upgrade advance`). Nothing has
   gone back out.

CI covers the admission side
(`first_install_from_signed_bundle_bootstraps_catalog_and_authenticated_plan`
and the refusal tests listed above) and the receipt path
(`connected_intermittent_and_isolated_complete_one_signed_upgrade`). The
zero-outbound-call check is the [isolated-network conformance](#isolated-network-conformance) job.

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

## Isolated-network conformance

`scripts/egress-conformance.sh` proves the install, first deploy, upgrade and
rollback drills make no outbound call, including the offline first install
into an empty catalog and the site-local directory OIDC bridge (login, group
mapping, and directory or issuer outage failing closed). It builds the drills
normally, then
runs each test binary in a fresh network namespace that has only loopback,
under `strace`. Any `connect()` or addressed send (as unconnected UDP uses)
to a non-loopback address, and any DNS lookup
to any address, is an outbound attempt. The report lists every attempted
destination with the process that made it, and the expected list is `none`.
CI runs it as the "Isolated-network conformance" job on pull requests that
touch executors, server configuration or the build, and on every push to
`main`. It needs Linux with `strace`, `unshare`, `ip` and root or
passwordless `sudo`.
