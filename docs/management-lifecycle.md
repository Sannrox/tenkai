# Remote management lifecycle v1

Operator lifecycle verbs share one versioned HTTP contract,
`tenkai.management-lifecycle.v1`. Both hosts call the same application core.
Transport is not a domain boundary.

The spoke runtime protocol is a different surface. Runtimes still initiate
every work, complete, heartbeat, and inventory exchange over HTTP JSON; the
v1 proto `Negotiate` / `Pull` / `CompleteStep` / `Heartbeat` /
`ReportObservation` messages are a separate typed contract, not the HTTP
payloads. See [runtime protocol v1](runtime-protocol-v1.md). Do not place
management verbs on that proto and do not overload `POST /v1/reconcile`.

Package-migration preview, apply, status, resume, and rollback stay on
`/v1/migrations/*` ([ADR 0026](decisions/0026-remote-package-migration-parity.md)).
They are not generic apply wrappers.

## Contract header

Every lifecycle request and result carries:

| Field | Rule |
| --- | --- |
| `version` | Must be `1`. Any other value fails closed. |
| `operation` | One of the closed vocabulary below. Unknown names fail closed. |
| `environment` | Required for environment-bound operations. Forbidden for catalog-wide operations. |
| `expected_generation` | Required for mutating environment-bound operations. A stale generation fails before the next effect. |

Unknown JSON fields in a request fail closed (`deny_unknown_fields`). A
client ignores unknown fields in a result, so a newer server can add one
without breaking older clients. A remote body must
not carry `--allow-unapproved-development` or any other embedded
local-development bypass.

The Rust admission entry is `tenkai::management_lifecycle`. HTTP adapters
call it before the Catalog, planner, or apply core.

## Operations

| Operation | Scope | Path | Status |
| --- | --- | --- | --- |
| `publish` | Catalog-wide | `POST /v1/releases` | Implemented ([#394](https://github.com/Sannrox/tenkai/issues/394)) |
| `promote` | Catalog-wide | `POST /v1/channels/{channel}/promote` | Implemented (#394). The result's `digest` is the promoted release's manifest digest (`sha256:<hex>`). Optional `expected_head` (`<product>@<version>`) refuses the promotion with `409` when the channel heads another release; an empty channel, or one already heading the spec, is promoted either way ([#1158](https://github.com/Sannrox/tenkai/issues/1158)). The result's `replaced_head` is the `<product>@<version>` the channel headed before the promotion; omitted when the channel had no head or already named the promoted release ([#1173](https://github.com/Sannrox/tenkai/issues/1173)) |
| `recall` | Catalog-wide | `POST /v1/releases/{release}/recall` | Implemented (#394) |
| `recall` (range) | Catalog-wide | `POST /v1/products/{product}/recall-range` | Implemented ([#1183](https://github.com/Sannrox/tenkai/issues/1183)). Inclusive `from`, exclusive optional `before`; omit `before` for open-ended. Same catalog-wide Recall grant. |
| `recall` (close range) | Catalog-wide | `POST /v1/products/{product}/recall-range/close` | Implemented (#1183). Sets exclusive `before` on an open-ended range; a range never widens. The close is the audited write that bounds an open range ([#1275](https://github.com/Sannrox/tenkai/issues/1275)). |
| `channel_remove` | Catalog-wide | `POST /v1/products/{product}/channels/{channel}/remove` | Implemented ([#1174](https://github.com/Sannrox/tenkai/issues/1174)). Clears the product's head from the channel; see [channel removal](manage-environments.md#channel-removal). Optional `expected_head` (`<product>@<version>`) refuses with `409` when another release heads the channel. A channel without a head succeeds, so a retry is safe. Every success appends a `channel_head_removed` change event (at least once across a crash) |
| `channel_configure` | Catalog-wide | `POST /v1/products/{product}/channels/{channel}/pace` | Implemented ([#1063](https://github.com/Sannrox/tenkai/issues/1063)). Sets or clears the channel upgrade pace (`upgrade_pace`: duration or `off`); see [channel upgrade pace](manage-environments.md#channel-upgrade-pace). `GET` on the same path reads pacing progress with read access ([#1276](https://github.com/Sannrox/tenkai/issues/1276)) |
| `channel_admit` | Catalog-wide | `POST /v1/products/{product}/channels/{channel}/admit` | Implemented (#1063). Admits one subscribed instance onto the current head before its paced slot. Requires `environment`, `instance`, and a non-empty `reason` |
| `channel_policy_pause` | Catalog-wide | `POST /v1/products/{product}/channels/{channel}/policy/pause` | Implemented (#1271). Pauses the channel promotion policy; durable, audited, names the actor |
| `channel_policy_resume` | Catalog-wide | `POST /v1/products/{product}/channels/{channel}/policy/resume` | Implemented (#1271). Resumes a paused channel promotion policy |
| `waiver_set` | Catalog-wide | `POST /v1/exposures/waivers` | Implemented ([#1064](https://github.com/Sannrox/tenkai/issues/1064)). Records an advisory waiver (`advisory_id`, `scope` `release`/`component`/`product`/`global`, `category`, `reason`, required `expires`). Narrowest matching scope wins; an expired narrowest match refuses even when a broader unexpired waiver exists |
| `waiver_clear` | Catalog-wide | `POST /v1/exposures/waivers/clear` | Implemented (#1064). Removes that waiver. Missing is success, so a retry is safe |
| `channel_exposure_grace` | Catalog-wide | `POST /v1/products/{product}/channels/{channel}/exposure-grace` | Implemented (#1064). Sets or clears the channel exposure grace (`grace`: duration or `off`) |
| `exposure_grace` | Environment | `POST /v1/environments/{environment}/exposure-grace` | Implemented (#1064). Sets or clears the environment exposure grace. Environment property wins over the subscribed channel. Counted from the durable first-seen stamp; missing first-seen is not grace |
| `subscribe` | Environment | `POST /v1/environments/{environment}/subscriptions` | Implemented (#394). Optional `instance` defaults to the product ([#1014](https://github.com/Sannrox/tenkai/issues/1014)) |
| `unsubscribe` | Environment | `DELETE /v1/environments/{environment}/subscriptions/{product}` | Implemented ([#969](https://github.com/Sannrox/tenkai/issues/969)). The next approved plan removes the instance (ADR 0049). Optional `instance` defaults to the product (#1014); `expected_version` names the recorded version and is required while one is recorded |
| `plan` | Environment | `POST /v1/environments/{environment}/plans` | Implemented ([#395](https://github.com/Sannrox/tenkai/issues/395)) |
| `approve` | Environment | `POST /v1/plans/{plan_id}/approve` | Implemented (#395) |
| `apply` | Environment | `POST /v1/plans/{plan_id}/apply` | Implemented (#395) |
| `cancel` | Environment | `POST /v1/environments/{environment}/apply/cancel` | Implemented ([#1061](https://github.com/Sannrox/tenkai/issues/1061)). Stops the live apply after the current step and sets the environment delivery hold. `expected_generation` is required; a stale generation is a no-op. The result's `cancel` names the outcome (`matched` or `stale`), the `live_generation`, and `hold_set` ([#1274](https://github.com/Sannrox/tenkai/issues/1274)). Steps the cancel stopped read `skipped` in apply step results. |
| `rollback` | Environment | `POST /v1/environments/{environment}/rollback` | Implemented (#395). A successful rollback plan apply holds the environment, as embedded rollback does. `no_hold_reason` on that apply request skips that hold and leaves any existing hold in place; any other plan refuses it ([#1274](https://github.com/Sannrox/tenkai/issues/1274)). |
| `retire` | Environment | `POST /v1/environments/{environment}/retire` | Implemented ([#451](https://github.com/Sannrox/tenkai/issues/451)) |
| `register` | Catalog-wide | `POST /v1/environments` | Implemented ([#679](https://github.com/Sannrox/tenkai/issues/679)) |
| `release_label_set` | Catalog-wide | `PUT /v1/releases/{product}/{version}/labels` | Implemented ([#1065](https://github.com/Sannrox/tenkai/issues/1065)). Sets one `label.*` property on a published release. Same-content republish keeps labels. Requires a non-empty `reason` |
| `release_label_clear` | Catalog-wide | `DELETE /v1/releases/{product}/{version}/labels` | Implemented (#1065). Clears one release label key. Requires a non-empty `reason` |
| `configure` | Environment | `PUT`/`DELETE /v1/environments/{environment}/facts`, `labels`, `constraints`, `maintenance-windows/{window}`, `webhooks`, `approval-policy` | Implemented (#679, labels #1065) |

`tenkaictl --target remote` publish, promote, `channel remove`, `channel configure`, `channel admit`, `channel policy --pause/--resume`, `exposure waive`, `exposure unwaive`, `exposure grace`, `release recall`, `env subscribe`, `env unsubscribe`, `env retire`, `plan`, `approval submit`, `apply`, `apply cancel`, and `rollback` map onto the implemented routes. Retirement requires a non-empty reason and records the authenticated actor and server timestamp. It is idempotent, refuses an active apply lease, and leaves environment history inspectable. Retirement requires the Tenkai server to own the operational store; remote catalog-provider mode fails closed because it cannot atomically fence retirement against apply admission. Remote publish requires a signature and trust roots; `--allow-unsigned-development` stays embedded-only. `PublishRequest.inputs` carries declared deploy inputs next to the manifest (relative path, `file` or `dir`, Unix mode bits the artifact digest binds, and standard-base64 file bytes). Directories expand to the directory and its children. Extra, undeclared, path-escaping, symlink, duplicate, or oversize inputs fail closed (32 MiB decoded file bytes). The field is omitted when empty, so a request with no deploy inputs stays the v1 shape; a server that still `deny_unknown_fields` without this field refuses the new request. The signature still binds the same digests. Remote subscribe, unsubscribe, plan, approve, apply, apply cancel, rollback, hold release, failed-target retry and configuration changes require `--generation` matching the environment's execution lease generation: the `lease.generation` that `env inspect` reports, and `0` only before the environment's first apply or change. Every apply and configuration change advances it, so a value read before one is refused as stale (#703). Remote apply and approval submit require a signed `tenkai.plan-approval.v1` envelope; `--allow-unapproved-development` stays embedded-only. `tenkaictl dev sign-approval --plan-digest --env` signs that envelope without a local hub database. Rollback creates the rollback plan only; the operator approves and applies it with the same evidence as an embedded drill.

`register` and `configure` back remote `env add`, `env facts set|clear`, `env labels set|clear`, `env constraints set|clear`, `env maintenance set|remove`, `env webhooks set|clear`, and `env approval-policy set|clear`. Each request carries a non-empty `reason`, and `configure` also carries `expected_generation` (`--generation`). The body's `change.kind` decides the route: a `set_*` kind is a `PUT` and a `clear_*` or `remove_*` kind is a `DELETE` on its resource, and any other pairing is refused. Validation is the CLI's own, so a refusal carries the same message. A change runs under the environment apply lease, so concurrent changes and an active apply are serialized, and the generation is checked again inside that lease. It appends an immutable `tenkai.environment_config_audit` event with the action, actor, reason, and time before the write (`requested`) and another after it (`completed` or `failed`). An approval-policy file that cannot be loaded is refused with a fixed message; the parser detail goes only to the server log. Registration is catalog-wide, so an environment-scoped credential cannot create environments. An approval-policy path names a file on the server host, never key material. `release labels set|clear` maps onto `release_label_set` / `release_label_clear`. `GET /v1/environments?selector=` and `GET /v1/environments/{environment}/labels` / `GET /v1/releases/{product}/{version}/labels` are read routes. `GET /v1/plans/{plan_id}` is a Read route that returns the stored plan summary with every step's `target_changes`. Environment inspect's `latest_plan` is the same summary, capped at 256 steps, with per-object `field_count` and without field values. Secret and SealedSecret changes stay digest-only. `GET /v1/releases/{release}/recall` is a Read route for the recorded recall (actor, reason, policy, failing instances, covering range, remaining deployments). `GET /v1/products/{product}/recall-ranges` lists recorded ranges, including whether an open range covers future publishes. The promotion-policy recall rule (`recall_on_failing`, `failing_max_share`, `healthy_min_share`, `soak_duration_ms`) is already on `GET /v1/products/{product}/channels/{channel}/policy`.

Community and spoke hosts serve these routes. Tenant-mode hubs bind the request tenant onto a catalog adapter in that tenant's schema (ADR 0038) for publish, promote, channel_remove, recall, subscribe, plan, apply, apply cancel, and rollback. Register and configure remain community-only. They do not write a shared catalog.

## Credentials

Authentication stays on `AuthStack` ([request context](auth-request-context.md)).
`publish`, `promote` and `channel_remove` require `DeliveryCapability::Publish`. Every other
lifecycle operation requires `DeliveryCapability::Management`. `read` is not
enough. `Management` satisfies `Publish`; `Publish` does not satisfy
`Management` or `Read`.

| Principal | Grant | Lifecycle effect |
| --- | --- | --- |
| Fleet management | No environment binding | May call catalog-wide and environment-bound operations on environments it can see. Tenant-mode hosts still apply the non-disclosing deny. |
| Environment-scoped management | Exactly one environment (`TENKAI_ENVIRONMENT_MANAGEMENT_TOKENS`) | May call environment-bound operations, including package migration apply, resume, and rollback, only for that environment. Catalog-wide publish, promote, channel_remove, channel_configure, channel_admit, channel_policy_pause, channel_policy_resume, waiver_set, waiver_clear, channel_exposure_grace, release_label_set, release_label_clear, and recall and fleet-wide reconcile fail closed. |
| Runtime | Exactly one environment | Refused on every management lifecycle operation. Runtime tokens stay on `/v1/runtime/*`. |

Missing approval evidence fails closed. A stale fencing generation cannot
complete apply. An apply whose delivery steps do not all succeed returns
`422 Unprocessable Entity` after recording the outcome. Earlier version `1`
servers answered such an apply with a success result; that was a defect, and
the correction only turns a false success into a refusal. Cached inspect payloads and retained files cannot grant
execution authority.

With `?steps=true`, an apply response carries `steps`: one entry per step
(#1076). A refused apply's `422` body carries the same list. Each entry has
these fields:

- `product`, `instance`, `action`, `status` and `to_version`;
- `detail`, cut to 2,000 characters, with `detail_truncated` set when it was
  cut;
- `cause`, the structured cause when one was recorded;
- `restored_version` when the step restored a version;
- `attempt_id`, the recorded deployment attempt;
- `stale_target` (`kind`, `name`) when apply refused the step because that live object moved since planning.

Without the query the response is unchanged, so older clients keep reading
it. `tenkaictl apply --target remote` asks for steps and prints them as an
embedded apply does. Against an older server, which ignores the query, it
prints the message.

`--allow-unapproved-development` remains embedded-only and restricted to the
built-in `local` environment.

## Compatibility

Within version `1`, a client may add a request field only through a new
minor contract revision that existing servers treat as unknown and refuse
when the field would change admission. A server may add an informational
result field; clients from before results accepted unknown fields (#1172)
refuse it, so such a field ships in a later release than that change. Removing an operation, changing digest meaning, or
changing failure semantics requires version `2` and an explicit migration
window.

Existing `/v1/reconcile`, `/v1/environments`, `/v1/fleet/status`, and
`/v1/migrations/*` routes are unchanged. Delivery-hold set, release,
schedule, cancel, and failed-target retry are additive `tenkai.http.v1`
routes that reuse this envelope's version, actor audit, and environment
fencing generation. `hold_schedule` and `hold_cancel` record dated
environment freezes; a server from before them answers `404`.
`hold_threshold` and `hold_threshold_clear` record the failed-target
count and window; a server from before them answers `404`.
Channel removal is an additive route too; a server from before it answers
`404`, so a client never mistakes an older server for a removal.
Product recall-range record and close are additive routes; a server from
before them answers `404`. An older binary does not consult
`tenkai.release_recall_range` records, so a range recorded on a newer replica
does not recall on an older replica until every replica runs this release.
`GET /v1/environments/{environment}/approval-policy` is an additive
`tenkai.http.v1` read of the effective plan-approval policy; it does not
edit the policy file. Channel promotion policy read, pause, and resume are
additive `tenkai.http.v1` routes; a server from before them answers `404`. Environment registration and the configuration
`PUT`/`DELETE` routes are additive `tenkai.http.v1` routes on the same
envelope.

## Machine-readable contract

`api/tenkai-http-v1.schema.json` (contract id `tenkai.http.v1`) lists every
public route with its method, path, required capability (`none`, `read`,
`publish`, or `management`), and JSON Schema request and response types. It is generated
from the handlers' serde types; `make update` regenerates it and
`make validate` fails when it is stale. Each release attaches it next to the
binaries, covered by `SHA256SUMS` and the attestation. `/healthz` lists the
contract ids a server serves in `contracts`, so clients can refuse an older
server before calling anything else. A response property outside `required`
whose schema does not admit `null` is omitted when unset, never sent as
`null`; request properties may be `null` or omitted. Additive changes keep
`v1`; a breaking change needs a new id. The pull runtime keeps its own contract in
[runtime protocol](runtime-protocol-v1.md).

## See also

- [ADR 0030](decisions/0030-remote-management-lifecycle.md)
- [Discussion #384](https://github.com/Sannrox/tenkai/discussions/384)
- [Catalog contract](catalog-contract.md)
- [Plan approval](plan-approval.md)
- [Release signing](release-signing.md)
