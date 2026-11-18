# Delivery report

`tenkaictl report delivery` shows how one environment delivered over a
period: how often it deployed, how long releases took to arrive, how often
changes failed, how long recovery took, and how old its open advisory
exposures are. Every number comes from records Tenkai already keeps:
deployment attempts, the publish time of each release, instance health
reports, and deployed exposure records. Nothing is estimated, and the same
records always give the same report.

```bash
tenkaictl report delivery --env prod
tenkaictl report delivery --env prod --since-ms 1767225600000 --until-ms 1769904000000
tenkaictl -o json report delivery --env prod > delivery.json
```

Remote mode reads `GET /v1/environments/{environment}/delivery-report` with
optional `since_ms` and `until_ms` query parameters, and needs read
capability. Source: `src/delivery_report.rs`.

## Period

The period is `[since_ms, until_ms)` in Unix milliseconds. `until_ms`
defaults to now and `since_ms` to 30 days before `until_ms`. The report
echoes both. An empty or inverted period is refused.

## Rows

One row per product and the channel its instances subscribe to now.
Instances that are no longer subscribed have no channel. A subscribed product
with no attempts in the period still gets a row of zeros.

## Definitions

An **attempt** counts in the period when it was created in it.

| Field | Definition |
| --- | --- |
| `change_attempts` | Install, upgrade and removal attempts that finished. Rollback attempts and blocked attempts are not changes. |
| `deployments` | Change attempts that succeeded. Deployment frequency is this count over the period. |
| `change_failures` | Change attempts that failed or were rolled back. |
| `change_failure_rate` | `change_failures / change_attempts`; absent without change attempts. |
| `lead_time_ms` | Median time from a release's publication to the end of its successful deployment. |
| `restores` | Failure incidents in the period that a later attempt ended. |
| `unrestored` | Failure incidents still open at the end of the period. |
| `time_to_restore_ms` | Median time from the first failure of an incident to its restore. |
| `open_exposures` | Advisory exposures open at the end of the period on the release each instance ran then. |
| `oldest_exposure_age_ms` | Age at the end of the period of the oldest of those exposures. |

**Failure and restore.** Consecutive failures on one instance form one
incident. The incident is restored by the first later attempt that leaves a
working release: a successful attempt of any kind, rollbacks included, or an
attempt the executor rolled back itself. An attempt that was rolled back is
therefore both a failure and its own restore. A failed upgrade followed by a
successful rollback counts once as a failure and once as a restore.

**Medians** are the lower of the two middle values, so each median is a
value that was recorded.

**Missing data.** `missing_data` is true when the environment recorded no
attempt in the period and no instance health report at or after its start.
The rows then say nothing about how the environment ran, and a row of zeros
is not a healthy one. A tenant-mode hub records no attempts, so its reports
are always missing data.
