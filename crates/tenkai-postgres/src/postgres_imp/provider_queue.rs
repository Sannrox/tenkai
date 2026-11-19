use super::*;
use super::{Inner, pg};
use postgres::Transaction;
use tenkai::storage::ProviderEventPosition;

pub(crate) fn enqueue_provider_event_in(
    tx: &mut Transaction<'_>,
    event: &ProviderEventRecord,
) -> Result<()> {
    if event.id.trim().is_empty()
        || event.provider_kind.trim().is_empty()
        || event.binding_digest.trim().is_empty()
        || event.payload_json.is_empty()
        || event.attempts != 0
        || event.delivered_at.is_some()
        || !event.last_error.is_empty()
        || event.claim_token.is_some()
        || event.claim_until.is_some()
    {
        return Err(StoreError::InvalidData {
            kind: "provider event",
            detail: "new events require identities, content, and pristine delivery state".into(),
        });
    }
    if let Some(conflict) = existing_provider_event(tx, event)? {
        return conflict;
    }
    let attempts = event.attempts as i32;
    let environment_id =
        tenkai::storage::provider_event_environment_id(&event.payload_json).unwrap_or_default();
    let observed_at =
        tenkai::storage::provider_event_observed_at(&event.payload_json, event.next_attempt_at);
    // A concurrent enqueue of the same event may commit between the read
    // above and this insert. The key conflict then means "already queued",
    // judged by the same rule as a sequential replay, not a store error
    // (#1310).
    let inserted = tx
        .execute(
            "INSERT INTO provider_events(id,provider_kind,binding_digest,payload_json,attempts,next_attempt_at,delivered_at,last_error,claim_token,claim_until,environment_id,observed_at)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
             ON CONFLICT (provider_kind,id) DO NOTHING",
            &[
                &event.id,
                &event.provider_kind,
                &event.binding_digest,
                &event.payload_json,
                &attempts,
                &event.next_attempt_at,
                &event.delivered_at,
                &event.last_error,
                &event.claim_token,
                &event.claim_until,
                &environment_id,
                &observed_at,
            ],
        )
        .map_err(pg)?;
    if inserted == 0 {
        return existing_provider_event(tx, event)?.unwrap_or_else(|| {
            Err(StoreError::InvalidData {
                kind: "provider event",
                detail: format!("event {} conflicted but is not stored", event.id),
            })
        });
    }
    Ok(())
}

/// The outcome for `event` when a row with its key already exists: `Ok` for
/// the same event (or a first-wins webhook replay), a conflict otherwise.
/// `None` when no row exists yet.
fn existing_provider_event(
    tx: &mut Transaction<'_>,
    event: &ProviderEventRecord,
) -> Result<Option<Result<()>>> {
    let Some(row) = tx
        .query_opt(
            "SELECT binding_digest,payload_json FROM provider_events
             WHERE provider_kind = $1 AND id = $2",
            &[&event.provider_kind, &event.id],
        )
        .map_err(pg)?
    else {
        return Ok(None);
    };
    let digest: String = row.get(0);
    let payload: String = row.get(1);
    if digest == event.binding_digest
        && provider_event_payloads_match(&payload, &event.payload_json)
    {
        return Ok(Some(Ok(())));
    }
    // Same first-wins rule as SQLite: a replayed observation id may carry a
    // new body and must not roll back capture (#1102).
    if event.provider_kind == "feedback_webhook" {
        return Ok(Some(Ok(())));
    }
    Ok(Some(Err(StoreError::ImmutableConflict {
        kind: "provider event",
        id: event.id.clone(),
    })))
}

impl Inner {
    pub fn enqueue_provider_event(&self, schema: &str, event: &ProviderEventRecord) -> Result<()> {
        let event = event.clone();
        self.with_writer_schema(schema, move |tx| enqueue_provider_event_in(tx, &event))
    }

    pub fn list_tenant_schemas(&self) -> Result<Vec<String>> {
        self.with_schema("public", move |tx| {
            let rows = tx
                .query(
                    "SELECT nspname FROM pg_namespace WHERE left(nspname, 9) = 'tenkai_t_' ORDER BY nspname",
                    &[],
                )
                .map_err(pg)?;
            Ok(rows.into_iter().map(|row| row.get(0)).collect())
        })
    }

    /// The hub and tenant schemas holding an event of any of `provider_kinds`
    /// that a claim at `now` would take (#872, #877): one catalog read and one
    /// query for the whole hub, so an idle export tick does not visit every
    /// tenant. Writer-gated like the claim it precedes.
    pub fn due_provider_event_schemas(
        &self,
        provider_kinds: &[&str],
        now: i64,
    ) -> Result<Vec<String>> {
        let provider_kinds: Vec<String> = provider_kinds
            .iter()
            .map(|kind| (*kind).to_owned())
            .collect();
        self.with_writer_schema("public", move |tx| {
            let schemas: Vec<String> = tx
                .query(
                    "SELECT n.nspname FROM pg_namespace n
                     JOIN pg_class c ON c.relnamespace = n.oid
                     WHERE c.relname = 'provider_events' AND c.relkind IN ('r','p')
                       AND (n.nspname LIKE 'tenkai_t_%' OR n.nspname = $1)
                     ORDER BY n.nspname",
                    &[&crate::HUB_SCHEMA],
                )
                .map_err(pg)?
                .into_iter()
                .map(|row| row.get(0))
                .collect();
            if schemas.is_empty() {
                return Ok(Vec::new());
            }
            // Same due rule as the claim: undelivered, attempt time reached,
            // and no live claim. Names come from the catalog, so quote them.
            let sql = schemas
                .iter()
                .map(|schema| {
                    format!(
                        "SELECT {literal}::text WHERE EXISTS (
                           SELECT 1 FROM {ident}.provider_events
                           WHERE provider_kind = ANY($1) AND delivered_at IS NULL
                             AND next_attempt_at <= $2
                             AND (claim_until IS NULL OR claim_until <= $2))",
                        literal = format_args!("'{}'", schema.replace('\'', "''")),
                        ident = format_args!("\"{}\"", schema.replace('"', "\"\"")),
                    )
                })
                .collect::<Vec<_>>()
                .join(" UNION ALL ");
            let rows = tx.query(&sql, &[&provider_kinds, &now]).map_err(pg)?;
            Ok(rows.into_iter().map(|row| row.get(0)).collect())
        })
    }

    pub fn list_provider_events(
        &self,
        schema: &str,
        provider_kind: &str,
        environment_id: &str,
        limit: usize,
    ) -> Result<Vec<ProviderEventRecord>> {
        self.inspect_provider_events(
            schema,
            provider_kind,
            environment_id,
            limit,
            "ORDER BY observed_at DESC,id DESC",
        )
    }

    /// Newest-first events strictly after `after`, each with its position.
    pub fn list_provider_events_after(
        &self,
        schema: &str,
        provider_kind: &str,
        environment_id: &str,
        after: Option<&ProviderEventPosition>,
        limit: usize,
    ) -> Result<Vec<(ProviderEventPosition, ProviderEventRecord)>> {
        if provider_kind.trim().is_empty() || environment_id.trim().is_empty() || limit == 0 {
            return Err(StoreError::InvalidData {
                kind: "provider event inspection",
                detail: "provider kind, environment, and a positive result limit are required"
                    .into(),
            });
        }
        // No position sorts after (i64::MAX, kind, id) for a fixed kind, so
        // a missing `after` reads from the newest event. Text compares
        // bytewise (`COLLATE "C"`) to match the caller's merge order.
        let (after_observed, after_kind, after_id) = after.map_or_else(
            || (i64::MAX, String::new(), String::new()),
            |after| {
                (
                    after.observed_at,
                    after.provider_kind.clone(),
                    after.id.clone(),
                )
            },
        );
        let provider_kind = provider_kind.to_owned();
        let environment_id = environment_id.to_owned();
        self.with_schema(schema, move |tx| {
            let limit_i = limit.min(128) as i64;
            let rows = tx
                .query(
                    "SELECT id,provider_kind,binding_digest,payload_json,attempts,
                        next_attempt_at,delivered_at,last_error,claim_token,claim_until,
                        observed_at
                    FROM provider_events
                    WHERE provider_kind=$1 AND environment_id=$2
                      AND (observed_at<$4 OR (observed_at=$4
                           AND (provider_kind COLLATE \"C\"<$5
                                OR (provider_kind=$5 AND id COLLATE \"C\"<$6))))
                    ORDER BY observed_at DESC,id COLLATE \"C\" DESC LIMIT $3",
                    &[
                        &provider_kind,
                        &environment_id,
                        &limit_i,
                        &after_observed,
                        &after_kind,
                        &after_id,
                    ],
                )
                .map_err(pg)?;
            Ok(rows
                .into_iter()
                .map(|row| {
                    let record = ProviderEventRecord {
                        id: row.get(0),
                        provider_kind: row.get(1),
                        binding_digest: row.get(2),
                        payload_json: row.get(3),
                        attempts: row.get::<_, i32>(4) as u32,
                        next_attempt_at: row.get(5),
                        delivered_at: row.get(6),
                        last_error: row.get(7),
                        claim_token: row.get(8),
                        claim_until: row.get(9),
                    };
                    let position = ProviderEventPosition {
                        observed_at: row.get(10),
                        provider_kind: record.provider_kind.clone(),
                        id: record.id.clone(),
                    };
                    (position, record)
                })
                .collect())
        })
    }

    /// Undelivered events, most failed attempts first.
    pub fn list_failing_provider_events(
        &self,
        schema: &str,
        provider_kind: &str,
        environment_id: &str,
        limit: usize,
    ) -> Result<Vec<ProviderEventRecord>> {
        self.inspect_provider_events(
            schema,
            provider_kind,
            environment_id,
            limit,
            "AND delivered_at IS NULL AND attempts>0 ORDER BY attempts DESC,observed_at,id",
        )
    }

    /// `tail` is a fixed filter and order suffix, never caller input.
    fn inspect_provider_events(
        &self,
        schema: &str,
        provider_kind: &str,
        environment_id: &str,
        limit: usize,
        tail: &'static str,
    ) -> Result<Vec<ProviderEventRecord>> {
        if provider_kind.trim().is_empty() || environment_id.trim().is_empty() || limit == 0 {
            return Err(StoreError::InvalidData {
                kind: "provider event inspection",
                detail: "provider kind, environment, and a positive result limit are required"
                    .into(),
            });
        }
        let provider_kind = provider_kind.to_owned();
        let environment_id = environment_id.to_owned();
        self.with_schema(schema, move |tx| {
            let limit_i = limit.min(128) as i64;
            let rows = tx
                .query(
                    &format!(
                        "SELECT id,provider_kind,binding_digest,payload_json,attempts,
                            next_attempt_at,delivered_at,last_error,claim_token,claim_until
                    FROM provider_events
                    WHERE provider_kind=$1 AND environment_id=$2
                     {tail} LIMIT $3"
                    ),
                    &[&provider_kind, &environment_id, &limit_i],
                )
                .map_err(pg)?;
            Ok(rows
                .into_iter()
                .map(|row| ProviderEventRecord {
                    id: row.get(0),
                    provider_kind: row.get(1),
                    binding_digest: row.get(2),
                    payload_json: row.get(3),
                    attempts: row.get::<_, i32>(4) as u32,
                    next_attempt_at: row.get(5),
                    delivered_at: row.get(6),
                    last_error: row.get(7),
                    claim_token: row.get(8),
                    claim_until: row.get(9),
                })
                .collect())
        })
    }
}
