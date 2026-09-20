use super::*;
use super::{Inner, pg};

impl Inner {
    pub fn promote_channel(&self, schema: &str, channel: &ChannelRecord) -> Result<ChannelRecord> {
        self.with_schema(schema, |tx| {
            if tx
                .query_one(
                    "SELECT EXISTS(
                        SELECT 1 FROM development_fixture_objects
                        WHERE (object_kind='release' AND object_id=$1)
                           OR (object_kind='channel' AND object_id=$2)
                     )",
                    &[&channel.release_id, &channel.id],
                )
                .map_err(pg)?
                .get::<_, bool>(0)
            {
                return Err(StoreError::InvalidData {
                    kind: "development_fixture",
                    detail: "fixture releases and channels cannot be promoted".into(),
                });
            }
            let release_product: String = tx
                .query_opt(
                    "SELECT product FROM releases WHERE id = $1",
                    &[&channel.release_id],
                )
                .map_err(pg)?
                .map(|row| row.get(0))
                .ok_or_else(|| StoreError::NotFound {
                    kind: "release",
                    id: channel.release_id.clone(),
                })?;
            if release_product != channel.product {
                return Err(StoreError::InvalidData {
                    kind: "channel",
                    detail: format!(
                        "release {} belongs to product {release_product}, not {}",
                        channel.release_id, channel.product
                    ),
                });
            }
            let existing = tx
                .query_opt(
                    "SELECT product,name,release_id,revision FROM channels WHERE id = $1",
                    &[&channel.id],
                )
                .map_err(pg)?;
            let inserting = existing.is_none();
            let next = match existing {
                Some(row) => {
                    let product: String = row.get(0);
                    let name: String = row.get(1);
                    let release_id: String = row.get(2);
                    let revision: i64 = row.get(3);
                    if product != channel.product || name != channel.name {
                        return Err(StoreError::ImmutableConflict {
                            kind: "channel",
                            id: channel.id.clone(),
                        });
                    }
                    if revision as u64 != channel.revision {
                        if release_id == channel.release_id
                            && revision as u64 == channel.revision.saturating_add(1)
                        {
                            return Ok(ChannelRecord {
                                revision: revision as u64,
                                ..channel.clone()
                            });
                        }
                        return Err(StoreError::RevisionConflict {
                            kind: "channel",
                            id: channel.id.clone(),
                            expected: channel.revision,
                            actual: revision as u64,
                        });
                    }
                    revision as u64 + 1
                }
                None if channel.revision == 0 => 1,
                None => {
                    return Err(StoreError::RevisionConflict {
                        kind: "channel",
                        id: channel.id.clone(),
                        expected: channel.revision,
                        actual: 0,
                    });
                }
            };
            let next_i = next as i64;
            let changed = if inserting {
                tx.execute(
                    "INSERT INTO channels(id,product,name,release_id,revision)
                     VALUES($1,$2,$3,$4,$5)
                     ON CONFLICT DO NOTHING",
                    &[
                        &channel.id,
                        &channel.product,
                        &channel.name,
                        &channel.release_id,
                        &next_i,
                    ],
                )
                .map_err(pg)?
            } else {
                tx.execute(
                    "UPDATE channels SET release_id=$1,revision=$2
                     WHERE id=$3 AND product=$4 AND name=$5 AND revision=$6",
                    &[
                        &channel.release_id,
                        &next_i,
                        &channel.id,
                        &channel.product,
                        &channel.name,
                        &(channel.revision as i64),
                    ],
                )
                .map_err(pg)?
            };
            if changed == 0 {
                let observed = tx
                    .query_one(
                        "SELECT release_id,revision FROM channels WHERE id=$1",
                        &[&channel.id],
                    )
                    .map_err(pg)?;
                let release_id: String = observed.get(0);
                let revision = observed.get::<_, i64>(1) as u64;
                if release_id == channel.release_id && revision == next {
                    return Ok(ChannelRecord {
                        revision,
                        ..channel.clone()
                    });
                }
                return Err(StoreError::RevisionConflict {
                    kind: "channel",
                    id: channel.id.clone(),
                    expected: channel.revision,
                    actual: revision,
                });
            }
            Ok(ChannelRecord {
                revision: next,
                ..channel.clone()
            })
        })
    }
}
