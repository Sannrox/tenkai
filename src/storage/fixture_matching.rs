use super::*;

pub(super) fn sqlite_fixture_matches(
    tx: &Transaction<'_>,
    fixture: &crate::development_fixtures::PreparedDevelopmentFixture,
) -> Result<bool> {
    for release in &fixture.releases {
        let row = tx
            .query_row(
                "SELECT product,version,content_digest,descriptor_json FROM releases WHERE id=?1",
                [&release.id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?;
        if row
            != Some((
                release.product.clone(),
                release.version.clone(),
                release.content_digest.clone(),
                release.descriptor_json.clone(),
            ))
        {
            return Ok(false);
        }
    }
    for channel in &fixture.channels {
        let row = tx
            .query_row(
                "SELECT product,name,release_id,revision FROM channels WHERE id=?1",
                [&channel.id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, u64>(3)?,
                    ))
                },
            )
            .optional()?;
        if row
            != Some((
                channel.product.clone(),
                channel.name.clone(),
                channel.release_id.clone(),
                channel.revision,
            ))
        {
            return Ok(false);
        }
    }
    for environment in &fixture.environments {
        let row = tx
            .query_row(
                "SELECT revision,configuration_json FROM environments WHERE id=?1",
                [&environment.id],
                |row| Ok((row.get::<_, u64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        if row != Some((environment.revision, environment.configuration_json.clone())) {
            return Ok(false);
        }
    }
    for plan in &fixture.plans {
        let row = tx
            .query_row(
                "SELECT environment_id,format_version,content_digest,plan_json,status,status_detail
                 FROM plans WHERE id=?1",
                [&plan.id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u32>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()?;
        if row
            != Some((
                plan.environment_id.clone(),
                plan.format_version,
                plan.content_digest.clone(),
                plan.plan_json.clone(),
                "blocked".into(),
                plan.status_detail.clone(),
            ))
        {
            return Ok(false);
        }
    }
    Ok(true)
}
