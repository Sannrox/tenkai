//! Private Catalog Release publication admission.
//!
//! The interface intentionally accepts one publication request and owns the
//! complete immutable-admission ordering. Public callers remain in the parent
//! Catalog module so this implementation can deepen without widening the
//! application seam.

use super::*;

pub(super) enum ResultContract {
    Message,
    Bounded,
}

pub(super) async fn admit(
    ctx: &mut Ctx,
    manifest_path: &Path,
    options: &PublishOptions,
    result_contract: ResultContract,
) -> Result<PublishResult> {
    let loaded = manifest::load(manifest_path)?;
    let name = loaded.manifest.product.name.clone();
    let version = loaded.manifest.product.version.clone();
    let published_spec = format!("{name}@{version}");
    if matches!(result_contract, ResultContract::Bounded) {
        crate::command_result::validate_resource_reference("release", &published_spec)
            .map_err(|message| anyhow::anyhow!(message))?;
    }
    let digest = manifest::digest(&loaded.raw);
    let artifact_digest =
        manifest::artifact_digest(&loaded.workdir, &loaded.manifest.immutable_inputs())?;
    let provenance = release_provenance::load_all(
        &options.provenance,
        options.provenance_trust_roots.as_deref(),
    )?;
    release_provenance::validate_release_binding(&provenance, &digest, &artifact_digest)?;
    let (provenance_properties, provenance_digests) = provenance_properties(&provenance)?;
    let rid = release_id(&name, &version);
    let preexisting_release = ctx.get(&rid).await?;
    validate_provenance_admission(
        &provenance,
        preexisting_release.is_some(),
        crate::now_millis(),
    )?;
    let verification = verify_publication(options, &digest, &artifact_digest)?;
    let verification_properties = verification.properties()?;
    let versioned_workdir = manifest::snapshot_workdir(
        &loaded.workdir,
        &loaded.manifest.immutable_inputs(),
        &digest,
        &artifact_digest,
    )?;

    let existing_release = if let Some(mut existing) = preexisting_release {
        let existing_digest = existing
            .properties
            .get("digest")
            .cloned()
            .unwrap_or_default();
        let existing_artifact_digest = existing
            .properties
            .get("artifact_digest")
            .cloned()
            .unwrap_or_default();
        if existing_digest == digest
            && (existing_artifact_digest.is_empty() || existing_artifact_digest == artifact_digest)
        {
            validate_stored_release_content(&existing, &digest, &artifact_digest)?;
            validate_stored_provenance(&existing, &provenance_properties)?;
            existing
                .properties
                .insert("artifact_digest".into(), artifact_digest.clone());
            existing
                .properties
                .insert("workdir".into(), versioned_workdir.display().to_string());
            existing.updated = crate::now_millis();
            ctx.put(existing).await?;
            true
        } else {
            bail!(
                "release {name}@{version} already exists with different content — releases are immutable, bump product.version"
            );
        }
    } else {
        let mut properties = HashMap::from([
            ("product".into(), name.clone()),
            ("version".into(), version.clone()),
            ("digest".into(), digest.clone()),
            ("artifact_digest".into(), artifact_digest.clone()),
            ("manifest".into(), loaded.raw.clone()),
            ("workdir".into(), versioned_workdir.display().to_string()),
        ]);
        properties.extend(provenance_properties.clone());
        let release = object(
            rid.clone(),
            KIND_RELEASE,
            format!("{name}@{version}"),
            properties,
        );
        match ctx.create_once(release).await {
            Ok(_) => {}
            Err(status)
                if status.code() == tonic::Code::AlreadyExists
                    || (status.code() == tonic::Code::Internal
                        && status.message().contains("UNIQUE")) =>
            {
                let existing = ctx.get(&rid).await?.ok_or_else(|| {
                    anyhow::anyhow!("release {rid} appeared concurrently then vanished")
                })?;
                let existing_artifact_digest = existing
                    .properties
                    .get("artifact_digest")
                    .map(String::as_str)
                    .unwrap_or_default();
                if existing.properties.get("digest") != Some(&digest)
                    || (!existing_artifact_digest.is_empty()
                        && existing_artifact_digest != artifact_digest)
                {
                    bail!(
                        "release {name}@{version} was concurrently published with different content"
                    );
                }
                validate_stored_release_content(&existing, &digest, &artifact_digest)?;
                validate_stored_provenance(&existing, &provenance_properties)?;
                let mut pinned = existing;
                pinned
                    .properties
                    .insert("artifact_digest".into(), artifact_digest.clone());
                pinned
                    .properties
                    .insert("workdir".into(), versioned_workdir.display().to_string());
                pinned.updated = crate::now_millis();
                ctx.put(pinned).await?;
            }
            Err(status) => return Err(status.into()),
        }
        false
    };

    backfill_legacy_verification(ctx, &rid, &verification_properties).await?;

    let pid = product_id(&name);
    ctx.put(object(
        pid.clone(),
        KIND_PRODUCT,
        name.clone(),
        HashMap::from([(
            "description".into(),
            loaded.manifest.product.description.clone(),
        )]),
    ))
    .await?;
    ctx.link(&rid, &pid, REL_RELEASE_OF).await?;

    if existing_release {
        Ok(PublishResult {
            release: published_spec,
            provenance_digests,
            message: format!("{name}@{version} already published (digest unchanged)"),
        })
    } else {
        let trust = verification.description();
        Ok(PublishResult {
            release: published_spec,
            provenance_digests,
            message: format!("published {name}@{version} ({}, {trust})", &digest[..12]),
        })
    }
}
