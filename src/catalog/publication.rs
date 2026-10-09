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
    crate::oci_artifact::verify_publication(
        &loaded.manifest.artifacts,
        options.artifact_registry.as_deref(),
    )?;
    let file_digest =
        manifest::artifact_digest(&loaded.workdir, &loaded.manifest.immutable_inputs())?;
    let artifact_digest = manifest::identity_digest(
        &loaded.workdir,
        &loaded.manifest.immutable_inputs(),
        &loaded.manifest.artifacts,
    )?;
    let provenance = release_provenance::load_all(
        &options.provenance,
        options.provenance_trust_roots.as_deref(),
    )?;
    release_provenance::validate_release_binding(&provenance, &digest, &artifact_digest)?;
    let (provenance_properties, provenance_digests) = provenance_properties(&provenance)?;
    let admitted_pin = change_set_pin::admit_publication(
        loaded.manifest.change_set_pin.as_ref(),
        options.change_set_evidence.as_ref(),
    )?;
    if loaded.manifest.product.kind == crate::manifest::ProductKind::WorkshopModule {
        crate::workshop_module::admit_publication(
            &loaded.manifest,
            &loaded.workdir,
            admitted_pin.as_ref(),
        )?;
    }
    let pin_properties = match &admitted_pin {
        Some(pin) => change_set_pin::stored_properties(pin)?,
        None => HashMap::new(),
    };
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
        &file_digest,
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
            change_set_pin::validate_stored(&existing, admitted_pin.as_ref())?;
            existing
                .properties
                .insert("artifact_digest".into(), artifact_digest.clone());
            persist_oci_artifacts(&mut existing.properties, &loaded.manifest.artifacts)?;
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
        persist_oci_artifacts(&mut properties, &loaded.manifest.artifacts)?;
        persist_delivery_properties(&mut properties, &loaded.manifest.delivery);
        properties.extend(provenance_properties.clone());
        properties.extend(pin_properties.clone());
        let release = object(
            rid.clone(),
            KIND_RELEASE,
            format!("{name}@{version}"),
            properties,
        );
        match ctx.create_once(release).await {
            Ok(_) => {}
            Err(status) if crate::client::is_unique_conflict(&status) => {
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
                change_set_pin::validate_stored(&existing, admitted_pin.as_ref())?;
                let mut pinned = existing;
                pinned
                    .properties
                    .insert("artifact_digest".into(), artifact_digest.clone());
                persist_oci_artifacts(&mut pinned.properties, &loaded.manifest.artifacts)?;
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

fn persist_delivery_properties(
    properties: &mut HashMap<String, String>,
    delivery: &crate::manifest::DeliverySection,
) {
    properties.insert(
        "has_migration".into(),
        if delivery.has_migration {
            "true".into()
        } else {
            "false".into()
        },
    );
    properties.insert(
        "changes_identity_config".into(),
        if delivery.changes_identity_config {
            "true".into()
        } else {
            "false".into()
        },
    );
}

fn persist_oci_artifacts(
    properties: &mut HashMap<String, String>,
    artifacts: &[crate::oci_artifact::OciArtifactRef],
) -> Result<()> {
    if artifacts.is_empty() {
        properties.remove("oci_artifacts");
        return Ok(());
    }
    properties.insert("oci_artifacts".into(), serde_json::to_string(artifacts)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Ctx;
    use crate::ontology::release_id;

    #[tokio::test]
    async fn changed_delivery_section_is_rejected_as_immutable() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-delivery-immutable-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let database = root.join("tenkai.db");
        std::fs::create_dir_all(&root).unwrap();
        write_manifest(&root, false);
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let options = PublishOptions {
            allow_unsigned_development: true,
            ..Default::default()
        };
        publish(&mut ctx, &root.join("tenkai.toml"), &options)
            .await
            .unwrap();
        let release = ctx
            .get(&release_id("delivery-demo", "1.0.0"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            release.properties.get("has_migration").map(String::as_str),
            Some("false")
        );
        assert_eq!(
            release
                .properties
                .get("changes_identity_config")
                .map(String::as_str),
            Some("false")
        );
        write_manifest(&root, true);
        let error = publish(&mut ctx, &root.join("tenkai.toml"), &options)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("immutable") || error.contains("bump product.version"),
            "{error}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    fn write_manifest(dir: &std::path::Path, has_migration: bool) {
        std::fs::write(
            dir.join("tenkai.toml"),
            format!(
                r#"
[product]
name = "delivery-demo"
version = "1.0.0"

[deploy]
install = "true"

[delivery]
has_migration = {has_migration}
changes_identity_config = false
"#
            ),
        )
        .unwrap();
    }
}
