//! Catalog operations: publish immutable releases, promote them into channels.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Result, bail};

use crate::client::Ctx;
use crate::manifest;
use crate::ontology::*;
use crate::pb::sekai::Object;

fn object(id: String, kind: &str, name: String, properties: HashMap<String, String>) -> Object {
    let now = crate::now_millis();
    Object {
        id,
        kind: kind.into(),
        name,
        namespace: NS.into(),
        external_id: String::new(),
        properties,
        created: now,
        updated: now,
    }
}

/// Publish the manifest as an immutable release of its product.
pub async fn publish(ctx: &mut Ctx, manifest_path: &Path) -> Result<String> {
    let loaded = manifest::load(manifest_path)?;
    let name = loaded.manifest.product.name.clone();
    let version = loaded.manifest.product.version.clone();
    let digest = manifest::digest(&loaded.raw);
    let artifact_digest =
        manifest::artifact_digest(&loaded.workdir, &loaded.manifest.deploy.inputs)?;
    let versioned_workdir = manifest::snapshot_workdir(
        &loaded.workdir,
        &loaded.manifest.deploy.inputs,
        &digest,
        &artifact_digest,
    )?;

    let rid = release_id(&name, &version);
    let existing_release = if let Some(mut existing) = ctx.get(&rid).await? {
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
        if existing_digest == digest && existing_artifact_digest == artifact_digest {
            existing
                .properties
                .insert("workdir".into(), versioned_workdir.display().to_string());
            existing.updated = crate::now_millis();
            ctx.put(existing).await?;
            true
        } else {
            bail!(
                "release {name}@{version} already exists with a different digest — releases are immutable, bump product.version"
            );
        }
    } else {
        let release = object(
            rid.clone(),
            KIND_RELEASE,
            format!("{name}@{version}"),
            HashMap::from([
                ("product".into(), name.clone()),
                ("version".into(), version.clone()),
                ("digest".into(), digest.clone()),
                ("artifact_digest".into(), artifact_digest.clone()),
                ("manifest".into(), loaded.raw.clone()),
                ("workdir".into(), versioned_workdir.display().to_string()),
            ]),
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
                if existing.properties.get("digest") != Some(&digest)
                    || existing.properties.get("artifact_digest") != Some(&artifact_digest)
                {
                    bail!(
                        "release {name}@{version} was concurrently published with a different digest"
                    );
                }
            }
            Err(status) => return Err(status.into()),
        }
        false
    };

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
        Ok(format!(
            "{name}@{version} already published (digest unchanged)"
        ))
    } else {
        Ok(format!("published {name}@{version} ({})", &digest[..12]))
    }
}

/// Point a channel of the product at an already-published release.
pub async fn promote(ctx: &mut Ctx, spec: &str, channel: &str) -> Result<String> {
    let Some((name, version)) = spec.split_once('@') else {
        bail!("expected <product>@<version>, got {spec:?}");
    };
    validate_identifier("product", name)?;
    validate_identifier("version", version)?;
    validate_identifier("channel", channel)?;
    let rid = release_id(name, version);
    if ctx.get(&rid).await?.is_none() {
        bail!("release {name}@{version} is not published");
    }

    let cid = channel_id(name, channel);
    let channel_head = object(
        cid.clone(),
        KIND_CHANNEL,
        format!("{name}/{channel}"),
        HashMap::from([
            ("product".into(), name.to_string()),
            ("channel".into(), channel.to_string()),
            ("current_version".into(), version.to_string()),
            ("current_release".into(), rid.clone()),
        ]),
    );
    if ctx.get(&cid).await?.is_none() {
        ctx.create_once(object(
            cid.clone(),
            KIND_CHANNEL,
            format!("{name}/{channel}"),
            HashMap::from([
                ("product".into(), name.to_string()),
                ("channel".into(), channel.to_string()),
            ]),
        ))
        .await?;
    }
    ctx.link(&cid, &rid, REL_PROMOTES).await?;
    ctx.put(channel_head).await?;

    Ok(format!("promoted {name}@{version} to channel {channel}"))
}
