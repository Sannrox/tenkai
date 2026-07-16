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

    let rid = release_id(&name, &version);
    if let Some(existing) = ctx.get(&rid).await? {
        let existing_digest = existing
            .properties
            .get("digest")
            .cloned()
            .unwrap_or_default();
        if existing_digest == digest {
            return Ok(format!(
                "{name}@{version} already published (digest unchanged)"
            ));
        }
        bail!(
            "release {name}@{version} already exists with a different digest — releases are immutable, bump product.version"
        );
    }

    ctx.put(object(
        rid.clone(),
        KIND_RELEASE,
        format!("{name}@{version}"),
        HashMap::from([
            ("product".into(), name.clone()),
            ("version".into(), version.clone()),
            ("digest".into(), digest.clone()),
            ("manifest".into(), loaded.raw.clone()),
            ("workdir".into(), loaded.workdir.display().to_string()),
        ]),
    ))
    .await?;
    ctx.link(&rid, &pid, REL_RELEASE_OF).await?;

    Ok(format!("published {name}@{version} ({})", &digest[..12]))
}

/// Point a channel of the product at an already-published release.
pub async fn promote(ctx: &mut Ctx, spec: &str, channel: &str) -> Result<String> {
    let Some((name, version)) = spec.split_once('@') else {
        bail!("expected <product>@<version>, got {spec:?}");
    };
    let rid = release_id(name, version);
    if ctx.get(&rid).await?.is_none() {
        bail!("release {name}@{version} is not published");
    }

    let cid = channel_id(name, channel);
    ctx.put(object(
        cid.clone(),
        KIND_CHANNEL,
        format!("{name}/{channel}"),
        HashMap::from([
            ("product".into(), name.to_string()),
            ("channel".into(), channel.to_string()),
            ("current_version".into(), version.to_string()),
            ("current_release".into(), rid.clone()),
        ]),
    ))
    .await?;
    ctx.link(&cid, &rid, REL_PROMOTES).await?;

    Ok(format!("promoted {name}@{version} to channel {channel}"))
}
