//! Catalog operations: publish immutable releases, promote them into channels.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use crate::client::Ctx;
use crate::manifest;
use crate::ontology::*;
use crate::pb::sekai::Object;
use crate::release_signing::{self, VerificationEvidence};

#[derive(Debug, Clone, Default)]
pub struct PublishOptions {
    pub signature: Option<PathBuf>,
    pub trust_roots: Option<PathBuf>,
    pub allow_unsigned_development: bool,
}

fn verify_publication(
    options: &PublishOptions,
    manifest_digest: &str,
    artifact_digest: &str,
) -> Result<Option<VerificationEvidence>> {
    match (&options.signature, &options.trust_roots) {
        (Some(signature), Some(trust_roots)) => {
            if options.allow_unsigned_development {
                bail!("--allow-unsigned-development cannot be combined with signed publication");
            }
            let envelope = release_signing::SignatureEnvelope::load(signature)?;
            let roots = release_signing::TrustRoots::load(trust_roots)?;
            Ok(Some(release_signing::verify_release(
                &envelope,
                &roots,
                manifest_digest,
                artifact_digest,
            )?))
        }
        (None, None) if options.allow_unsigned_development => Ok(None),
        (None, None) => bail!(
            "release publication requires --signature and --trust-roots; use --allow-unsigned-development only for local development"
        ),
        _ => bail!("signed publication requires both --signature and --trust-roots"),
    }
}

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
pub async fn publish(
    ctx: &mut Ctx,
    manifest_path: &Path,
    options: &PublishOptions,
) -> Result<String> {
    let loaded = manifest::load(manifest_path)?;
    let name = loaded.manifest.product.name.clone();
    let version = loaded.manifest.product.version.clone();
    let digest = manifest::digest(&loaded.raw);
    let artifact_digest =
        manifest::artifact_digest(&loaded.workdir, &loaded.manifest.deploy.inputs)?;
    let verification = verify_publication(options, &digest, &artifact_digest)?;
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
        let trust = verification
            .as_ref()
            .map(|evidence| format!("signed by {}", evidence.signer_identity))
            .unwrap_or_else(|| "unsigned development release".into());
        Ok(format!(
            "published {name}@{version} ({}, {trust})",
            &digest[..12]
        ))
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
    let owner = format!("promotion:{spec}:{}", crate::now_millis());
    let lock = crate::canary::claim_promotion_lock(ctx, name, channel, &owner).await?;
    let result = async {
        let canary_authorization =
            crate::canary::authorize_promotion(ctx, name, version, channel).await?;

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
        if let Some(expected) = canary_authorization.as_ref() {
            crate::canary::confirm_policy_active(ctx, expected).await?;
        }
        crate::canary::confirm_promotion_lock(ctx, &lock).await?;
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

        Ok::<_, anyhow::Error>(format!("promoted {name}@{version} to channel {channel}"))
    }
    .await;
    let unlock = crate::canary::release_promotion_lock(ctx, &lock).await;
    match (result, unlock) {
        (Ok(message), Ok(())) => Ok(message),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(unlock)) => {
            Err(error.context(format!("releasing promotion lock also failed: {unlock}")))
        }
        (Ok(_), Err(error)) => Err(error.context("releasing promotion lock failed")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_fails_closed_without_signature_configuration() {
        let error =
            verify_publication(&PublishOptions::default(), &"a".repeat(64), &"b".repeat(64))
                .unwrap_err();
        assert!(error.to_string().contains("requires --signature"));
    }

    #[test]
    fn unsigned_development_policy_must_be_explicit() {
        let options = PublishOptions {
            allow_unsigned_development: true,
            ..Default::default()
        };
        assert!(
            verify_publication(&options, &"a".repeat(64), &"b".repeat(64))
                .unwrap()
                .is_none()
        );
    }
}
