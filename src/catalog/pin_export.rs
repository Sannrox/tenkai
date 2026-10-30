//! Authorized tenant export of Catalog release pins as a digest-pinned bundle
//! section.
//!
//! A pin is identity, channel, and content digest. Callers who cannot take a
//! pin see it named as withheld rather than dropped. The section carries no
//! keys, tokens, or provider secrets. Import restores matching channel heads
//! on another catalog or lists every pin that could not transfer.

use std::collections::HashMap;

use anyhow::{Result, bail};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{list_channels, pin_isolated_channel, release_list_entry};
use crate::auth_context::{AuthenticatedRequestContext, DeliveryCapability};
use crate::client::Ctx;
use crate::ontology::{KIND_RELEASE, release_id};

/// Portable schema for an authorized release-pin bundle section.
pub const PIN_BUNDLE_SCHEMA: &str = "tenkai.release-pin-bundle.v1";

const WITHHELD_UNAUTHORIZED: &str = "unauthorized";
const TRANSFER_MISSING_RELEASE: &str = "release not published";
const TRANSFER_DIGEST_MISMATCH: &str = "content digest mismatch";
const TRANSFER_PIN_REFUSED: &str = "channel pin refused";

/// One authorized release pin: identity, channel, and content digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReleasePin {
    pub release_id: String,
    pub product: String,
    pub version: String,
    pub channel: String,
    pub content_digest: String,
}

/// A pin present in the catalog that this caller is not authorized to take.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WithheldReleasePin {
    pub release_id: String,
    pub product: String,
    pub version: String,
    pub channel: String,
    pub reason: String,
}

/// Digest-pinned bundle section of a tenant's authorized release pins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReleasePinBundleSection {
    pub schema: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub tenant_id: Option<String>,
    pub pins: Vec<ReleasePin>,
    pub withheld: Vec<WithheldReleasePin>,
    pub digest: String,
}

/// A pin the importer was authorized to take that the destination could not
/// accept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PinTransferFailure {
    pub release_id: String,
    pub product: String,
    pub version: String,
    pub channel: String,
    pub reason: String,
}

/// Result of importing a release-pin bundle section into a destination catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PinImportReport {
    pub imported: Vec<ReleasePin>,
    pub withheld: Vec<WithheldReleasePin>,
    pub failed: Vec<PinTransferFailure>,
}

/// Export this caller's authorized catalog release pins as a digest-pinned
/// section. Unauthorized pins are named in `withheld`.
pub async fn export_release_pins(
    ctx: &mut Ctx,
    actor: &AuthenticatedRequestContext,
) -> Result<ReleasePinBundleSection> {
    actor
        .require_delivery_capability(DeliveryCapability::Read)
        .map_err(|error| anyhow::anyhow!("{error}"))?;

    let releases = ctx.list_kind(KIND_RELEASE).await?;
    let mut by_id = HashMap::with_capacity(releases.len());
    for object in releases {
        let entry = release_list_entry(object);
        by_id.insert(entry.id.clone(), entry);
    }

    let mut pins = Vec::new();
    let mut withheld = Vec::new();
    for channel in list_channels(ctx).await? {
        if channel.head.trim().is_empty() {
            continue;
        }
        let Some(release) = by_id.get(&channel.head) else {
            bail!(
                "channel {}/{} head {} is not a published release",
                channel.product,
                channel.name,
                channel.head
            );
        };
        if !pin_authorized(actor, &channel.product, &channel.name) {
            withheld.push(WithheldReleasePin {
                release_id: release.id.clone(),
                product: release.product.clone(),
                version: release.version.clone(),
                channel: channel.name,
                reason: WITHHELD_UNAUTHORIZED.into(),
            });
            continue;
        }
        pins.push(ReleasePin {
            release_id: release.id.clone(),
            product: release.product.clone(),
            version: release.version.clone(),
            channel: channel.name,
            content_digest: release.digest.clone(),
        });
    }

    pins.sort_by(|left, right| pin_order(left).cmp(&pin_order(right)));
    withheld.sort_by(|left, right| withheld_order(left).cmp(&withheld_order(right)));

    let tenant_id = actor
        .tenant()
        .map(|tenant| tenant.tenant_id().to_string())
        .filter(|value| !value.is_empty());
    let digest = pin_section_digest(tenant_id.as_deref(), &pins, &withheld)?;
    Ok(ReleasePinBundleSection {
        schema: PIN_BUNDLE_SCHEMA.into(),
        tenant_id,
        pins,
        withheld,
        digest,
    })
}

/// Import authorized pins from `section` into `ctx`. Each accepted pin's
/// content digest must match the destination release; unauthorized pins are
/// withheld and pins the destination cannot accept are listed as failed.
pub async fn import_release_pins(
    ctx: &mut Ctx,
    actor: &AuthenticatedRequestContext,
    section: &ReleasePinBundleSection,
) -> Result<PinImportReport> {
    actor
        .require_delivery_capability(DeliveryCapability::Publish)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    if section.schema != PIN_BUNDLE_SCHEMA {
        bail!(
            "release-pin bundle schema {} is not {PIN_BUNDLE_SCHEMA}",
            section.schema
        );
    }
    let expected = pin_section_digest(
        section.tenant_id.as_deref(),
        &section.pins,
        &section.withheld,
    )?;
    if expected != section.digest {
        bail!("release-pin bundle digest does not match pin content");
    }

    let mut imported = Vec::new();
    let mut withheld = section.withheld.clone();
    let mut failed = Vec::new();
    for pin in &section.pins {
        if !pin_authorized(actor, &pin.product, &pin.channel) {
            withheld.push(WithheldReleasePin {
                release_id: pin.release_id.clone(),
                product: pin.product.clone(),
                version: pin.version.clone(),
                channel: pin.channel.clone(),
                reason: WITHHELD_UNAUTHORIZED.into(),
            });
            continue;
        }
        match transfer_pin(ctx, pin).await {
            Ok(()) => imported.push(pin.clone()),
            Err(reason) => failed.push(PinTransferFailure {
                release_id: pin.release_id.clone(),
                product: pin.product.clone(),
                version: pin.version.clone(),
                channel: pin.channel.clone(),
                reason,
            }),
        }
    }

    imported.sort_by(|left, right| pin_order(left).cmp(&pin_order(right)));
    withheld.sort_by(|left, right| withheld_order(left).cmp(&withheld_order(right)));
    failed.sort_by(|left, right| {
        (
            left.product.as_str(),
            left.channel.as_str(),
            left.release_id.as_str(),
        )
            .cmp(&(
                right.product.as_str(),
                right.channel.as_str(),
                right.release_id.as_str(),
            ))
    });
    Ok(PinImportReport {
        imported,
        withheld,
        failed,
    })
}

/// Empty product or channel bindings mean no confinement, matching
/// `list_releases` / `list_channels`.
fn pin_authorized(actor: &AuthenticatedRequestContext, product: &str, channel: &str) -> bool {
    let products = actor.product_bindings();
    let channels = actor.channel_bindings();
    (products.is_empty() || products.contains(product))
        && (channels.is_empty() || channels.contains(channel))
}

fn pin_order(pin: &ReleasePin) -> (&str, &str, &str) {
    (
        pin.product.as_str(),
        pin.channel.as_str(),
        pin.release_id.as_str(),
    )
}

fn withheld_order(pin: &WithheldReleasePin) -> (&str, &str, &str) {
    (
        pin.product.as_str(),
        pin.channel.as_str(),
        pin.release_id.as_str(),
    )
}

fn pin_section_digest(
    tenant_id: Option<&str>,
    pins: &[ReleasePin],
    withheld: &[WithheldReleasePin],
) -> Result<String> {
    let body = serde_json::json!({
        "schema": PIN_BUNDLE_SCHEMA,
        "tenant_id": tenant_id,
        "pins": pins,
        "withheld": withheld,
    });
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&body)?)
    ))
}

async fn transfer_pin(ctx: &mut Ctx, pin: &ReleasePin) -> Result<(), String> {
    let expected_id = release_id(&pin.product, &pin.version);
    if expected_id != pin.release_id {
        return Err(TRANSFER_PIN_REFUSED.into());
    }
    let Some(object) = ctx
        .get(&pin.release_id)
        .await
        .map_err(|error| error.to_string())?
    else {
        return Err(TRANSFER_MISSING_RELEASE.into());
    };
    let stored = release_list_entry(object);
    if stored.digest != pin.content_digest {
        return Err(TRANSFER_DIGEST_MISMATCH.into());
    }
    pin_isolated_channel(ctx, &pin.product, &pin.version, &pin.channel)
        .await
        .map_err(|error| {
            let message = error.to_string();
            if message.contains("no longer points") {
                TRANSFER_PIN_REFUSED.into()
            } else {
                message
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_context::{
        AuthenticatedRequestContext, AuthenticatedRequestContextBuilder, DeliveryCapability,
        PrincipalIdentity, PrincipalKind, TenantDerivationAuthority,
    };
    use crate::catalog::{PublishOptions, promote, publish};
    use crate::ontology::{KIND_CHANNEL, NS, channel_id, register};
    use crate::pb::sekai::Object;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static FIXTURE: AtomicU64 = AtomicU64::new(0);

    fn fixture_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "tenkai-pin-export-{}-{}-{label}",
            std::process::id(),
            FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn write_manifest(dir: &Path, product: &str, version: &str, install: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join("tenkai.toml"),
            format!(
                "[product]\nname = \"{product}\"\nversion = \"{version}\"\n\n[deploy]\ninstall = \"{install}\"\n"
            ),
        )
        .unwrap();
    }

    fn management_actor(
        request_id: &str,
        products: &[&str],
        channels: &[&str],
        tenant: Option<&str>,
    ) -> AuthenticatedRequestContext {
        let mut builder = AuthenticatedRequestContextBuilder::new(
            request_id,
            PrincipalIdentity {
                id: "tenant-export".into(),
                kind: PrincipalKind::Management,
            },
            "test-auth",
        )
        .with_product_bindings(products.iter().map(|product| (*product).to_string()));
        if !channels.is_empty() {
            builder = builder.with_channel_bindings(channels.iter().copied());
        }
        if let Some(tenant_id) = tenant {
            let authority = TenantDerivationAuthority::new("test-extension");
            builder = builder.with_tenant(tenant_id, &authority).unwrap();
        }
        builder.build().expect("test actor")
    }

    async fn catalog_with(root: &Path, products: &[(&str, &str, &str)]) -> Ctx {
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        register(&mut ctx).await.unwrap();
        let options = PublishOptions {
            allow_unsigned_development: true,
            state_dir: Some(root.join("state")),
            ..Default::default()
        };
        for (product, version, install) in products {
            let dir = root.join(format!("{product}-{version}"));
            write_manifest(&dir, product, version, install);
            publish(&mut ctx, &dir.join("tenkai.toml"), &options)
                .await
                .unwrap();
        }
        ctx
    }

    fn assert_secret_free(section: &ReleasePinBundleSection) {
        let json = serde_json::to_string(section).unwrap();
        for needle in [
            "bearer",
            "token",
            "password",
            "private_key",
            "signing_key",
            "credential",
            "api_key",
            "secret",
        ] {
            assert!(
                !json.to_ascii_lowercase().contains(needle),
                "bundle leaked {needle}: {json}"
            );
        }
        let value = serde_json::to_value(section).unwrap();
        let object = value.as_object().expect("section object");
        for key in object.keys() {
            assert!(
                matches!(
                    key.as_str(),
                    "schema" | "tenant_id" | "pins" | "withheld" | "digest"
                ),
                "unexpected section field {key}"
            );
        }
        for pin in object["pins"].as_array().unwrap() {
            let keys: std::collections::BTreeSet<&str> = pin
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(
                keys,
                std::collections::BTreeSet::from([
                    "release_id",
                    "product",
                    "version",
                    "channel",
                    "content_digest",
                ])
            );
        }
    }

    #[tokio::test]
    async fn fixture_tenant_export_import_reproduces_authorized_pin_digests() {
        let source_root = fixture_root("source");
        let dest_root = fixture_root("dest");
        let mut source = catalog_with(
            &source_root,
            &[("api", "1.0.0", "true"), ("billing", "2.0.0", "true")],
        )
        .await;
        let actor = crate::auth_context::test_management_context("pin-export-full");
        promote(&mut source, &actor, "api@1.0.0", "stable")
            .await
            .unwrap();
        promote(&mut source, &actor, "billing@2.0.0", "stable")
            .await
            .unwrap();

        let tenant = management_actor("pin-export-tenant", &[], &[], Some("tenant-a"));
        let section = export_release_pins(&mut source, &tenant).await.unwrap();
        assert_eq!(section.schema, PIN_BUNDLE_SCHEMA);
        assert_eq!(section.tenant_id.as_deref(), Some("tenant-a"));
        assert!(section.withheld.is_empty(), "{:?}", section.withheld);
        assert_eq!(section.pins.len(), 2, "{:?}", section.pins);
        assert_secret_free(&section);

        let mut dest = catalog_with(
            &dest_root,
            &[("api", "1.0.0", "true"), ("billing", "2.0.0", "true")],
        )
        .await;
        let report = import_release_pins(&mut dest, &tenant, &section)
            .await
            .unwrap();
        assert!(report.failed.is_empty(), "{:?}", report.failed);
        assert!(report.withheld.is_empty(), "{:?}", report.withheld);
        assert_eq!(report.imported.len(), 2);
        for pin in &section.pins {
            let imported = report
                .imported
                .iter()
                .find(|item| item.release_id == pin.release_id && item.channel == pin.channel)
                .expect("imported pin");
            assert_eq!(imported.content_digest, pin.content_digest);
        }

        let replay = export_release_pins(&mut dest, &tenant).await.unwrap();
        assert_eq!(replay.digest, section.digest);
        assert_eq!(replay.pins, section.pins);
        let _ = std::fs::remove_dir_all(source_root);
        let _ = std::fs::remove_dir_all(dest_root);
    }

    #[tokio::test]
    async fn unauthorized_pin_is_withheld_not_omitted() {
        let source_root = fixture_root("withheld-source");
        let dest_root = fixture_root("withheld-dest");
        let mut source = catalog_with(
            &source_root,
            &[("api", "1.0.0", "true"), ("billing", "2.0.0", "true")],
        )
        .await;
        let owner = crate::auth_context::test_management_context("pin-export-owner");
        promote(&mut source, &owner, "api@1.0.0", "stable")
            .await
            .unwrap();
        promote(&mut source, &owner, "billing@2.0.0", "stable")
            .await
            .unwrap();

        let confined = management_actor(
            "pin-export-confined",
            &["api"],
            &["stable"],
            Some("tenant-a"),
        );
        let section = export_release_pins(&mut source, &confined).await.unwrap();
        assert_eq!(section.pins.len(), 1, "{:?}", section.pins);
        assert_eq!(section.pins[0].product, "api");
        assert_eq!(section.pins[0].channel, "stable");
        assert!(!section.pins[0].content_digest.is_empty());
        assert_eq!(section.withheld.len(), 1, "{:?}", section.withheld);
        assert_eq!(section.withheld[0].product, "billing");
        assert_eq!(section.withheld[0].channel, "stable");
        assert_eq!(section.withheld[0].reason, WITHHELD_UNAUTHORIZED);
        assert_secret_free(&section);
        let mut stripped = section.clone();
        stripped.withheld.clear();
        let stripped_err = import_release_pins(&mut source, &confined, &stripped)
            .await
            .unwrap_err()
            .to_string();
        assert!(stripped_err.contains("digest"), "{stripped_err}");

        let mut dest = catalog_with(
            &dest_root,
            &[("api", "1.0.0", "true"), ("billing", "2.0.0", "true")],
        )
        .await;
        let report = import_release_pins(&mut dest, &confined, &section)
            .await
            .unwrap();
        assert_eq!(report.imported.len(), 1);
        assert_eq!(
            report.imported[0].content_digest,
            section.pins[0].content_digest
        );
        assert_eq!(report.withheld.len(), 1);
        assert_eq!(report.withheld[0].product, "billing");
        assert!(report.failed.is_empty(), "{:?}", report.failed);

        let dest_section = export_release_pins(&mut dest, &confined).await.unwrap();
        assert_eq!(dest_section.pins.len(), 1);
        assert_eq!(
            dest_section.pins[0].content_digest,
            section.pins[0].content_digest
        );
        assert!(
            dest_section.withheld.is_empty(),
            "{:?}",
            dest_section.withheld
        );
        let _ = std::fs::remove_dir_all(source_root);
        let _ = std::fs::remove_dir_all(dest_root);
    }

    #[tokio::test]
    async fn import_lists_pins_that_could_not_transfer() {
        let source_root = fixture_root("fail-source");
        let missing_root = fixture_root("fail-missing");
        let mismatch_root = fixture_root("fail-mismatch");
        let mut source = catalog_with(&source_root, &[("api", "1.0.0", "true")]).await;
        let actor = crate::auth_context::test_management_context("pin-export-fail");
        promote(&mut source, &actor, "api@1.0.0", "stable")
            .await
            .unwrap();
        let section = export_release_pins(&mut source, &actor).await.unwrap();
        assert_eq!(section.pins.len(), 1);

        let mut missing = catalog_with(&missing_root, &[("billing", "2.0.0", "true")]).await;
        let missing_report = import_release_pins(&mut missing, &actor, &section)
            .await
            .unwrap();
        assert!(missing_report.imported.is_empty());
        assert_eq!(missing_report.failed.len(), 1);
        assert_eq!(missing_report.failed[0].product, "api");
        assert_eq!(missing_report.failed[0].reason, TRANSFER_MISSING_RELEASE);

        let mut mismatch = catalog_with(&mismatch_root, &[("api", "1.0.0", "false")]).await;
        let mismatch_report = import_release_pins(&mut mismatch, &actor, &section)
            .await
            .unwrap();
        assert!(mismatch_report.imported.is_empty());
        assert_eq!(mismatch_report.failed.len(), 1);
        assert_eq!(mismatch_report.failed[0].reason, TRANSFER_DIGEST_MISMATCH);

        let mut tampered = section.clone();
        tampered.pins[0].content_digest = "sha256:deadbeef".into();
        let digest_err = import_release_pins(&mut missing, &actor, &tampered)
            .await
            .unwrap_err()
            .to_string();
        assert!(digest_err.contains("digest"), "{digest_err}");
        let _ = std::fs::remove_dir_all(source_root);
        let _ = std::fs::remove_dir_all(missing_root);
        let _ = std::fs::remove_dir_all(mismatch_root);
    }

    #[tokio::test]
    async fn export_and_import_fail_closed_without_capability() {
        let root = fixture_root("capability");
        let mut ctx = catalog_with(&root, &[("api", "1.0.0", "true")]).await;
        let owner = crate::auth_context::test_management_context("pin-export-cap");
        promote(&mut ctx, &owner, "api@1.0.0", "stable")
            .await
            .unwrap();
        let human = crate::auth_context::test_human_context("pin-export-human");
        let export_err = export_release_pins(&mut ctx, &human)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            export_err.contains("insufficient delivery capability"),
            "{export_err}"
        );

        let reader = AuthenticatedRequestContextBuilder::new(
            "pin-export-reader",
            PrincipalIdentity {
                id: "reader".into(),
                kind: PrincipalKind::Human,
            },
            "test-auth",
        )
        .with_delivery_capabilities([DeliveryCapability::Read])
        .build()
        .unwrap();
        let section = export_release_pins(&mut ctx, &reader).await.unwrap();
        let import_err = import_release_pins(&mut ctx, &reader, &section)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            import_err.contains("insufficient delivery capability"),
            "{import_err}"
        );

        let now = crate::now_millis();
        ctx.put(Object {
            id: channel_id("api", "ghost"),
            kind: KIND_CHANNEL.into(),
            name: "api/ghost".into(),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("product".into(), "api".into()),
                ("channel".into(), "ghost".into()),
                (
                    "current_release".into(),
                    "tenkai:release:missing@9.9.9".into(),
                ),
            ]),
            created: now,
            updated: now,
        })
        .await
        .unwrap();
        let dangling = export_release_pins(&mut ctx, &owner)
            .await
            .unwrap_err()
            .to_string();
        assert!(dangling.contains("not a published release"), "{dangling}");
        let _ = std::fs::remove_dir_all(root);
    }
}
