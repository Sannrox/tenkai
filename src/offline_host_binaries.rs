//! Signed Tenkai host binaries inside `tenkai.offline-bundle.v1` (#640).
//!
//! Server, CLI, and executor hosts travel as v1 archive entries under
//! `hosts/<platform>/<name>`. A signed `hosts/manifest.json` and
//! `hosts/SHA256SUMS` name each file, digest, and release provenance. The
//! bundle signature authenticates them against trust roots received out of
//! band. A tampered file is refused before any destination write, and the
//! refusal names that file. Swapping a running host is #678.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{ErrorKind, Read as _, Write as _};
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::offline_bundle::{BundleEnvelope, VerifiedBundle};
use crate::release_signing::TrustRoots;

pub const HOST_MANIFEST_SCHEMA: &str = "tenkai.offline-host-binaries.v1";
pub const HOST_MANIFEST_PATH: &str = "hosts/manifest.json";
pub const HOST_MANIFEST_MEDIA: &str = "application/vnd.tenkai.offline-host-binaries.v1+json";
pub const HOST_SUMS_PATH: &str = "hosts/SHA256SUMS";
pub const HOST_SUMS_MEDIA: &str = "text/plain";
pub const HOST_BINARY_MEDIA: &str = "application/octet-stream";

const PLATFORMS: [&str; 2] = ["linux-x86_64", "darwin-aarch64"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostBinaryRole {
    Cli,
    Server,
    Executor,
}

impl HostBinaryRole {
    pub fn binary_name(self) -> &'static str {
        match self {
            Self::Cli => "tenkaictl",
            Self::Server => "tenkai-server",
            Self::Executor => "tenkai-executor-guard",
        }
    }

    pub fn all() -> [Self; 3] {
        [Self::Cli, Self::Server, Self::Executor]
    }
}

impl std::fmt::Display for HostBinaryRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Cli => "cli",
            Self::Server => "server",
            Self::Executor => "executor",
        })
    }
}

/// Release provenance recorded next to a host binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostBinaryProvenance {
    pub tag: String,
    pub git_sha: String,
    pub workflow: String,
}

/// One host binary listed in `hosts/manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostBinaryEntry {
    pub name: String,
    pub role: HostBinaryRole,
    pub platform: String,
    pub path: String,
    pub digest: String,
    pub size: u64,
    pub provenance: HostBinaryProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostBinaryManifest {
    pub schema: String,
    pub binaries: Vec<HostBinaryEntry>,
}

/// Bytes and provenance to insert for one host.
#[derive(Clone)]
pub struct HostBinaryInput {
    pub role: HostBinaryRole,
    pub platform: String,
    pub bytes: Vec<u8>,
    pub provenance: HostBinaryProvenance,
}

/// A host written to the install destination after verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledHostBinary {
    pub name: String,
    pub role: HostBinaryRole,
    pub platform: String,
    pub digest: String,
}

/// Detect the packaged platform for this process.
pub fn detect_platform() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok("linux-x86_64"),
        ("macos", "aarch64") => Ok("darwin-aarch64"),
        (os, arch) => bail!(
            "host platform {os}-{arch} is not a packaged Tenkai host; pass --platform linux-x86_64 or darwin-aarch64"
        ),
    }
}

/// Insert host binaries, their signed index, and SHA256SUMS into a bundle.
pub fn insert(
    payloads: &mut BTreeMap<String, (String, Vec<u8>)>,
    inputs: Vec<HostBinaryInput>,
) -> Result<()> {
    if inputs.is_empty() {
        bail!("offline host binary set must not be empty");
    }
    let mut binaries = Vec::new();
    let mut sums = BTreeMap::new();
    for input in inputs {
        let entry = describe(&input)?;
        if payloads.contains_key(&entry.path) {
            bail!("bundle already contains host binary {}", entry.path);
        }
        let asset = asset_name(&entry.name, &entry.platform);
        if sums.insert(asset, hex_digest(&input.bytes)).is_some() {
            bail!(
                "offline host binary set contains duplicate asset {}-{}",
                entry.name,
                entry.platform
            );
        }
        payloads.insert(entry.path.clone(), (HOST_BINARY_MEDIA.into(), input.bytes));
        binaries.push(entry);
    }
    binaries.sort_by(|left, right| left.path.cmp(&right.path));
    let manifest = HostBinaryManifest {
        schema: HOST_MANIFEST_SCHEMA.into(),
        binaries,
    };
    payloads.insert(
        HOST_MANIFEST_PATH.into(),
        (HOST_MANIFEST_MEDIA.into(), serde_json::to_vec(&manifest)?),
    );
    payloads.insert(
        HOST_SUMS_PATH.into(),
        (HOST_SUMS_MEDIA.into(), encode_sums(&sums)),
    );
    Ok(())
}

/// Parse the host index when present.
pub fn manifest(bundle: &VerifiedBundle) -> Result<Option<HostBinaryManifest>> {
    let Some(raw) = bundle.entry(HOST_MANIFEST_PATH) else {
        return Ok(None);
    };
    let parsed: HostBinaryManifest =
        serde_json::from_slice(raw).context("parsing offline host binary manifest")?;
    if parsed.schema != HOST_MANIFEST_SCHEMA {
        bail!("unsupported offline host binary schema {}", parsed.schema);
    }
    Ok(Some(parsed))
}

/// Verify host binaries when the bundle carries them.
///
/// Bundles without `hosts/manifest.json` are unchanged. A present index is
/// required to be complete and to match the signed bytes.
pub fn preflight(bundle: &VerifiedBundle) -> Result<()> {
    let Some(parsed) = manifest(bundle)? else {
        return Ok(());
    };
    verify_manifest(bundle, &parsed)?;
    Ok(())
}

/// Verify the bundle against trust roots and install one platform's hosts.
pub fn verify_and_install(
    envelope: &BundleEnvelope,
    roots: &TrustRoots,
    tenant_id: &str,
    environment_id: &str,
    now_unix_ms: i64,
    dest: &Path,
    platform: &str,
) -> Result<Vec<InstalledHostBinary>> {
    let verified = envelope.verify(roots, tenant_id, environment_id, now_unix_ms)?;
    install(&verified, dest, platform)
}

/// Write verified CLI, server, and executor hosts for `platform` into `dest`.
///
/// A destination that already holds the signed bytes is left in place so a
/// retry can finish. A different file, a symlink, or a non-file is refused
/// before any replacement. Publishing uses an exclusive link so a concurrent
/// installer cannot overwrite a name that appeared after preflight.
pub fn install(
    bundle: &VerifiedBundle,
    dest: &Path,
    platform: &str,
) -> Result<Vec<InstalledHostBinary>> {
    validate_platform(platform)?;
    let parsed = manifest(bundle)?.ok_or_else(|| {
        anyhow::anyhow!("offline bundle requires {HOST_MANIFEST_PATH} to install Tenkai hosts")
    })?;
    let entries = verify_manifest(bundle, &parsed)?;
    let selected: Vec<&HostBinaryEntry> = entries
        .iter()
        .filter(|entry| entry.platform == platform)
        .collect();
    if selected.is_empty() {
        bail!("offline bundle does not carry Tenkai hosts for platform {platform}");
    }
    require_roles(platform, &selected)?;
    std::fs::create_dir_all(dest)
        .with_context(|| format!("creating host install directory {}", dest.display()))?;
    let mut pending = Vec::new();
    for entry in selected {
        let dest_path = dest.join(&entry.name);
        match inspect_destination(&dest_path, &entry.digest, &entry.path)? {
            DestState::Matching => {}
            DestState::Missing => pending.push(entry),
        }
    }
    let mut installed = Vec::new();
    for entry in pending {
        let bytes = bundle
            .entry(&entry.path)
            .expect("preflight listed this host binary");
        publish_host(&dest.join(&entry.name), bytes, entry)?;
        installed.push(InstalledHostBinary {
            name: entry.name.clone(),
            role: entry.role,
            platform: entry.platform.clone(),
            digest: entry.digest.clone(),
        });
    }
    std::fs::File::open(dest)
        .with_context(|| format!("opening host install directory {}", dest.display()))?
        .sync_all()
        .with_context(|| format!("syncing host install directory {}", dest.display()))?;
    Ok(installed)
}

enum DestState {
    Matching,
    Missing,
}

fn inspect_destination(dest: &Path, digest: &str, label: &str) -> Result<DestState> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = match options.open(dest) {
        Ok(file) => file,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(DestState::Missing),
        #[cfg(unix)]
        Err(err) if err.raw_os_error() == Some(libc::ELOOP) => {
            bail!(
                "refusing to replace host binary {} ({}) because the destination is a symlink",
                dest.display(),
                label
            );
        }
        Err(err) => {
            return Err(err).with_context(|| {
                format!("inspecting host install destination {}", dest.display())
            });
        }
    };
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting host install destination {}", dest.display()))?;
    if !metadata.is_file() {
        bail!(
            "refusing to replace host binary {} ({}) because the destination is not a regular file",
            dest.display(),
            label
        );
    }
    let mut existing = Vec::new();
    file.read_to_end(&mut existing)
        .with_context(|| format!("reading existing host binary {}", dest.display()))?;
    if format!("sha256:{:x}", Sha256::digest(&existing)) == digest {
        ensure_executable(&file, dest)?;
        return Ok(DestState::Matching);
    }
    bail!(
        "refusing to replace existing host binary {} ({}); host upgrade is a separate operation",
        dest.display(),
        label
    );
}

fn exclusive_link(temporary: &Path, dest: &Path, entry: &HostBinaryEntry) -> Result<()> {
    match std::fs::hard_link(temporary, dest) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::AlreadyExists => {
            match inspect_destination(dest, &entry.digest, &entry.path)? {
                DestState::Matching => Ok(()),
                DestState::Missing => bail!(
                    "host binary {} vanished while creating {}",
                    entry.path,
                    dest.display()
                ),
            }
        }
        Err(err) => Err(err).with_context(|| {
            format!(
                "installing host binary {} as {}",
                entry.path,
                dest.display()
            )
        }),
    }
}

fn publish_host(dest: &Path, bytes: &[u8], entry: &HostBinaryEntry) -> Result<()> {
    match inspect_destination(dest, &entry.digest, &entry.path)? {
        DestState::Matching => return Ok(()),
        DestState::Missing => {}
    }
    let temporary = dest.with_file_name(format!(".{}.{}.tmp", entry.name, uuid::Uuid::new_v4()));
    let published = (|| {
        write_executable(&temporary, bytes)
            .with_context(|| format!("writing host binary {}", entry.path))?;
        exclusive_link(&temporary, dest, entry)
    })();
    let _ = std::fs::remove_file(&temporary);
    published
}

fn describe(input: &HostBinaryInput) -> Result<HostBinaryEntry> {
    validate_platform(&input.platform)?;
    validate_text("host binary tag", &input.provenance.tag, 64)?;
    validate_text("host binary git sha", &input.provenance.git_sha, 64)?;
    validate_text("host binary workflow", &input.provenance.workflow, 128)?;
    if input.bytes.is_empty() {
        bail!(
            "host binary {} for {} must not be empty",
            input.role.binary_name(),
            input.platform
        );
    }
    if input.bytes.len() as u64 > crate::offline_bundle::MAX_ENTRY_BYTES {
        bail!(
            "host binary {} for {} exceeds the archive entry byte limit",
            input.role.binary_name(),
            input.platform
        );
    }
    let name = input.role.binary_name().to_string();
    let path = format!("hosts/{}/{}", input.platform, name);
    Ok(HostBinaryEntry {
        name,
        role: input.role,
        platform: input.platform.clone(),
        path,
        digest: format!("sha256:{:x}", Sha256::digest(&input.bytes)),
        size: input.bytes.len() as u64,
        provenance: input.provenance.clone(),
    })
}

fn verify_manifest(
    bundle: &VerifiedBundle,
    parsed: &HostBinaryManifest,
) -> Result<Vec<HostBinaryEntry>> {
    if parsed.binaries.is_empty() {
        bail!("offline host binary manifest must list at least one binary");
    }
    let sums = parse_sums(
        bundle
            .entry(HOST_SUMS_PATH)
            .ok_or_else(|| anyhow::anyhow!("offline host binaries require {HOST_SUMS_PATH}"))?,
    )?;
    let mut seen_paths = BTreeSet::new();
    let mut seen_assets = BTreeSet::new();
    let mut by_platform: BTreeMap<String, Vec<&HostBinaryEntry>> = BTreeMap::new();
    for entry in &parsed.binaries {
        validate_platform(&entry.platform)?;
        if entry.name != entry.role.binary_name() {
            bail!(
                "host binary {} has role {} but name {}",
                entry.path,
                entry.role,
                entry.name
            );
        }
        let expected_path = format!("hosts/{}/{}", entry.platform, entry.name);
        if entry.path != expected_path {
            bail!(
                "host binary path {} does not match hosts/{}/{}",
                entry.path,
                entry.platform,
                entry.name
            );
        }
        crate::signature_verification::validate_prefixed_digest(
            "host binary digest",
            &entry.digest,
        )?;
        if !seen_paths.insert(entry.path.clone()) {
            bail!("offline host binary manifest lists {} twice", entry.path);
        }
        let asset = asset_name(&entry.name, &entry.platform);
        if !seen_assets.insert(asset.clone()) {
            bail!("offline host binary manifest lists asset {asset} twice");
        }
        let Some(bytes) = bundle.entry(&entry.path) else {
            bail!("bundle is missing host binary {}", entry.path);
        };
        if bytes.len() as u64 != entry.size
            || format!("sha256:{:x}", Sha256::digest(bytes)) != entry.digest
        {
            bail!(
                "tampered host binary {} does not match its signed digest and size",
                entry.path
            );
        }
        let Some(sum) = sums.get(&asset) else {
            bail!("hosts/SHA256SUMS does not list {asset}");
        };
        if *sum != hex_digest(bytes) {
            bail!(
                "tampered host binary {} does not match hosts/SHA256SUMS",
                entry.path
            );
        }
        validate_text("host binary tag", &entry.provenance.tag, 64)?;
        validate_text("host binary git sha", &entry.provenance.git_sha, 64)?;
        validate_text("host binary workflow", &entry.provenance.workflow, 128)?;
        by_platform
            .entry(entry.platform.clone())
            .or_default()
            .push(entry);
    }
    for path in bundle.paths() {
        if path.starts_with("hosts/")
            && path != HOST_MANIFEST_PATH
            && path != HOST_SUMS_PATH
            && !seen_paths.contains(path)
        {
            bail!("offline host binary manifest does not name {path}");
        }
    }
    for asset in sums.keys() {
        if !seen_assets.contains(asset) {
            bail!("hosts/SHA256SUMS lists unnamed host asset {asset}");
        }
    }
    for (platform, entries) in &by_platform {
        require_roles(platform, entries)?;
    }
    Ok(parsed.binaries.clone())
}

fn require_roles(platform: &str, entries: &[&HostBinaryEntry]) -> Result<()> {
    for role in HostBinaryRole::all() {
        if !entries.iter().any(|entry| entry.role == role) {
            bail!(
                "offline host binaries for {platform} are missing the {} host ({})",
                role,
                role.binary_name()
            );
        }
    }
    Ok(())
}

fn validate_platform(platform: &str) -> Result<()> {
    if !PLATFORMS.contains(&platform) {
        bail!(
            "host platform {platform} is not a packaged Tenkai host (linux-x86_64 or darwin-aarch64)"
        );
    }
    Ok(())
}

fn asset_name(name: &str, platform: &str) -> String {
    format!("{name}-{platform}")
}

fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn encode_sums(sums: &BTreeMap<String, String>) -> Vec<u8> {
    let mut out = String::new();
    for (asset, digest) in sums {
        out.push_str(digest);
        out.push_str("  ");
        out.push_str(asset);
        out.push('\n');
    }
    out.into_bytes()
}

fn parse_sums(raw: &[u8]) -> Result<BTreeMap<String, String>> {
    let text = std::str::from_utf8(raw).context("parsing hosts/SHA256SUMS")?;
    let mut sums = BTreeMap::new();
    for line in text.lines() {
        let Some((digest, asset)) = line.split_once("  ") else {
            bail!("hosts/SHA256SUMS is not in the GitHub Release checksum format");
        };
        crate::signature_verification::validate_hex_digest("host checksum", digest)?;
        validate_text("host checksum asset", asset, 128)?;
        if asset.contains('/') || asset.contains('\\') {
            bail!("hosts/SHA256SUMS asset {asset} is not a release asset name");
        }
        if sums.insert(asset.to_string(), digest.to_string()).is_some() {
            bail!("hosts/SHA256SUMS lists {asset} twice");
        }
    }
    if sums.is_empty() {
        bail!("hosts/SHA256SUMS lists no host binaries");
    }
    Ok(sums)
}

fn ensure_executable(file: &std::fs::File, path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = file
            .metadata()
            .with_context(|| format!("reading mode of {}", path.display()))?
            .permissions();
        if permissions.mode() & 0o777 != 0o755 {
            permissions.set_mode(0o755);
            file.set_permissions(permissions)
                .with_context(|| format!("restoring executable mode on {}", path.display()))?;
            file.sync_all()
                .with_context(|| format!("syncing {} after mode restore", path.display()))?;
        }
    }
    Ok(())
}

fn write_executable(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o755);
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("setting executable mode on {}", path.display()))?;
    }
    file.sync_all()
        .with_context(|| format!("syncing {}", path.display()))?;
    Ok(())
}

fn validate_text(name: &str, value: &str, max: usize) -> Result<()> {
    if value.is_empty()
        || value != value.trim()
        || value.len() > max
        || value.contains('\0')
        || value.chars().any(char::is_control)
    {
        bail!("{name} is empty, non-canonical, contains control characters, or is too long");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::SigningKey;

    use crate::offline_bundle::{BundleEnvelope, BundleStatement};
    use crate::release_signing::{TrustRoots, TrustedSigner};

    fn digest(value: &[u8]) -> String {
        format!("sha256:{:x}", Sha256::digest(value))
    }

    fn roots(key: &SigningKey) -> TrustRoots {
        TrustRoots {
            version: 1,
            signers: vec![TrustedSigner {
                key_id: crate::signature_verification::key_id(&key.verifying_key().to_bytes()),
                identity: "exporter".into(),
                public_key: STANDARD.encode(key.verifying_key().to_bytes()),
                not_before: None,
                not_after: None,
            }],
        }
    }

    fn provenance() -> HostBinaryProvenance {
        HostBinaryProvenance {
            tag: "v0.5.0".into(),
            git_sha: "0123456789abcdef0123456789abcdef01234567".into(),
            workflow: "release-binaries.yml".into(),
        }
    }

    fn host(role: HostBinaryRole, platform: &str, bytes: &[u8]) -> HostBinaryInput {
        HostBinaryInput {
            role,
            platform: platform.into(),
            bytes: bytes.to_vec(),
            provenance: provenance(),
        }
    }

    type BundlePayloads = BTreeMap<String, (String, Vec<u8>)>;

    fn payloads_with_plan() -> (BundlePayloads, Vec<u8>, Vec<u8>) {
        let mut payloads = BTreeMap::new();
        let approval = br#"{"approval":"plan-1"}"#.to_vec();
        payloads.insert(
            "approvals/plan-1.json".into(),
            ("application/json".into(), approval.clone()),
        );
        let plan = br#"{"plan":"plan-1"}"#.to_vec();
        payloads.insert(
            "plans/plan-1.json".into(),
            ("application/json".into(), plan.clone()),
        );
        payloads.insert(
            "releases/app@1.0.0/payload.bin".into(),
            (
                "application/octet-stream".into(),
                b"immutable payload".to_vec(),
            ),
        );
        (payloads, plan, approval)
    }

    fn envelope_from(
        key: &SigningKey,
        payloads: BundlePayloads,
        plan: &[u8],
        approval: &[u8],
    ) -> BundleEnvelope {
        BundleEnvelope::create(
            BundleStatement {
                tenant_id: "tenkai".into(),
                environment_id: "airgap-1".into(),
                plan_id: "plan-1".into(),
                plan_digest: digest(plan),
                approval_digest: digest(approval),
                release_ids: vec!["app@1.0.0".into()],
                exporter_identity: "exporter".into(),
                issued_at_unix_ms: 1_000,
                expires_at_unix_ms: 10_000,
                entries: Vec::new(),
            },
            payloads,
            key,
        )
        .unwrap()
    }

    fn host_bundle(key: &SigningKey) -> BundleEnvelope {
        let (mut payloads, plan, approval) = payloads_with_plan();
        insert(
            &mut payloads,
            vec![
                host(HostBinaryRole::Cli, "linux-x86_64", b"cli-linux"),
                host(HostBinaryRole::Server, "linux-x86_64", b"server-linux"),
                host(HostBinaryRole::Executor, "linux-x86_64", b"executor-linux"),
                host(HostBinaryRole::Cli, "darwin-aarch64", b"cli-darwin"),
                host(HostBinaryRole::Server, "darwin-aarch64", b"server-darwin"),
                host(
                    HostBinaryRole::Executor,
                    "darwin-aarch64",
                    b"executor-darwin",
                ),
            ],
        )
        .unwrap();
        envelope_from(key, payloads, &plan, &approval)
    }

    fn temp_dest() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "tenkai-hosts-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn offline_install_of_tenkai_hosts_from_signed_bundle() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let dest = temp_dest();
        let installed = verify_and_install(
            &host_bundle(&key),
            &roots(&key),
            "tenkai",
            "airgap-1",
            2_000,
            &dest,
            "linux-x86_64",
        )
        .unwrap();
        assert_eq!(installed.len(), 3);
        assert_eq!(std::fs::read(dest.join("tenkaictl")).unwrap(), b"cli-linux");
        assert_eq!(
            std::fs::read(dest.join("tenkai-server")).unwrap(),
            b"server-linux"
        );
        assert_eq!(
            std::fs::read(dest.join("tenkai-executor-guard")).unwrap(),
            b"executor-linux"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dest.join("tenkaictl"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o755);
        }
        std::fs::remove_dir_all(dest).unwrap();
    }

    #[test]
    fn tampered_host_binary_is_refused_before_install_and_names_the_file() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut envelope = host_bundle(&key);
        let index = envelope
            .entries
            .iter()
            .position(|entry| entry.path == "hosts/linux-x86_64/tenkaictl")
            .unwrap();
        envelope.entries[index].content_base64 = STANDARD.encode(b"tampered-cli");
        let dest = temp_dest();
        let err = verify_and_install(
            &envelope,
            &roots(&key),
            "tenkai",
            "airgap-1",
            2_000,
            &dest,
            "linux-x86_64",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("hosts/linux-x86_64/tenkaictl"), "{err}");
        assert!(!dest.join("tenkaictl").exists());
        assert!(!dest.join("tenkai-server").exists());
        assert!(!dest.join("tenkai-executor-guard").exists());
        std::fs::remove_dir_all(dest).unwrap();
    }

    #[test]
    fn mismatched_host_manifest_digest_is_refused_before_install() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let (mut payloads, plan, approval) = payloads_with_plan();
        insert(
            &mut payloads,
            vec![
                host(HostBinaryRole::Cli, "linux-x86_64", b"cli-linux"),
                host(HostBinaryRole::Server, "linux-x86_64", b"server-linux"),
                host(HostBinaryRole::Executor, "linux-x86_64", b"executor-linux"),
            ],
        )
        .unwrap();
        let mut parsed: HostBinaryManifest =
            serde_json::from_slice(&payloads[HOST_MANIFEST_PATH].1).unwrap();
        let cli = parsed
            .binaries
            .iter_mut()
            .find(|entry| entry.name == "tenkaictl")
            .unwrap();
        cli.digest = digest(b"other-cli");
        payloads.get_mut(HOST_MANIFEST_PATH).unwrap().1 = serde_json::to_vec(&parsed).unwrap();
        let envelope = envelope_from(&key, payloads, &plan, &approval);
        let dest = temp_dest();
        let err = verify_and_install(
            &envelope,
            &roots(&key),
            "tenkai",
            "airgap-1",
            2_000,
            &dest,
            "linux-x86_64",
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("tampered host binary hosts/linux-x86_64/tenkaictl"),
            "{err}"
        );
        assert!(!dest.join("tenkaictl").exists());
        std::fs::remove_dir_all(dest).unwrap();
    }

    #[test]
    fn missing_executor_host_is_refused() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let (mut payloads, plan, approval) = payloads_with_plan();
        insert(
            &mut payloads,
            vec![
                host(HostBinaryRole::Cli, "linux-x86_64", b"cli-linux"),
                host(HostBinaryRole::Server, "linux-x86_64", b"server-linux"),
            ],
        )
        .unwrap();
        let envelope = envelope_from(&key, payloads, &plan, &approval);
        let verified = envelope
            .verify(&roots(&key), "tenkai", "airgap-1", 2_000)
            .unwrap();
        let err = preflight(&verified).unwrap_err().to_string();
        assert!(err.contains("tenkai-executor-guard"), "{err}");
    }

    #[test]
    fn bundles_without_hosts_skip_preflight() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let (payloads, plan, approval) = payloads_with_plan();
        let verified = envelope_from(&key, payloads, &plan, &approval)
            .verify(&roots(&key), "tenkai", "airgap-1", 2_000)
            .unwrap();
        preflight(&verified).unwrap();
    }

    #[test]
    fn existing_destination_host_is_refused_before_replace() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let dest = temp_dest();
        std::fs::write(dest.join("tenkaictl"), b"already-installed").unwrap();
        let err = verify_and_install(
            &host_bundle(&key),
            &roots(&key),
            "tenkai",
            "airgap-1",
            2_000,
            &dest,
            "linux-x86_64",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("tenkaictl"), "{err}");
        assert_eq!(
            std::fs::read(dest.join("tenkaictl")).unwrap(),
            b"already-installed"
        );
        assert!(!dest.join("tenkai-server").exists());
        std::fs::remove_dir_all(dest).unwrap();
    }

    #[test]
    fn matching_partial_install_resumes_remaining_hosts() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let dest = temp_dest();
        std::fs::write(dest.join("tenkaictl"), b"cli-linux").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                dest.join("tenkaictl"),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap();
        }
        verify_and_install(
            &host_bundle(&key),
            &roots(&key),
            "tenkai",
            "airgap-1",
            2_000,
            &dest,
            "linux-x86_64",
        )
        .unwrap();
        assert_eq!(std::fs::read(dest.join("tenkaictl")).unwrap(), b"cli-linux");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dest.join("tenkaictl"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o755);
        }
        assert_eq!(
            std::fs::read(dest.join("tenkai-server")).unwrap(),
            b"server-linux"
        );
        assert_eq!(
            std::fs::read(dest.join("tenkai-executor-guard")).unwrap(),
            b"executor-linux"
        );
        std::fs::remove_dir_all(dest).unwrap();
    }

    #[test]
    fn destination_symlink_is_refused_before_replace() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let dest = temp_dest();
        std::os::unix::fs::symlink("missing-cli", dest.join("tenkaictl")).unwrap();
        let err = verify_and_install(
            &host_bundle(&key),
            &roots(&key),
            "tenkai",
            "airgap-1",
            2_000,
            &dest,
            "linux-x86_64",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("symlink"), "{err}");
        assert!(err.contains("tenkaictl"), "{err}");
        assert!(!dest.join("tenkai-server").exists());
        std::fs::remove_dir_all(dest).unwrap();
    }

    #[test]
    fn destination_symlink_does_not_chmod_its_target() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let dest = temp_dest();
        let victim = dest.join("victim");
        std::fs::write(&victim, b"cli-linux").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
            std::os::unix::fs::symlink(&victim, dest.join("tenkaictl")).unwrap();
        }
        let err = verify_and_install(
            &host_bundle(&key),
            &roots(&key),
            "tenkai",
            "airgap-1",
            2_000,
            &dest,
            "linux-x86_64",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("symlink"), "{err}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644);
        }
        assert!(!dest.join("tenkai-server").exists());
        std::fs::remove_dir_all(dest).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn destination_fifo_is_refused_without_blocking() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let dest = temp_dest();
        let fifo = dest.join("tenkaictl");
        let c_path = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: `c_path` is a valid C string; mkfifo only reads it.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) }, 0);
        let err = verify_and_install(
            &host_bundle(&key),
            &roots(&key),
            "tenkai",
            "airgap-1",
            2_000,
            &dest,
            "linux-x86_64",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not a regular file"), "{err}");
        assert!(err.contains("tenkaictl"), "{err}");
        assert!(!dest.join("tenkai-server").exists());
        std::fs::remove_dir_all(dest).unwrap();
    }
}
