//! On-site key-provider deploy profile and lab ceremony.
//!
//! A deploy profile names the customer key provider ([ADR 0113] in sekai-chisei).
//! Production profiles refuse file, memory, and software providers. The software
//! provider exists for labs and CI: `tenkaictl keys ceremony` creates a root key
//! reference that never leaves the provider directory, mints per-tenant data-key
//! ids, and writes signed evidence of those ids and the custodians. PKCS#11, KMIP,
//! and cloud KMS adapters are follow-up slices.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const PROFILE_VERSION: u32 = 1;
pub const CEREMONY_SCHEMA: &str = "tenkai.key-ceremony.v1";
const SIGNING_DOMAIN: &[u8] = b"TENKAI-KEY-CEREMONY-V1\0";
const ROOT_KEK: &str = "root.kek";
const ROOT_ID: &str = "root.id";
const TENANT_DEK_WRAP: &str = "dek.wrap";
const TENANT_ID: &str = "id";

/// Who this profile is for. Production refuses lab-only providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileClass {
    Lab,
    Production,
}

/// Key-provider kinds named in a deploy profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyProviderKind {
    Software,
    File,
    Memory,
    Pkcs11,
    Kmip,
    CloudKms,
}

impl KeyProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Software => "software",
            Self::File => "file",
            Self::Memory => "memory",
            Self::Pkcs11 => "pkcs11",
            Self::Kmip => "kmip",
            Self::CloudKms => "cloud_kms",
        }
    }

    pub fn is_lab_only(self) -> bool {
        matches!(self, Self::Software | Self::File | Self::Memory)
    }
}

impl std::fmt::Display for KeyProviderKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyProviderSection {
    pub kind: KeyProviderKind,
}

/// Version 1 deploy profile. Production plus a lab-only provider fails closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployProfile {
    pub version: u32,
    pub class: ProfileClass,
    pub key_provider: KeyProviderSection,
}

impl DeployProfile {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading deploy profile {}", path.display()))?;
        let profile: Self = toml::from_str(&raw)
            .with_context(|| format!("parsing deploy profile {}", path.display()))?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != PROFILE_VERSION {
            bail!("deploy profile version must be {PROFILE_VERSION}");
        }
        if self.class == ProfileClass::Production && self.key_provider.kind.is_lab_only() {
            bail!(
                "production profile refuses lab-only key provider {}",
                self.key_provider.kind
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantDataKey {
    pub tenant: String,
    pub key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyStatement {
    pub issued_at: i64,
    pub class: ProfileClass,
    pub provider_kind: KeyProviderKind,
    pub root_key_id: String,
    pub data_keys: Vec<TenantDataKey>,
    pub custodians: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyEvidence {
    pub schema: String,
    pub key_id: String,
    pub public_key: String,
    pub statement: CeremonyStatement,
    pub signature: String,
}

/// Inputs for `tenkaictl keys ceremony`.
pub struct CeremonyRequest<'a> {
    pub profile: &'a DeployProfile,
    pub signing_key: &'a Path,
    pub custodians: &'a [String],
    pub tenants: &'a [String],
    pub provider_dir: &'a Path,
    pub issued_at: i64,
}

impl CeremonyEvidence {
    pub fn verify(&self) -> Result<()> {
        if self.schema != CEREMONY_SCHEMA {
            bail!("unsupported key-ceremony schema {}", self.schema);
        }
        let public = STANDARD
            .decode(&self.public_key)
            .context("key-ceremony public_key is not valid base64")?;
        let public: [u8; 32] = public.try_into().map_err(|bytes: Vec<u8>| {
            anyhow::anyhow!(
                "key-ceremony public_key must decode to 32 bytes, got {}",
                bytes.len()
            )
        })?;
        let expected_id = crate::signature_verification::key_id(&public);
        if self.key_id != expected_id {
            bail!("key-ceremony key_id does not match public_key");
        }
        let signature = STANDARD
            .decode(&self.signature)
            .context("key-ceremony signature is not valid base64")?;
        let signature: [u8; 64] = signature.try_into().map_err(|bytes: Vec<u8>| {
            anyhow::anyhow!(
                "key-ceremony signature must decode to 64 bytes, got {}",
                bytes.len()
            )
        })?;
        let verifying = VerifyingKey::from_bytes(&public)
            .map_err(|_| anyhow::anyhow!("key-ceremony public_key is not a valid Ed25519 key"))?;
        verifying
            .verify(
                &canonical_bytes(&self.statement)?,
                &ed25519_dalek::Signature::from_bytes(&signature),
            )
            .context("key-ceremony signature does not verify")?;
        Ok(())
    }
}

fn canonical_bytes(statement: &CeremonyStatement) -> Result<Vec<u8>> {
    let mut bytes = SIGNING_DOMAIN.to_vec();
    serde_json::to_writer(&mut bytes, statement)?;
    Ok(bytes)
}

/// Run the ceremony against the profile's provider.
///
/// The software provider writes key material only under `provider_dir` with
/// owner-only permissions. Evidence, and any later copy into a bundle or plan,
/// contains key ids and custodians only.
pub fn run_ceremony(request: CeremonyRequest<'_>) -> Result<CeremonyEvidence> {
    request.profile.validate()?;
    let kind = request.profile.key_provider.kind;
    match kind {
        KeyProviderKind::Software => run_software_ceremony(request),
        KeyProviderKind::File | KeyProviderKind::Memory => {
            bail!(
                "key provider {kind} is lab-only and is not a ceremony adapter; use software for labs"
            )
        }
        KeyProviderKind::Pkcs11 => {
            bail!("PKCS#11 adapter is not in this slice")
        }
        KeyProviderKind::Kmip => {
            bail!("KMIP adapter is not in this slice")
        }
        KeyProviderKind::CloudKms => {
            bail!("cloud KMS adapter is not in this slice")
        }
    }
}

fn run_software_ceremony(request: CeremonyRequest<'_>) -> Result<CeremonyEvidence> {
    if request.profile.class != ProfileClass::Lab {
        bail!(
            "software key provider is lab-only; production profile refuses {}",
            request.profile.key_provider.kind
        );
    }
    let custodians = normalize_names("custodian", request.custodians)?;
    let tenants = normalize_names("tenant", request.tenants)?;
    if tenants.is_empty() {
        bail!("key ceremony needs at least one tenant");
    }
    if custodians.len() < 2 {
        bail!("key ceremony needs at least two custodians");
    }
    for tenant in &tenants {
        crate::ontology::validate_identifier("tenant", tenant)?;
    }
    let signing_key = SigningKey::from_bytes(&crate::approval_policy::load_signer_seed(
        request.signing_key,
    )?);

    let provider_dir = request.provider_dir;
    if provider_dir.exists() {
        refuse_symlink(provider_dir, "software provider dir")?;
        let meta = fs::symlink_metadata(provider_dir)
            .with_context(|| format!("inspecting provider dir {}", provider_dir.display()))?;
        if !meta.file_type().is_dir() {
            bail!(
                "software provider dir {} must be a directory",
                provider_dir.display()
            );
        }
        if provider_dir.join(ROOT_KEK).exists() || provider_dir.join(ROOT_ID).exists() {
            bail!(
                "software provider dir {} already holds a root key; use a new directory",
                provider_dir.display()
            );
        }
    } else {
        fs::create_dir_all(provider_dir)
            .with_context(|| format!("creating provider dir {}", provider_dir.display()))?;
        refuse_symlink(provider_dir, "software provider dir")?;
    }
    restrict_dir(provider_dir)?;
    let tenants_root = provider_dir.join("tenants");
    create_owned_dir(&tenants_root)?;
    let mut tenant_dirs = Vec::with_capacity(tenants.len());
    for tenant in &tenants {
        let tenant_dir = tenants_root.join(tenant);
        create_owned_dir(&tenant_dir)?;
        if tenant_dir.join(TENANT_DEK_WRAP).exists() || tenant_dir.join(TENANT_ID).exists() {
            bail!(
                "software provider dir {} already holds tenant keys for {tenant}; use a new directory",
                provider_dir.display()
            );
        }
        tenant_dirs.push(tenant_dir);
    }
    let mut unique_dirs = std::collections::BTreeSet::new();
    for tenant_dir in &tenant_dirs {
        let resolved = fs::canonicalize(tenant_dir)
            .with_context(|| format!("resolving tenant directory {}", tenant_dir.display()))?;
        if !unique_dirs.insert(resolved) {
            bail!("tenant directories collide on this filesystem; use distinct directory names");
        }
    }

    let root_secret = random_bytes()?;
    let root_key_id = key_id_for(&random_bytes()?);
    write_secret(provider_dir.join(ROOT_KEK), &root_secret)?;
    write_text(provider_dir.join(ROOT_ID), &root_key_id)?;

    let mut data_keys = Vec::with_capacity(tenants.len());
    for (tenant, tenant_dir) in tenants.iter().zip(tenant_dirs) {
        let dek = random_bytes()?;
        let key_id = key_id_for(&random_bytes()?);
        write_owner_only(
            &tenant_dir.join(TENANT_DEK_WRAP),
            &wrap_dek(&root_secret, &dek)?,
        )?;
        write_text(tenant_dir.join(TENANT_ID), &key_id)?;
        data_keys.push(TenantDataKey {
            tenant: tenant.clone(),
            key_id,
        });
    }

    let statement = CeremonyStatement {
        issued_at: request.issued_at,
        class: request.profile.class,
        provider_kind: KeyProviderKind::Software,
        root_key_id,
        data_keys,
        custodians,
    };
    sign_statement(statement, &signing_key)
}

fn sign_statement(
    statement: CeremonyStatement,
    signing_key: &SigningKey,
) -> Result<CeremonyEvidence> {
    let public = signing_key.verifying_key().to_bytes();
    let signature = signing_key.sign(&canonical_bytes(&statement)?);
    Ok(CeremonyEvidence {
        schema: CEREMONY_SCHEMA.into(),
        key_id: crate::signature_verification::key_id(&public),
        public_key: STANDARD.encode(public),
        statement,
        signature: STANDARD.encode(signature.to_bytes()),
    })
}

fn refuse_symlink(path: &Path, label: &str) -> Result<()> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("inspecting {label} {}", path.display()))?;
    if meta.file_type().is_symlink() {
        bail!("{label} {} must not be a symlink", path.display());
    }
    Ok(())
}

fn create_owned_dir(path: &Path) -> Result<()> {
    if path.exists() {
        refuse_symlink(path, "key directory")?;
        let meta = fs::symlink_metadata(path)
            .with_context(|| format!("inspecting key directory {}", path.display()))?;
        if !meta.file_type().is_dir() {
            bail!("key directory {} must be a directory", path.display());
        }
    } else {
        fs::create_dir(path)
            .with_context(|| format!("creating key directory {}", path.display()))?;
        refuse_symlink(path, "key directory")?;
    }
    restrict_dir(path)
}

fn normalize_names(label: &str, values: &[String]) -> Result<Vec<String>> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            bail!("{label} must not be empty");
        }
        if trimmed.chars().any(char::is_control) {
            bail!("{label} must not contain control characters");
        }
        if !seen.insert(trimmed.to_string()) {
            bail!("{label} {trimmed} is listed twice");
        }
        out.push(trimmed.to_string());
    }
    Ok(out)
}

fn key_id_for(id_seed: &[u8; 32]) -> String {
    format!("sha256:{:x}", Sha256::digest(id_seed))
}

fn random_bytes() -> Result<[u8; 32]> {
    let mut bytes = [0_u8; 32];
    fill_random(&mut bytes)?;
    Ok(bytes)
}

fn fill_random(bytes: &mut [u8]) -> Result<()> {
    SystemRandom::new()
        .fill(bytes)
        .map_err(|_| anyhow::anyhow!("failed to read CSPRNG"))
}

fn wrap_key(root: &[u8; 32]) -> Result<LessSafeKey> {
    let unbound = UnboundKey::new(&AES_256_GCM, root)
        .map_err(|_| anyhow::anyhow!("software provider root is not a valid wrapping key"))?;
    Ok(LessSafeKey::new(unbound))
}

fn wrap_dek(root: &[u8; 32], dek: &[u8; 32]) -> Result<Vec<u8>> {
    let mut nonce = [0_u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    let mut body = dek.to_vec();
    wrap_key(root)?
        .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut body)
        .map_err(|_| anyhow::anyhow!("failed to wrap tenant data key"))?;
    let mut wrapped = nonce.to_vec();
    wrapped.extend_from_slice(&body);
    Ok(wrapped)
}

#[cfg(test)]
fn unwrap_dek(root: &[u8; 32], wrapped: &[u8]) -> Result<[u8; 32]> {
    if wrapped.len() < NONCE_LEN {
        bail!("wrapped tenant data key is truncated");
    }
    let mut nonce = [0_u8; NONCE_LEN];
    nonce.copy_from_slice(&wrapped[..NONCE_LEN]);
    let mut body = wrapped[NONCE_LEN..].to_vec();
    let plaintext = wrap_key(root)?
        .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut body)
        .map_err(|_| anyhow::anyhow!("failed to unwrap tenant data key"))?;
    let len = plaintext.len();
    plaintext
        .try_into()
        .map_err(|_| anyhow::anyhow!("unwrapped tenant data key is {len} bytes"))
}

fn restrict_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = fs::metadata(path)
            .with_context(|| format!("inspecting {}", path.display()))?
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions)
            .with_context(|| format!("restricting {}", path.display()))?;
    }
    Ok(())
}

fn write_secret(path: PathBuf, bytes: &[u8; 32]) -> Result<()> {
    write_owner_only(&path, bytes)
}

fn write_text(path: PathBuf, text: &str) -> Result<()> {
    write_owner_only(&path, text.as_bytes())
}

fn create_owner_only(path: &Path) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options
        .open(path)
        .with_context(|| format!("creating {}", path.display()))
}

fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = create_owner_only(path)?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", path.display()))?;
    Ok(())
}

/// Evidence must not replace the signing seed or land inside the provider directory.
pub fn refuse_evidence_path(out: &Path, provider_dir: &Path, signing_key: &Path) -> Result<()> {
    if out.as_os_str().is_empty() {
        bail!("evidence path is empty");
    }
    let parent = out.parent().filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        if !parent.exists() {
            bail!("evidence directory {} is missing", parent.display());
        }
        refuse_symlink(parent, "evidence directory")?;
        if !parent.is_dir() {
            bail!("evidence directory {} is not a directory", parent.display());
        }
    }
    match fs::symlink_metadata(out) {
        Ok(meta) if meta.file_type().is_symlink() => {
            bail!("evidence path {} must not be a symlink", out.display());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspecting evidence path {}", out.display()));
        }
    }
    if out.exists() {
        refuse_symlink(out, "evidence path")?;
    }
    let resolved = resolved_path(out)?;
    if paths_equal(&resolved, signing_key)? {
        bail!(
            "evidence path {} must not be the ceremony signing key",
            out.display()
        );
    }
    if path_is_within(&resolved, provider_dir)? {
        bail!(
            "evidence path {} must not be inside the software provider directory",
            out.display()
        );
    }
    if out.exists() {
        bail!("evidence path {} already exists", out.display());
    }
    Ok(())
}

/// Exclusive create of the evidence file. Keep the handle until `write_evidence`.
#[derive(Debug)]
pub struct EvidenceReservation {
    file: fs::File,
    path: PathBuf,
}

impl EvidenceReservation {
    /// Remove the reserved file after a failed ceremony.
    pub fn discard(self) {
        let path = self.path;
        drop(self.file);
        let _ = fs::remove_file(path);
    }
}

/// Create the evidence file before the ceremony writes keys.
pub fn reserve_evidence(out: &Path) -> Result<EvidenceReservation> {
    Ok(EvidenceReservation {
        file: create_owner_only(out)?,
        path: out.to_path_buf(),
    })
}

/// Write signed evidence through the reserved file handle.
pub fn write_evidence(
    mut reservation: EvidenceReservation,
    evidence: &CeremonyEvidence,
) -> Result<()> {
    let encoded = serde_json::to_vec_pretty(evidence)?;
    reservation
        .file
        .set_len(0)
        .with_context(|| format!("truncating {}", reservation.path.display()))?;
    reservation
        .file
        .write_all(&encoded)
        .with_context(|| format!("writing {}", reservation.path.display()))?;
    reservation
        .file
        .sync_all()
        .with_context(|| format!("syncing {}", reservation.path.display()))?;
    Ok(())
}

fn resolved_path(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        return fs::canonicalize(path).with_context(|| format!("resolving {}", path.display()));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("evidence path {} has no file name", path.display()))?;
    let parent = match parent {
        Some(parent) if parent.exists() => {
            fs::canonicalize(parent).with_context(|| format!("resolving {}", parent.display()))?
        }
        Some(parent) => std::env::current_dir()?.join(parent),
        None => std::env::current_dir()?,
    };
    Ok(parent.join(file_name))
}

fn paths_equal(left: &Path, right: &Path) -> Result<bool> {
    Ok(resolved_path(left)? == resolved_path(right)?)
}

fn path_is_within(child: &Path, parent: &Path) -> Result<bool> {
    let child = resolved_path(child)?;
    let parent = resolved_path(parent)?;
    Ok(child.starts_with(&parent))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-keys-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn seed_file(dir: &Path) -> PathBuf {
        let path = dir.join("ceremony.ed25519");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(&[17_u8; 32]).unwrap();
        path
    }

    fn write_profile(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("profile.toml");
        fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn production_profile_refuses_software_file_and_memory_providers() {
        let dir = temp_dir();
        for kind in ["software", "file", "memory"] {
            let path = write_profile(
                &dir,
                &format!(
                    "version = 1\nclass = \"production\"\n[key_provider]\nkind = \"{kind}\"\n"
                ),
            );
            let error = DeployProfile::load(&path).unwrap_err().to_string();
            assert!(
                error.contains("production profile refuses lab-only key provider"),
                "{kind}: {error}"
            );
            fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn production_profile_accepts_on_site_kinds() {
        let dir = temp_dir();
        for kind in ["pkcs11", "kmip", "cloud_kms"] {
            let path = write_profile(
                &dir,
                &format!(
                    "version = 1\nclass = \"production\"\n[key_provider]\nkind = \"{kind}\"\n"
                ),
            );
            let profile = DeployProfile::load(&path).unwrap();
            assert_eq!(profile.class, ProfileClass::Production);
            fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn lab_software_ceremony_records_ids_and_never_writes_key_material_to_evidence() {
        let dir = temp_dir();
        let profile_path = write_profile(
            &dir,
            "version = 1\nclass = \"lab\"\n[key_provider]\nkind = \"software\"\n",
        );
        let profile = DeployProfile::load(&profile_path).unwrap();
        let provider = dir.join("provider");
        let signing = seed_file(&dir);
        let evidence = run_ceremony(CeremonyRequest {
            profile: &profile,
            signing_key: &signing,
            custodians: &["alice".into(), "bob".into()],
            tenants: &["acme".into(), "contoso".into()],
            provider_dir: &provider,
            issued_at: 1_700_000_000_000,
        })
        .unwrap();
        evidence.verify().unwrap();
        assert_eq!(evidence.schema, CEREMONY_SCHEMA);
        assert_eq!(evidence.statement.custodians, ["alice", "bob"]);
        assert_eq!(evidence.statement.data_keys.len(), 2);
        assert_eq!(evidence.statement.provider_kind, KeyProviderKind::Software);

        let encoded = serde_json::to_string(&evidence).unwrap();
        let root_kek = fs::read(provider.join(ROOT_KEK)).unwrap();
        let wrapped = fs::read(provider.join("tenants/acme").join(TENANT_DEK_WRAP)).unwrap();
        assert_eq!(root_kek.len(), 32);
        let root: [u8; 32] = root_kek.as_slice().try_into().unwrap();
        let dek = unwrap_dek(&root, &wrapped).unwrap();
        assert_ne!(root.as_slice(), dek.as_slice());
        assert!(
            unwrap_dek(&[0_u8; 32], &wrapped).is_err(),
            "tenant wrap opens without the root"
        );
        assert!(
            !encoded
                .as_bytes()
                .windows(32)
                .any(|window| window == root_kek),
            "evidence contains root key material"
        );
        assert!(
            !encoded
                .as_bytes()
                .windows(32)
                .any(|window| window == dek.as_slice()),
            "evidence contains tenant key material"
        );
        let root_hex = root_kek
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert!(
            !encoded.contains(&root_hex),
            "evidence contains root key hex"
        );
        let out = dir.join("ceremony.json");
        refuse_evidence_path(&out, &provider, &signing).unwrap();
        write_evidence(reserve_evidence(&out).unwrap(), &evidence).unwrap();
        let loaded: CeremonyEvidence = serde_json::from_slice(&fs::read(&out).unwrap()).unwrap();
        loaded.verify().unwrap();
        assert_eq!(loaded.statement.root_key_id, evidence.statement.root_key_id);
    }

    fn lab_profile() -> DeployProfile {
        DeployProfile {
            version: 1,
            class: ProfileClass::Lab,
            key_provider: KeyProviderSection {
                kind: KeyProviderKind::Software,
            },
        }
    }

    fn ceremony<'a>(
        profile: &'a DeployProfile,
        custodians: &'a [String],
        tenants: &'a [String],
        provider: &'a Path,
        signing_key: &'a Path,
    ) -> CeremonyRequest<'a> {
        CeremonyRequest {
            profile,
            signing_key,
            custodians,
            tenants,
            provider_dir: provider,
            issued_at: 1,
        }
    }

    #[test]
    fn ceremony_requires_two_custodians_before_writing_keys() {
        let dir = temp_dir();
        let provider = dir.join("provider");
        let profile = lab_profile();
        let error = run_ceremony(ceremony(
            &profile,
            &["alice".into()],
            &["acme".into()],
            &provider,
            &seed_file(&dir),
        ))
        .unwrap_err()
        .to_string();
        assert!(error.contains("at least two custodians"), "{error}");
        assert!(!provider.join(ROOT_KEK).exists());
    }

    #[test]
    fn invalid_tenant_or_signing_key_does_not_leave_a_root() {
        let dir = temp_dir();
        let provider = dir.join("provider");
        let profile = lab_profile();
        let error = run_ceremony(ceremony(
            &profile,
            &["alice".into(), "bob".into()],
            &["bad/tenant".into()],
            &provider,
            &seed_file(&dir),
        ))
        .unwrap_err()
        .to_string();
        assert!(error.contains("tenant"), "{error}");
        assert!(!provider.join(ROOT_KEK).exists());

        let missing = dir.join("missing.ed25519");
        let error = run_ceremony(ceremony(
            &profile,
            &["alice".into(), "bob".into()],
            &["acme".into()],
            &provider,
            &missing,
        ))
        .unwrap_err()
        .to_string();
        assert!(error.contains("missing"), "{error}");
        assert!(!provider.join(ROOT_KEK).exists());
    }

    #[test]
    fn colliding_tenant_directories_do_not_leave_a_root() {
        let dir = temp_dir();
        let provider = dir.join("provider");
        let profile = lab_profile();
        let result = run_ceremony(ceremony(
            &profile,
            &["alice".into(), "bob".into()],
            &["acme".into(), "Acme".into()],
            &provider,
            &seed_file(&dir),
        ));
        match result {
            Ok(evidence) => {
                assert_eq!(evidence.statement.data_keys.len(), 2);
                assert!(provider.join(ROOT_KEK).exists());
            }
            Err(error) => {
                let error = error.to_string();
                assert!(error.contains("collide on this filesystem"), "{error}");
                assert!(!provider.join(ROOT_KEK).exists());
            }
        }
    }

    #[test]
    fn leftover_tenant_wrap_does_not_leave_a_root() {
        let dir = temp_dir();
        let provider = dir.join("provider");
        let leftover = provider.join("tenants").join("acme");
        fs::create_dir_all(&leftover).unwrap();
        fs::write(leftover.join(TENANT_ID), "sha256:leftover").unwrap();
        let profile = lab_profile();
        let error = run_ceremony(ceremony(
            &profile,
            &["alice".into(), "bob".into()],
            &["acme".into()],
            &provider,
            &seed_file(&dir),
        ))
        .unwrap_err()
        .to_string();
        assert!(error.contains("already holds tenant keys"), "{error}");
        assert!(!provider.join(ROOT_KEK).exists());
    }

    #[test]
    fn tenant_directory_symlink_is_refused() {
        let dir = temp_dir();
        let provider = dir.join("provider");
        fs::create_dir_all(provider.join("tenants")).unwrap();
        let outside = dir.join("outside");
        fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, provider.join("tenants").join("acme")).unwrap();
        let profile = lab_profile();
        let error = run_ceremony(ceremony(
            &profile,
            &["alice".into(), "bob".into()],
            &["acme".into()],
            &provider,
            &seed_file(&dir),
        ))
        .unwrap_err()
        .to_string();
        assert!(error.contains("symlink"), "{error}");
        assert!(!outside.join(TENANT_DEK_WRAP).exists());
        assert!(!provider.join(ROOT_KEK).exists());
    }

    #[test]
    fn evidence_path_cannot_overwrite_provider_or_signing_key() {
        let dir = temp_dir();
        let provider = dir.join("provider");
        fs::create_dir_all(&provider).unwrap();
        let signing = seed_file(&dir);
        let inside = provider.join(ROOT_KEK);
        let error = refuse_evidence_path(&inside, &provider, &signing)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("inside the software provider directory"),
            "{error}"
        );
        let error = refuse_evidence_path(&signing, &provider, &signing)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("must not be the ceremony signing key"),
            "{error}"
        );
        let missing_parent = dir.join("missing-directory").join("evidence.json");
        let error = refuse_evidence_path(&missing_parent, &provider, &signing)
            .unwrap_err()
            .to_string();
        assert!(error.contains("is missing"), "{error}");
        let not_dir = dir.join("not-a-dir");
        fs::write(&not_dir, b"file").unwrap();
        let nested = not_dir.join("evidence.json");
        let error = refuse_evidence_path(&nested, &provider, &signing)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a directory"), "{error}");
        let dangling = dir.join("dangling-evidence.json");
        std::os::unix::fs::symlink(dir.join("missing-target"), &dangling).unwrap();
        let error = refuse_evidence_path(&dangling, &provider, &signing)
            .unwrap_err()
            .to_string();
        assert!(error.contains("symlink"), "{error}");
        let reserved = dir.join("reserved.json");
        refuse_evidence_path(&reserved, &provider, &signing).unwrap();
        let _held = reserve_evidence(&reserved).unwrap();
        let error = reserve_evidence(&reserved).unwrap_err().to_string();
        assert!(error.contains("creating"), "{error}");
        let locked = dir.join("locked");
        fs::create_dir(&locked).unwrap();
        let mut permissions = fs::metadata(&locked).unwrap().permissions();
        permissions.set_mode(0o555);
        fs::set_permissions(&locked, permissions).unwrap();
        let blocked = locked.join("evidence.json");
        let error = reserve_evidence(&blocked).unwrap_err().to_string();
        let mut permissions = fs::metadata(&locked).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&locked, permissions).unwrap();
        assert!(error.contains("creating"), "{error}");

        let out = dir.join("evidence.json");
        refuse_evidence_path(&out, &provider, &signing).unwrap();
        fs::write(&out, b"taken").unwrap();
        let error = refuse_evidence_path(&out, &provider, &signing)
            .unwrap_err()
            .to_string();
        assert!(error.contains("already exists"), "{error}");
    }

    #[test]
    fn production_pkcs11_ceremony_is_refused_until_the_adapter_exists() {
        let profile = DeployProfile {
            version: 1,
            class: ProfileClass::Production,
            key_provider: KeyProviderSection {
                kind: KeyProviderKind::Pkcs11,
            },
        };
        let dir = temp_dir();
        let error = run_ceremony(CeremonyRequest {
            profile: &profile,
            signing_key: &seed_file(&dir),
            custodians: &["alice".into()],
            tenants: &["acme".into()],
            provider_dir: &dir.join("unused"),
            issued_at: 1,
        })
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("PKCS#11 adapter is not in this slice"),
            "{error}"
        );
    }
}
