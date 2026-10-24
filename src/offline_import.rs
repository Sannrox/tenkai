//! Server-side offline bundle import (#680).
//!
//! Operators place a `tenkai.offline-bundle.v1` archive, and its `.chunks/`
//! store, in a server-owned staging directory. Requests name a file in that
//! directory, never a path, so a caller cannot point the server elsewhere.
//! An import verifies the bundle with the host's trust roots and binds it to
//! an isolated upgrade exactly as `tenkaictl upgrade bind-bundle` does; a dry
//! run reports what the bind would do and writes nothing.
//!
//! Each import is a durable job under `<staging>/imports/<id>.json` with its
//! state and the exact refusal. The id is derived from the bundle file, the
//! upgrade and the environment, so a retry continues the same job: layer
//! import is a no-op for matching bytes and chunked weights resume from the
//! last verified chunk. One import runs at a time per host, so imports never
//! race on an upgrade record or on shared content in the stores.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::client::Ctx;
use crate::connectivity::BindPreview;
use crate::offline_bundle::BundleEnvelope;
use crate::release_signing::TrustRoots;

pub const IMPORT_JOB_SCHEMA: &str = "tenkai.offline-import.v1";
const JOB_DIR: &str = "imports";
/// Unannounced failures a retry moved aside, under the job directory.
const PENDING_DIR: &str = "pending";

/// Host-owned import settings: the staging directory and the trust roots
/// that must authenticate a bundle exporter. Neither is request input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportSettings {
    pub staging: PathBuf,
    pub trust_roots: PathBuf,
}

/// One archive in the staging directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StagedBundle {
    pub file: String,
    pub size_bytes: u64,
    /// True when a `<stem>.chunks/` store sits beside the archive.
    pub chunked: bool,
    /// Present when the file parses as a bundle; signatures are not checked here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub plan_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub expires_at_ms: Option<i64>,
    /// Why the file is not a readable bundle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub unreadable: Option<String>,
}

/// Body of `POST /v1/imports`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImportRequest {
    pub version: u32,
    pub operation: String,
    /// File name inside the staging directory.
    pub bundle: String,
    /// The isolated upgrade the bundle binds to.
    pub upgrade: String,
    pub environment: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ImportState {
    Running,
    Succeeded,
    Failed,
    /// A dry run that would succeed.
    Previewed,
}

/// `GET /v1/imports/{id}` and the job file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImportJob {
    pub schema: String,
    pub id: String,
    pub bundle: String,
    pub upgrade: String,
    pub environment: String,
    pub dry_run: bool,
    pub state: ImportState,
    pub actor: String,
    pub started_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub finished_at_ms: Option<i64>,
    /// What the bind does (or did); present once the bundle verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub preview: Option<BindPreview>,
    /// The exact refusal, for example a missing layer digest or an expired interval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub refusal: Option<String>,
}

/// Bundles in `staging`, by file name. Files that do not parse are listed
/// with the reason, so an operator sees why a transfer is unusable.
pub fn list_staged(staging: &Path) -> Result<Vec<StagedBundle>> {
    let mut staged = Vec::new();
    for entry in
        std::fs::read_dir(staging).with_context(|| format!("reading {}", staging.display()))?
    {
        let entry = entry?;
        let Some(file) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let metadata = entry.metadata()?;
        if !metadata.is_file() || !file.ends_with(".json") || file.starts_with('.') {
            continue;
        }
        let path = entry.path();
        let mut bundle = StagedBundle {
            chunked: crate::offline_chunk_store::chunk_dir_beside(&path)
                .is_ok_and(|dir| dir.is_dir()),
            file,
            size_bytes: metadata.len(),
            environment: None,
            plan_id: None,
            expires_at_ms: None,
            unreadable: None,
        };
        match BundleEnvelope::load(&path) {
            Ok(envelope) => {
                bundle.environment = Some(envelope.statement.environment_id);
                bundle.plan_id = Some(envelope.statement.plan_id);
                bundle.expires_at_ms = Some(envelope.statement.expires_at_unix_ms);
            }
            Err(error) => bundle.unreadable = Some(format!("{error:#}")),
        }
        staged.push(bundle);
    }
    staged.sort_by(|left, right| left.file.cmp(&right.file));
    Ok(staged)
}

/// The staged archive `file` names: a plain file name of a regular file
/// (not a link) directly inside `staging`.
pub fn staged_path(staging: &Path, file: &str) -> Result<PathBuf> {
    if file.is_empty()
        || file.starts_with('.')
        || file.contains(['/', '\\'])
        || !file.ends_with(".json")
    {
        bail!("bundle must name a .json file in the staging directory, not a path");
    }
    let path = staging.join(file);
    let metadata = std::fs::symlink_metadata(&path)
        .with_context(|| format!("staged bundle {file} does not exist"))?;
    if !metadata.file_type().is_file() {
        bail!("staged bundle {file} is not a regular file");
    }
    Ok(path)
}

/// Stable job id for one bundle file, upgrade and environment.
pub fn job_id(request: &ImportRequest) -> String {
    let mut hasher = Sha256::new();
    for part in [&request.bundle, &request.upgrade, &request.environment] {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    let digest = format!("{:x}", hasher.finalize());
    format!(
        "imp-{}{}",
        &digest[..16],
        if request.dry_run { "-dry" } else { "" }
    )
}

pub fn job(staging: &Path, id: &str) -> Result<ImportJob> {
    if !id.starts_with("imp-")
        || !id[4..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        bail!("unknown import {id}");
    }
    let path = staging.join(JOB_DIR).join(format!("{id}.json"));
    let raw = std::fs::read(&path).with_context(|| format!("unknown import {id}"))?;
    serde_json::from_slice(&raw).with_context(|| format!("reading import {id}"))
}

/// Run one import or dry run and return its finished job. A refusal is a
/// `failed` job, not an error; errors are left for the job store itself.
pub async fn run(
    ctx: &mut Ctx,
    staging: &Path,
    request: &ImportRequest,
    trust_roots: &TrustRoots,
    actor: &str,
) -> Result<ImportJob> {
    let id = job_id(request);
    let jobs = staging.join(JOB_DIR);
    std::fs::create_dir_all(&jobs).with_context(|| format!("creating {}", jobs.display()))?;
    // One import at a time on this host: a bind rewrites the whole upgrade
    // record, and imports share the OCI store and the weight cache.
    let lock = std::fs::File::create(jobs.join(".lock"))?;
    if lock.try_lock().is_err() {
        bail!("another import is already running");
    }
    // A retry replaces the job file; a failure not yet announced moves aside
    // first, so its `import.failed` event is not lost.
    let previous = self::job(staging, &id).ok();
    // Each attempt of a job starts strictly after the last, even within one
    // millisecond or after the clock steps back: `<id>@<started>` names it.
    let started_at_ms = previous
        .as_ref()
        .map_or(0, |previous| previous.started_at_ms.saturating_add(1))
        .max(crate::now_millis());
    if let Some(previous) = previous
        && previous.state == ImportState::Failed
        && !is_announced(&jobs, &previous)
    {
        let pending = jobs.join(PENDING_DIR);
        std::fs::create_dir_all(&pending)?;
        write_job(
            &pending,
            &ImportJob {
                id: format!("{id}@{}", previous.started_at_ms),
                ..previous
            },
        )?;
    }
    let mut job = ImportJob {
        schema: IMPORT_JOB_SCHEMA.into(),
        id: id.clone(),
        bundle: request.bundle.clone(),
        upgrade: request.upgrade.clone(),
        environment: request.environment.clone(),
        dry_run: request.dry_run,
        state: ImportState::Running,
        actor: actor.into(),
        started_at_ms,
        finished_at_ms: None,
        preview: None,
        refusal: None,
    };
    write_job(&jobs, &job)?;
    let outcome = async {
        let path = staged_path(staging, &request.bundle)?;
        let envelope = BundleEnvelope::load(&path)?;
        if request.dry_run {
            return crate::connectivity::preview_isolated_bundle(
                ctx,
                &request.upgrade,
                &request.environment,
                &envelope,
                trust_roots,
                Some(&path),
            )
            .await;
        }
        // A real import keeps the CLI's order: bundled revocations are
        // installed before the bundle itself is trusted, even if it is then
        // refused.
        let before =
            crate::connectivity::bound_bundle_digest(ctx, &request.upgrade, &request.environment)
                .await
                .ok()
                .flatten();
        let record = crate::connectivity::bind_isolated_bundle(
            ctx,
            &request.upgrade,
            &request.environment,
            &envelope,
            trust_roots,
            Some(&path),
        )
        .await?;
        let bundle_digest = record
            .environments
            .iter()
            .find(|environment| environment.name == request.environment)
            .and_then(|environment| environment.isolated.as_ref())
            .map(|evidence| evidence.bundle_digest.clone())
            .unwrap_or_default();
        let preview = BindPreview {
            already_bound: before.as_deref() == Some(bundle_digest.as_str()),
            bundle_digest,
            plan_id: envelope.statement.plan_id.clone(),
            release_ids: envelope.statement.release_ids.clone(),
            carries_revocations: crate::key_revocation::bundle_carries_revocations(&envelope),
            scan: record
                .environments
                .iter()
                .find(|environment| environment.name == request.environment)
                .and_then(|environment| environment.isolated.as_ref())
                .and_then(|evidence| evidence.scan.clone()),
        };
        Ok::<_, anyhow::Error>(preview)
    }
    .await;
    match outcome {
        Ok(preview) => {
            job.preview = Some(preview);
            job.state = if request.dry_run {
                ImportState::Previewed
            } else {
                ImportState::Succeeded
            };
        }
        Err(error) => {
            job.state = ImportState::Failed;
            job.refusal = Some(format!("{error:#}"));
        }
    }
    job.finished_at_ms = Some(crate::now_millis());
    write_job(&jobs, &job)?;
    Ok(job)
}

/// Failed jobs not yet handed to the `import.failed` webhooks: current jobs,
/// and earlier attempts a retry moved aside.
pub fn unannounced_failures(staging: &Path) -> Result<Vec<ImportJob>> {
    let jobs = staging.join(JOB_DIR);
    let mut failures = Vec::new();
    for dir in [jobs.clone(), jobs.join(PENDING_DIR)] {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", dir.display()));
            }
        };
        for entry in entries {
            let path = entry?.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let Ok(job) = serde_json::from_slice::<ImportJob>(&std::fs::read(&path)?) else {
                continue;
            };
            if job.state == ImportState::Failed && !is_announced(&jobs, &job) {
                failures.push(job);
            }
        }
    }
    Ok(failures)
}

/// Record that `job`'s failure was announced, with a marker file beside the
/// job. Takes the import lock, so it never races an import rewriting the same
/// job. A moved-aside attempt is removed; a current job is reread and marked
/// only if it is still the same failed attempt. While an import holds the lock this defers, returning
/// `false`.
pub fn mark_announced(staging: &Path, job: &ImportJob) -> Result<bool> {
    let jobs = staging.join(JOB_DIR);
    let lock = std::fs::File::create(jobs.join(".lock"))?;
    if lock.try_lock().is_err() {
        return Ok(false);
    }
    if job.id.contains('@') {
        let path = jobs.join(PENDING_DIR).join(format!("{}.json", job.id));
        std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
        return Ok(true);
    }
    let current = self::job(staging, &job.id)?;
    if current.started_at_ms != job.started_at_ms || current.state != ImportState::Failed {
        return Ok(false);
    }
    std::fs::write(announced_marker(&jobs, &current), b"")
        .context("recording an announced import failure")?;
    Ok(true)
}

/// The marker recording that one failed attempt was announced. It sits
/// beside the job, so the job file keeps the format earlier versions read.
fn announced_marker(jobs: &Path, job: &ImportJob) -> PathBuf {
    jobs.join(format!("{}@{}.announced", job.id, job.started_at_ms))
}

fn is_announced(jobs: &Path, job: &ImportJob) -> bool {
    announced_marker(jobs, job).exists()
}

fn write_job(jobs: &Path, job: &ImportJob) -> Result<()> {
    crate::atomic_state::write_json_verified(
        &jobs.join(format!("{}.json", job.id)),
        job,
        |observed: &ImportJob| {
            anyhow::ensure!(observed == job, "import job changed while writing");
            Ok(())
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staged_names_are_file_names_only() {
        let staging = std::env::temp_dir().join(format!(
            "tenkai-staging-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("site.json"), b"{}").unwrap();
        std::fs::write(staging.join("notes.txt"), b"x").unwrap();
        std::os::unix::fs::symlink("/etc/hosts", staging.join("link.json")).unwrap();
        assert!(staged_path(&staging, "site.json").is_ok());
        for refused in [
            "../site.json",
            "/etc/passwd.json",
            ".hidden.json",
            "link.json",
            "notes.txt",
            "",
        ] {
            assert!(staged_path(&staging, refused).is_err(), "{refused}");
        }
        let staged = list_staged(&staging).unwrap();
        assert_eq!(staged.len(), 1, "{staged:?}");
        assert_eq!(staged[0].file, "site.json");
        assert!(staged[0].unreadable.is_some());
        assert!(job(&staging, "../../etc").is_err());
        let _ = std::fs::remove_dir_all(staging);
    }
}
