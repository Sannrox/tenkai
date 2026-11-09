//! Copy a spooled request into root-owned storage without following links.
//!
//! The spool belongs to the unprivileged server, which may swap files while
//! the applier reads them. Every path component is opened relative to its
//! parent's descriptor with `O_NOFOLLOW`, every entry is checked before it is
//! opened and again on the open descriptor, and only regular files and
//! directories are accepted. From then on the applier reads only the copy.

use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat};
use tenkai::host_apply::sealed::{HostSealedValues, MAX_SEALED_BYTES, SEALED_FILE};
use tenkai::host_apply::{ARTIFACTS_DIR, HostApplyRequest, MAX_REQUEST_BYTES, REQUEST_FILE};

/// Bounds on what one release may copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyLimits {
    pub max_bytes: u64,
    /// Files and directories, counted as they are listed, so an oversized
    /// directory fails before its names are held in memory.
    pub max_entries: u64,
}

/// A spooled request document, copied and parsed, with its spool directory
/// still open so the artifacts come from the same directory.
#[derive(Debug)]
pub struct SpooledRequest {
    pub request: HostApplyRequest,
    instance_fd: OwnedFd,
    dest: PathBuf,
}

/// Copy `<spool>/<instance>/request.json` into `dest`, an empty root-owned
/// directory, and parse the copied bytes.
pub fn copy_request(spool: &Path, instance: &str, dest: &Path) -> Result<SpooledRequest> {
    tenkai::host_apply::validate_instance_name(instance)?;
    let spool_fd = rustix::fs::open(
        spool,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening spool directory {}", spool.display()))?;
    let instance_fd = open_dir_at(spool_fd.as_fd(), instance)
        .with_context(|| format!("opening spooled instance {instance}"))?;
    if std::fs::read_dir(dest)
        .with_context(|| format!("reading {}", dest.display()))?
        .next()
        .is_some()
    {
        bail!("{} is not empty", dest.display());
    }
    let (file, mode, size) = open_regular_at(instance_fd.as_fd(), REQUEST_FILE)
        .context("opening the host apply request")?;
    if size > MAX_REQUEST_BYTES {
        bail!("the host apply request exceeds {MAX_REQUEST_BYTES} bytes");
    }
    let mut bytes = Vec::with_capacity(size as usize);
    file.take(size.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != size {
        bail!("{REQUEST_FILE} changed size while it was copied");
    }
    let mut out = create_copy(&dest.join(REQUEST_FILE))?;
    out.write_all(&bytes)?;
    out.sync_all()?;
    std::fs::set_permissions(
        dest.join(REQUEST_FILE),
        std::fs::Permissions::from_mode(mode),
    )?;
    Ok(SpooledRequest {
        request: HostApplyRequest::parse(&bytes)?,
        instance_fd,
        dest: dest.to_path_buf(),
    })
}

impl SpooledRequest {
    /// Copy the deploy `inputs` from `<spool>/<instance>/artifacts/` into the
    /// copy's `artifacts/` and return that workdir. Call it only after the
    /// request verified; its `inputs` come from the signed manifest.
    pub fn copy_artifacts(&self, inputs: &[String], limits: CopyLimits) -> Result<PathBuf> {
        let workdir = self.dest.join(ARTIFACTS_DIR);
        std::fs::create_dir(&workdir)?;
        std::fs::set_permissions(&workdir, std::fs::Permissions::from_mode(0o755))?;
        let mut budget = Budget {
            bytes_left: limits.max_bytes,
            entries_left: limits.max_entries,
        };
        if !inputs.is_empty() {
            let artifacts_fd = open_dir_at(self.instance_fd.as_fd(), ARTIFACTS_DIR)
                .context("opening the spooled release artifacts")?;
            for input in disjoint_inputs(inputs) {
                budget.entry()?;
                copy_input(artifacts_fd.as_fd(), input, &workdir, &mut budget)
                    .with_context(|| format!("copying deploy input {input}"))?;
            }
        }
        Ok(workdir)
    }
}

impl SpooledRequest {
    /// The sealed values spooled next to the request, or `None` when there
    /// are none. They are read into memory only, never copied, and only from
    /// memory-backed storage: a value on a disk would outlive the step.
    pub fn read_sealed(&self) -> Result<Option<HostSealedValues>> {
        match rustix::fs::statat(
            self.instance_fd.as_fd(),
            SEALED_FILE,
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => return Err(error).context("reading the spooled sealed values"),
            Ok(_) => {}
        }
        let (file, _mode, size) = open_regular_at(self.instance_fd.as_fd(), SEALED_FILE)
            .context("opening the spooled sealed values")?;
        let fs = rustix::fs::fstatfs(&file)?;
        #[allow(clippy::unnecessary_cast)]
        if !tenkai::host_apply::sealed::is_memory_backed(fs.f_type as i64) {
            bail!(
                "the spooled sealed values are on persistent storage; the spool must be memory-backed (tmpfs)"
            );
        }
        if size > MAX_SEALED_BYTES {
            bail!("the spooled sealed values exceed {MAX_SEALED_BYTES} bytes");
        }
        let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(size as usize));
        file.take(size.saturating_add(1)).read_to_end(&mut bytes)?;
        if bytes.len() as u64 != size {
            bail!("{SEALED_FILE} changed size while it was read");
        }
        HostSealedValues::parse(&bytes).map(Some)
    }
}

struct Budget {
    bytes_left: u64,
    entries_left: u64,
}

impl Budget {
    fn entry(&mut self) -> Result<()> {
        self.entries_left = self
            .entries_left
            .checked_sub(1)
            .context("release artifacts have too many entries")?;
        Ok(())
    }

    fn bytes(&mut self, bytes: u64) -> Result<()> {
        self.bytes_left = self
            .bytes_left
            .checked_sub(bytes)
            .context("release artifacts exceed the size limit")?;
        Ok(())
    }
}

/// The inputs to copy, each source path once: an input inside another input
/// (a document under a declared directory, or a duplicate) is already part
/// of that copy. The digest is still computed over the full input list.
fn disjoint_inputs(inputs: &[String]) -> Vec<&str> {
    let mut sorted: Vec<&str> = inputs.iter().map(String::as_str).collect();
    sorted.sort_by(|left, right| Path::new(left).cmp(Path::new(right)));
    let mut kept: Vec<&str> = Vec::new();
    for input in sorted {
        if !kept
            .iter()
            .any(|parent| Path::new(input).starts_with(Path::new(parent)))
        {
            kept.push(input);
        }
    }
    kept
}

/// Walk `input`'s components from `root`, then copy what it names.
fn copy_input(
    root: BorrowedFd<'_>,
    input: &str,
    dest_root: &Path,
    budget: &mut Budget,
) -> Result<()> {
    let names: Vec<&str> = Path::new(input)
        .components()
        .map(|component| match component {
            Component::Normal(name) => name.to_str().context("deploy input is not UTF-8"),
            _ => bail!("deploy input must be a safe relative path"),
        })
        .collect::<Result<_>>()?;
    let Some((last, parents)) = names.split_last() else {
        bail!("deploy input is empty");
    };
    let mut dir = rustix::io::dup(root)?;
    let mut dest = dest_root.to_path_buf();
    for name in parents {
        dir = open_dir_at(dir.as_fd(), name)?;
        dest.push(name);
        if !dest.exists() {
            budget.entry()?;
            std::fs::create_dir(&dest)?;
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))?;
        }
    }
    copy_entry_at(dir.as_fd(), last, &dest.join(last), budget)
}

/// Copy one entry (a regular file, or a directory recursively).
fn copy_entry_at(dir: BorrowedFd<'_>, name: &str, dest: &Path, budget: &mut Budget) -> Result<()> {
    let stat = entry_stat(dir, name)?;
    match FileType::from_raw_mode(stat.st_mode as _) {
        FileType::RegularFile => copy_file_at(dir, name, dest, budget),
        FileType::Directory => {
            let child = open_dir_at(dir, name)?;
            same_entry(&stat, &rustix::fs::fstat(&child)?, name)?;
            std::fs::create_dir(dest).with_context(|| format!("creating {}", dest.display()))?;
            let mut names = Vec::new();
            for entry in Dir::read_from(&child)? {
                let entry = entry?;
                let entry_name = entry.file_name().to_bytes();
                if entry_name == b"." || entry_name == b".." {
                    continue;
                }
                budget.entry()?;
                names.push(
                    std::str::from_utf8(entry_name)
                        .context("artifact entry name is not UTF-8")?
                        .to_owned(),
                );
            }
            names.sort();
            for entry_name in names {
                copy_entry_at(child.as_fd(), &entry_name, &dest.join(&entry_name), budget)?;
            }
            std::fs::set_permissions(
                dest,
                std::fs::Permissions::from_mode(permission_bits(&stat, name)?),
            )?;
            Ok(())
        }
        FileType::Symlink => bail!("artifact {name} is a symbolic link"),
        _ => bail!("artifact {name} is not a regular file or directory"),
    }
}

/// Stream one regular file into `dest` through a bounded buffer.
fn copy_file_at(dir: BorrowedFd<'_>, name: &str, dest: &Path, budget: &mut Budget) -> Result<()> {
    let (file, mode, size) = open_regular_at(dir, name)?;
    budget.bytes(size)?;
    let mut out = create_copy(dest)?;
    let copied = std::io::copy(&mut file.take(size.saturating_add(1)), &mut out)?;
    if copied != size {
        bail!("{name} changed size while it was copied");
    }
    out.sync_all()?;
    std::fs::set_permissions(dest, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// Open a regular file without following links. The open descriptor must
/// be the same single-link file the earlier `lstat` saw. Returns the file,
/// its permission bits, and its size.
fn open_regular_at(dir: BorrowedFd<'_>, name: &str) -> Result<(std::fs::File, u32, u64)> {
    let before = entry_stat(dir, name)?;
    if FileType::from_raw_mode(before.st_mode as _) != FileType::RegularFile {
        bail!("{name} is not a regular file");
    }
    let fd = rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening {name}"))?;
    let opened = rustix::fs::fstat(&fd)?;
    same_entry(&before, &opened, name)?;
    if opened.st_nlink != 1 {
        bail!("{name} is a hard link");
    }
    let mode = permission_bits(&opened, name)?;
    let size = u64::try_from(opened.st_size).context("negative file size")?;
    Ok((std::fs::File::from(fd), mode, size))
}

/// A new file in the root-owned copy, readable only by root until its
/// permission bits are set.
fn create_copy(dest: &Path) -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .mode(0o600)
        .open(dest)
        .with_context(|| format!("creating {}", dest.display()))
}

fn open_dir_at(dir: BorrowedFd<'_>, name: &str) -> Result<OwnedFd> {
    let stat = entry_stat(dir, name)?;
    if FileType::from_raw_mode(stat.st_mode as _) != FileType::Directory {
        bail!("{name} is not a directory");
    }
    let fd = rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening directory {name}"))?;
    same_entry(&stat, &rustix::fs::fstat(&fd)?, name)?;
    Ok(fd)
}

/// `lstat` of `name` in `dir`, refusing links before anything opens them.
fn entry_stat(dir: BorrowedFd<'_>, name: &str) -> Result<Stat> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        bail!("invalid artifact entry name {name:?}");
    }
    let stat = rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)
        .with_context(|| format!("reading {name}"))?;
    if FileType::from_raw_mode(stat.st_mode as _) == FileType::Symlink {
        bail!("{name} is a symbolic link");
    }
    Ok(stat)
}

/// The entry opened must be the entry checked: a swap in between is refused.
fn same_entry(checked: &Stat, opened: &Stat, name: &str) -> Result<()> {
    if checked.st_dev != opened.st_dev || checked.st_ino != opened.st_ino {
        bail!("{name} was replaced while it was copied");
    }
    Ok(())
}

/// Permission bits to keep on the copy; the artifact digest covers them.
/// Set-id and sticky bits are refused rather than copied as root.
fn permission_bits(stat: &Stat, name: &str) -> Result<u32> {
    // `st_mode` is narrower than `u32` on some platforms.
    let mode: u32 = stat.st_mode as _;
    if mode & 0o7000 != 0 {
        bail!("{name} carries set-id or sticky bits");
    }
    Ok(mode & 0o777)
}
