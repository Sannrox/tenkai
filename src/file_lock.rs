//! Non-blocking advisory file locks that tell a real holder from a child
//! being spawned.
//!
//! A child process shares this process's open file descriptions, and so any
//! lock taken through them, until it execs. A lock this process just released
//! can therefore still read as held for a few milliseconds (longer on a loaded
//! host) whenever another thread is spawning a child. An acquire that refuses
//! on a held lock retries for [`SETTLE`] first, so that window does not read
//! as another holder (#947).

use std::fs::{File, TryLockError};
use std::time::{Duration, Instant};

/// How long a held lock is retried before it counts as another holder's.
pub const SETTLE: Duration = Duration::from_secs(2);

/// Take `file`'s exclusive lock. `Ok(false)` when it is still held after
/// `settle`; `Duration::ZERO` tries once.
pub fn try_lock_within(file: &File, settle: Duration) -> std::io::Result<bool> {
    let deadline = Instant::now() + settle;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(true),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(TryLockError::WouldBlock) => return Ok(false),
            Err(TryLockError::Error(error)) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(path: &std::path::Path) -> File {
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)
            .unwrap()
    }

    /// A second open description stands in for the one a spawning child
    /// inherits: held briefly, the lock is still taken; held past the
    /// settle window, it is refused.
    #[test]
    fn a_briefly_inherited_lock_settles_and_a_held_one_is_refused() {
        let path = std::env::temp_dir().join(format!(
            "tenkai-file-lock-{}-{}.lock",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let inherited = open(&path);
        inherited.try_lock().unwrap();
        let ours = open(&path);
        assert!(!try_lock_within(&ours, Duration::ZERO).unwrap());
        assert!(!try_lock_within(&ours, Duration::from_millis(50)).unwrap());

        let exec = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(inherited);
        });
        assert!(try_lock_within(&ours, SETTLE).unwrap());
        exec.join().unwrap();
        drop(ours);
        let _ = std::fs::remove_file(path);
    }
}
