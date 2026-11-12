//! How far a runner's or console's version trails the server (#761).
//!
//! A runner may trail the server by one minor release during a rolling
//! upgrade. Before 1.0 the minor number is the compatibility line, so
//! 0.5.x against a 0.6.x server is one behind; another major is never
//! supported.

/// This server's version.
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// `other` against `server`: `current`, `behind` (one minor release
/// behind, supported), `unsupported` (further behind, or another major),
/// or `ahead`. `None` when either is not a `major.minor[.patch]` version.
pub fn skew(server: &str, other: &str) -> Option<&'static str> {
    let (server_major, server_minor) = major_minor(server)?;
    let (major, minor) = major_minor(other)?;
    Some(if major != server_major {
        "unsupported"
    } else if minor == server_minor {
        "current"
    } else if minor > server_minor {
        "ahead"
    } else if server_minor - minor == 1 {
        "behind"
    } else {
        "unsupported"
    })
}

/// Why a host applier at `applier` must not run host steps this `server`
/// would plan. Same minor (`current`) or newer (`ahead`) is fine. One or
/// more minors behind, another major, or an unreadable version is not.
pub fn applier_blocks_host_plans(server: &str, applier: &str) -> Option<String> {
    match skew(server, applier) {
        Some("current") | Some("ahead") => None,
        Some(kind) => Some(format!(
            "host applier {applier} is {kind} relative to server {server}; upgrade it with install.sh --role host-applier"
        )),
        None => Some(format!(
            "host applier version {applier:?} is not comparable to server {server}; upgrade it with install.sh --role host-applier"
        )),
    }
}

fn major_minor(version: &str) -> Option<(u64, u64)> {
    let core = version.trim().trim_start_matches('v');
    let core = core.split(['-', '+']).next()?;
    // `major.minor` or `major.minor.patch`, each a plain number.
    let parts: Vec<u64> = core
        .split('.')
        .map(|part| {
            (!part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
                .then(|| part.parse().ok())
                .flatten()
        })
        .collect::<Option<_>>()?;
    match parts.as_slice() {
        [major, minor] | [major, minor, _] => Some((*major, *minor)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_minor_behind_is_supported_and_two_are_not() {
        assert_eq!(skew("0.6.1", "0.6.0"), Some("current"));
        assert_eq!(skew("0.6.1", "0.5.9"), Some("behind"));
        assert_eq!(skew("0.6.1", "0.4.0"), Some("unsupported"));
        assert_eq!(skew("0.6.1", "0.7.0"), Some("ahead"));
        assert_eq!(skew("1.2.0", "0.9.0"), Some("unsupported"));
        assert_eq!(skew("0.6.1", "v0.6.0-rc.1"), Some("current"));
        assert_eq!(skew("0.6.1", "dev"), None);
        assert_eq!(skew("0.6.1", "0.6.invalid"), None);
        assert_eq!(skew("0.6.1", "0.6.0.1"), None);
        assert_eq!(skew("0.6.1", "0.+6.0"), None);
    }

    #[test]
    fn an_older_applier_blocks_host_plans_and_the_same_minor_does_not() {
        assert!(applier_blocks_host_plans("0.8.0", "0.8.0").is_none());
        assert!(applier_blocks_host_plans("0.8.1", "0.8.0").is_none());
        assert!(applier_blocks_host_plans("0.8.0", "0.9.0").is_none());
        let behind = applier_blocks_host_plans("0.8.0", "0.7.0-rc.1").unwrap();
        assert!(
            behind.contains("0.7.0-rc.1") && behind.contains("0.8.0") && behind.contains("behind"),
            "{behind}"
        );
        let unknown = applier_blocks_host_plans("0.8.0", "dev").unwrap();
        assert!(
            unknown.contains("dev") && unknown.contains("0.8.0"),
            "{unknown}"
        );
    }
}
