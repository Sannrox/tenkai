//! Pinned web-console bundle (ADR 0031). Shared by `build.rs` and tests.

use sha2::{Digest, Sha256};

/// The pin file: one line, `<tag> <sha256-of-zip>`.
pub const PIN_FILE: &str = "ui/console.pin";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsolePin {
    pub tag: String,
    pub sha256: String,
}

impl ConsolePin {
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut fields = text.split_whitespace();
        let (Some(tag), Some(sha256), None) = (fields.next(), fields.next(), fields.next()) else {
            return Err(format!("{PIN_FILE} must contain exactly `<tag> <sha256>`"));
        };
        let semver = tag.strip_prefix('v').unwrap_or_default().split('.');
        if !tag.starts_with('v')
            || semver.clone().count() != 3
            || !semver
                .into_iter()
                .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(format!("{PIN_FILE}: tag {tag:?} is not vMAJOR.MINOR.PATCH"));
        }
        if sha256.len() != 64
            || !sha256
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(format!(
                "{PIN_FILE}: sha256 must be 64 lowercase hex characters"
            ));
        }
        Ok(Self {
            tag: tag.into(),
            sha256: sha256.into(),
        })
    }

    /// Release asset URL published by the tenkai-console release workflow.
    pub fn url(&self) -> String {
        format!(
            "https://github.com/Sannrox/tenkai-console/releases/download/{tag}/tenkai-console-{tag}.zip",
            tag = self.tag
        )
    }

    /// Refuse any bundle whose SHA-256 differs from the pin.
    pub fn verify(&self, bundle: &[u8]) -> Result<(), String> {
        let actual: String = Sha256::digest(bundle)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if actual == self.sha256 {
            Ok(())
        } else {
            Err(format!(
                "console bundle {} checksum mismatch: pinned {}, got {actual}",
                self.tag, self.sha256
            ))
        }
    }
}
