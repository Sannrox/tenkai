//! A production deploy profile refuses seed-file signing keys (#1136).

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "common/bin.rs"]
mod workspace_bin;

fn sign_revocations(root: &Path, profile: Option<&Path>) -> Output {
    let mut command = Command::new(workspace_bin::workspace_bin("tenkaictl"));
    if let Some(profile) = profile {
        command.arg("--deploy-profile").arg(profile);
    }
    command
        .args(["revocations", "sign", "--sequence", "1"])
        .args([
            "--revoke",
            concat!(
                "sha256:",
                "1111111111111111111111111111111111111111111111111111111111111111",
                "=retired"
            ),
            "--signing-key",
        ])
        .arg(root.join("revocation.ed25519"))
        .arg("--out")
        .arg(root.join("revocations.json"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("TENKAI_SYSTEM_CLIENT_CONFIG", root.join("absent.toml"))
        .env_remove("TENKAI_DEPLOY_PROFILE")
        .env_remove("TENKAI_KEY_REVOCATIONS")
        .output()
        .unwrap_or_else(|error| panic!("failed to launch tenkaictl: {error}"))
}

#[test]
fn a_production_profile_refuses_a_seed_file_and_no_profile_signs_with_it() {
    let root: PathBuf = std::env::temp_dir().join(format!(
        "tenkai-deploy-profile-cli-{}-{}",
        std::process::id(),
        tenkai::now_millis()
    ));
    fs::create_dir_all(&root).unwrap();
    let seed = root.join("revocation.ed25519");
    fs::write(&seed, [9u8; 32]).unwrap();
    fs::set_permissions(&seed, fs::Permissions::from_mode(0o600)).unwrap();
    let production = root.join("production.toml");
    fs::write(
        &production,
        "version = 1\nclass = \"production\"\n[key_provider]\nkind = \"pkcs11\"\n",
    )
    .unwrap();

    let refused = sign_revocations(&root, Some(&production));
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(!refused.status.success(), "{stderr}");
    assert!(
        stderr.contains("revocations sign --signing-key names a seed file"),
        "{stderr}"
    );
    assert!(!root.join("revocations.json").exists());

    let signed = sign_revocations(&root, None);
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    assert!(root.join("revocations.json").exists());
    fs::remove_dir_all(root).unwrap();
}
