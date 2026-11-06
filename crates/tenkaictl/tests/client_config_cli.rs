//! Client config must not hijack local-only commands on a server host.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[path = "common/bin.rs"]
mod workspace_bin;

fn bin() -> PathBuf {
    workspace_bin::workspace_bin("tenkaictl")
}

#[test]
fn dev_init_keys_ignores_remote_client_config() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-client-config-cli-{}-{}",
        std::process::id(),
        tenkai::now_millis()
    ));
    fs::create_dir_all(&root).unwrap();
    let system = root.join("client.toml");
    fs::write(
        &system,
        r#"
target = "remote"
server_url = "http://127.0.0.1:8080"
token_file = "/etc/tenkai/management.token"
"#,
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&system, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let keys = root.join("keys");
    let output = Command::new(bin())
        .args(["dev", "init-keys", "--dir"])
        .arg(&keys)
        .env("TENKAI_SYSTEM_CLIENT_CONFIG", &system)
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("TMPDIR", &root)
        .env_remove("TENKAI_TARGET")
        .env_remove("TENKAI_SERVER_URL")
        .env_remove("TENKAI_MANAGEMENT_TOKEN")
        .output()
        .unwrap_or_else(|error| panic!("failed to launch tenkaictl: {error}"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let _ = fs::remove_dir_all(&root);
    assert!(
        output.status.success(),
        "dev init-keys failed under remote client.toml\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("not logged in"),
        "dev init-keys used the remote target:\n{stderr}"
    );
}
