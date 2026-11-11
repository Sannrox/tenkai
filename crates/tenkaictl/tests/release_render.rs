//! Drive `tenkaictl release render` without a catalog, then publish the bytes.

#[allow(dead_code)]
mod common;

use std::fs;
use std::path::Path;
use std::process::Command;

fn render_command(root: &Path) -> Command {
    let mut command = Command::new(common::workspace_bin("tenkaictl"));
    command
        .env("TMPDIR", root)
        .env(
            "TENKAI_SYSTEM_CLIENT_CONFIG",
            root.join("no-system-client.toml"),
        )
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env_remove("TENKAI_TARGET")
        .env_remove("TENKAI_SERVER_URL")
        .env_remove("TENKAI_MANAGEMENT_TOKEN")
        .env_remove("TENKAI_DATABASE");
    command
}

#[test]
fn render_signs_and_publishes_the_written_bytes() {
    let drill = common::CliDrill::new("tenkai-release-render", "render-token", &[]);
    let app = drill.root.join("app");
    fs::create_dir_all(&app).unwrap();
    let input = app.join("tenkai.toml");
    let output = app.join("rendered.toml");
    fs::write(
        &input,
        "# keep this comment\n[product]\nname = \"app\"\nversion = \"0.0.0\"\n[deploy]\ninstall = \"true\"\n",
    )
    .unwrap();
    drill.ok(&["init"]);
    drill.ok(&["dev", "init-keys", "--dir", drill.keys.to_str().unwrap()]);

    let stdout = drill.ok(&[
        "release",
        "render",
        input.to_str().unwrap(),
        "--version",
        "1.4.0",
        "--out",
        output.to_str().unwrap(),
    ]);
    assert!(
        stdout.contains(&format!("wrote {}", output.display())),
        "render should name the output path: {stdout}"
    );
    let rendered = fs::read_to_string(&output).unwrap();
    assert!(rendered.contains("# keep this comment"));
    assert!(rendered.contains("version = \"1.4.0\""));
    let expected = format!("sha256:{}", tenkai::manifest::digest(&rendered));

    let signature = drill.root.join("tenkai.sig.json");
    drill.sign_release(&output, &signature);
    drill.ok(&[
        "publish",
        output.to_str().unwrap(),
        "--signature",
        signature.to_str().unwrap(),
        "--trust-roots",
        drill.release_trust.to_str().unwrap(),
    ]);
    let inspect = drill.ok(&["release", "inspect", "app@1.4.0"]);
    let view: serde_json::Value = serde_json::from_str(&inspect).unwrap();
    let digest = view["manifest_digest"]
        .as_str()
        .unwrap_or_else(|| panic!("missing manifest_digest: {inspect}"));
    let digest = if digest.starts_with("sha256:") {
        digest.to_string()
    } else {
        format!("sha256:{digest}")
    };
    assert_eq!(digest, expected);
}

#[test]
fn render_does_not_open_a_store_or_server() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-release-render-offline-{}-{}",
        std::process::id(),
        tenkai::now_millis()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let input = root.join("tenkai.toml");
    fs::write(
        &input,
        "[product]\nname = \"app\"\nversion = \"1.0.0\"\n[deploy]\ninstall = \"true\"\n",
    )
    .unwrap();
    let output = render_command(&root)
        .args([
            "--target",
            "remote",
            "release",
            "render",
            input.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "render with --target remote must not need a server\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let _ = fs::remove_dir_all(&root);
}
