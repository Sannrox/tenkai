//! Writes a throwaway host-applier configuration and two spooled, signed,
//! approved host steps for the systemd drill
//! (`scripts/host-applier-systemd-drill.sh`). Test keys only.
//!
//! Usage: `host_apply_drill <out-dir> <spool-dir> <evidence-dir>`. Writes
//! `<out-dir>/etc/` (config and trust for `/etc/tenkai`), `<out-dir>/spool/`
//! (one directory per instance), and `<out-dir>/instances.env` naming the
//! `INSTALL`, `SLOW`, and `CRASH` instances. The signed commands write to
//! `<evidence-dir>`.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use tenkai::host_apply::HostAction;
use tenkai::host_apply::fixture::{HostFixture, StepSpec};
use tenkai::plan::Action;

fn main() {
    let args: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    let [out, spool, evidence] = args.as_slice() else {
        eprintln!("usage: host_apply_drill <out-dir> <spool-dir> <evidence-dir>");
        std::process::exit(2);
    };
    let fixture = HostFixture::new(&[("drill-approver", &["ops"])], Vec::new());
    let etc = out.join("etc");
    std::fs::create_dir_all(&etc).unwrap();
    write(
        &etc.join("host-applier.toml"),
        &format!(
            "version = 1\nspool_dir = {:?}\ntimeout_seconds = 120\n",
            spool.display().to_string()
        ),
    );
    write(
        &etc.join("release-trust-roots.toml"),
        &toml::to_string(&fixture.trust.release_roots).unwrap(),
    );
    write(
        &etc.join("host-approval-policy.toml"),
        &toml::to_string(&fixture.trust.policy).unwrap(),
    );

    let evidence = evidence.display();
    let install = fixture.release(
        &out.join("stage-install"),
        "drill",
        "1.0.0",
        [
            &format!(
                "mkdir -p {evidence} && cp bin/payload {evidence}/payload && id -u > {evidence}/uid && env > {evidence}/env && echo run >> {evidence}/runs"
            ),
            "true",
            "true",
        ],
        &[("bin/payload", b"host release payload\n")],
    );
    let slow = fixture.release(
        &out.join("stage-slow"),
        "drill",
        "2.0.0",
        [
            &format!("sleep 300 & echo $! > {evidence}/child; wait"),
            "true",
            "true",
        ],
        &[("bin/payload", b"slow\n")],
    );
    let crash = fixture.release(
        &out.join("stage-crash"),
        "drill",
        "2.0.0",
        [
            &format!("sleep 300 & echo $! > {evidence}/crash-child; wait"),
            "true",
            "true",
        ],
        &[("bin/payload", b"slow\n")],
    );
    let now = tenkai::now_millis();
    let mut lines = String::new();
    // SLOW is stopped, which leaves dirty(1.0.0, 2.0.0) at generation 2.
    for (name, release, from, generation, created_at) in [
        ("INSTALL", &install, None, 0, now),
        ("SLOW", &slow, Some("1.0.0".to_string()), 1, now + 1),
        ("CRASH", &crash, Some("2.0.0".to_string()), 2, now + 2),
    ] {
        let plan = fixture.plan(
            "drill",
            created_at,
            &[StepSpec {
                release: release.clone(),
                action: HostAction::Install,
                step_action: Action::Upgrade,
                from,
                expected_generation: generation,
            }],
        );
        let request = fixture.request(&plan, 0, release, vec![fixture.approve(&plan, 0, now)]);
        let instance = request.instance().unwrap();
        let dir = out.join("spool").join(&instance);
        std::fs::create_dir_all(&dir).unwrap();
        write(
            &dir.join("request.json"),
            &serde_json::to_string(&request).unwrap(),
        );
        let stage = format!("stage-{}", name.to_lowercase());
        std::fs::rename(out.join(stage), dir.join("artifacts")).unwrap();
        lines.push_str(&format!("{name}={instance}\n"));
    }
    write(&out.join("instances.env"), &lines);
}

fn write(path: &Path, contents: &str) {
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
}
