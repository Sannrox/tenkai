//! An interrupted step is settled only once its control group is empty.

use std::path::PathBuf;

use tenkai::host_apply::HostAction;
use tenkai::host_apply::HostRelease;
use tenkai::host_apply::state::{HostApplyStarted, STARTED_SCHEMA};
use tenkai_host_applier::fence::{execution_gone, is_unit_group};

fn started(cgroup: Option<&str>) -> HostApplyStarted {
    HostApplyStarted {
        schema: STARTED_SCHEMA.into(),
        instance: "a".repeat(64),
        plan_id: "plan".into(),
        plan_digest: format!("sha256:{}", "0".repeat(64)),
        step_id: "plan:step:0".into(),
        environment: "edge".into(),
        product: "k3s".into(),
        action: HostAction::Install,
        release: HostRelease {
            version: "1.0.0".into(),
            manifest_digest: "0".repeat(64),
        },
        generation: 1,
        started_at: 1,
        cgroup: cgroup.map(str::to_owned),
    }
}

fn cgroup_root() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "tenkai-host-fence-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

#[test]
fn a_group_with_another_process_holds_the_product() {
    let root = cgroup_root();
    let unit = format!("/system.slice/tenkai-host-apply@{}.service", "b".repeat(64));
    let group = root.join(unit.trim_start_matches('/'));
    std::fs::create_dir_all(&group).unwrap();
    std::fs::write(group.join("cgroup.procs"), "4242\n").unwrap();
    let step = started(Some(&unit));
    let error = execution_gone(&root, &step).unwrap_err();
    assert!(format!("{error:#}").contains("still running"), "{error:#}");

    // A process in a group below the unit's group counts too.
    std::fs::write(group.join("cgroup.procs"), "").unwrap();
    let worker = group.join("workers");
    std::fs::create_dir_all(&worker).unwrap();
    std::fs::write(worker.join("cgroup.procs"), "4343\n").unwrap();
    let error = execution_gone(&root, &step).unwrap_err();
    assert!(format!("{error:#}").contains("4343"), "{error:#}");
    std::fs::remove_dir_all(&worker).unwrap();

    // Only the settling applier itself is left.
    std::fs::write(
        group.join("cgroup.procs"),
        format!("{}\n", std::process::id()),
    )
    .unwrap();
    execution_gone(&root, &step).unwrap();
    // The unit stopped and its group is gone.
    std::fs::remove_dir_all(&group).unwrap();
    execution_gone(&root, &step).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn only_an_instance_of_the_unit_is_a_fence() {
    let root = cgroup_root();
    execution_gone(&root, &started(None)).unwrap();
    assert!(execution_gone(&root, &started(Some("/user.slice/session-1.scope"))).is_err());
    assert!(!is_unit_group(
        "/system.slice/tenkai-host-apply@../x.service"
    ));
    assert!(!is_unit_group(
        "/system.slice/tenkai-host-apply@nothex.service"
    ));
    assert!(is_unit_group(&format!(
        "/system.slice/system-tenkai\\x2dhost\\x2dapply.slice/tenkai-host-apply@{}.service",
        "c".repeat(64)
    )));
    std::fs::remove_dir_all(root).unwrap();
}
