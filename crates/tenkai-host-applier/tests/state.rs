//! The applied-state record and the per-product critical section: each host
//! step runs at most once, only at the generation its approved plan names.

mod common;

use common::{Host, Step};
use tenkai::approval_policy::{QuorumPurpose, QuorumRule};
use tenkai::host_apply::HostAction;
use tenkai::host_apply::state::{AppliedState, HostApplyOutcome};
use tenkai::plan::Action;
use tenkai_host_applier::store::{self, Admission};

fn downgrade_needs_qa() -> Vec<QuorumRule> {
    vec![QuorumRule {
        purpose: QuorumPurpose::Downgrade,
        n: 1,
        groups: vec!["qa".into()],
        exclude_requester: false,
        min_criticality: None,
    }]
}

fn install<'a>(release: &'a common::Staged, from: Option<&'a str>, generation: u64) -> Step<'a> {
    Step {
        release,
        action: HostAction::Install,
        step_action: Action::Upgrade,
        from,
        generation,
        approvers: &[0],
    }
}

fn refusal<T: std::fmt::Debug>(result: anyhow::Result<T>) -> String {
    format!(
        "{:#}",
        result.expect_err("the critical section must refuse")
    )
}

#[test]
fn install_advances_the_generation_and_records_the_release() {
    let host = Host::new(Vec::new());
    let a = host.release("1.0.0");
    let (instance, _) = host.spool(install(&a, None, 0));
    let result = host.step(&instance, HostApplyOutcome::Succeeded).unwrap();
    assert_eq!(result.outcome, HostApplyOutcome::Succeeded);
    assert_eq!(result.generation, 1);
    let record = host.record();
    assert_eq!(record.generation, 1);
    assert!(
        matches!(record.state, AppliedState::Applied { ref release } if release.version == "1.0.0")
    );
    assert_eq!(record.high_water.unwrap().version, "1.0.0");
}

#[test]
fn a_replayed_instance_returns_its_result_also_after_a_reboot() {
    let host = Host::new(Vec::new());
    let a = host.release("1.0.0");
    let (instance, _) = host.spool(install(&a, None, 0));
    let first = host.step(&instance, HostApplyOutcome::Succeeded).unwrap();
    let again = host.step(&instance, HostApplyOutcome::Failed).unwrap();
    assert_eq!(again, first);
    assert_eq!(host.record().generation, 1);
    host.reboot();
    assert_eq!(
        store::recorded_result(&host.paths, &instance).unwrap(),
        Some(first.clone())
    );
    assert!(
        matches!(host.admit(&instance).unwrap(), Admission::Recorded(result) if result == first)
    );
}

#[test]
fn an_old_approved_plan_never_runs_after_a_newer_one() {
    let host = Host::new(Vec::new());
    let a = host.release("1.0.0");
    let b = host.release("2.0.0");
    let (install_a, _) = host.spool(install(&a, None, 0));
    host.step(&install_a, HostApplyOutcome::Succeeded).unwrap();
    // Both approved against generation 1; only the first to run may.
    let (upgrade_b, _) = host.spool(install(&b, Some("1.0.0"), 1));
    let (stale_reinstall_a, _) = host.spool(install(&a, Some("1.0.0"), 1));
    host.step(&upgrade_b, HostApplyOutcome::Succeeded).unwrap();
    assert!(refusal(host.admit(&stale_reinstall_a)).contains("expects generation 1"));
    // A, B, A: a rollback to A needs a new plan at the current generation.
    let mut rollback = install(&a, Some("2.0.0"), 2);
    rollback.step_action = Action::Rollback;
    let (rollback_a, _) = host.spool(rollback);
    host.step(&rollback_a, HostApplyOutcome::Succeeded).unwrap();
    let record = host.record();
    assert_eq!(record.generation, 3);
    assert!(
        matches!(record.state, AppliedState::Applied { ref release } if release.version == "1.0.0")
    );
    assert_eq!(record.high_water.unwrap().version, "2.0.0");
    // Replaying B's instance returns its recorded result; it never runs again.
    assert!(matches!(
        host.admit(&upgrade_b).unwrap(),
        Admission::Recorded(result) if result.generation == 2
    ));
    assert_eq!(host.record().generation, 3);
}

#[test]
fn uninstall_then_reinstall_needs_downgrade_approvals_for_older_releases() {
    let host = Host::new(downgrade_needs_qa());
    let a = host.release("1.0.0");
    let b = host.release("2.0.0");
    let c = host.release("3.0.0");
    let (install_b, _) = host.spool(install(&b, None, 0));
    host.step(&install_b, HostApplyOutcome::Succeeded).unwrap();
    let (uninstall_b, _) = host.spool(Step {
        release: &b,
        action: HostAction::Uninstall,
        step_action: Action::Upgrade,
        from: Some("2.0.0"),
        generation: 1,
        approvers: &[0],
    });
    let result = host
        .step(&uninstall_b, HostApplyOutcome::Succeeded)
        .unwrap();
    assert_eq!(result.action, HostAction::Uninstall);
    let record = host.record();
    assert_eq!(record.state, AppliedState::Empty);
    assert_eq!(record.high_water.as_ref().unwrap().version, "2.0.0");

    // Older than the high-water release, approved by ops only: refused.
    let (older, _) = host.spool(install(&a, None, 2));
    assert!(refusal(host.admit(&older)).contains("not newer than the high-water release 2.0.0"));
    // The same release again is not newer either.
    let (same, _) = host.spool(install(&b, None, 2));
    assert!(refusal(host.admit(&same)).contains("not newer"));
    // With the qa downgrade approval it runs.
    let (older_approved, _) = host.spool(Step {
        approvers: &[0, 2],
        ..install(&a, None, 2)
    });
    host.step(&older_approved, HostApplyOutcome::Succeeded)
        .unwrap();
    // A release newer than the high-water release needs no downgrade approval.
    let (newer, _) = host.spool(install(&c, Some("1.0.0"), 3));
    host.step(&newer, HostApplyOutcome::Succeeded).unwrap();
    assert_eq!(host.record().high_water.unwrap().version, "3.0.0");
}

#[test]
fn a_step_whose_source_differs_from_the_record_is_refused() {
    let host = Host::new(Vec::new());
    let a = host.release("1.0.0");
    let b = host.release("2.0.0");
    let (install_a, _) = host.spool(install(&a, None, 0));
    host.step(&install_a, HostApplyOutcome::Succeeded).unwrap();
    let (wrong_source, _) = host.spool(install(&b, Some("0.5.0"), 1));
    assert!(refusal(host.admit(&wrong_source)).contains("starts from 0.5.0"));
    let (from_nothing, _) = host.spool(install(&b, None, 1));
    assert!(refusal(host.admit(&from_nothing)).contains("starts from nothing"));
    assert_eq!(host.record().generation, 1);
}

#[test]
fn two_plans_racing_for_one_generation_run_once() {
    let host = Host::new(Vec::new());
    let a = host.release("1.0.0");
    let b = host.release("2.0.0");
    let (first, _) = host.spool(install(&a, None, 0));
    let (second, _) = host.spool(install(&b, None, 0));
    let intakes = [host.intake(&first).unwrap(), host.intake(&second).unwrap()];
    let barrier = std::sync::Barrier::new(2);
    let outcomes: Vec<anyhow::Result<bool>> = std::thread::scope(|scope| {
        let handles: Vec<_> = intakes
            .iter()
            .map(|intake| {
                let barrier = &barrier;
                let paths = &host.paths;
                scope.spawn(move || {
                    barrier.wait();
                    match store::admit(paths, &intake.verified, tenkai::now_millis())? {
                        Admission::Run(running) => {
                            std::thread::sleep(std::time::Duration::from_millis(50));
                            running.finish(HostApplyOutcome::Succeeded, Some(0), "", 0)?;
                            Ok(true)
                        }
                        Admission::Recorded(_) => Ok(false),
                    }
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect()
    });
    let ran = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Ok(true)))
        .count();
    let refused = outcomes
        .iter()
        .filter(|outcome| {
            outcome
                .as_ref()
                .is_err_and(|error| format!("{error:#}").contains("expects generation 0"))
        })
        .count();
    assert_eq!((ran, refused), (1, 1), "{outcomes:?}");
    assert_eq!(host.record().generation, 1);
}

#[test]
fn a_failed_install_leaves_dirty_and_any_side_may_continue() {
    let host = Host::new(downgrade_needs_qa());
    let a = host.release("1.0.0");
    let b = host.release("2.0.0");
    let (install_a, _) = host.spool(install(&a, None, 0));
    host.step(&install_a, HostApplyOutcome::Succeeded).unwrap();
    let (upgrade_b, _) = host.spool(install(&b, Some("1.0.0"), 1));
    let failed = host.step(&upgrade_b, HostApplyOutcome::Failed).unwrap();
    assert_eq!(failed.outcome, HostApplyOutcome::Failed);
    let record = host.record();
    assert_eq!(record.generation, 2);
    assert!(matches!(
        record.state,
        AppliedState::Dirty { from: Some(ref from), to: Some(ref to) }
            if from.version == "1.0.0" && to.version == "2.0.0"
    ));
    // The failed step stays failed; nothing restores A on its own.
    assert_eq!(
        host.step(&upgrade_b, HostApplyOutcome::Succeeded).unwrap(),
        failed
    );
    // Retrying B from the dirty B side at the new generation is allowed and
    // needs no downgrade approval: B never applied.
    let (retry_b, _) = host.spool(install(&b, Some("2.0.0"), 2));
    host.step(&retry_b, HostApplyOutcome::Succeeded).unwrap();
    assert!(
        matches!(host.record().state, AppliedState::Applied { ref release } if release.version == "2.0.0")
    );
}

#[test]
fn rolling_back_from_dirty_needs_the_rollback_approvals() {
    let host = Host::new(vec![QuorumRule {
        purpose: QuorumPurpose::Rollback,
        n: 2,
        groups: Vec::new(),
        exclude_requester: false,
        min_criticality: None,
    }]);
    let a = host.release("1.0.0");
    let b = host.release("2.0.0");
    let (install_a, _) = host.spool(install(&a, None, 0));
    host.step(&install_a, HostApplyOutcome::Succeeded).unwrap();
    let (upgrade_b, _) = host.spool(install(&b, Some("1.0.0"), 1));
    host.step(&upgrade_b, HostApplyOutcome::Failed).unwrap();
    let rollback = |approvers| Step {
        step_action: Action::Rollback,
        approvers,
        ..install(&a, Some("1.0.0"), 2)
    };
    let (one, _) = host.spool(rollback(&[0]));
    assert!(refusal(host.intake(&one)).contains("need 2 rollback approvals"));
    let (two, _) = host.spool(rollback(&[0, 1]));
    host.step(&two, HostApplyOutcome::Succeeded).unwrap();
    assert_eq!(host.record().generation, 3);
}

#[test]
fn a_crash_mid_command_resolves_as_interrupted_and_never_reruns() {
    let host = Host::new(Vec::new());
    let a = host.release("1.0.0");
    let b = host.release("2.0.0");
    let (install_a, _) = host.spool(install(&a, None, 0));
    let Admission::Run(running) = host.admit(&install_a).unwrap() else {
        panic!("first admission runs");
    };
    // The applier dies with the command running: no result, lock released.
    drop(running);
    host.reboot();
    assert_eq!(
        store::recorded_result(&host.paths, &install_a).unwrap(),
        None
    );
    let Admission::Recorded(interrupted) = host.admit(&install_a).unwrap() else {
        panic!("a started instance never runs again");
    };
    assert_eq!(interrupted.outcome, HostApplyOutcome::Interrupted);
    let record = host.record();
    assert_eq!(record.generation, 1);
    assert!(matches!(
        record.state,
        AppliedState::Dirty {
            from: None,
            to: Some(_)
        }
    ));
    // Continuing takes a new approved plan at the current generation.
    let (install_b, _) = host.spool(install(&b, None, 1));
    host.step(&install_b, HostApplyOutcome::Succeeded).unwrap();
    assert_eq!(host.record().generation, 2);
}

#[test]
fn the_next_step_settles_a_crashed_one_it_finds_in_the_record() {
    let host = Host::new(Vec::new());
    let a = host.release("1.0.0");
    let (install_a, _) = host.spool(install(&a, None, 0));
    let Admission::Run(running) = host.admit(&install_a).unwrap() else {
        panic!("first admission runs");
    };
    drop(running);
    // Another instance of the product settles the crashed one first.
    let (retry, _) = host.spool(install(&a, None, 1));
    host.step(&retry, HostApplyOutcome::Succeeded).unwrap();
    assert_eq!(
        store::recorded_result(&host.paths, &install_a)
            .unwrap()
            .unwrap()
            .outcome,
        HostApplyOutcome::Interrupted
    );
}

#[test]
fn health_checks_the_generation_without_advancing_it() {
    let host = Host::new(Vec::new());
    let a = host.release("1.0.0");
    let health = |generation| Step {
        action: HostAction::Health,
        from: Some("1.0.0"),
        ..install(&a, Some("1.0.0"), generation)
    };
    let (early, _) = host.spool(health(0));
    assert!(refusal(host.admit(&early)).contains("starts from 1.0.0"));
    let (install_a, _) = host.spool(install(&a, None, 0));
    host.step(&install_a, HostApplyOutcome::Succeeded).unwrap();
    let (stale, _) = host.spool(health(0));
    assert!(refusal(host.admit(&stale)).contains("expects generation 0"));
    let (check, _) = host.spool(health(1));
    let result = host.step(&check, HostApplyOutcome::Failed).unwrap();
    assert_eq!((result.action, result.generation), (HostAction::Health, 1));
    let record = host.record();
    assert_eq!(record.generation, 1);
    assert!(matches!(record.state, AppliedState::Applied { .. }));
    // A crashed health check is interrupted, never re-run, and changes nothing.
    let (again, _) = host.spool(health(1));
    let Admission::Run(running) = host.admit(&again).unwrap() else {
        panic!("health admits at the current generation");
    };
    drop(running);
    let Admission::Recorded(result) = host.admit(&again).unwrap() else {
        panic!("never re-run");
    };
    assert_eq!(result.outcome, HostApplyOutcome::Interrupted);
    assert_eq!(host.record().generation, 1);
}

#[test]
fn a_release_that_does_not_compare_keeps_the_high_water_release() {
    let host = Host::new(downgrade_needs_qa());
    let three = host.release("3.0.0");
    let nightly = host.release("nightly");
    let two = host.release("2.0.0");
    let (install_three, _) = host.spool(install(&three, None, 0));
    host.step(&install_three, HostApplyOutcome::Succeeded)
        .unwrap();
    let (install_nightly, _) = host.spool(Step {
        approvers: &[0, 2],
        ..install(&nightly, Some("3.0.0"), 1)
    });
    host.step(&install_nightly, HostApplyOutcome::Succeeded)
        .unwrap();
    assert_eq!(host.record().high_water.unwrap().version, "3.0.0");
    // 2.0.0 is still older than 3.0.0, which was applied.
    let (install_two, _) = host.spool(install(&two, Some("nightly"), 2));
    assert!(refusal(host.admit(&install_two)).contains("high-water release 3.0.0"));
}
