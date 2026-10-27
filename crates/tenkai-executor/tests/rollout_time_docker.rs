//! Docker rollout-time harness against the fake CLI.

use std::fs;
use std::path::PathBuf;

use tenkai::rollout_time::{
    Gate, RolloutReport, baseline_path, docker_daemon_available, evaluate, format_report,
    install_fake_docker, live_pause_image, load_baseline, measure_docker, measure_docker_count,
};
use tenkai_executor::DockerHostExecutor;

const FAKE_IMAGE_A: &str = "registry.example/rollout/svc@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const FAKE_IMAGE_B: &str = "registry.example/rollout/svc@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

// Keep `rollout_time` in the test path so `cargo test rollout_time` and
// `scripts/check-rollout-time.sh` still select these after the move.
mod rollout_time {
    use super::*;

    #[test]
    fn one_service_upgrade_recreates_only_the_changed_container() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-rollout-one-{}-{}",
            std::process::id(),
            tenkai::now_millis()
        ));
        fs::create_dir_all(&root).unwrap();
        let (script, state) = install_fake_docker(&root).unwrap();
        let executor = DockerHostExecutor::for_fake_cli(&script, &state);
        let samples = measure_docker_count(
            &executor,
            "docker-fake",
            5,
            FAKE_IMAGE_A,
            FAKE_IMAGE_B,
            &root,
        )
        .unwrap();
        let log = fs::read_to_string(root.join("argv.log")).unwrap();
        let runs: Vec<&str> = log
            .lines()
            .filter(|line| line.starts_with(r#"["run""#))
            .collect();
        // A new release identity alone recreates nothing (#669).
        assert_eq!(
            runs.len(),
            7,
            "fresh 5 + upgrade 1 + rollback 1, got {}: {runs:?}",
            runs.len()
        );
        assert!(
            samples
                .iter()
                .any(|sample| sample.scenario == "one_service_upgrade"),
            "{samples:?}"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn docker_fake_runs_all_scenarios() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-rollout-docker-{}-{}",
            std::process::id(),
            tenkai::now_millis()
        ));
        fs::create_dir_all(&root).unwrap();
        let (script, state) = install_fake_docker(&root).unwrap();
        let executor = DockerHostExecutor::for_fake_cli(&script, &state);
        let samples =
            measure_docker(&executor, "docker-fake", FAKE_IMAGE_A, FAKE_IMAGE_B, &root).unwrap();
        assert_eq!(samples.len(), 12);
        let baseline = load_baseline(&baseline_path()).unwrap();
        let report = RolloutReport {
            samples,
            reconcile: Vec::new(),
        };
        println!("{}", format_report(&report));
        evaluate(&report, &baseline, Gate::Absolute).unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[ignore = "requires a Docker daemon"]
    fn docker_live_against_runner_baseline() {
        assert!(
            docker_daemon_available(),
            "docker info must succeed for the live rollout-time job"
        );
        let root = std::env::temp_dir().join(format!(
            "tenkai-rollout-live-{}-{}",
            std::process::id(),
            tenkai::now_millis()
        ));
        fs::create_dir_all(&root).unwrap();
        let image_a = live_pause_image("3.9").unwrap();
        let image_b = live_pause_image("3.10").unwrap();
        let executor = DockerHostExecutor::for_binary(PathBuf::from("docker"));
        let samples = measure_docker(&executor, "docker-live", &image_a, &image_b, &root).unwrap();
        let baseline = load_baseline(&baseline_path()).unwrap();
        let report = RolloutReport {
            samples,
            reconcile: Vec::new(),
        };
        println!("{}", format_report(&report));
        evaluate(&report, &baseline, Gate::from_env()).unwrap();
        let _ = fs::remove_dir_all(root);
    }
}
