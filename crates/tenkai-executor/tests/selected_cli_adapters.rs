//! Isolated-process check that `install()` registers Helm, kubectl, and Docker.

use tenkai::software_executor::{request_from_parts, selected_software_executor};

#[test]
fn install_selects_helm_kubernetes_and_docker_adapters() {
    tenkai_executor::install();
    let root = std::env::temp_dir().join(format!(
        "tenkai-exec-select-{}-{}",
        std::process::id(),
        tenkai::now_millis()
    ));
    std::fs::create_dir_all(&root).unwrap();

    let cases = [
        ("helm", root.join("missing-chart"), "helm chart workdir"),
        ("kubernetes", root.clone(), "manifests"),
        ("k8s", root.clone(), "manifests"),
        ("docker", root.clone(), "docker/"),
    ];
    for (value, workdir, needle) in cases {
        unsafe {
            std::env::set_var("TENKAI_SOFTWARE_EXECUTOR", value);
        }
        let request =
            request_from_parts("api", "1.0.0", "prod", &workdir, "tenkai:release:api@1.0.0");
        let executor = selected_software_executor()
            .unwrap_or_else(|| panic!("{value} adapter missing after tenkai_executor::install()"));
        let err = executor.apply(&request).unwrap_err().to_string();
        assert!(
            err.contains(needle),
            "{value} adapter error {err:?} missing {needle:?}"
        );
    }

    unsafe {
        std::env::remove_var("TENKAI_SOFTWARE_EXECUTOR");
    }
    let _ = std::fs::remove_dir_all(root);
}
