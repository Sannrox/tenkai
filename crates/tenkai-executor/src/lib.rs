//! Software-executor adapters. Hosts call [`install`] at process start.

mod docker;
mod helm;
mod in_process_kubernetes;
mod kubernetes;
mod kubernetes_model_runtime;

pub use docker::{
    DOCKER_TOPOLOGY_DIR, DOCKER_TOPOLOGY_FILE, DockerHostExecutor, DockerHostTopology,
    load_topology, validate_topology,
};
pub use helm::HelmSoftwareExecutor;
pub use in_process_kubernetes::{
    ClusterApplyApi, FIELD_MANAGER, InProcessKubernetesExecutor, LiveKubeApi, WorkloadCondition,
    WorkloadObservation, selected_in_process_executor,
};
pub use kubernetes::KubernetesSoftwareExecutor;
pub use kubernetes_model_runtime::{
    HttpSmokeProbe, KubernetesModelRuntimeExecutor, KubernetesModelRuntimeFactory, NgcEntitlement,
    ServingConfig, ServingEngine, SmokeProbe,
};

/// Register CLI and in-process adapters with Tenkai's executor selector.
pub fn install() {
    tenkai::software_executor::install_helm_software_executor(|| {
        Box::new(HelmSoftwareExecutor::default())
    });
    tenkai::software_executor::install_kubernetes_software_executor(|| {
        Box::new(KubernetesSoftwareExecutor::default())
    });
    tenkai::software_executor::install_docker_software_executor(|| {
        Box::new(DockerHostExecutor::default())
    });
    tenkai::software_executor::install_in_process_software_executor(|| {
        Box::new(selected_in_process_executor())
    });
    tenkai::model_runtime::install_model_runtime_executor_factory(std::sync::Arc::new(
        KubernetesModelRuntimeFactory,
    ));
}
