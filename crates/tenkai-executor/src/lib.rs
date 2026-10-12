//! Kubernetes software-executor adapters. Hosts call [`install`] at process start.

mod in_process_kubernetes;
mod vllm_model_runtime;

pub use in_process_kubernetes::{
    ClusterApplyApi, FIELD_MANAGER, InProcessKubernetesExecutor, LiveKubeApi, WorkloadCondition,
    WorkloadObservation, selected_in_process_executor,
};
pub use vllm_model_runtime::{
    HttpSmokeProbe, SmokeProbe, VllmConfig, VllmExecutorFactory, VllmModelRuntimeExecutor,
};

/// Register the in-process Kubernetes adapter with Tenkai's executor selector.
pub fn install() {
    tenkai::software_executor::install_in_process_software_executor(|| {
        Box::new(selected_in_process_executor())
    });
    tenkai::model_runtime::install_model_runtime_executor_factory(std::sync::Arc::new(
        VllmExecutorFactory,
    ));
}
