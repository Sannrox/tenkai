//! Kubernetes software-executor adapters. Hosts call [`install`] at process start.

mod in_process_kubernetes;

pub use in_process_kubernetes::{
    FIELD_MANAGER, InProcessKubernetesExecutor, LiveKubeApi, selected_in_process_executor,
};

/// Register the in-process Kubernetes adapter with Tenkai's executor selector.
pub fn install() {
    tenkai::software_executor::install_in_process_software_executor(|| {
        Box::new(selected_in_process_executor())
    });
}
