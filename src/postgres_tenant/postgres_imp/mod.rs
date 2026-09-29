use postgres::{Client, Transaction};
use std::sync::mpsc::{self, SyncSender};
use std::thread::{self, JoinHandle};

pub(crate) use crate::storage::{
    AuditRecord, ChannelRecord, EnvironmentRecord, LeaseRecord, OfflineImportRecord,
    OfflineStepImportRecord, PlanRecord, PlanStatus, ProviderEventRecord, ReceiptRecord,
    ReleaseRecord, Result, RollbackRecord, RollbackStatus, RuntimeClaim, SCHEMA_VERSION,
    StoreError, provider_event_payloads_match, rollback_intent_digest,
};

pub struct Inner {
    worker: Worker<Client>,
}

enum WorkerMessage<C> {
    Run(Box<dyn FnOnce(&mut C) + Send + 'static>),
    Stop,
}

/// Keeps the synchronous client on one handle-free thread and bounds waiting callers.
struct Worker<C> {
    sender: SyncSender<WorkerMessage<C>>,
    thread: Option<JoinHandle<()>>,
}

impl<C: Send + 'static> Worker<C> {
    fn start(initialize: impl FnOnce() -> Result<C> + Send + 'static) -> Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(0);
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("tenkai-postgres-client".into())
            .spawn(move || {
                let mut client = match initialize() {
                    Ok(client) => {
                        if ready_sender.send(Ok(())).is_err() {
                            return;
                        }
                        client
                    }
                    Err(error) => {
                        let _ = ready_sender.send(Err(error));
                        return;
                    }
                };

                while let Ok(WorkerMessage::Run(work)) = receiver.recv() {
                    work(&mut client);
                }
            })
            .map_err(|error| {
                StoreError::Postgres(format!("failed to start postgres worker: {error}"))
            })?;

        match ready_receiver.recv() {
            Ok(Ok(())) => Ok(Self {
                sender,
                thread: Some(thread),
            }),
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(error)
            }
            Err(_) => {
                let _ = thread.join();
                Err(StoreError::AdapterUnavailable(
                    "postgres worker exited during startup".into(),
                ))
            }
        }
    }

    fn run<T: Send + 'static, E: Send + 'static>(
        &self,
        work: impl FnOnce(&mut C) -> std::result::Result<T, E> + Send + 'static,
        worker_failure: E,
    ) -> std::result::Result<T, E> {
        let (result_sender, result_receiver) = mpsc::sync_channel(1);
        let message = WorkerMessage::Run(Box::new(move |client| {
            let _ = result_sender.send(work(client));
        }));
        if self.sender.send(message).is_err() {
            return Err(worker_failure);
        }
        result_receiver.recv().unwrap_or(Err(worker_failure))
    }
}

impl<C> Drop for Worker<C> {
    fn drop(&mut self) {
        let _ = self.sender.send(WorkerMessage::Stop);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub(crate) fn pg(err: postgres::Error) -> StoreError {
    let message = err
        .as_db_error()
        .map(|database| format!("{} ({})", database.message(), database.code().code()))
        .unwrap_or_else(|| err.to_string());
    StoreError::Postgres(message)
}

pub(crate) fn ensure_environment_active(
    tx: &mut Transaction<'_>,
    environment: &str,
    operation: &str,
) -> Result<()> {
    let id = if environment.starts_with("tenkai:env:") {
        environment.to_owned()
    } else {
        crate::ontology::env_id(environment)
    };
    let configuration = tx
        .query_opt(
            "SELECT configuration_json FROM environments WHERE id=$1",
            &[&id],
        )
        .map_err(pg)?
        .map(|row| row.get::<_, String>(0));
    let configuration = match configuration {
        Some(configuration) => Some(configuration),
        None if id != environment => tx
            .query_opt(
                "SELECT configuration_json FROM environments WHERE id=$1",
                &[&environment],
            )
            .map_err(pg)?
            .map(|row| row.get::<_, String>(0)),
        None => None,
    };
    if configuration
        .as_deref()
        .and_then(crate::environment::retirement_from_configuration_json)
        .is_some()
    {
        return Err(StoreError::InvalidData {
            kind: "environment",
            detail: format!("retired environment {environment} cannot accept {operation}"),
        });
    }
    Ok(())
}

mod catalog;
mod channels;
mod connect;
mod fixtures;
mod fixtures_reset;
mod leases;
mod plans;
mod provider_claim;
mod provider_lifecycle;
mod provider_queue;
mod receipts;
mod reconcile;
mod rollbacks;
mod runtime;
mod schema;

pub(crate) use leases::{lock_lease, require_lease, require_plan_environment};
pub(crate) use schema::migrate_tenant_schema;

impl Inner {
    pub(crate) fn with_schema<T: Send + 'static>(
        &self,
        schema: &str,
        f: impl FnOnce(&mut Transaction<'_>) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let schema = schema.to_owned();
        self.worker.run(
            move |client| {
                let mut tx = client.transaction().map_err(pg)?;
                // Identifier is sanitized by tenant_schema_name (alnum + underscore only).
                tx.batch_execute(&format!("SET LOCAL search_path TO {schema}, public"))
                    .map_err(pg)?;
                let out = f(&mut tx)?;
                tx.commit().map_err(pg)?;
                Ok(out)
            },
            StoreError::Postgres("postgres worker thread panicked".into()),
        )
    }
}

impl Inner {
    pub fn check_health(&self) -> Result<()> {
        self.worker.run(
            |client| {
                client.query_one("SELECT 1", &[]).map_err(pg)?;
                Ok(())
            },
            StoreError::Postgres("postgres worker thread panicked".into()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::Worker;
    use crate::storage::StoreError;
    use std::thread;

    #[test]
    fn worker_reuses_one_handle_free_thread_for_multiple_operations() {
        let worker = Worker::start(|| {
            assert!(tokio::runtime::Handle::try_current().is_err());
            Ok::<_, StoreError>(thread::current().id())
        })
        .unwrap();
        let caller = thread::current().id();
        let worker_thread = worker
            .run(
                |owner| {
                    assert_eq!(*owner, thread::current().id());
                    assert!(tokio::runtime::Handle::try_current().is_err());
                    Ok::<_, StoreError>(thread::current().id())
                },
                StoreError::Poisoned,
            )
            .unwrap();
        let later_worker_thread = worker
            .run(
                |owner| {
                    assert_eq!(*owner, thread::current().id());
                    assert!(tokio::runtime::Handle::try_current().is_err());
                    Ok::<_, StoreError>(thread::current().id())
                },
                StoreError::Poisoned,
            )
            .unwrap();

        assert_ne!(worker_thread, caller);
        assert_eq!(later_worker_thread, worker_thread);
    }
}
