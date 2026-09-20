use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::pb::sekai::{
    CreateObjectRequest, Decision, GovernedActionType, Lease, Link, Object, UpdateObjectRequest,
};

pub(super) type CapturedMetadata = (Option<String>, Option<String>);

#[derive(Clone)]
pub(super) struct MockSekaiState {
    pub(super) creates: Arc<Mutex<Vec<CreateObjectRequest>>>,
    pub(super) updates: Arc<Mutex<Vec<UpdateObjectRequest>>>,
    pub(super) governed_actions: Arc<Mutex<Vec<GovernedActionType>>>,
    pub(super) metadata: Arc<Mutex<Vec<CapturedMetadata>>>,
    pub(super) objects: Arc<Mutex<BTreeMap<String, Object>>>,
    pub(super) links: Arc<Mutex<BTreeMap<String, Link>>>,
    pub(super) leases: Arc<Mutex<BTreeMap<(String, String), Lease>>>,
    pub(super) decisions: Arc<Mutex<Vec<Decision>>>,
    pub(super) create_failures: Arc<AtomicUsize>,
    pub(super) create_internal_failures: Arc<AtomicUsize>,
    pub(super) update_failures: Arc<AtomicUsize>,
}

impl Default for MockSekaiState {
    fn default() -> Self {
        Self {
            creates: Arc::new(Mutex::new(Vec::new())),
            updates: Arc::new(Mutex::new(Vec::new())),
            governed_actions: Arc::new(Mutex::new(Vec::new())),
            metadata: Arc::new(Mutex::new(Vec::new())),
            objects: Arc::new(Mutex::new(BTreeMap::new())),
            links: Arc::new(Mutex::new(BTreeMap::new())),
            leases: Arc::new(Mutex::new(BTreeMap::new())),
            decisions: Arc::new(Mutex::new(Vec::new())),
            create_failures: Arc::new(AtomicUsize::new(0)),
            create_internal_failures: Arc::new(AtomicUsize::new(0)),
            update_failures: Arc::new(AtomicUsize::new(0)),
        }
    }
}

pub(super) fn mock_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

pub(super) fn mock_lease_key(namespace: &str, key: &str) -> (String, String) {
    (namespace.to_owned(), key.to_owned())
}

pub(super) fn consume_failure(counter: &AtomicUsize) -> bool {
    counter
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
            if remaining > 0 {
                Some(remaining - 1)
            } else {
                None
            }
        })
        .is_ok()
}
