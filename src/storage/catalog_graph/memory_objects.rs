//! Catalog objects of one in-memory partition (#1578).

use std::collections::{BTreeMap, BTreeSet};

use crate::pb::record::Object;

/// Objects by id with an index by kind, so a kind or property lookup reads
/// only that kind's objects instead of the whole partition. Planning makes
/// such lookups for every environment, so a scan made a fleet pass quadratic.
/// Every write goes through [`Self::insert`] and [`Self::remove`], which keep
/// the index equal to the objects.
#[derive(Clone, Default)]
pub(super) struct MemoryObjects {
    by_id: BTreeMap<String, Object>,
    by_kind: BTreeMap<String, BTreeSet<String>>,
}

impl MemoryObjects {
    pub(super) fn get(&self, id: &str) -> Option<&Object> {
        self.by_id.get(id)
    }

    pub(super) fn contains_key(&self, id: &str) -> bool {
        self.by_id.contains_key(id)
    }

    /// Objects of `kind`, in id order.
    pub(super) fn of_kind<'a>(&'a self, kind: &str) -> impl Iterator<Item = &'a Object> + 'a {
        self.by_kind
            .get(kind)
            .into_iter()
            .flatten()
            .filter_map(|id| self.by_id.get(id))
    }

    /// Store `object`, replacing the object with its id.
    pub(super) fn insert(&mut self, object: Object) {
        if let Some(previous) = self.by_id.get(&object.id)
            && previous.kind != object.kind
        {
            let (id, kind) = (previous.id.clone(), previous.kind.clone());
            self.unindex(&kind, &id);
        }
        self.by_kind
            .entry(object.kind.clone())
            .or_default()
            .insert(object.id.clone());
        self.by_id.insert(object.id.clone(), object);
    }

    pub(super) fn remove(&mut self, id: &str) -> Option<Object> {
        let removed = self.by_id.remove(id)?;
        self.unindex(&removed.kind, id);
        Some(removed)
    }

    fn unindex(&mut self, kind: &str, id: &str) {
        if let Some(ids) = self.by_kind.get_mut(kind) {
            ids.remove(id);
            if ids.is_empty() {
                self.by_kind.remove(kind);
            }
        }
    }
}
