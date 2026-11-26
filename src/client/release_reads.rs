//! Release reads shared within one planning computation (#1575).
//!
//! Planning reads the same release, its verification claim, and its recall
//! claim from many helpers (selection, manifest, recall, pin, placement,
//! compatibility). Inside a [`ReleaseReadScope`], `Ctx::get` answers those ids
//! from the first read. The scope ends with the planning call, so apply
//! admission and every check before a write read the store again: a recall
//! recorded after planning still refuses the write.
//!
//! `Ctx` holds only a weak reference; the planning frame owns the memo, so a
//! dropped or failed planning future cannot leave it behind for a later apply.
//! Planning never writes release records; `put`, `create_once`, and `delete`
//! still forget an id they write.
//! A `Ctx` cloned inside the scope shares it, as it belongs to the same call.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::pb::record::Object;

use super::Ctx;

/// Ids that name a release or one of its claims share this prefix.
const RELEASE_PREFIX: &str = "tenkai:release:";

#[derive(Default)]
pub(crate) struct ReleaseReads(Mutex<HashMap<String, Option<Object>>>);

/// Keeps a planning call's release reads alive until dropped.
#[must_use = "release reads are shared only while the scope is held"]
pub(crate) struct ReleaseReadScope {
    _reads: Option<Arc<ReleaseReads>>,
}

impl Ctx {
    /// Share release reads on this context until the scope drops. A nested
    /// call inside an open scope reuses it.
    pub(crate) fn share_release_reads(&mut self) -> ReleaseReadScope {
        if self.release_reads.upgrade().is_some() {
            return ReleaseReadScope { _reads: None };
        }
        let reads = Arc::new(ReleaseReads::default());
        self.release_reads = Arc::downgrade(&reads);
        ReleaseReadScope {
            _reads: Some(reads),
        }
    }

    /// The memo answering `id`, when a scope is open and `id` is a release record.
    pub(super) fn release_reads_for(&self, id: &str) -> Option<Arc<ReleaseReads>> {
        id.starts_with(RELEASE_PREFIX)
            .then(|| self.release_reads.upgrade())
            .flatten()
    }

    pub(super) fn forget_release_read(&self, id: &str) {
        if let Some(reads) = self.release_reads_for(id) {
            reads.lock().remove(id);
        }
    }
}

impl ReleaseReads {
    pub(super) fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Option<Object>>> {
        self.0.lock().expect("release reads lock")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::client::Ctx;
    use crate::pb::record::Object;

    fn release(marker: &str) -> Object {
        Object {
            id: crate::ontology::release_id("api", "1.0.0"),
            kind: crate::ontology::KIND_RELEASE.into(),
            name: "api@1.0.0".into(),
            namespace: crate::ontology::NS.into(),
            external_id: String::new(),
            properties: HashMap::from([("marker".into(), marker.into())]),
            created: 1,
            updated: 1,
        }
    }

    async fn registered() -> (std::path::PathBuf, Ctx) {
        let database = std::env::temp_dir().join(format!(
            "tenkai-release-reads-{}-{}.db",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        (database, ctx)
    }

    async fn marker(ctx: &mut Ctx) -> String {
        let id = crate::ontology::release_id("api", "1.0.0");
        ctx.get(&id).await.unwrap().unwrap().properties["marker"].clone()
    }

    /// Inside a scope a release is read from the store once, except after the
    /// scoped context writes it; a write elsewhere is seen once the scope ends.
    #[tokio::test]
    async fn a_scope_reads_each_release_once_and_ends_fresh() {
        let (database, mut ctx) = registered().await;
        ctx.put(release("first")).await.unwrap();
        // Another writer, such as an operator recording a recall mid-pass.
        let mut writer = ctx.clone();

        let scope = ctx.share_release_reads();
        assert_eq!(marker(&mut ctx).await, "first");
        writer.put(release("second")).await.unwrap();
        assert_eq!(marker(&mut ctx).await, "first", "one read per scope");
        {
            let _nested = ctx.share_release_reads();
            assert_eq!(marker(&mut ctx).await, "first", "nested scopes share");
        }
        assert_eq!(marker(&mut ctx).await, "first");
        // A write through the scoped context replaces what it remembered.
        ctx.put(release("third")).await.unwrap();
        assert_eq!(marker(&mut ctx).await, "third");
        writer.put(release("fourth")).await.unwrap();
        drop(scope);

        assert_eq!(marker(&mut ctx).await, "fourth", "reads are fresh after");
        let _ = std::fs::remove_file(database);
    }
}
