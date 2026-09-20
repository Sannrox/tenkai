//! Relation, property-index, and kind-list query methods on `Ctx`.

use anyhow::Result;

use sekai_client::CallOptions;

use super::{Ctx, apply_remote_property_index, block_embedded};
use crate::pb::sekai::{
    FindByPropertyRequest, Link, ListFilter, ListObjectsRequest, ListObjectsResponse, Object,
};

impl Ctx {
    /// Create a link with a deterministic id; already-exists is treated as success.
    pub async fn link(&mut self, from_id: &str, to_id: &str, relation: &str) -> Result<()> {
        self.backend
            .relation_lifecycle()
            .link(from_id, to_id, relation)
            .await
    }

    /// Create one exact link and preserve duplicate errors for lock acquisition.
    pub(crate) async fn create_link_once(
        &mut self,
        link: Link,
    ) -> std::result::Result<(), tonic::Status> {
        self.backend
            .relation_lifecycle()
            .create_link_once(link)
            .await
    }

    pub async fn unlink(&mut self, from_id: &str, to_id: &str, relation: &str) -> Result<()> {
        self.backend
            .relation_lifecycle()
            .unlink(from_id, to_id, relation)
            .await
    }

    pub async fn linked(
        &mut self,
        object_id: &str,
        relation: &str,
        direction: &str,
    ) -> Result<Vec<Object>> {
        self.backend
            .relation_lifecycle()
            .linked(object_id, relation, direction)
            .await
    }

    pub async fn find_by_property(
        &mut self,
        kind: &str,
        key: &str,
        value: &str,
    ) -> Result<Vec<Object>> {
        self.find_by_property_matching(crate::embedded::PropertyIndexQuery::new(kind, key, value))
            .await
    }

    pub async fn find_by_property_matching(
        &mut self,
        query: crate::embedded::PropertyIndexQuery<'_>,
    ) -> Result<Vec<Object>> {
        anyhow::ensure!(
            !query.kind.trim().is_empty() && !query.key.trim().is_empty(),
            "find_by_property requires non-empty kind and key"
        );
        if let Some(filter_key) = query.matching_key {
            anyhow::ensure!(
                !filter_key.trim().is_empty(),
                "find_by_property matching key must be non-empty"
            );
        }
        if let Some(equals_key) = query.equals_key {
            anyhow::ensure!(
                !equals_key.trim().is_empty(),
                "find_by_property equals key must be non-empty"
            );
            anyhow::ensure!(
                query
                    .equals_value
                    .is_some_and(|value| !value.trim().is_empty()),
                "find_by_property equals value must be non-empty"
            );
        }
        if let Some(order_key) = query.order_key {
            anyhow::ensure!(
                !order_key.trim().is_empty(),
                "find_by_property order key must be non-empty"
            );
        }
        if let Some(store) = self.embedded_arc() {
            let kind = query.kind.to_string();
            let key = query.key.to_string();
            let value = query.value.to_string();
            let matching_key = query.matching_key.map(str::to_string);
            let matching_values = query
                .matching_values
                .iter()
                .map(|value| (*value).to_string())
                .collect::<Vec<_>>();
            let equals_key = query.equals_key.map(str::to_string);
            let equals_value = query.equals_value.map(str::to_string);
            let order_key = query.order_key.map(str::to_string);
            let descending = query.descending;
            let limit = query.limit;
            let offset = query.offset;
            return block_embedded(store, move |store| {
                let matching_refs = matching_values
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>();
                store.find_by_property_matching(crate::embedded::PropertyIndexQuery {
                    matching_key: matching_key.as_deref(),
                    matching_values: &matching_refs,
                    equals_key: equals_key.as_deref(),
                    equals_value: equals_value.as_deref(),
                    order_key: order_key.as_deref(),
                    descending,
                    limit,
                    offset,
                    ..crate::embedded::PropertyIndexQuery::new(&kind, &key, &value)
                })
            })
            .await;
        }
        if query.matching_key.is_some() && query.matching_values.is_empty() {
            return Ok(Vec::new());
        }
        let response: ListObjectsResponse = self
            .remote_unary(
                "/sekai.SekaiService/FindByProperty",
                FindByPropertyRequest {
                    kind: query.kind.into(),
                    key: query.key.into(),
                    value: query.value.into(),
                },
                CallOptions::default(),
            )
            .await?;
        apply_remote_property_index(response.objects, &query)
    }

    pub async fn links(&mut self, object_id: &str, relation: &str) -> Result<Vec<Link>> {
        self.backend
            .relation_lifecycle()
            .links(object_id, relation)
            .await
    }

    pub async fn list_kind(&mut self, kind: &str) -> Result<Vec<Object>> {
        if let Some(store) = self.embedded_arc() {
            let kind = kind.to_string();
            return block_embedded(store, move |store| store.list_kind(&kind)).await;
        }
        const PAGE_SIZE: i32 = 100;
        let mut objects = Vec::new();
        loop {
            let response: ListObjectsResponse = self
                .remote_unary(
                    "/sekai.SekaiService/ListObjects",
                    ListObjectsRequest {
                        filter: Some(ListFilter {
                            kind: kind.into(),
                            limit: PAGE_SIZE,
                            offset: objects.len() as i32,
                            ..Default::default()
                        }),
                    },
                    CallOptions::default(),
                )
                .await?;
            let received = response.objects.len();
            objects.extend(response.objects);
            if received < PAGE_SIZE as usize {
                return Ok(objects);
            }
        }
    }

    /// List ids of `kind` without materializing embedded object payloads.
    ///
    /// Remote adapters still page `ListObjects` and keep only ids; there is no
    /// cheaper name/id RPC on the vendored protocol.
    pub(crate) async fn list_kind_ids(&mut self, kind: &str) -> Result<Vec<String>> {
        if let Some(store) = self.embedded_arc() {
            let kind = kind.to_string();
            return block_embedded(store, move |store| store.list_kind_ids(&kind)).await;
        }
        Ok(self
            .list_kind(kind)
            .await?
            .into_iter()
            .map(|object| object.id)
            .collect())
    }
}
