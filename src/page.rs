//! Cursor paging shared by catalog HTTP list routes.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::schema_contract::omitted_when_none;

/// Default page size for catalog list routes.
pub const DEFAULT_PAGE_LIMIT: u32 = 50;
/// Maximum page size accepted by catalog list routes.
pub const MAX_PAGE_LIMIT: u32 = 100;

/// Query parameters for cursor-paged catalog lists.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PageQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

impl PageQuery {
    /// Resolved page size, or a caller-facing error when `limit` is out of range.
    pub fn limit(&self) -> Result<usize, String> {
        let limit = self.limit.unwrap_or(DEFAULT_PAGE_LIMIT);
        if (1..=MAX_PAGE_LIMIT).contains(&limit) {
            Ok(limit as usize)
        } else {
            Err(format!("limit must be between 1 and {MAX_PAGE_LIMIT}"))
        }
    }
}

/// One page of catalog list items with an exclusive cursor for the next page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Page<T> {
    pub items: Vec<T>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = omitted_when_none)]
    pub next_cursor: Option<String>,
}

/// Sort `items` by `id`, skip through `cursor` (exclusive), and take `limit`.
pub fn page_items<T>(
    mut items: Vec<T>,
    limit: usize,
    cursor: Option<&str>,
    id: impl Fn(&T) -> &str,
) -> Page<T> {
    items.sort_by(|left, right| id(left).cmp(id(right)));
    if let Some(cursor) = cursor {
        items.retain(|item| id(item) > cursor);
    }
    let has_more = items.len() > limit;
    if has_more {
        items.truncate(limit);
    }
    let next_cursor = has_more
        .then(|| items.last().map(|item| id(item).to_string()))
        .flatten();
    Page { items, next_cursor }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_by_exclusive_id_cursor() {
        let items = vec!["a", "c", "b"];
        let first = page_items(items.clone(), 1, None, |item| *item);
        assert_eq!(first.items, ["a"]);
        assert_eq!(first.next_cursor.as_deref(), Some("a"));
        let second = page_items(items.clone(), 1, first.next_cursor.as_deref(), |item| *item);
        assert_eq!(second.items, ["b"]);
        assert_eq!(second.next_cursor.as_deref(), Some("b"));
        let last = page_items(items, 1, second.next_cursor.as_deref(), |item| *item);
        assert_eq!(last.items, ["c"]);
        assert_eq!(last.next_cursor, None);
    }

    #[test]
    fn empty_list_has_no_cursor() {
        let page = page_items(Vec::<String>::new(), 10, None, String::as_str);
        assert!(page.items.is_empty());
        assert_eq!(page.next_cursor, None);
    }

    #[test]
    fn rejects_zero_and_oversized_limit() {
        assert!(
            PageQuery {
                limit: Some(0),
                cursor: None
            }
            .limit()
            .is_err()
        );
        assert!(
            PageQuery {
                limit: Some(MAX_PAGE_LIMIT + 1),
                cursor: None
            }
            .limit()
            .is_err()
        );
        assert_eq!(
            PageQuery::default().limit().unwrap(),
            DEFAULT_PAGE_LIMIT as usize
        );
    }
}
