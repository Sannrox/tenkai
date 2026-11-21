//! Catalog property-index lookup used by embedded and remote sessions.

/// Property-index lookup with optional value filter, integer order, and limit.
#[derive(Clone, Copy, Debug)]
pub struct PropertyIndexQuery<'a> {
    pub kind: &'a str,
    pub key: &'a str,
    pub value: &'a str,
    pub matching_key: Option<&'a str>,
    pub matching_values: &'a [&'a str],
    pub equals_key: Option<&'a str>,
    pub equals_value: Option<&'a str>,
    pub order_key: Option<&'a str>,
    pub descending: bool,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

impl<'a> PropertyIndexQuery<'a> {
    pub fn new(kind: &'a str, key: &'a str, value: &'a str) -> Self {
        Self {
            kind,
            key,
            value,
            matching_key: None,
            matching_values: &[],
            equals_key: None,
            equals_value: None,
            order_key: None,
            descending: false,
            limit: None,
            offset: None,
        }
    }
}
