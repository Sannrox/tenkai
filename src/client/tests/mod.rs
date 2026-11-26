use tonic::Status;

use super::ClientError;
use crate::storage::StoreError;

mod action_lifecycle;
mod helper_units;
mod lease_lifecycle;
mod object_lifecycle;
mod plan_kind_list;
mod relation_lifecycle;

#[test]
fn unique_conflict_treats_already_exists_and_internal_unique_as_the_same() {
    assert!(super::is_unique_conflict(&ClientError::from_status(
        Status::already_exists("object exists")
    )));
    assert!(super::is_unique_conflict(&ClientError::from_status(
        Status::internal("UNIQUE constraint failed: objects.id")
    )));
    assert!(!super::is_unique_conflict(&ClientError::from_status(
        Status::internal("object IDs with audit history cannot be reused")
    )));
    assert!(!super::is_unique_conflict(&ClientError::from_status(
        Status::internal("storage unavailable")
    )));
    assert!(!super::is_unique_conflict(&ClientError::from_status(
        Status::not_found("missing")
    )));
    assert!(super::is_unique_conflict(&ClientError::from(
        StoreError::already_exists("object", "tenkai:conformance:object")
    )));
}
