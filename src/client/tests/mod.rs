use tonic::Status;

mod action_lifecycle;
mod helper_units;
mod lease_lifecycle;
mod mock_action_rpc;
mod mock_lease_rpc;
mod mock_object_rpc;
mod mock_relation_rpc;
mod mock_router;
mod mock_state;
mod object_lifecycle;
mod plan_kind_list;
mod relation_lifecycle;
mod remote;

#[test]
fn unique_conflict_treats_already_exists_and_internal_unique_as_the_same() {
    assert!(super::is_unique_conflict(&Status::already_exists(
        "object exists"
    )));
    assert!(super::is_unique_conflict(&Status::internal(
        "UNIQUE constraint failed: objects.id"
    )));
    assert!(!super::is_unique_conflict(&Status::internal(
        "object IDs with audit history cannot be reused"
    )));
    assert!(!super::is_unique_conflict(&Status::internal(
        "storage unavailable"
    )));
    assert!(!super::is_unique_conflict(&Status::not_found("missing")));
}
