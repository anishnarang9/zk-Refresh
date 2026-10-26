//! Pin the custom error ordinals consumed by v3 RPC callers.
//! Existing Execute tests cover the rejection variants and unchanged accounts.

use zk_fresh_program::application_v3::AppError;

#[test]
fn status_and_capacity_errors_keep_their_custom_rpc_ordinals() {
    assert_eq!(AppError::Status as u32, 705);
    assert_eq!(AppError::Capacity as u32, 708);
}
