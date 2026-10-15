//! Independent tests-first target; no library export or setup admission changes.
pub use dynark_native_client::{ClientError, Digest};
#[path = "../src/v3_action.rs"]
mod action;
