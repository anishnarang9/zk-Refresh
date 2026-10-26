//! Independent compiler-map target; no key, credential or state admission.
pub use dynark_native_client::{ClientError, Digest, OperationControl};
#[path = "../src/v3_input_map.rs"]
mod input_map;
