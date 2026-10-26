//! The bound entry is compiled as the actual native library module. Its focused
//! unit coverage lives in src/v3_binding.rs; private source inclusion cannot
//! exercise the concrete admitted setup/state methods across a crate boundary.
pub use dynark_native_client::{V3BoundWitness, V3FullProofInput};
