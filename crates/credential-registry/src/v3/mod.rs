//! Separate bounded-v3 membership math. Protocol authentication is not
//! implemented in this first slice; tree membership alone grants no authority.
mod tree;
pub use crate::{Error, Field};
pub use tree::{leaf_hash, Tree};

/// Fixed by credential-v3-bounded-der-v1; callers cannot select a leaf domain.
pub const LEAF_DOMAIN: u64 = 2026101504;
pub const DEPTH: usize = 10;
pub const CAPACITY: usize = 1 << DEPTH;
