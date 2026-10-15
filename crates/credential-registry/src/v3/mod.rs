//! Separate bounded-v3 registry tree namespace. Protocol authentication is not
//! implemented in this first slice. The RED scaffold cannot admit membership.
mod tree;
pub use crate::{Error, Field};
pub use tree::{leaf_hash, Tree};

/// Fixed by credential-v3-bounded-der-v1; callers cannot select a leaf domain.
pub const LEAF_DOMAIN: u64 = 2026101504;
pub const DEPTH: usize = 10;
pub const CAPACITY: usize = 1 << DEPTH;
