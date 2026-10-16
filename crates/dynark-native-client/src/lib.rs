#![forbid(unsafe_code)]

#[cfg(test)]
extern crate self as dynark_native_client;

mod client;
mod control;
mod identity;
mod witness;
mod worker;
mod v2;
mod v2_input;
mod v3_admission;
mod v3;
mod v3_input;
mod v3_setup;
mod v3_input_worker;
mod v3_input_map;

pub use client::*;
pub use control::*;
pub use identity::*;
pub use witness::*;
pub use worker::*;
pub use v2::*;
pub use v2_input::*;
pub use v3_admission::*;
pub use v3::*;
pub use v3_input::*;
pub use v3_setup::*;
pub use v3_input_worker::*;
pub use v3_input_map::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidationReason {
    Logout, Revoked, Expired, IssuerChanged, PolicyChanged, ProfileChanged,
    ActionChanged, KeyLost, Corruption, Completed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientError {
    Identity, Encoding, Bound, Version, Generation, Superseded, Cancelled,
    Deadline, StaleIssuer, Revoked, Expired, RebuildRequired, Unsupported,
    Invalidated(InvalidationReason), UncertainOutcome, RetryExhausted,
    Completed, State, Worker, Io, Relation, Proof, Entropy,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{self:?}") }
}
impl std::error::Error for ClientError {}
