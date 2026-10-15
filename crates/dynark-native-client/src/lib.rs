#![forbid(unsafe_code)]

mod client;
mod control;
mod identity;
mod witness;
mod worker;
mod v2;

pub use client::*;
pub use control::*;
pub use identity::*;
pub use witness::*;
pub use worker::*;
pub use v2::*;

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
