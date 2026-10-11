//! Validated fixed-relation BN254 full and immutable anchored proving with bounded imports.
//! Setup provenance, trusted legacy context and application authorization remain caller obligations.
//! Full target validation is charged; quadratic correction has an explicit pair-work cap.
//! No raw/blinder, deterministic proof, vendor setup or RNG convenience API is re-exported.
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate self as dynark_bn254;
#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod test_fixture;

mod artifact;
mod anchored;
mod delta;
mod full;
pub mod import;
mod randomness;
mod reconstruction;
mod dynamic;

pub use artifact::{
    public_schema_digest, CircuitDescriptor, PackageIdentity, PublicPackage, Reduction, Shape,
    ValidatedAssignment,
};
pub use full::{prove, ProofStatement};
pub use anchored::{Anchor, UpdatingMaterial};
pub use delta::{AnchorBinding, Limits, MatrixTouch, PreparedTransition, RowDeltas, Transition, TransitionStats};
pub use reconstruction::{ReconstructionMaterial, ReconstructionPhase, WorkEvent};
pub use dynamic::{CapPolicy, DynamicConfig, DynamicPreparation, DynamicState, DynamicStatus, PreparationProgress, UpdateProgress, WorkLedger};

/// Typed failures never contain a partial proof or private assignment.
#[derive(Debug)]
pub enum Error {
    Busy,
    NotReady,
    Cancelled,
    Shape(&'static str),
    Matrix(&'static str),
    Schema(&'static str),
    Key(&'static str),
    IdentityMismatch,
    Bound(&'static str),
    Import(&'static str),
    Io(std::io::Error),
    DeltaCoordinate,
    ConstantMutation,
    Generation,
    AnchorBinding,
    UpdatingPackage,
    AssignmentCount,
    NonCanonicalField { coordinate: usize },
    ConstantOne,
    PublicStatement,
    Unsatisfied { row: usize },
    AssignmentPackage,
    Entropy { draw: usize, source: rand::Error },
    RejectionLimit { draw: usize },
    QuotientDegree,
    Arithmetic(ark_relations::r1cs::SynthesisError),
    Serialization(ark_serialize::SerializationError),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
impl From<ark_serialize::SerializationError> for Error {
    fn from(e: ark_serialize::SerializationError) -> Self {
        Self::Serialization(e)
    }
}
