//! Validated, fixed-relation BN254 full proving. Setup provenance is a caller obligation.
//! No vendor setup, fixed-blinder, matrix wrapper, cache, or RNG convenience API is re-exported.
#![forbid(unsafe_code)]

mod artifact;
mod full;
mod randomness;

pub use artifact::{
    public_schema_digest, CircuitDescriptor, PackageIdentity, PublicPackage, Reduction, Shape,
    ValidatedAssignment,
};
pub use full::{prove, ProofStatement};

/// Typed failures never contain a partial proof or private assignment.
#[derive(Debug)]
pub enum Error {
    Shape(&'static str),
    Matrix(&'static str),
    Schema(&'static str),
    Key(&'static str),
    IdentityMismatch,
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
