//! Non-authorizing complete v3 relation boundary, tests-first RED only.
//!
//! Input candidate values must originate in the pinned native input worker.
//! Candidate JSON and WTNS are untrusted outputs, never expected-value sources.
//! Structural/cryptographic relation acceptance authenticates no chain account,
//! enrollment, allocation, clock, request, signer capability or application right.
//! V3BoundWitness::open_full remains closed until concrete live authorities and
//! exact admitted credential/action/state bindings are integrated separately.
use crate::{
    ClientError, OperationControl, V3CompilerInputMap, V3InputCandidate, V3SharedSetup, WitnessMode,
};
use dynark_bn254::ValidatedAssignment;

/// Private complete-assignment result, not a chain or application capability.
/// No public constructor, deserializer, Debug, or proof interface is supplied.
pub struct V3CheckedRelation {
    assignment: ValidatedAssignment,
}
impl V3CheckedRelation {
    /// Derive exact 14-key canonical JSON from the 751 checked input scalars;
    /// compare the supplied serialization byte-for-byte. Require Full mode,
    /// canonical 25,113,548-byte WTNS with 784,796 coordinates, constant one and
    /// the exact six public values. Compare all 751 input coordinates using the
    /// independently authenticated compiler map before relation evaluation.
    /// Validate every field and the entire R1CS using the admitted shared
    /// PublicPackage::validate_assignment before constructing this object.
    /// Check OperationControl at each bounded stage. No proof is created.
    pub fn check(
        _: &V3SharedSetup,
        _: &V3CompilerInputMap,
        _: &V3InputCandidate,
        _: &[u8],
        _: &[u8],
        _: WitnessMode,
        _: &OperationControl,
    ) -> Result<Self, ClientError> {
        Err(ClientError::Unsupported)
    }
}
