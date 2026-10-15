//! Full-only v3 orchestration scaffold. Concrete imported/setup tokens are
//! required; neither caller labels nor six matching publics admit a credential.
//! The private envelope check below is not full relation or source authentication.
use crate::{
    AuthenticatedV3State, ClientError, Digest, FieldBytes, ImportedV3Credential, OperationControl,
    V3PreparedAction, V3SharedSetup, WitnessMode,
};
use dynark_bn254::{PublicPackage, ValidatedAssignment};

/// Untrusted complete generator output. No offsets, setup or credential labels
/// are accepted from the generator. Input-to-WTNS binding is mandatory at import.
pub struct V3FullWitnessCandidate<'a> {
    pub canonical_input: &'a [u8],
    pub complete_wtns: &'a [u8],
    pub mode: WitnessMode,
}

pub struct V3FullProofInput<'a> {
    pub credential: &'a ImportedV3Credential,
    pub setup: &'a V3SharedSetup,
    pub state: &'a dyn AuthenticatedV3State,
    pub prepared_action: &'a V3PreparedAction,
    /// Untrusted until verified under the imported holder modulus and action.
    pub holder_signature: &'a [u8; 256],
    pub candidate: V3FullWitnessCandidate<'a>,
}

/// No Debug/serialization; constructed from actual admitted inputs, not labels.
#[derive(Clone, PartialEq, Eq)]
struct V3PrivateBinding {
    package: Digest,
    profile: Digest,
    semantic_schema: Digest,
    credential: Digest,
    holder_key: Digest,
    issuer: Digest,
    issuer_version: u64,
    policy_version: u64,
    action_be: Digest,
    holder_signature: Digest,
    root_version: u64,
    source_sequence: u64,
    source_digest: Digest,
    slot: u16,
    allocation_epoch: u64,
    generation: u64,
    publics: [FieldBytes; 6],
}

/// Private complete relation admission; no deserializer or public constructor.
pub struct V3BoundWitness {
    package: PublicPackage,
    assignment: ValidatedAssignment,
    binding: V3PrivateBinding,
}
impl V3BoundWitness {
    /// Must authenticate/recheck live state, match imported DER/signature/action
    /// to all 751 declared input coordinates, and validate the full relation.
    /// Until the pinned input-builder/map dependencies exist, remain closed.
    pub fn open_full(
        _: V3FullProofInput<'_>,
        _: u64,
        _: &OperationControl,
    ) -> Result<Self, ClientError> {
        Err(ClientError::Unsupported)
    }
}

/// Only an internal envelope/coherence check, never a credential/proof gate.
/// Product admission additionally requires mapping all actual private inputs and
/// PublicPackage::validate_assignment against the authenticated six fields.
fn check_full_envelope(
    expected: &V3PrivateBinding,
    installed: &V3PrivateBinding,
    publics: &[FieldBytes],
    witness: &[u8],
    mode: WitnessMode,
) -> Result<(), ClientError> {
    use ark_bn254::Fr;
    use ark_ff::{BigInteger, PrimeField};
    use ark_serialize::CanonicalDeserialize;

    // Fixed bounded-v3 profile dimensions; no candidate-supplied count controls
    // allocation or changes the admitted envelope. No relation is checked here.
    const COORDINATES: usize = 784_796;
    const WITNESS_BYTES: usize = 76 + 32 * COORDINATES;
    if mode != WitnessMode::Full {
        return Err(ClientError::Unsupported);
    }
    if witness.len() != WITNESS_BYTES
        || &witness[..4] != b"wtns"
        || witness[4..12] != [2, 0, 0, 0, 2, 0, 0, 0]
        || witness[12..28] != [1, 0, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0]
        || witness[28..60] != Fr::MODULUS.to_bytes_le()
        || witness[60..64] != (COORDINATES as u32).to_le_bytes()
        || witness[64..68] != 2u32.to_le_bytes()
        || witness[68..76] != (32 * COORDINATES as u64).to_le_bytes()
        || publics.len() != 6
    {
        return Err(ClientError::Encoding);
    }
    let mut one = [0; 32];
    one[0] = 1;
    if witness[76..108] != one {
        return Err(ClientError::Encoding);
    }
    for word in witness[76..]
        .chunks_exact(32)
        .chain(publics.iter().map(|word| &word[..]))
    {
        Fr::deserialize_compressed(word).map_err(|_| ClientError::Encoding)?;
    }
    let mut action_le = expected.action_be;
    action_le.reverse();
    if expected != installed || publics != expected.publics.as_slice() || publics[4] != action_le {
        return Err(ClientError::Identity);
    }
    for (index, public) in publics.iter().enumerate() {
        if witness[108 + 32 * index..140 + 32 * index] != *public {
            return Err(ClientError::Identity);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::{BigInteger, PrimeField};
    use dynark_native_client::{V3FullManifest, V3_COORDINATES, V3_WITNESS_BYTES};

    fn word(n: u8) -> FieldBytes {
        let mut word = [0; 32];
        word[0] = n;
        word
    }
    fn binding() -> V3PrivateBinding {
        let manifest = V3FullManifest::frozen_development().unwrap();
        let mut action = word(5);
        action.reverse();
        V3PrivateBinding {
            package: manifest.package.package_digest,
            profile: manifest.admission.profile,
            semantic_schema: manifest.admission.semantic_schema,
            credential: [21; 32],
            holder_key: [22; 32],
            issuer: [23; 32],
            issuer_version: 1,
            policy_version: 1,
            action_be: action,
            holder_signature: [24; 32],
            root_version: 0,
            source_sequence: 1,
            source_digest: [25; 32],
            slot: 7,
            allocation_epoch: 1,
            generation: 1,
            publics: [word(1), word(2), word(3), word(4), word(5), word(6)],
        }
    }
    fn envelope(binding: &V3PrivateBinding) -> Vec<u8> {
        // Synthetic canonical container only; zero private coordinates do not
        // satisfy the credential relation and this fixture proves no admission.
        let mut bytes = Vec::with_capacity(V3_WITNESS_BYTES);
        bytes.extend(b"wtns");
        bytes.extend(2u32.to_le_bytes());
        bytes.extend(2u32.to_le_bytes());
        bytes.extend(1u32.to_le_bytes());
        bytes.extend(40u64.to_le_bytes());
        bytes.extend(32u32.to_le_bytes());
        bytes.extend(Fr::MODULUS.to_bytes_le());
        bytes.extend((V3_COORDINATES as u32).to_le_bytes());
        bytes.extend(2u32.to_le_bytes());
        bytes.extend((32 * V3_COORDINATES as u64).to_le_bytes());
        bytes.resize(V3_WITNESS_BYTES, 0);
        bytes[76] = 1;
        for (index, word) in binding.publics.iter().enumerate() {
            bytes[108 + 32 * index..140 + 32 * index].copy_from_slice(word);
        }
        bytes
    }
    #[test]
    fn complete_full_envelope_binds_six_publics_and_private_credential_context() {
        let expected = binding();
        let witness = envelope(&expected);
        assert_eq!(
            check_full_envelope(
                &expected,
                &expected,
                &expected.publics,
                &witness,
                WitnessMode::Full
            ),
            Ok(()),
            "complete v3 envelope binding is implemented"
        );
        for index in 0..6 {
            let mut wrong = expected.publics;
            wrong[index][0] ^= 8;
            assert_eq!(
                check_full_envelope(&expected, &expected, &wrong, &witness, WitnessMode::Full),
                Err(ClientError::Identity)
            );
        }
        // Identical six public fields do not identify a private credential.
        // Local binding must reject an installed witness from another context.
        for field in 0..8 {
            let mut other = expected.clone();
            match field {
                0 => other.credential[0] ^= 1,
                1 => other.holder_key[0] ^= 1,
                2 => other.action_be[31] ^= 1,
                3 => other.holder_signature[0] ^= 1,
                4 => other.package[0] ^= 1,
                5 => other.allocation_epoch += 1,
                6 => other.generation += 1,
                _ => other.source_sequence += 1,
            }
            assert_eq!(
                check_full_envelope(
                    &expected,
                    &other,
                    &expected.publics,
                    &witness,
                    WitnessMode::Full
                ),
                Err(ClientError::Identity)
            );
        }
    }
    #[test]
    fn incremental_truncated_and_noncanonical_containers_are_not_full_candidates() {
        let binding = binding();
        let mut witness = envelope(&binding);
        assert_eq!(
            check_full_envelope(
                &binding,
                &binding,
                &binding.publics,
                &witness,
                WitnessMode::IncrementalV1
            ),
            Err(ClientError::Unsupported)
        );
        assert_eq!(
            check_full_envelope(
                &binding,
                &binding,
                &binding.publics,
                &witness[..76],
                WitnessMode::Full
            ),
            Err(ClientError::Encoding)
        );
        witness[76] = 0;
        assert_eq!(
            check_full_envelope(
                &binding,
                &binding,
                &binding.publics,
                &witness,
                WitnessMode::Full
            ),
            Err(ClientError::Encoding)
        );
        witness[76] = 1;
        witness[108..140].copy_from_slice(&Fr::MODULUS.to_bytes_le());
        assert_eq!(
            check_full_envelope(
                &binding,
                &binding,
                &binding.publics,
                &witness,
                WitnessMode::Full
            ),
            Err(ClientError::Encoding)
        );
    }
}
