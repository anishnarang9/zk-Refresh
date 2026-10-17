//! Request-bound v3 Full proving from a concrete local verifier, signed history
//! and the independently admitted complete relation. Deployment-pin provenance
//! remains trusted application configuration; a proof is not execution authority.
use crate::{
    ClientError, Digest, FieldBytes, ImportedV3Credential, OperationControl, V3CompilerInputMap,
    V3InputWorker, V3PreparedAction, V3RequestStateSource, V3SharedSetup, V3CheckedRelation, WitnessMode,
};
use dynark_bn254::{PublicPackage, ValidatedAssignment};
use sha2::{Digest as _, Sha256};

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
    pub state: &'a V3RequestStateSource<'a>,
    pub worker: &'a V3InputWorker,
    pub input_map: &'a V3CompilerInputMap,
    pub prepared_action: &'a V3PreparedAction,
    /// Untrusted until verified under the imported holder modulus and action.
    pub holder_signature: &'a [u8; 256],
    pub candidate: V3FullWitnessCandidate<'a>,
}

/// No Debug/serialization; constructed from actual admitted inputs, not labels.
#[derive(Clone, PartialEq, Eq)]
struct V3PrivateBinding {
    package: Digest,
    live_context: Digest,
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
    statement: dynark_bn254::ProofStatement,
}
impl V3BoundWitness {
    /// Every gate must succeed before returning a bound randomized ordinary
    /// proof. Candidate JSON/WTNS remain untrusted; neither a caller state trait
    /// nor matching six public values can bypass full input/relation checks.
    /// `now` must agree with the trusted local wall clock at operation start.
    pub fn open_full(
        input: V3FullProofInput<'_>,
        now: u64,
        control: &OperationControl,
    ) -> Result<Self, ClientError> {
        control.check()?;
        if input.candidate.mode != WitnessMode::Full { return Err(ClientError::Unsupported); }
        check_operation_clock(now, crate::v3_live_state::wall_clock()?)?;
        input.setup.manifest().check_identity(input.setup.package().identity(), input.setup.package().shape())?;
        let action = input.prepared_action.action_be();
        let before = input.state.authenticate(input.credential, input.setup, action, input.holder_signature, control)?;
        let candidate = input.worker.build(&before.request, control)?;
        let checked = V3CheckedRelation::check(input.setup, input.input_map, &candidate,
            input.candidate.canonical_input, input.candidate.complete_wtns, WitnessMode::Full, control)?;
        let after = input.state.authenticate(input.credential, input.setup, action, input.holder_signature, control)?;
        recheck_frames(&before, &after, input.credential, input.setup, control)?;
        let binding = V3PrivateBinding {
            package: input.setup.package().identity().package_digest,
            live_context: before.context,
            profile: input.setup.manifest().admission.profile,
            semantic_schema: input.setup.manifest().admission.semantic_schema,
            credential: Sha256::digest(input.credential.certificate_der()).into(),
            holder_key: Sha256::digest(input.credential.summary().holder_modulus_be).into(),
            issuer: input.credential.summary().issuer_hash,
            issuer_version: before.snapshot.enrollment.issuer_version,
            policy_version: before.snapshot.enrollment.policy_version,
            action_be: action,
            holder_signature: Sha256::digest(input.holder_signature).into(),
            root_version: before.snapshot.publication.root_version,
            source_sequence: before.snapshot.source.sequence,
            source_digest: before.snapshot.source.digest,
            slot: before.snapshot.slot,
            allocation_epoch: before.snapshot.publication.allocation_epoch,
            generation: before.snapshot.generation,
            publics: before.publics,
        };
        let assignment = checked.into_assignment();
        control.check()?;
        let statement = dynark_bn254::prove(input.setup.package(), &assignment, binding.generation, &mut rand::rngs::OsRng)
            .map_err(|error| match error {
                dynark_bn254::Error::Entropy { .. } | dynark_bn254::Error::RejectionLimit { .. } => ClientError::Entropy,
                _ => ClientError::Proof,
            });
        control.check()?;
        let statement = statement?;
        let verification = verify_bound_statement(input.setup.package(), &statement, binding.generation, &binding.publics);
        control.check()?;
        verification?;
        let final_state = input.state.authenticate(input.credential, input.setup, action, input.holder_signature, control)?;
        recheck_frames(&after, &final_state, input.credential, input.setup, control)?;
        control.check()?;
        Ok(Self { package: input.setup.package().clone(), assignment, binding, statement })
    }

    /// Ordinary proof and exact statement only; no assignment or execution right.
    /// Submission must reauthenticate current state and enforce current-root and
    /// request-consumption policy at the application boundary.
    pub fn ordinary_full_proof(&self) -> &dynark_bn254::ProofStatement {
        &self.statement
    }
}

fn check_operation_clock(requested: u64, actual: u64) -> Result<(), ClientError> {
    if requested.abs_diff(actual) > 1 { return Err(ClientError::Deadline); }
    Ok(())
}
fn recheck_frames(
    before: &crate::v3_live_state::AuthenticatedFrame,
    after: &crate::v3_live_state::AuthenticatedFrame,
    credential: &ImportedV3Credential,
    setup: &V3SharedSetup,
    control: &OperationControl,
) -> Result<(), ClientError> {
    if before.context != after.context || before.publics != after.publics || after.checked_at < before.checked_at {
        return Err(ClientError::Superseded);
    }
    crate::v3::check_full_state_recheck(&before.snapshot, &after.snapshot, credential.summary(), setup.manifest(), after.checked_at, control)
}
fn verify_bound_statement(
    package: &PublicPackage,
    statement: &dynark_bn254::ProofStatement,
    generation: u64,
    expected: &[FieldBytes; 6],
) -> Result<(), ClientError> {
    use ark_bn254::Fr;
    use ark_serialize::CanonicalDeserialize;
    if statement.package != package.identity() || statement.generation != generation || statement.public_values.len() != 6 {
        return Err(ClientError::Identity);
    }
    let public: Vec<_> = expected.iter().map(|word| Fr::deserialize_compressed(&word[..])
        .map_err(|_| ClientError::Encoding)).collect::<Result<_, _>>()?;
    if statement.public_values != public { return Err(ClientError::Identity); }
    let vk = package.ordinary_verifying_key();
    if vk.gamma_abc_g1.len() != 7 { return Err(ClientError::Identity); }
    match ordinary::Groth16::<ark_bn254::Bn254>::verify_proof(&ordinary::prepare_verifying_key(&vk), &statement.proof, &public) {
        Ok(true) => Ok(()),
        _ => Err(ClientError::Proof),
    }
}

/// Only an internal envelope/coherence check, never a credential/proof gate.
/// Product admission additionally requires mapping all actual private inputs and
/// PublicPackage::validate_assignment against the authenticated six fields.
#[cfg(test)]
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
            live_context: [29; 32],
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
    fn operation_clock_rejects_caller_backdating_and_future_time() {
        assert_eq!(check_operation_clock(100, 100), Ok(()));
        assert_eq!(check_operation_clock(100, 101), Ok(()));
        assert_eq!(check_operation_clock(98, 100), Err(ClientError::Deadline));
        assert_eq!(check_operation_clock(102, 100), Err(ClientError::Deadline));
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
