//! Explicit bounded-v3 authentication contract. Implementing the trait or
//! constructing these records does not authenticate chain, issuer or clock data.
//! A product adapter must verify those authorities before issuing a snapshot.
use crate::{
    ClientError, Digest, FieldBytes, OperationControl, V3CredentialSummary, V3FullManifest,
    V3OrdinaryVkIdentity,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V3SourceObservation {
    pub issuer_account: Digest,
    pub sequence: u64,
    pub digest: Digest,
    pub observed_at: u64,
    pub valid_until: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V3RootPublication {
    pub publisher_account: Digest,
    pub issuer_account: Digest,
    pub source_sequence: u64,
    pub source_digest: Digest,
    pub root: FieldBytes,
    pub root_version: u64,
    pub allocation_epoch: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V3Enrollment {
    pub issuer_account: Digest,
    pub config_account: Digest,
    pub issuer_hash: FieldBytes,
    pub policy_hash: FieldBytes,
    pub profile: Digest,
    pub circuit: Digest,
    pub issuer_version: u64,
    pub policy_version: u64,
    pub issuer_enabled: bool,
    pub policy_enabled: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V3AuthenticatedClock {
    pub finalized_slot: u64,
    pub unix_timestamp: u64,
    pub valid_until: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V3FinalizedAction {
    pub request_account: Digest,
    pub queue_account: Digest,
    pub config_account: Digest,
    pub action_be: Digest,
    pub nonce: Digest,
    pub deadline: u64,
    pub consumed: bool,
}
/// Holder-private membership context; deliberately no Debug or serialization.
#[derive(Clone, PartialEq, Eq)]
pub struct V3StateSnapshot {
    pub source: V3SourceObservation,
    pub publication: V3RootPublication,
    pub enrollment: V3Enrollment,
    pub clock: V3AuthenticatedClock,
    pub action: V3FinalizedAction,
    pub adapter_key: V3OrdinaryVkIdentity,
    pub slot: u16,
    pub siblings: [FieldBytes; 10],
    pub generation: u64,
}
/// Trusted verifier capability. Implementations MUST authenticate finalized
/// request/config/enrollment/clock/queue accounts and source/publisher authorities,
/// verify source signatures and exact current heads, and bind allocation/path.
/// Synthetic test implementations establish no product authentication evidence.
pub trait AuthenticatedV3State {
    fn authenticated_snapshot(
        &self,
        now: u64,
        control: &OperationControl,
    ) -> Result<V3StateSnapshot, ClientError>;
}
impl V3StateSnapshot {
    /// Pure coherence check for already authenticated records; it cannot admit
    /// the adapter key or authorize an operation. The input builder must also
    /// call the manifest admission gate and the live authenticated capability.
    pub(crate) fn validate_record_coherence(
        &self,
        _: &V3CredentialSummary,
        _: &V3FullManifest,
        _: u64,
    ) -> Result<(), ClientError> {
        // RED scaffold: no unimplemented authentication contract can authorize.
        Err(ClientError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(n: u8) -> FieldBytes {
        let mut word = [0; 32];
        word[0] = n;
        word
    }
    fn fixture() -> (V3CredentialSummary, V3FullManifest, V3StateSnapshot) {
        let manifest = V3FullManifest::frozen_development().unwrap();
        let credential = V3CredentialSummary {
            layout: 0,
            tbs_digest: [1; 32],
            holder_modulus_be: [2; 256],
            issuer_hash: word(3),
            policy_hash: word(4),
            not_before: 100,
            not_after: 200,
            signed_aki: [5; 20],
            signed_organization: [6; 16],
            signed_group: [7; 32],
            structural_offsets: [0; 9],
        };
        let state = V3StateSnapshot {
            source: V3SourceObservation {
                issuer_account: [8; 32],
                sequence: 2,
                digest: [9; 32],
                observed_at: 140,
                valid_until: 170,
            },
            publication: V3RootPublication {
                publisher_account: [10; 32],
                issuer_account: [8; 32],
                source_sequence: 2,
                source_digest: [9; 32],
                root: word(11),
                root_version: 3,
                allocation_epoch: 1,
            },
            enrollment: V3Enrollment {
                issuer_account: [8; 32],
                config_account: [12; 32],
                issuer_hash: word(3),
                policy_hash: word(4),
                profile: manifest.admission.profile,
                circuit: manifest.package.circuit_digest,
                issuer_version: 1,
                policy_version: 1,
                issuer_enabled: true,
                policy_enabled: true,
            },
            clock: V3AuthenticatedClock {
                finalized_slot: 100,
                unix_timestamp: 150,
                valid_until: 160,
            },
            action: V3FinalizedAction {
                request_account: [13; 32],
                queue_account: [14; 32],
                config_account: [12; 32],
                action_be: {
                    let mut n = word(15);
                    n.reverse();
                    n
                },
                nonce: [16; 32],
                deadline: 180,
                consumed: false,
            },
            adapter_key: V3OrdinaryVkIdentity {
                file_sha256: manifest.ordinary_vk_file_sha256,
                tagged_digest: [17; 32],
                root_receipt_sha256: [18; 32],
            },
            slot: 7,
            siblings: [word(19); 10],
            generation: 1,
        };
        (credential, manifest, state)
    }
    #[test]
    fn coherent_source_publisher_enrollment_clock_and_action_are_required() {
        let (credential, manifest, state) = fixture();
        assert_eq!(
            state.validate_record_coherence(&credential, &manifest, 150),
            Ok(())
        );
        let mut wrong = state.clone();
        wrong.publication.source_sequence += 1;
        assert_eq!(
            wrong.validate_record_coherence(&credential, &manifest, 150),
            Err(ClientError::StaleIssuer)
        );
        wrong = state.clone();
        wrong.publication.source_digest[0] ^= 1;
        assert_eq!(
            wrong.validate_record_coherence(&credential, &manifest, 150),
            Err(ClientError::StaleIssuer)
        );
        wrong = state.clone();
        wrong.publication.issuer_account[0] ^= 1;
        assert_eq!(
            wrong.validate_record_coherence(&credential, &manifest, 150),
            Err(ClientError::Identity)
        );
        wrong = state.clone();
        wrong.enrollment.policy_hash = word(20);
        assert_eq!(
            wrong.validate_record_coherence(&credential, &manifest, 150),
            Err(ClientError::Identity)
        );
        wrong = state.clone();
        wrong.enrollment.issuer_enabled = false;
        assert_eq!(
            wrong.validate_record_coherence(&credential, &manifest, 150),
            Err(ClientError::StaleIssuer)
        );
        wrong = state.clone();
        wrong.enrollment.policy_enabled = false;
        assert_eq!(
            wrong.validate_record_coherence(&credential, &manifest, 150),
            Err(ClientError::Identity)
        );
        wrong = state.clone();
        wrong.action.config_account[0] ^= 1;
        assert_eq!(
            wrong.validate_record_coherence(&credential, &manifest, 150),
            Err(ClientError::Identity)
        );
    }
    #[test]
    fn expired_clock_source_action_and_consumed_requests_are_rejected() {
        let (credential, manifest, state) = fixture();
        assert_eq!(
            state.validate_record_coherence(&credential, &manifest, 161),
            Err(ClientError::Deadline)
        );
        assert_eq!(
            state.validate_record_coherence(&credential, &manifest, 149),
            Err(ClientError::Deadline)
        );
        let mut wrong = state.clone();
        wrong.source.valid_until = 149;
        assert_eq!(
            wrong.validate_record_coherence(&credential, &manifest, 150),
            Err(ClientError::StaleIssuer)
        );
        wrong = state.clone();
        wrong.action.deadline = 149;
        assert_eq!(
            wrong.validate_record_coherence(&credential, &manifest, 150),
            Err(ClientError::Expired)
        );
        wrong = state.clone();
        wrong.action.consumed = true;
        assert_eq!(
            wrong.validate_record_coherence(&credential, &manifest, 150),
            Err(ClientError::Completed)
        );
        let mut expired = credential.clone();
        expired.not_after = 149;
        assert_eq!(
            state.validate_record_coherence(&expired, &manifest, 150),
            Err(ClientError::Expired)
        );
    }
    #[test]
    fn malformed_path_action_and_missing_versions_are_rejected() {
        let (credential, manifest, state) = fixture();
        let mut wrong = state.clone();
        wrong.slot = 1024;
        assert_eq!(
            wrong.validate_record_coherence(&credential, &manifest, 150),
            Err(ClientError::Bound)
        );
        wrong = state.clone();
        wrong.generation = 0;
        assert_eq!(
            wrong.validate_record_coherence(&credential, &manifest, 150),
            Err(ClientError::Generation)
        );
        wrong = state.clone();
        wrong.enrollment.issuer_version = 0;
        assert_eq!(
            wrong.validate_record_coherence(&credential, &manifest, 150),
            Err(ClientError::Version)
        );
        use ark_ff::{BigInteger, PrimeField};
        wrong = state.clone();
        wrong.siblings[0] = ark_bn254::Fr::MODULUS.to_bytes_le().try_into().unwrap();
        assert_eq!(
            wrong.validate_record_coherence(&credential, &manifest, 150),
            Err(ClientError::Encoding)
        );
        wrong = state.clone();
        wrong.action.action_be = ark_bn254::Fr::MODULUS.to_bytes_be().try_into().unwrap();
        assert_eq!(
            wrong.validate_record_coherence(&credential, &manifest, 150),
            Err(ClientError::Encoding)
        );
    }
}
