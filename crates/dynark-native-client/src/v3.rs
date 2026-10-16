//! Bounded-v3 identity records and exact reviewed ordinary-key receipt admission.
//! Receipt admission authenticates ordinary key identity only; it does not
//! authenticate the full PK/setup, issuer enrollment or application authorization.
use crate::{decode_digest, ClientError, Digest, V3AdmissionIdentity};
use dynark_bn254::{PackageIdentity, Shape};
use sha2::{Digest as _, Sha256};

pub const V3_COORDINATES: usize = 784_796;
pub const V3_WITNESS_BYTES: usize = 76 + 32 * V3_COORDINATES;

/// Three distinct commitments, supplied by an adapter that authenticated ROOT's
/// key-gate receipt. Public construction is data construction, not authentication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V3OrdinaryVkIdentity {
    pub file_sha256: Digest,
    pub tagged_digest: Digest,
    pub root_receipt_sha256: Digest,
}

/// Public development-key identity accepted against a fixed ROOT receipt.
/// Its private field prevents callers constructing admission from record data.
/// This token authenticates no issuer, status source, credential or application.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V3AdmittedAdapterKey {
    identity: V3OrdinaryVkIdentity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V3FullManifest {
    pub admission: V3AdmissionIdentity,
    pub package: PackageIdentity,
    pub ordinary_vk_file_sha256: Digest,
}
impl V3FullManifest {
    pub fn frozen_development() -> Result<Self, ClientError> {
        Ok(Self {
            admission: V3AdmissionIdentity::frozen_development()
                .map_err(|_| ClientError::Identity)?,
            package: PackageIdentity {
                circuit_digest: decode_digest(
                    "eae99530daf7331037f2d1c6dc93ccc582603bd448f38d06e6469c734e8252fe",
                )?,
                matrix_digest: decode_digest(
                    "da82ee7cfbe33f6780032bece071a4c2a11d84d4744ba230f4c5149ceb72a471",
                )?,
                proving_key_digest: decode_digest(
                    "14ddfd5773edda5cf02771ebfe2ac4e7af18437848d7822d6d28e2e0085bb671",
                )?,
                verifying_key_digest: decode_digest(
                    "2611d58c8c8d0b0c1f2c3f0facc4516e5c08e1fb3a7f14b16e32b948bc8f3c70",
                )?,
                package_digest: decode_digest(
                    "61d941890d823433468048dd1bd91da80c1bf7e1b3d2b6f5d509077a47ed06c8",
                )?,
            },
            ordinary_vk_file_sha256: decode_digest(
                "87edb4608c2140f3c7fddc8503e49b68931cda973711ce2c831bd44f1b98a875",
            )?,
        })
    }
    pub fn check(&self) -> Result<(), ClientError> {
        if *self != Self::frozen_development()? {
            return Err(ClientError::Identity);
        }
        Ok(())
    }
    pub fn check_identity(
        &self,
        package: PackageIdentity,
        shape: Shape,
    ) -> Result<(), ClientError> {
        self.check()?;
        if package != self.package
            || shape.assignment_len != V3_COORDINATES
            || shape.instance_len != 7
            || shape.constraint_rows != 793_681
            || shape.reduction_rows != 793_681
            || shape.domain_size != 1_048_576
        {
            return Err(ClientError::Identity);
        }
        Ok(())
    }
    /// Pure record-shape validation. Success establishes no adapter admission.
    pub fn validate_adapter_record_shape(
        &self,
        identity: V3OrdinaryVkIdentity,
    ) -> Result<(), ClientError> {
        self.check()?;
        if identity.file_sha256 != self.ordinary_vk_file_sha256
            || identity.tagged_digest == [0; 32]
            || identity.root_receipt_sha256 == [0; 32]
            || identity.tagged_digest == identity.file_sha256
            || identity.tagged_digest == self.package.verifying_key_digest
        {
            return Err(ClientError::Identity);
        }
        Ok(())
    }
    /// Admit only the exact ROOT-reviewed development-key receipt and identity.
    /// Exact byte authentication preserves its canonical schema/public order and
    /// package/profile/raw/tagged/engine commitments. This reads no key material
    /// and authenticates no issuer, status source, credential or application.
    pub fn admit_adapter_key(
        &self,
        identity: V3OrdinaryVkIdentity,
        receipt: &[u8],
    ) -> Result<V3AdmittedAdapterKey, ClientError> {
        self.check()?;
        if receipt.is_empty() {
            return Err(ClientError::Unsupported);
        }
        let expected = V3OrdinaryVkIdentity {
            file_sha256: self.ordinary_vk_file_sha256,
            tagged_digest: decode_digest(
                "2f9b770ff51ac399619a3127ddb32efad67697402f10c4549441a3578e4f9a4e",
            )?,
            root_receipt_sha256: decode_digest(
                "6a6fd9d207c778b085f56de3327ec15ccee886ab127de1e90e970da039fef429",
            )?,
        };
        // The expected receipt hash comes from reviewed source policy, never
        // from the caller's record or from a receipt's own declarations. Hashing
        // the exact 1458 canonical bytes authenticates every reviewed JSON field;
        // semantically equivalent reserialization is intentionally not admitted.
        if identity != expected
            || receipt.len() != 1458
            || <Digest>::from(Sha256::digest(receipt)) != expected.root_receipt_sha256
        {
            return Err(ClientError::Identity);
        }
        self.validate_adapter_record_shape(identity)?;
        Ok(V3AdmittedAdapterKey { identity })
    }
}

/// Non-authorizing record recheck for a future concrete state adapter. Coherent
/// caller-created records cannot establish chain, deployment or registry trust.
/// Reauthenticate both observations outside this helper before using its result.
pub(crate) fn check_full_state_recheck(
    before: &crate::V3StateSnapshot,
    after: &crate::V3StateSnapshot,
    credential: &crate::V3CredentialSummary,
    manifest: &V3FullManifest,
    now: u64,
    control: &crate::OperationControl,
) -> Result<(), ClientError> {
    control.check()?;
    if after.clock.finalized_slot < before.clock.finalized_slot
        || after.clock.unix_timestamp < before.clock.unix_timestamp
        || after.clock.valid_until < before.clock.valid_until
        || before.source != after.source
        || before.publication != after.publication
        || before.enrollment != after.enrollment
        || before.action != after.action
        || before.adapter_key != after.adapter_key
        || before.slot != after.slot
        || before.siblings != after.siblings
        || before.generation != after.generation
    {
        return Err(ClientError::Superseded);
    }
    before.validate_record_coherence(credential, manifest, now)?;
    after.validate_record_coherence(credential, manifest, now)?;
    control.check()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode_digest;
    use crate::{FieldBytes, OperationControl};

    fn word(n: u8) -> FieldBytes {
        let mut word = [0; 32];
        word[0] = n;
        word
    }
    fn state_fixture() -> (
        crate::V3CredentialSummary,
        V3FullManifest,
        crate::V3StateSnapshot,
    ) {
        use crate::{
            V3AuthenticatedClock, V3CredentialSummary, V3Enrollment, V3FinalizedAction,
            V3OrdinaryVkIdentity, V3RootPublication, V3SourceObservation, V3StateSnapshot,
        };
        let manifest = V3FullManifest::frozen_development().unwrap();
        let summary = V3CredentialSummary {
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
        let snapshot = V3StateSnapshot {
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
                root_version: 0,
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
                    let mut action = word(15);
                    action.reverse();
                    action
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
        (summary, manifest, snapshot)
    }
    #[test]
    fn state_recheck_accepts_only_unchanged_context_with_monotonic_clock() {
        use std::time::{Duration, Instant};
        let (credential, manifest, before) = state_fixture();
        let control = OperationControl::new(Instant::now() + Duration::from_secs(10));
        let mut after = before.clone();
        after.clock.finalized_slot += 1;
        after.clock.unix_timestamp += 1;
        after.clock.valid_until += 1;
        assert_eq!(
            check_full_state_recheck(&before, &after, &credential, &manifest, 151, &control),
            Ok(())
        );
        for field in 0..14 {
            let mut changed = after.clone();
            match field {
                0 => changed.source.digest[0] ^= 1,
                1 => changed.publication.root = word(20),
                2 => changed.publication.root_version += 1,
                3 => changed.enrollment.issuer_version += 1,
                4 => changed.enrollment.policy_version += 1,
                5 => changed.action.action_be[31] ^= 1,
                6 => changed.action.nonce[0] ^= 1,
                7 => changed.action.request_account[0] ^= 1,
                8 => changed.action.queue_account[0] ^= 1,
                9 => changed.adapter_key.tagged_digest[0] ^= 1,
                10 => changed.slot += 1,
                11 => changed.siblings[0] = word(21),
                12 => changed.publication.allocation_epoch += 1,
                _ => changed.generation += 1,
            }
            assert_eq!(
                check_full_state_recheck(&before, &changed, &credential, &manifest, 151, &control),
                Err(ClientError::Superseded),
                "changed field {field}"
            );
        }
        for field in 0..3 {
            let mut backwards = after.clone();
            match field {
                0 => backwards.clock.finalized_slot = before.clock.finalized_slot - 1,
                1 => backwards.clock.unix_timestamp = before.clock.unix_timestamp - 1,
                _ => backwards.clock.valid_until = before.clock.valid_until - 1,
            }
            assert_eq!(
                check_full_state_recheck(
                    &before,
                    &backwards,
                    &credential,
                    &manifest,
                    151,
                    &control
                ),
                Err(ClientError::Superseded)
            );
        }
    }
    #[test]
    fn state_recheck_rejects_expiry_consumption_and_cancelled_work() {
        use std::time::{Duration, Instant};
        let (credential, manifest, before) = state_fixture();
        let control = OperationControl::new(Instant::now() + Duration::from_secs(10));
        assert!(
            check_full_state_recheck(&before, &before, &credential, &manifest, 171, &control)
                .is_err()
        );
        let mut consumed = before.clone();
        consumed.action.consumed = true;
        assert!(check_full_state_recheck(
            &before,
            &consumed,
            &credential,
            &manifest,
            150,
            &control
        )
        .is_err());
        let mut unobserved = before.clone();
        unobserved.source.sequence = 0;
        unobserved.publication.source_sequence = 0;
        assert!(check_full_state_recheck(
            &unobserved,
            &unobserved,
            &credential,
            &manifest,
            150,
            &control
        )
        .is_err());
        control.cancel();
        assert_eq!(
            check_full_state_recheck(&before, &before, &credential, &manifest, 150, &control),
            Err(ClientError::Cancelled)
        );
        let expired = OperationControl::new(Instant::now());
        assert_eq!(
            check_full_state_recheck(&before, &before, &credential, &manifest, 150, &expired),
            Err(ClientError::Deadline)
        );
    }

    // Public identity evidence only. No PK, credential, holder key or assignment.
    const KEY_RECEIPT: &[u8] =
        include_bytes!("../../../results/dynark/part5/v3-ordinary-vk-identity-001.json");

    fn actual_key_identity() -> V3OrdinaryVkIdentity {
        V3OrdinaryVkIdentity {
            file_sha256: decode_digest(
                "87edb4608c2140f3c7fddc8503e49b68931cda973711ce2c831bd44f1b98a875",
            )
            .unwrap(),
            tagged_digest: decode_digest(
                "2f9b770ff51ac399619a3127ddb32efad67697402f10c4549441a3578e4f9a4e",
            )
            .unwrap(),
            root_receipt_sha256: decode_digest(
                "6a6fd9d207c778b085f56de3327ec15ccee886ab127de1e90e970da039fef429",
            )
            .unwrap(),
        }
    }

    #[test]
    fn accepted_adapter_key_requires_exact_authenticated_receipt() {
        let manifest = V3FullManifest::frozen_development().unwrap();
        let identity = actual_key_identity();
        assert_eq!(KEY_RECEIPT.len(), 1458);
        let token = manifest
            .admit_adapter_key(identity, KEY_RECEIPT)
            .expect("reviewed actual-key receipt admits its exact development identity");
        assert_eq!(token.identity, identity);
    }

    #[test]
    fn absent_adapter_receipt_cannot_admit_even_the_actual_key_identity() {
        let manifest = V3FullManifest::frozen_development().unwrap();
        assert_eq!(
            manifest.validate_adapter_record_shape(actual_key_identity()),
            Ok(())
        );
        assert_eq!(
            manifest.admit_adapter_key(actual_key_identity(), &[]),
            Err(ClientError::Unsupported)
        );
    }

    #[test]
    fn altered_adapter_receipt_and_identity_substitutions_fail_admission() {
        let manifest = V3FullManifest::frozen_development().unwrap();
        let identity = actual_key_identity();
        let mut altered = KEY_RECEIPT.to_vec();
        altered[0] ^= 1;
        let mut extended = KEY_RECEIPT.to_vec();
        extended.push(b'\n');
        for receipt in [
            altered.as_slice(),
            &KEY_RECEIPT[..KEY_RECEIPT.len() - 1],
            extended.as_slice(),
        ] {
            assert_eq!(
                manifest.admit_adapter_key(identity, receipt),
                Err(ClientError::Identity)
            );
        }
        for wrong in [
            V3OrdinaryVkIdentity {
                tagged_digest: [7; 32],
                ..identity
            },
            V3OrdinaryVkIdentity {
                file_sha256: [8; 32],
                ..identity
            },
            V3OrdinaryVkIdentity {
                root_receipt_sha256: [9; 32],
                ..identity
            },
            V3OrdinaryVkIdentity {
                tagged_digest: identity.file_sha256,
                ..identity
            },
            V3OrdinaryVkIdentity {
                tagged_digest: manifest.package.verifying_key_digest,
                ..identity
            },
        ] {
            assert_eq!(
                manifest.admit_adapter_key(wrong, KEY_RECEIPT),
                Err(ClientError::Identity)
            );
        }
        let mut wrong = manifest;
        wrong.package.package_digest = [0; 32];
        assert_eq!(
            wrong.admit_adapter_key(identity, KEY_RECEIPT),
            Err(ClientError::Identity)
        );
    }

    #[test]
    fn canonical_receipt_contents_cannot_be_rebound_by_caller_hashes() {
        let manifest = V3FullManifest::frozen_development().unwrap();
        let canonical = std::str::from_utf8(KEY_RECEIPT).unwrap();
        for (before, after) in [
            ("[\"root\",\"issuerHash\"", "[\"issuerHash\",\"root\""),
            ("\"ordinary_vk_ic_count\":7", "\"ordinary_vk_ic_count\":6"),
            ("\"profile_admitted\":false", "\"profile_admitted\": true"),
        ] {
            let altered = canonical.replace(before, after);
            assert_ne!(altered.as_bytes(), KEY_RECEIPT);
            assert_eq!(altered.len(), KEY_RECEIPT.len());
            let mut claimed = actual_key_identity();
            claimed.root_receipt_sha256 = Sha256::digest(altered.as_bytes()).into();
            assert_eq!(
                manifest.admit_adapter_key(actual_key_identity(), altered.as_bytes()),
                Err(ClientError::Identity)
            );
            assert_eq!(
                manifest.admit_adapter_key(claimed, altered.as_bytes()),
                Err(ClientError::Identity)
            );
        }
    }

    fn shape() -> Shape {
        Shape {
            assignment_len: V3_COORDINATES,
            instance_len: 7,
            constraint_rows: 793_681,
            reduction_rows: 793_681,
            domain_size: 1_048_576,
        }
    }

    #[test]
    fn frozen_shared_package_accepts_exact_six_field_shape() {
        let manifest = V3FullManifest::frozen_development()
            .expect("bounded-v3 frozen shared package contract is implemented");
        assert_eq!(manifest.check_identity(manifest.package, shape()), Ok(()));
        assert_eq!(
            manifest.package.package_digest,
            decode_digest("61d941890d823433468048dd1bd91da80c1bf7e1b3d2b6f5d509077a47ed06c8")
                .unwrap()
        );
        assert_eq!(
            manifest.ordinary_vk_file_sha256,
            decode_digest("87edb4608c2140f3c7fddc8503e49b68931cda973711ce2c831bd44f1b98a875")
                .unwrap()
        );
    }

    #[test]
    fn shape_package_and_admission_substitutions_are_rejected() {
        let manifest = V3FullManifest::frozen_development().unwrap();
        for wrong in [
            Shape {
                instance_len: 6,
                ..shape()
            },
            Shape {
                assignment_len: crate::V2_COORDINATES,
                ..shape()
            },
            Shape {
                reduction_rows: 793_680,
                ..shape()
            },
        ] {
            assert_eq!(
                manifest.check_identity(manifest.package, wrong),
                Err(ClientError::Identity)
            );
        }
        let mut wrong = manifest;
        wrong.package.package_digest = [0; 32];
        assert_eq!(
            manifest.check_identity(wrong.package, shape()),
            Err(ClientError::Identity)
        );
        wrong = manifest;
        wrong.admission.semantic_schema = [0; 32];
        assert_eq!(
            wrong.check_identity(manifest.package, shape()),
            Err(ClientError::Identity)
        );
    }

    #[test]
    fn missing_or_conflated_adapter_receipts_fail_closed() {
        let manifest = V3FullManifest::frozen_development().unwrap();
        // Synthetic data exercises identity separation only; no real key receipt.
        let identity = V3OrdinaryVkIdentity {
            file_sha256: manifest.ordinary_vk_file_sha256,
            tagged_digest: [7; 32],
            root_receipt_sha256: [8; 32],
        };
        assert_eq!(manifest.validate_adapter_record_shape(identity), Ok(()));
        assert_eq!(
            manifest.admit_adapter_key(identity, &[]),
            Err(ClientError::Unsupported)
        );
        for wrong in [
            V3OrdinaryVkIdentity {
                tagged_digest: [0; 32],
                ..identity
            },
            V3OrdinaryVkIdentity {
                root_receipt_sha256: [0; 32],
                ..identity
            },
            V3OrdinaryVkIdentity {
                tagged_digest: identity.file_sha256,
                ..identity
            },
            V3OrdinaryVkIdentity {
                tagged_digest: manifest.package.verifying_key_digest,
                ..identity
            },
            V3OrdinaryVkIdentity {
                file_sha256: [0; 32],
                ..identity
            },
        ] {
            assert_eq!(
                manifest.validate_adapter_record_shape(wrong),
                Err(ClientError::Identity)
            );
        }
    }
}
