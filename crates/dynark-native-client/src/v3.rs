//! Bounded-v3 shared setup identity. These records do not authenticate a setup
//! receipt or admit an issuer. No accepted tagged adapter-key digest is invented.
use crate::{ClientError, Digest, V3AdmissionIdentity};
use dynark_bn254::{PackageIdentity, Shape};

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V3FullManifest {
    pub admission: V3AdmissionIdentity,
    pub package: PackageIdentity,
    pub ordinary_vk_file_sha256: Digest,
}
impl V3FullManifest {
    pub fn frozen_development() -> Result<Self, ClientError> {
        // RED scaffold: never admit an unimplemented package contract.
        Err(ClientError::Unsupported)
    }
    pub fn check_identity(&self, _: PackageIdentity, _: Shape) -> Result<(), ClientError> {
        Err(ClientError::Unsupported)
    }
    /// Pure record-shape validation. Success establishes no adapter admission.
    pub fn validate_adapter_record_shape(
        &self,
        _: V3OrdinaryVkIdentity,
    ) -> Result<(), ClientError> {
        Err(ClientError::Unsupported)
    }
    /// No accepted external key-gate receipt exists yet. This must remain closed
    /// until exact tagged/receipt pins are independently measured and reviewed.
    pub fn admit_adapter_key(&self, _: V3OrdinaryVkIdentity) -> Result<(), ClientError> {
        Err(ClientError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode_digest;

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
            manifest.admit_adapter_key(identity),
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
