//! Bounded-v3 shared setup identity. These records do not authenticate a setup
//! receipt or admit an issuer. No accepted tagged adapter-key digest is invented.
use crate::{decode_digest, ClientError, Digest, V3AdmissionIdentity};
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
