//! One immutable bounded-v3 development setup shared by independent credentials.
//! Artifact hash assertions and manifests supplied by callers are untrusted data;
//! admission must compare them to the independently reviewed fixed receipt pins.
//! No credential, witness, holder signer or private Anchor belongs in this object.
use crate::{ClientError, Digest, OperationControl, V3FullManifest, V3OrdinaryVkIdentity};
use dynark_bn254::PublicPackage;
use std::path::PathBuf;

/// Caller-supplied artifact location and hash assertion, not a trust anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V3SetupArtifact {
    pub path: PathBuf,
    pub asserted_sha256: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V3SetupSources {
    pub setup_manifest: V3SetupArtifact,
    pub r1cs: V3SetupArtifact,
    pub wasm: V3SetupArtifact,
    pub profile: V3SetupArtifact,
    pub proving_key: V3SetupArtifact,
    pub ordinary_vk: V3SetupArtifact,
    pub ordinary_key_receipt: V3SetupArtifact,
}

/// Admission token for the exact development package and ordinary-key identity.
/// Private fields prohibit caller construction from a self-asserted manifest.
/// Setup admission establishes no issuer enrollment, status or application right.
pub struct V3SharedSetup {
    package: PublicPackage,
    manifest: V3FullManifest,
    adapter_identity: V3OrdinaryVkIdentity,
}
impl V3SharedSetup {
    /// Authenticate fixed setup/receipt pins before key decoding; fully validate
    /// the package and its exact ordinary VK projection before returning it.
    pub fn load(
        _: &V3SetupSources,
        _: &V3FullManifest,
        _: &OperationControl,
    ) -> Result<Self, ClientError> {
        // Tests-first scaffold: no artifact reads or key decoding are admitted.
        Err(ClientError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decode_digest, V3_COORDINATES};
    use ark_serialize::CanonicalSerialize;
    use sha2::{Digest as _, Sha256};
    use std::time::{Duration, Instant};

    fn digest(value: &str) -> Digest {
        decode_digest(value).unwrap()
    }
    fn sources() -> V3SetupSources {
        // Public path assertions only: this helper neither opens nor hashes keys.
        let repo = PathBuf::from("/Users/anishnarang/Zk-refresh");
        let setup = repo.join("artifacts/dynark/part5/v3-development-setup-001");
        let compile = repo.join("artifacts/dynark/part5/v3-compile-001");
        let artifact = |path, hash| V3SetupArtifact {
            path,
            asserted_sha256: digest(hash),
        };
        V3SetupSources {
            setup_manifest: artifact(
                setup.join("setup-manifest.json"),
                "d31f82e3f147e31b30074b3a570a9d7945c5e1f5d3f3dd74172801abbe984918",
            ),
            r1cs: artifact(
                compile.join("credential.r1cs"),
                "976e9a76356ad015f0e4c587ccd79bba601b5caf80817b561aa4ca5442656888",
            ),
            wasm: artifact(
                compile.join("credential_js/credential.wasm"),
                "fbf73cff59660574add16ba8acafe824a9d57e0c91f23557b6462979b85c9aa6",
            ),
            profile: artifact(
                repo.join("circuits/credential-v3-bounded/profile.json"),
                "2e5d26564fb055e70cff924c4cb6e296509030b8c0062130f86ad5af783f7918",
            ),
            proving_key: artifact(
                setup.join("development.pk"),
                "879563839a95ab1a9e5a44b316ba86290918a5cf522863c1ddc58379365293bc",
            ),
            ordinary_vk: artifact(
                setup.join("ordinary.vk"),
                "87edb4608c2140f3c7fddc8503e49b68931cda973711ce2c831bd44f1b98a875",
            ),
            ordinary_key_receipt: artifact(
                repo.join("results/dynark/part5/v3-ordinary-vk-identity-001.json"),
                "6a6fd9d207c778b085f56de3327ec15ccee886ab127de1e90e970da039fef429",
            ),
        }
    }

    #[test]
    #[ignore = "ROOT-owned bounded shared-package admission execution grant required"]
    fn accepted_development_setup_loads_one_shared_six_field_package() {
        assert_eq!(
            std::env::var("M2_V3_SETUP_SCOPE").as_deref(),
            Ok("native-v3-shared-setup"),
            "exact ROOT execution scope"
        );
        let manifest = V3FullManifest::frozen_development().unwrap();
        let sources = sources();
        let control = OperationControl::new(Instant::now() + Duration::from_secs(570));
        let setup = V3SharedSetup::load(&sources, &manifest, &control)
            .expect("accepted shared development setup admission is implemented");
        assert_eq!(setup.manifest, manifest);
        assert_eq!(setup.package.identity(), manifest.package);
        let shape = setup.package.shape();
        assert_eq!(shape.assignment_len, V3_COORDINATES);
        assert_eq!(shape.instance_len, 7);
        assert_eq!(shape.constraint_rows, 793_681);
        assert_eq!(shape.reduction_rows, 793_681);
        assert_eq!(shape.domain_size, 1_048_576);
        assert_eq!(
            manifest.check_identity(setup.package.identity(), shape),
            Ok(())
        );
        let vk = setup.package.ordinary_verifying_key();
        assert_eq!(vk.gamma_abc_g1.len(), 7);
        let mut raw = Vec::new();
        vk.serialize_compressed(&mut raw).unwrap();
        assert_eq!(raw.len(), 456);
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(&raw)),
            manifest.ordinary_vk_file_sha256
        );
        assert_eq!(
            setup.adapter_identity,
            V3OrdinaryVkIdentity {
                file_sha256: manifest.ordinary_vk_file_sha256,
                tagged_digest: digest(
                    "2f9b770ff51ac399619a3127ddb32efad67697402f10c4549441a3578e4f9a4e"
                ),
                root_receipt_sha256: sources.ordinary_key_receipt.asserted_sha256,
            }
        );
        control.check().unwrap();
    }

    #[test]
    fn wrong_pk_vk_setup_profile_and_receipt_hashes_fail_before_key_decoding() {
        let manifest = V3FullManifest::frozen_development().unwrap();
        let original = sources();
        let control = OperationControl::new(Instant::now() + Duration::from_secs(2));
        for field in 0..5 {
            let mut wrong = original.clone();
            let artifact = match field {
                0 => &mut wrong.proving_key,
                1 => &mut wrong.ordinary_vk,
                2 => &mut wrong.setup_manifest,
                3 => &mut wrong.profile,
                _ => &mut wrong.ordinary_key_receipt,
            };
            artifact.asserted_sha256[0] ^= 1;
            assert!(
                matches!(
                    V3SharedSetup::load(&wrong, &manifest, &control),
                    Err(ClientError::Identity)
                ),
                "untrusted artifact hash assertion"
            );
        }
    }

    #[test]
    fn caller_manifest_cannot_establish_its_own_setup_authority() {
        let sources = sources();
        let control = OperationControl::new(Instant::now() + Duration::from_secs(2));
        let manifest = V3FullManifest::frozen_development().unwrap();
        let mut wrong = manifest;
        wrong.package.package_digest[0] ^= 1;
        assert!(matches!(
            V3SharedSetup::load(&sources, &wrong, &control),
            Err(ClientError::Identity)
        ));
        wrong = manifest;
        wrong.admission.profile[0] ^= 1;
        assert!(matches!(
            V3SharedSetup::load(&sources, &wrong, &control),
            Err(ClientError::Identity)
        ));
    }
}
