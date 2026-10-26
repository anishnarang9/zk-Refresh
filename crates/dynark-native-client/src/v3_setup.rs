//! One immutable bounded-v3 development setup shared by independent credentials.
//! Artifact hash assertions and manifests supplied by callers are untrusted data;
//! admission must compare them to the independently reviewed fixed receipt pins.
//! No credential, witness, holder signer or private Anchor belongs in this object.
use crate::{
    decode_digest, ClientError, Digest, OperationControl, V3FullManifest, V3OrdinaryVkIdentity,
};
use ark_bn254::Bn254;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use dynark_bn254::{
    import, public_schema_digest, CircuitDescriptor, Limits, PublicPackage, Reduction,
};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Cursor, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static SNAPSHOT_SERIAL: AtomicU64 = AtomicU64::new(0);

fn protected_setup(path: &Path) -> Result<u32, ClientError> {
    let meta = fs::symlink_metadata(path).map_err(|_| ClientError::Io)?;
    if !path.is_absolute()
        || fs::canonicalize(path).map_err(|_| ClientError::Identity)? != path
        || !meta.is_dir()
        || meta.permissions().mode() & 0o777 != 0o700
    {
        return Err(ClientError::Identity);
    }
    Ok(meta.uid())
}

fn verified_bytes(
    artifact: &V3SetupArtifact,
    expected: Digest,
    cap: u64,
    private: bool,
    owner: u32,
    control: &OperationControl,
) -> Result<Vec<u8>, ClientError> {
    control.check()?;
    let path = &artifact.path;
    if artifact.asserted_sha256 != expected
        || !path.is_absolute()
        || fs::canonicalize(path).map_err(|_| ClientError::Identity)? != *path
    {
        return Err(ClientError::Identity);
    }
    let meta = fs::symlink_metadata(path).map_err(|_| ClientError::Io)?;
    let mode = meta.permissions().mode() & 0o777;
    if !meta.is_file()
        || meta.uid() != owner
        || meta.len() > cap
        || if private {
            mode != 0o600 || meta.nlink() != 1
        } else {
            !matches!(mode, 0o600 | 0o644)
        }
    {
        return Err(ClientError::Identity);
    }
    let mut file = File::open(path).map_err(|_| ClientError::Io)?;
    let opened = file.metadata().map_err(|_| ClientError::Io)?;
    if (
        opened.dev(),
        opened.ino(),
        opened.len(),
        opened.uid(),
        opened.permissions().mode(),
    ) != (
        meta.dev(),
        meta.ino(),
        meta.len(),
        meta.uid(),
        meta.permissions().mode(),
    ) || private && opened.nlink() != 1
    {
        return Err(ClientError::Identity);
    }
    let mut bytes = Vec::new();
    let mut buffer = [0; 65_536];
    let mut hash = Sha256::new();
    loop {
        control.check()?;
        let count = file.read(&mut buffer).map_err(|_| ClientError::Io)?;
        if count == 0 {
            break;
        }
        if bytes.len() as u64 + count as u64 > meta.len() {
            return Err(ClientError::Bound);
        }
        hash.update(&buffer[..count]);
        bytes.extend_from_slice(&buffer[..count]);
    }
    if bytes.len() as u64 != meta.len()
        || file.metadata().map_err(|_| ClientError::Io)?.len() != meta.len()
        || <Digest>::from(hash.finalize()) != expected
    {
        return Err(ClientError::Identity);
    }
    control.check()?;
    Ok(bytes)
}

struct R1csSnapshot(PathBuf);
impl Drop for R1csSnapshot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

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
    /// Identity already admitted by load; caller records cannot replace it.
    pub(crate) fn manifest(&self) -> &V3FullManifest {
        &self.manifest
    }

    pub(crate) fn adapter_identity(&self) -> V3OrdinaryVkIdentity {
        self.adapter_identity
    }

    /// Borrow the already admitted shared package; no replacement or mutation.
    pub(crate) fn package(&self) -> &PublicPackage {
        &self.package
    }

    /// Authenticate fixed setup/receipt pins before key decoding; fully validate
    /// the package and its exact ordinary VK projection before returning it.
    pub fn load(
        sources: &V3SetupSources,
        manifest: &V3FullManifest,
        control: &OperationControl,
    ) -> Result<Self, ClientError> {
        control.check()?;
        manifest.check()?;
        // Expected values come from ROOT-reviewed source policy. All caller hash
        // assertions are checked together before any file or key is opened.
        let setup_pin =
            decode_digest("d31f82e3f147e31b30074b3a570a9d7945c5e1f5d3f3dd74172801abbe984918")?;
        let wasm_pin =
            decode_digest("fbf73cff59660574add16ba8acafe824a9d57e0c91f23557b6462979b85c9aa6")?;
        let pk_pin =
            decode_digest("879563839a95ab1a9e5a44b316ba86290918a5cf522863c1ddc58379365293bc")?;
        let receipt_pin =
            decode_digest("6a6fd9d207c778b085f56de3327ec15ccee886ab127de1e90e970da039fef429")?;
        for (artifact, expected) in [
            (&sources.setup_manifest, setup_pin),
            (&sources.r1cs, manifest.admission.r1cs),
            (&sources.wasm, wasm_pin),
            (&sources.profile, manifest.admission.profile),
            (&sources.proving_key, pk_pin),
            (&sources.ordinary_vk, manifest.ordinary_vk_file_sha256),
            (&sources.ordinary_key_receipt, receipt_pin),
        ] {
            if artifact.asserted_sha256 != expected {
                return Err(ClientError::Identity);
            }
        }
        let setup_root = sources
            .setup_manifest
            .path
            .parent()
            .ok_or(ClientError::Identity)?;
        let owner = protected_setup(setup_root)?;
        if sources.proving_key.path.parent() != Some(setup_root)
            || sources.ordinary_vk.path.parent() != Some(setup_root)
        {
            return Err(ClientError::Identity);
        }
        // Exact manifest/profile hashes authenticate their canonical contents;
        // the PK file hash is separately pinned, never learned from that JSON.
        drop(verified_bytes(
            &sources.setup_manifest,
            setup_pin,
            65_536,
            true,
            owner,
            control,
        )?);
        drop(verified_bytes(
            &sources.profile,
            manifest.admission.profile,
            65_536,
            false,
            owner,
            control,
        )?);
        drop(verified_bytes(
            &sources.wasm,
            wasm_pin,
            16 * 1024 * 1024,
            false,
            owner,
            control,
        )?);
        let receipt = verified_bytes(
            &sources.ordinary_key_receipt,
            receipt_pin,
            1458,
            false,
            owner,
            control,
        )?;
        let raw_vk = verified_bytes(
            &sources.ordinary_vk,
            manifest.ordinary_vk_file_sha256,
            456,
            true,
            owner,
            control,
        )?;
        if raw_vk.len() != 456 {
            return Err(ClientError::Identity);
        }
        let mut vk_reader = Cursor::new(&raw_vk);
        let vk = ordinary::VerifyingKey::<Bn254>::deserialize_compressed(&mut vk_reader)
            .map_err(|_| ClientError::Encoding)?;
        if vk_reader.position() != raw_vk.len() as u64 || vk.gamma_abc_g1.len() != 7 {
            return Err(ClientError::Identity);
        }
        let mut canonical_vk = Vec::new();
        vk.serialize_compressed(&mut canonical_vk)
            .map_err(|_| ClientError::Encoding)?;
        if canonical_vk != raw_vk {
            return Err(ClientError::Encoding);
        }
        drop(vk);
        drop(canonical_vk);

        let r1cs = verified_bytes(
            &sources.r1cs,
            manifest.admission.r1cs,
            192 * 1024 * 1024,
            false,
            owner,
            control,
        )?;
        // The engine imports R1CS by filename. Snapshot only the authenticated
        // public relation, so parsing never reopens a mutable source artifact.
        let snapshot_path = setup_root.join(format!(
            "native-v3-r1cs-{}-{}",
            std::process::id(),
            SNAPSHOT_SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&snapshot_path)
            .map_err(|_| ClientError::Io)?;
        let snapshot = R1csSnapshot(snapshot_path);
        let r1cs_path = snapshot.0.join("credential.r1cs");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&r1cs_path)
            .map_err(|_| ClientError::Io)?;
        for chunk in r1cs.chunks(65_536) {
            control.check()?;
            file.write_all(chunk).map_err(|_| ClientError::Io)?;
        }
        drop(file);
        drop(r1cs);
        let imports = import::ImportLimits {
            operation: Limits {
                max_domain: 1_048_576,
                max_assignment: crate::V3_COORDINATES,
                max_matrix_entries: 4_500_000,
                max_delta_entries: 8192,
                max_pair_work: 11_000_000,
                max_allocation_bytes: 4 * 1024 * 1024 * 1024,
            },
            max_file_bytes: 192 * 1024 * 1024,
            max_section_bytes: 160 * 1024 * 1024,
            max_sections: 3,
            max_row_entries: 4096,
        };
        control.check()?;
        let matrices = import::read_r1cs(&r1cs_path, imports).map_err(|_| ClientError::Relation)?;
        drop(snapshot);
        control.check()?;
        if matrices.num_constraints != 793_681
            || matrices.num_instance_variables != 7
            || matrices
                .num_instance_variables
                .checked_add(matrices.num_witness_variables)
                != Some(crate::V3_COORDINATES)
            || matrices
                .a_num_non_zero
                .checked_add(matrices.b_num_non_zero)
                .and_then(|n| n.checked_add(matrices.c_num_non_zero))
                != Some(4_257_583)
        {
            return Err(ClientError::Identity);
        }
        let names = [
            "root",
            "issuerHash",
            "notBefore",
            "notAfter",
            "actionHash",
            "policyHash",
        ]
        .map(str::to_owned)
        .to_vec();
        let descriptor = CircuitDescriptor {
            r1cs_artifact_digest: manifest.admission.r1cs,
            witness_executable_digest: wasm_pin,
            profile_digest: manifest.admission.profile,
            public_schema_digest: public_schema_digest(&names),
            public_schema: names,
            reduction: Reduction::Original,
        };
        let pk_bytes = verified_bytes(
            &sources.proving_key,
            pk_pin,
            512 * 1024 * 1024,
            true,
            owner,
            control,
        )?;
        // Exact authenticated bytes permit unchecked codec decoding; no decoded
        // key is exposed or used before PublicPackage::new performs full checks.
        let mut reader = Cursor::new(&pk_bytes);
        let pk = CanonicalDeserialize::deserialize_compressed_unchecked(&mut reader)
            .map_err(|_| ClientError::Encoding)?;
        if reader.position() != pk_bytes.len() as u64 {
            return Err(ClientError::Encoding);
        }
        drop(pk_bytes);
        control.check()?;
        let package = PublicPackage::new(matrices, descriptor, pk, manifest.package)
            .map_err(|_| ClientError::Identity)?;
        control.check()?;
        manifest.check_identity(package.identity(), package.shape())?;
        let mut projected_vk = Vec::new();
        package
            .ordinary_verifying_key()
            .serialize_compressed(&mut projected_vk)
            .map_err(|_| ClientError::Encoding)?;
        if projected_vk != raw_vk {
            return Err(ClientError::Identity);
        }
        let adapter_identity = V3OrdinaryVkIdentity {
            file_sha256: manifest.ordinary_vk_file_sha256,
            tagged_digest: decode_digest(
                "2f9b770ff51ac399619a3127ddb32efad67697402f10c4549441a3578e4f9a4e",
            )?,
            root_receipt_sha256: receipt_pin,
        };
        manifest.admit_adapter_key(adapter_identity, &receipt)?;
        control.check()?;
        Ok(Self {
            package,
            manifest: *manifest,
            adapter_identity,
        })
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
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
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
