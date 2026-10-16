//! Qualification only: no application or chain authorization is established.
use super::*;
use crate::{
    decode_digest, FieldBytes, V3CompilerSymbols, V3CredentialSummary, V3FullManifest,
    V3InputWorker, V3InputWorkerRequest, V3SetupArtifact, V3SetupSources,
};
use ark_bn254::Bn254;
use ark_serialize::CanonicalSerialize;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[test]
fn full_qualification_rejects_wrong_public_count_before_pairing() {
    let proof = ordinary::Proof::<Bn254>::default();
    let mut vk = ordinary::VerifyingKey::<Bn254>::default();
    vk.gamma_abc_g1 = vec![ark_bn254::G1Affine::default(); 7];
    assert_eq!(
        verify_qualification_full(&vk, &proof, &[Fr::from(1u64); 5]),
        Err(ClientError::Identity)
    );
    assert_eq!(
        verify_qualification_full(&vk, &proof, &[Fr::from(1u64); 7]),
        Err(ClientError::Identity)
    );
}

#[cfg(target_os = "macos")]
const PRIVATE_FLAGS: i32 = 0x0100 | 0x0004;
#[cfg(target_os = "linux")]
const PRIVATE_FLAGS: i32 = 0x20000 | 0x0800;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const PRIVATE_FLAGS: i32 = 0;

fn read_private(path: &Path, length: usize, owner: u32) -> Vec<u8> {
    let before = fs::symlink_metadata(path).expect("private fixture metadata");
    assert!(before.is_file());
    assert_eq!(before.permissions().mode() & 0o7777, 0o600);
    assert_eq!(before.uid(), owner);
    assert_eq!(before.nlink(), 1);
    assert_eq!(before.len(), length as u64);
    let identity = |metadata: &fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.mode(),
            metadata.uid(),
            metadata.nlink(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    };
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(PRIVATE_FLAGS)
        .open(path)
        .expect("private fixture handle");
    assert_eq!(identity(&file.metadata().unwrap()), identity(&before));
    let mut bytes = Vec::with_capacity(length + 1);
    (&mut file)
        .take(length as u64 + 1)
        .read_to_end(&mut bytes)
        .expect("bounded private fixture read");
    assert_eq!(identity(&file.metadata().unwrap()), identity(&before));
    assert_eq!(bytes.len(), length);
    bytes
}

fn summary(bytes: &[u8]) -> V3CredentialSummary {
    assert_eq!(bytes.len(), 459);
    assert!(bytes[..4] == *b"V3A1");
    let word =
        |start: usize| -> FieldBytes { bytes[start..start + 32].try_into().expect("summary word") };
    V3CredentialSummary {
        layout: bytes[4],
        tbs_digest: word(5),
        holder_modulus_be: bytes[37..293].try_into().expect("holder width"),
        issuer_hash: word(293),
        policy_hash: word(325),
        not_before: u64::from_be_bytes(bytes[357..365].try_into().expect("epoch width")),
        not_after: u64::from_be_bytes(bytes[365..373].try_into().expect("epoch width")),
        signed_aki: bytes[373..393].try_into().expect("AKI width"),
        signed_organization: bytes[393..409].try_into().expect("organization width"),
        signed_group: bytes[409..441].try_into().expect("group width"),
        structural_offsets: std::array::from_fn(|index| {
            u16::from_be_bytes(
                bytes[441 + 2 * index..443 + 2 * index]
                    .try_into()
                    .expect("offset width"),
            )
        }),
    }
}

struct WorkerRoot(PathBuf);
impl Drop for WorkerRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
#[ignore = "explicit private request-bound training fixture and serialized heavy-job scope required"]
fn native_v3_request_bound_full_qualification() {
    assert_eq!(
        std::env::var("M2_V3_FULL_SCOPE").as_deref(),
        Ok("native-v3-training-full")
    );
    assert!(cfg!(any(target_os = "macos", target_os = "linux")));
    let fixture =
        PathBuf::from(std::env::var_os("M2_V3_FULL_FIXTURE").expect("private fixture required"));
    assert!(fixture.is_absolute());
    assert_eq!(fs::canonicalize(&fixture).unwrap(), fixture);
    let meta = fs::symlink_metadata(&fixture).unwrap();
    assert!(meta.is_dir());
    assert_eq!(meta.permissions().mode() & 0o7777, 0o700);
    let owner = meta.uid();
    let wire = read_private(&fixture.join("request.bin"), 1918, owner);
    let metadata = read_private(&fixture.join("summary.bin"), 459, owner);
    let request =
        V3InputWorkerRequest::from_wire(&wire, &summary(&metadata)).expect("training request");
    let worker_path = fixture.join("full-qualification-worker");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&worker_path)
        .unwrap();
    let worker_root = WorkerRoot(worker_path);
    let control = OperationControl::new(Instant::now() + Duration::from_secs(150));
    let candidate = V3InputWorker::new(&worker_root.0)
        .unwrap()
        .build(&request, &control)
        .unwrap();
    let input_map = V3CompilerInputMap::load(
        &V3CompilerSymbols {
            path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../artifacts/dynark/part5/v3-compile-001/credential.sym")
                .canonicalize()
                .unwrap(),
            asserted_sha256: decode_digest(
                "d2d66e238bdc0a731c86c1897c2978d23908dcc19460582cc873dc2d41e5dbf0",
            )
            .unwrap(),
        },
        &control,
    )
    .unwrap();
    let repo = PathBuf::from("/Users/anishnarang/Zk-refresh");
    let setup = repo.join("artifacts/dynark/part5/v3-development-setup-001");
    let compile = repo.join("artifacts/dynark/part5/v3-compile-001");
    let artifact = |path, hash: &str| V3SetupArtifact {
        path,
        asserted_sha256: decode_digest(hash).expect("fixed development artifact digest"),
    };
    let sources = V3SetupSources {
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
    };
    let manifest = V3FullManifest::frozen_development().expect("fixed development manifest");
    let setup_control = OperationControl::new(Instant::now() + Duration::from_secs(570));
    let setup = V3SharedSetup::load(&sources, &manifest, &setup_control)
        .expect("accepted shared development setup admission");

    let input_len = fs::symlink_metadata(fixture.join("input.json"))
        .unwrap()
        .len();
    assert!((1..=65536).contains(&input_len));
    let input = read_private(&fixture.join("input.json"), input_len as usize, owner);
    let wtns = read_private(&fixture.join("output.wtns"), V3_WITNESS_BYTES, owner);
    let control = OperationControl::new(Instant::now() + Duration::from_secs(180));
    let checked = V3CheckedRelation::check(
        &setup,
        &input_map,
        &candidate,
        &input,
        &wtns,
        WitnessMode::Full,
        &control,
    )
    .unwrap();
    let control = OperationControl::new(Instant::now() + Duration::from_secs(180));
    let statement = checked
        .prove_qualification_full(&setup, &control)
        .expect("ordinary verified training Full proof");
    // Private ordinary encodings for a downstream adapter/host verification join.
    // Neither file is the Solana ABI or an application authorization capability.
    let mut proof = Vec::new();
    statement.proof.serialize_compressed(&mut proof).unwrap();
    let mut public = Vec::new();
    for value in &statement.public_values {
        value.serialize_compressed(&mut public).unwrap();
    }
    assert_eq!(public.len(), 192);
    for (name, bytes) in [
        ("full-ordinary.proof", proof),
        ("full-public-le.bin", public),
    ] {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(PRIVATE_FLAGS)
            .open(fixture.join(name))
            .unwrap();
        output.write_all(&bytes).unwrap();
        output.sync_all().unwrap();
        assert_eq!(
            output.metadata().unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }
}
