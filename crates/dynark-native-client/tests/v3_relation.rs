//! First harness stage only; this is not relation-admission evidence.

use dynark_native_client::{
    decode_digest, FieldBytes, OperationControl, V3CompilerInputMap, V3CompilerSymbols,
    V3CredentialSummary, V3FullManifest, V3InputWorker, V3InputWorkerRequest, V3SetupArtifact,
    V3SetupSources, V3SharedSetup,
};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

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

struct PrivateRoot(PathBuf);
impl Drop for PrivateRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ReapedChild(Child);
impl Drop for ReapedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "requires explicit native-v3-relation scope and a fresh private root"]
fn native_v3_relation_harness() {
    assert_eq!(
        std::env::var("M2_V3_RELATION_SCOPE").as_deref(),
        Ok("native-v3-relation"),
        "explicit relation scope required"
    );
    assert!(cfg!(any(target_os = "macos", target_os = "linux")));
    let root = std::path::PathBuf::from(
        std::env::var_os("M2_V3_RELATION_PRIVATE_ROOT")
            .expect("fresh private-root environment variable required"),
    );
    assert!(root.is_absolute(), "private root must be absolute");
    assert!(
        matches!(std::fs::symlink_metadata(&root), Err(error)
            if error.kind() == std::io::ErrorKind::NotFound),
        "private root must not already exist"
    );
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let private_root = PrivateRoot(root);
    assert_eq!(fs::metadata(&private_root.0).unwrap().permissions().mode() & 0o7777, 0o700);
    let fixture = private_root.0.join("fixture");
    fs::DirBuilder::new().mode(0o700).create(&fixture).unwrap();
    assert_eq!(fs::metadata(&fixture).unwrap().permissions().mode() & 0o7777, 0o700);

    let helper = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/support/prepare_v3_relation.py");
    let mut child = ReapedChild(Command::new(
        "/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14",
    )
        .arg("-B")
        .arg(&helper)
        .arg("generate")
        .arg(&fixture)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("fixture helper must start"));
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = child.0.try_wait().expect("fixture helper wait failed") {
            assert!(status.success(), "fixture helper failed: {status}");
            break;
        }
        assert!(Instant::now() < deadline, "fixture helper exceeded 60 seconds");
        std::thread::sleep(Duration::from_millis(100));
    }
    for (name, exact_len) in [
        ("request.bin", Some(1918)),
        ("summary.bin", Some(459)),
        ("input-coordinates.bin", Some(3004)),
        ("internal-coordinate.bin", Some(4)),
        ("input.json", None),
        ("public.json", None),
    ] {
        let metadata = fs::symlink_metadata(fixture.join(name)).unwrap();
        assert!(metadata.file_type().is_file(), "{name} must be regular");
        assert_eq!(metadata.nlink(), 1, "{name} must have one link");
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600, "{name} mode");
        if let Some(expected) = exact_len {
            assert_eq!(metadata.len(), expected, "{name} width");
        } else {
            assert!((1..=65536).contains(&metadata.len()), "{name} bounds");
        }
    }

    let owner = fs::symlink_metadata(&private_root.0).unwrap().uid();
    let wire = read_private(&fixture.join("request.bin"), 1918, owner);
    let metadata = read_private(&fixture.join("summary.bin"), 459, owner);
    let request = V3InputWorkerRequest::from_wire(&wire, &summary(&metadata))
        .expect("fresh independent fixture request structure");
    let worker_root = private_root.0.join("native-worker");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&worker_root)
        .expect("fresh private worker root");
    assert_eq!(fs::symlink_metadata(&worker_root).unwrap().uid(), owner);
    assert_eq!(
        fs::symlink_metadata(&worker_root).unwrap().permissions().mode() & 0o7777,
        0o700
    );
    let control = OperationControl::new(Instant::now() + Duration::from_secs(150));
    control.check().expect("worker construction deadline");
    let worker = V3InputWorker::new(&worker_root).expect("fixed native worker construction");
    assert!(
        fs::read_dir(&worker_root).unwrap().next().is_none(),
        "worker constructor child cleanup"
    );
    let _candidate = worker
        .build(&request, &control)
        .expect("fresh fixture native private-worker candidate");
    assert!(
        fs::read_dir(&worker_root).unwrap().next().is_none(),
        "worker invocation child cleanup"
    );
    // Candidate construction supplies no complete-relation or authorization admission.

    let _input_map = V3CompilerInputMap::load(
        &V3CompilerSymbols {
            path: PathBuf::from(
                "/Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-compile-001/credential.sym",
            ),
            asserted_sha256: [
                0xd2, 0xd6, 0x6e, 0x23, 0x8b, 0xdc, 0x0a, 0x73, 0x1c, 0x86, 0xc1, 0x89, 0x7c, 0x29,
                0x78, 0xd2, 0x39, 0x08, 0xdc, 0xc1, 0x94, 0x60, 0x58, 0x2c, 0xc8, 0x73, 0xdc, 0x2d,
                0x41, 0xe5, 0xdb, 0xf0,
            ],
        },
        &control,
    )
    .expect("fixed compiler input map");

    let witness_helper = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/support/v3_relation_witness.cjs");
    let mut witness = ReapedChild(Command::new(
        "/Users/anishnarang/.nvm/versions/node/v24.10.0/bin/node",
    )
        .arg(witness_helper)
        .arg(&fixture)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("witness helper must start"));
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if let Some(status) = witness.0.try_wait().expect("witness helper wait failed") {
            assert!(status.success(), "witness helper failed: {status}");
            break;
        }
        assert!(Instant::now() < deadline, "witness helper exceeded 90 seconds");
        std::thread::sleep(Duration::from_millis(100));
    }
    let witness_metadata = fs::symlink_metadata(fixture.join("output.wtns")).unwrap();
    assert!(witness_metadata.file_type().is_file());
    assert_eq!(witness_metadata.nlink(), 1);
    assert_eq!(witness_metadata.permissions().mode() & 0o7777, 0o600);
    assert_eq!(witness_metadata.len(), 25_113_548);

    let mut checker = ReapedChild(Command::new(
        "/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14",
    )
        .arg("-B")
        .arg(&helper)
        .arg("check")
        .arg(&fixture)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("preflight checker must start"));
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if let Some(status) = checker.0.try_wait().expect("preflight checker wait failed") {
            assert!(status.success(), "preflight checker failed: {status}");
            break;
        }
        assert!(Instant::now() < deadline, "preflight checker exceeded 90 seconds");
        std::thread::sleep(Duration::from_millis(100));
    }
    let preflight_metadata = fs::symlink_metadata(fixture.join("preflight.bin")).unwrap();
    assert!(preflight_metadata.file_type().is_file());
    assert_eq!(preflight_metadata.nlink(), 1);
    assert_eq!(preflight_metadata.permissions().mode() & 0o7777, 0o600);
    assert_eq!(preflight_metadata.len(), 16);
    let mut expected = b"V3R1".to_vec();
    for value in [784_796u32, 793_681, 4_257_583] {
        expected.extend_from_slice(&value.to_le_bytes());
    }
    assert_eq!(fs::read(fixture.join("preflight.bin")).unwrap(), expected);
    assert!(
        matches!(fs::symlink_metadata(fixture.join("preflight.r1cs")), Err(error)
            if error.kind() == std::io::ErrorKind::NotFound),
        "preflight R1CS snapshot must be removed"
    );

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
    let _setup = V3SharedSetup::load(&sources, &manifest, &setup_control)
        .expect("accepted shared development setup admission");
}
