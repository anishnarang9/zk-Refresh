//! First actual native/private-worker roundtrip qualification, not proof or chain
//! authorization. Fresh fixture keys exist only in generator memory. Private DER,
//! signature/request and summary bytes are temporary and removed on every exit.
use dynark_native_client::{
    ClientError, FieldBytes, OperationControl, V3CredentialSummary, V3InputWorker,
    V3InputWorkerRequest,
};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const PYTHON: &str = "/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14";
const GENERATOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/support/prepare_v3_input_roundtrip.py"
);
const GENERATOR_SOURCE: &[u8] = include_bytes!("support/prepare_v3_input_roundtrip.py");
const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/workers/v3_input_worker.py");
const WORKER_SHA: &str = "b1349652a0acc86b4d8a820020ea6c8cdbba1f021958c6a9770a200e3124762e";
const FIXTURE_LAUNCH: &str = r#"import hashlib, os, stat, sys
try:
    path, expected, directory = sys.argv[1:]
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 65536:
        raise ValueError()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as handle:
        opened = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise ValueError()
        source = handle.read(65537)
        after = os.fstat(handle.fileno())
    if (len(source) != before.st_size or len(source) > 65536
            or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            or hashlib.sha256(source).hexdigest() != expected):
        raise ValueError()
    sys.argv = [path, directory]
    exec(compile(source, path, 'exec'), {'__name__': '__main__', '__file__': path})
except Exception:
    raise SystemExit(2) from None
"#;

#[cfg(target_os = "macos")]
const PRIVATE_FLAGS: i32 = 0x0100 | 0x0004;
#[cfg(target_os = "linux")]
const PRIVATE_FLAGS: i32 = 0x20000 | 0x0800;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const PRIVATE_FLAGS: i32 = 0;

struct PrivateFixture(PathBuf);
impl Drop for PrivateFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_private(path: &Path, length: usize, owner: u32) -> Vec<u8> {
    let before = fs::symlink_metadata(path).expect("private fixture metadata");
    assert!(before.is_file());
    assert_eq!(before.permissions().mode() & 0o7777, 0o600);
    assert_eq!(before.uid(), owner);
    assert_eq!(before.nlink(), 1);
    assert_eq!(before.len(), length as u64);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(PRIVATE_FLAGS)
        .open(path)
        .expect("private fixture handle");
    let opened = file.metadata().expect("opened fixture metadata");
    assert_eq!(
        (opened.dev(), opened.ino(), opened.len()),
        (before.dev(), before.ino(), before.len())
    );
    let mut bytes = Vec::new();
    (&mut file)
        .take(length as u64 + 1)
        .read_to_end(&mut bytes)
        .expect("bounded private fixture read");
    let after = file.metadata().expect("final fixture metadata");
    assert_eq!(
        (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec()
        ),
        (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec()
        )
    );
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

fn generate(directory: &Path, control: &OperationControl) {
    control.check().expect("fixture operation control");
    let expected = hex(&Sha256::digest(GENERATOR_SOURCE));
    let process = Command::new(PYTHON)
        .args(["-B", "-c", FIXTURE_LAUNCH, GENERATOR, &expected])
        .arg(directory)
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PYTHONHASHSEED", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("private independent fixture generator");
    let mut child = OwnedChild(process);
    loop {
        control
            .check()
            .expect("fixture generation bounded by operation control");
        match child.0.try_wait().expect("fixture child status") {
            Some(status) => {
                assert!(
                    status.success(),
                    "independent fixture generation must succeed"
                );
                break;
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn source_identity() -> String {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(PRIVATE_FLAGS)
        .open(SCRIPT)
        .expect("fixed worker source");
    let mut bytes = Vec::new();
    (&mut file)
        .take(131073)
        .read_to_end(&mut bytes)
        .expect("bounded worker source read");
    assert!(bytes.len() <= 131072);
    hex(&Sha256::digest(bytes))
}

#[test]
#[ignore = "ROOT-owned bounded real native/private-worker roundtrip grant required"]
fn independent_credentials_roundtrip_same_native_worker_and_reject_revoked_path() {
    assert_eq!(
        std::env::var("M2_V3_NATIVE_WORKER_SCOPE").as_deref(),
        Ok("native-v3-input-roundtrip"),
        "exact ROOT execution scope"
    );
    assert!(cfg!(any(target_os = "macos", target_os = "linux")));
    let path = PathBuf::from(
        std::env::var_os("M2_V3_NATIVE_WORKER_PRIVATE_ROOT")
            .expect("fresh absolute ROOT-owned fixture path"),
    );
    assert!(path.is_absolute());
    assert!(!path.exists(), "fixture root must be fresh");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .expect("fresh private fixture root");
    let private = PrivateFixture(path);
    assert!(fs::canonicalize(&private.0).expect("canonical fixture root") == private.0);
    let owner = fs::symlink_metadata(&private.0)
        .expect("fixture root metadata")
        .uid();
    assert_eq!(
        fs::symlink_metadata(&private.0)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o700
    );
    let fixture_root = private.0.join("fixtures");
    let worker_root = private.0.join("native-worker");
    for directory in [&fixture_root, &worker_root] {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(directory)
            .expect("private test child");
    }
    let control = OperationControl::new(Instant::now() + Duration::from_secs(150));
    assert!(
        source_identity() == WORKER_SHA,
        "fixed worker source before operation"
    );
    generate(&fixture_root, &control);
    let worker = V3InputWorker::new(&worker_root).expect("fixed native worker construction");
    assert_eq!(
        fs::read_dir(&worker_root).unwrap().count(),
        0,
        "constructor cleanup"
    );
    let mut cases = Vec::new();
    for index in 0..2 {
        let wire = read_private(
            &fixture_root.join(format!("case-{index}.request.bin")),
            1918,
            owner,
        );
        let metadata = read_private(
            &fixture_root.join(format!("case-{index}.summary.bin")),
            459,
            owner,
        );
        cases.push((wire, summary(&metadata)));
    }
    assert!(
        cases[0].0[956..1212] != cases[1].0[956..1212],
        "different issuer keys"
    );
    assert!(
        cases[0].1.holder_modulus_be != cases[1].1.holder_modulus_be,
        "different holder keys"
    );
    assert!(
        cases[0].0[1212..1244] != cases[1].0[1212..1244],
        "different exact actions"
    );
    assert!(
        cases[0].0[1822..1854] != cases[1].0[1822..1854],
        "different membership roots"
    );
    for (wire, metadata) in &cases {
        let request = V3InputWorkerRequest::from_wire(wire, metadata)
            .expect("real independent fixture request structure");
        let _candidate = worker
            .build(&request, &control)
            .expect("actual native private-worker cryptographic roundtrip");
        assert_eq!(
            fs::read_dir(&worker_root).unwrap().count(),
            0,
            "successful invocation cleanup"
        );
        assert!(
            source_identity() == WORKER_SHA,
            "same worker identity after each credential"
        );
    }
    let revoked_wire = read_private(&fixture_root.join("own-revoked.request.bin"), 1918, owner);
    let revoked = V3InputWorkerRequest::from_wire(&revoked_wire, &cases[0].1)
        .expect("revoked-root request remains structurally well formed");
    assert!(
        matches!(worker.build(&revoked, &control), Err(ClientError::Encoding)),
        "real worker must reject mathematically revoked membership"
    );
    assert_eq!(
        fs::read_dir(&worker_root).unwrap().count(),
        0,
        "rejected invocation cleanup"
    );
    assert!(
        source_identity() == WORKER_SHA,
        "unchanged fixed worker source"
    );
    // No Full witness, setup, proof, chain authority or application authorization
    // was created or admitted by these opaque non-authorizing candidates.
}
