//! First harness stage only; this is not relation-admission evidence.

use std::{
    fs,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

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
}
