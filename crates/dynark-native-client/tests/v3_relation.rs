//! First harness stage only; this is not relation-admission evidence.

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
    panic!("harness not yet connected");
}
