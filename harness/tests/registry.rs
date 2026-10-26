use zk_fresh_benchmark::{
    fixtures::create_fixtures,
    registry::{hash, Registry},
};
#[test]
fn poseidon_matches_the_circom_parameter_vector() {
    assert_eq!(
        hash(&[[1; 32], [2; 32]]).unwrap(),
        [
            13, 84, 225, 147, 143, 138, 140, 28, 125, 235, 94, 3, 85, 242, 99, 25, 32, 123, 132,
            254, 156, 162, 206, 27, 38, 231, 53, 200, 41, 130, 25, 144
        ]
    );
}
#[test]
fn revoked_leaf_changes_root_and_retains_original_snapshot() {
    let mut registry =
        Registry::new(create_fixtures(2, 1_791_000_000, 1_791_086_400).unwrap()).unwrap();
    let old = registry.snapshot(1000).unwrap();
    let input = registry.input(0, [0; 32]).unwrap();
    let updated = registry.revoke(1, 1010).unwrap();
    assert_ne!(old.root, updated.root);
    assert_eq!(registry.version, 1);
    assert_eq!(registry.history[0].root, old.root);
    assert_eq!(input["siblings"].as_array().unwrap().len(), 10);
    assert!(registry.revoke(1, 1011).is_err());
    assert!(registry.revoke(0, 999).is_err());
    assert_eq!(registry.version, 1);
}
