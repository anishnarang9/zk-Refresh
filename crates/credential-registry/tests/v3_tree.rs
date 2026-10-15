//! Public synthetic vectors; no certificates, keys, witnesses or authority claims.
use credential_registry::{
    v3::{leaf_hash, Tree, DEPTH, LEAF_DOMAIN},
    Error, Field,
};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/v3-membership-v1.json")).unwrap()
}
fn field(value: &Value) -> Field {
    let s = value.as_str().unwrap();
    assert_eq!(s.len(), 64);
    std::array::from_fn(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
}
fn path(value: &Value) -> Vec<Field> {
    value.as_array().unwrap().iter().map(field).collect()
}
fn digest(label: &str) -> Field {
    use sha2::{Digest, Sha256};
    Sha256::digest(label.as_bytes()).into()
}

#[test]
fn independent_v3_active_leaf_vector_matches_exactly() {
    let v = vectors();
    let row = &v["leaf_vectors"][0];
    assert_eq!(LEAF_DOMAIN, 2026101504);
    assert_eq!(DEPTH, 10);
    assert_eq!(
        leaf_hash(
            field(&row["digest"]),
            row["slot"].as_u64().unwrap() as usize,
            true
        ),
        Ok(field(&row["leaf"])),
        "independent fixed-domain v3 active leaf must match"
    );
}

#[test]
fn all_independent_active_revoked_and_boundary_slot_leaf_vectors_match() {
    for row in vectors()["leaf_vectors"].as_array().unwrap() {
        assert_eq!(
            leaf_hash(
                field(&row["digest"]),
                row["slot"].as_u64().unwrap() as usize,
                row["active"].as_bool().unwrap()
            ),
            Ok(field(&row["leaf"]))
        );
        assert_ne!(field(&row["leaf"]), field(&row["v2_leaf"]));
    }
}

#[test]
fn independent_sparse_tree_roots_paths_and_lsb_directions_match() {
    let v = vectors();
    let mut tree = Tree::new().unwrap();
    assert_eq!(tree.root(), field(&v["empty_root"]));
    for row in v["sparse_tree"]["records"].as_array().unwrap() {
        tree.set(
            row["slot"].as_u64().unwrap() as usize,
            field(&row["digest"]),
            true,
        )
        .unwrap();
    }
    assert_eq!(tree.root(), field(&v["sparse_tree"]["root"]));
    for row in v["sparse_tree"]["paths"].as_array().unwrap() {
        let slot = row["slot"].as_u64().unwrap() as usize;
        let expected = path(&row["siblings"]);
        assert_eq!(tree.path(slot).unwrap(), expected);
        assert_eq!(expected.len(), 10);
        let bits: Vec<u64> = (0..10).map(|i| ((slot >> i) & 1) as u64).collect();
        assert_eq!(serde_json::json!(bits), row["path_indices"]);
        Tree::verify(field(&row["digest"]), slot, true, &expected, tree.root()).unwrap();
    }
}

#[test]
fn unrelated_then_own_revocation_match_independent_roots() {
    let v = vectors();
    let scenario = &v["revocation"];
    let own = field(&scenario["own_digest"]);
    let other = field(&scenario["other_digest"]);
    let mut tree = Tree::new().unwrap();
    tree.set(17, own, true).unwrap();
    tree.set(18, other, true).unwrap();
    let old_path = tree.path(17).unwrap();
    assert_eq!(tree.root(), field(&scenario["before_root"]));
    tree.set(18, other, false).unwrap();
    assert_eq!(tree.root(), field(&scenario["unrelated_root"]));
    let near_path = tree.path(17).unwrap();
    assert_eq!(near_path, path(&scenario["unrelated_path"]));
    assert_eq!(
        old_path
            .iter()
            .zip(&near_path)
            .filter(|(a, b)| a != b)
            .count(),
        1
    );
    Tree::verify(own, 17, true, &near_path, tree.root()).unwrap();
    assert!(Tree::verify(own, 17, true, &old_path, tree.root()).is_err());
    tree.set(17, own, false).unwrap();
    assert_eq!(tree.root(), field(&scenario["own_revoked_root"]));
    let revoked_path = tree.path(17).unwrap();
    assert!(Tree::verify(own, 17, true, &revoked_path, tree.root()).is_err());
    Tree::verify(own, 17, false, &revoked_path, tree.root()).unwrap();
    assert_ne!(tree.root(), field(&v["empty_root"]));
}

#[test]
fn swapped_digest_halves_bytes_and_path_order_are_rejected() {
    let v = vectors();
    let row = &v["sparse_tree"]["paths"][2];
    let original = field(&row["digest"]);
    let root = field(&v["sparse_tree"]["root"]);
    let slot = row["slot"].as_u64().unwrap() as usize;
    let siblings = path(&row["siblings"]);
    let mut swapped = original;
    swapped[..16].copy_from_slice(&original[16..]);
    swapped[16..].copy_from_slice(&original[..16]);
    assert!(Tree::verify(swapped, slot, true, &siblings, root).is_err());
    let mut reversed = original;
    reversed.reverse();
    assert!(Tree::verify(reversed, slot, true, &siblings, root).is_err());
    let mut reversed_path = siblings.clone();
    reversed_path.reverse();
    assert!(Tree::verify(original, slot, true, &reversed_path, root).is_err());
    assert!(Tree::verify(original, slot ^ 1, true, &siblings, root).is_err());
}

#[test]
fn malformed_fields_paths_and_slots_reject_before_tree_mutation() {
    let mut tree = Tree::new().unwrap();
    tree.set(17, digest("public v3 bounds"), true).unwrap();
    let before = tree.root();
    assert_eq!(tree.set(1024, [1; 32], true), Err(Error::Invalid));
    assert_eq!(tree.path(1024), Err(Error::Invalid));
    assert_eq!(leaf_hash([1; 32], usize::MAX, true), Err(Error::Invalid));
    assert_eq!(tree.root(), before);
    for length in [0, 9, 11] {
        assert!(Tree::verify([1; 32], 17, true, &vec![[0; 32]; length], before).is_err());
    }
    let valid = tree.path(17).unwrap();
    let mut bad = valid.clone();
    bad[0] = [255; 32];
    assert!(Tree::verify(digest("public v3 bounds"), 17, true, &bad, before).is_err());
    assert!(Tree::verify(digest("public v3 bounds"), 17, true, &valid, [255; 32]).is_err());
    let modulus = field(&serde_json::json!(
        "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"
    ));
    let mut noncanonical = valid.clone();
    noncanonical[0] = modulus;
    assert!(Tree::verify(digest("public v3 bounds"), 17, true, &noncanonical, before).is_err());
    assert!(Tree::verify(digest("public v3 bounds"), 17, true, &valid, modulus).is_err());
    let mut changed = valid;
    changed[0][31] ^= 1;
    assert!(Tree::verify(digest("public v3 bounds"), 17, true, &changed, before).is_err());
}

#[test]
fn v2_and_v3_nonempty_membership_do_not_cross_verify() {
    let d = digest("public v3 cross-version");
    let mut old = credential_registry::Tree::new().unwrap();
    let mut new = Tree::new().unwrap();
    // Zero empty leaves share an empty root: protocol scopes must still differ.
    assert_eq!(old.root(), new.root());
    old.set(17, d, true).unwrap();
    new.set(17, d, true).unwrap();
    assert_ne!(old.root(), new.root());
    assert!(Tree::verify(d, 17, true, &old.path(17).unwrap(), old.root()).is_err());
    assert!(
        credential_registry::Tree::verify(d, 17, true, &new.path(17).unwrap(), new.root()).is_err()
    );
}
