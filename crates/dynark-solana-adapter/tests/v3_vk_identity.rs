//! Public setup identity qualification only. No setup, witness, proof or key generation.
//! The actual-artifact test is ignored until ROOT grants a serialized bounded gate.
use ark_bn254::Bn254;
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use dynark_solana_adapter::v3;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

const VK_SHA: &str = "87edb4608c2140f3c7fddc8503e49b68931cda973711ce2c831bd44f1b98a875";
const MANIFEST_SHA: &str = "d31f82e3f147e31b30074b3a570a9d7945c5e1f5d3f3dd74172801abbe984918";
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn sha(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}
fn checked(path: &Path, size: usize, expected: &str) -> Vec<u8> {
    assert!(path.is_absolute());
    let meta = fs::symlink_metadata(path).unwrap();
    assert!(meta.is_file() && !meta.file_type().is_symlink());
    assert!(meta.len() <= size as u64);
    let b = fs::read(path).unwrap();
    assert_eq!(sha(&b), expected);
    b
}
fn parse(bytes: &[u8]) -> ordinary::VerifyingKey<Bn254> {
    // Compressed BN254 ordinary key: alpha32 + 3*G2_64 + vec_len_u64LE + 7*G1_32.
    // Validate the pinned finite vector length before ark deserialization allocates.
    assert_eq!(bytes.len(), 456);
    assert_eq!(&bytes[224..232], &7u64.to_le_bytes());
    let mut cursor = bytes;
    let key = ordinary::VerifyingKey::<Bn254>::deserialize_compressed(&mut cursor).unwrap();
    assert!(cursor.is_empty());
    assert_eq!(key.gamma_abc_g1.len(), 7);
    let mut roundtrip = vec![];
    key.serialize_compressed(&mut roundtrip).unwrap();
    assert_eq!(bytes, roundtrip);
    key
}
fn be<F: PrimeField>(f: F) -> [u8; 32] {
    let b = f.into_bigint().to_bytes_be();
    let mut out = [0; 32];
    out[32 - b.len()..].copy_from_slice(&b);
    out
}
fn independently_tagged(key: &ordinary::VerifyingKey<Bn254>) -> String {
    let mut bytes = b"dynark-solana-adapter/ordinary-vk/v2".to_vec();
    bytes.extend(6u32.to_be_bytes());
    bytes.extend(7u32.to_be_bytes());
    bytes.extend(be(key.alpha_g1.x));
    bytes.extend(be(key.alpha_g1.y));
    for p in [key.beta_g2, key.gamma_g2, key.delta_g2] {
        for f in [p.x.c1, p.x.c0, p.y.c1, p.y.c0] {
            bytes.extend(be(f));
        }
    }
    for p in &key.gamma_abc_g1 {
        if p.is_zero() {
            bytes.extend([0; 64]);
        } else {
            bytes.extend(be(p.x));
            bytes.extend(be(p.y));
        }
    }
    sha(&bytes)
}
#[test]
fn compressed_ic_allocation_guard_rejects_other_counts_before_deserialization() {
    for count in [0u64, 6, 8, u64::MAX] {
        let mut b = vec![0; 456];
        b[224..232].copy_from_slice(&count.to_le_bytes());
        assert!(std::panic::catch_unwind(|| parse(&b)).is_err());
    }
    for size in [0, 455, 457] {
        assert!(std::panic::catch_unwind(|| parse(&vec![0; size])).is_err());
    }
}
#[test]
#[ignore = "ROOT must grant bounded public-artifact identity measurement and fresh private receipt path"]
fn reviewed_setup_vk_identity_receipt() {
    let vk_path = std::env::var("P5_V3_IDENTITY_VK").expect("reviewed VK path required");
    let manifest_path =
        std::env::var("P5_V3_IDENTITY_MANIFEST").expect("reviewed manifest path required");
    let receipt = std::env::var("P5_V3_IDENTITY_RECEIPT").expect("fresh receipt path required");
    let bytes = checked(Path::new(&vk_path), 456, VK_SHA);
    assert_eq!(bytes.len(), 456);
    let manifest = checked(Path::new(&manifest_path), 16384, MANIFEST_SHA);
    let key = parse(&bytes);
    let tagged = hex(&v3::ordinary_vk_digest(&key).unwrap());
    assert_eq!(tagged, independently_tagged(&key));
    assert_eq!(
        v3::PUBLIC_NAMES,
        [
            "root",
            "issuerHash",
            "notBefore",
            "notAfter",
            "actionHash",
            "policyHash"
        ]
    );
    assert_eq!(v3::ORDINARY_VK_TAG, b"dynark-solana-adapter/ordinary-vk/v2");
    assert_ne!(v3::ORDINARY_VK_TAG, dynark_solana_adapter::ORDINARY_VK_TAG);
    // Manifest bytes are pinned first. Values below are independently reviewed
    // labels from that exact manifest, not a claimed precomputed tagged digest.
    let report=format!(concat!(
        "{{\n  \"schema\":\"credential-v3-ordinary-vk-identity-v1\",\n",
        "  \"development_only\":true,\n  \"profile_admitted\":false,\n  \"proof_verified\":false,\n",
        "  \"setup_manifest_sha256\":\"{}\",\n  \"ordinary_vk_file_sha256\":\"{}\",\n",
        "  \"ordinary_vk_file_bytes\":456,\n  \"ordinary_vk_ic_count\":7,\n",
        "  \"ordered_public_inputs\":[\"root\",\"issuerHash\",\"notBefore\",\"notAfter\",\"actionHash\",\"policyHash\"],\n",
        "  \"ordinary_vk_tag\":\"dynark-solana-adapter/ordinary-vk/v2\",\n",
        "  \"ordinary_vk_tagged_digest\":\"{}\",\n",
        "  \"circuit_id\":\"eae99530daf7331037f2d1c6dc93ccc582603bd448f38d06e6469c734e8252fe\",\n",
        "  \"package_id\":\"61d941890d823433468048dd1bd91da80c1bf7e1b3d2b6f5d509077a47ed06c8\",\n",
        "  \"engine_extended_vk_digest\":\"2611d58c8c8d0b0c1f2c3f0facc4516e5c08e1fb3a7f14b16e32b948bc8f3c70\",\n",
        "  \"profile_sha256\":\"2e5d26564fb055e70cff924c4cb6e296509030b8c0062130f86ad5af783f7918\",\n",
        "  \"semantic_schema_sha256\":\"eabfaa2d95e4abc9126b87a04e94397091c103891e92dbaefaafba79cf3b26d4\",\n",
        "  \"public_schema_file_sha256\":\"ebb3ce4b4eef3ad43c5e21ad76d1bf9f0883a8ebc9e1a37c55c9894f1c00444b\",\n",
        "  \"adapter_lib_sha256\":\"{}\",\n  \"adapter_v3_sha256\":\"{}\",\n  \"gate_source_sha256\":\"{}\"\n}}\n"
    ),sha(&manifest),sha(&bytes),tagged,sha(include_bytes!("../src/lib.rs")),sha(include_bytes!("../src/v3.rs")),sha(include_bytes!("v3_vk_identity.rs")));
    let output = Path::new(&receipt);
    assert!(output.is_absolute());
    let parent = fs::symlink_metadata(output.parent().unwrap()).unwrap();
    assert!(parent.is_dir() && !parent.file_type().is_symlink());
    assert_eq!(parent.permissions().mode() & 0o077, 0);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output)
        .unwrap();
    file.write_all(report.as_bytes()).unwrap();
    file.sync_all().unwrap();
    println!("{}", report);
}
