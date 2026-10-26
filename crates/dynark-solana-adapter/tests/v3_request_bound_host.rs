//! Private training proof -> adapter -> program host verifier only.
//! No setup/proving, authenticated chain observation, Execute or queue effect.
//! Run the ignored test only with M2_V3_HOST_FIXTURE (canonical owner0700 path)
//! and M2_V3_HOST_RECEIPT_SHA256 (independently recorded training receipt hash).
use ark_bn254::{Bn254, Fr};
use ark_ff::{Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use dynark_solana_adapter::v3;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    str::FromStr,
};
use zk_fresh_program::{application_runtime_v3::verify, generated_vk_v3 as program_vk};

type Result<T> = std::result::Result<T, &'static str>;
fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn owner() -> u32 {
    // Metadata check for a host-only test; no application code uses this syscall.
    unsafe { libc::geteuid() }
}
fn directory(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path).map_err(|_| "private directory metadata")?;
    if !path.is_absolute()
        || fs::canonicalize(path).ok().as_deref() != Some(path)
        || !meta.is_dir()
        || meta.permissions().mode() & 0o7777 != 0o700
        || meta.uid() != owner()
    {
        return Err("canonical owner0700 directory required");
    }
    Ok(())
}
fn private(path: &Path, cap: usize, exact: Option<usize>) -> Result<Vec<u8>> {
    directory(path.parent().ok_or("private parent")?)?;
    let before = fs::symlink_metadata(path).map_err(|_| "private metadata")?;
    if !before.is_file()
        || before.permissions().mode() & 0o7777 != 0o600
        || before.uid() != owner()
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > cap as u64
        || exact.is_some_and(|n| before.len() != n as u64)
    {
        return Err("private file shape");
    }
    let identity = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.mode(),
            m.uid(),
            m.nlink(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "private open")?;
    if identity(&file.metadata().map_err(|_| "private handle")?) != identity(&before) {
        return Err("private identity");
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "private read")?;
    if bytes.len() != before.len() as usize
        || identity(&file.metadata().map_err(|_| "private handle")?) != identity(&before)
        || identity(&fs::symlink_metadata(path).map_err(|_| "private name")?) != identity(&before)
    {
        return Err("private changed");
    }
    Ok(bytes)
}
fn public_values(raw: &[u8]) -> Result<Vec<Fr>> {
    let raw = if raw.len() == 200 && raw[..8] == 6u64.to_le_bytes() {
        &raw[8..]
    } else {
        raw
    };
    if raw.len() != 192 {
        return Err("six raw LE fields required");
    }
    raw.chunks_exact(32)
        .map(|word| Fr::deserialize_compressed(word).map_err(|_| "canonical public field"))
        .collect()
}
fn proof(raw: &[u8]) -> Result<ordinary::Proof<Bn254>> {
    if raw.len() != 128 {
        return Err("compressed proof128 required");
    }
    let mut cursor = raw;
    let proof = ordinary::Proof::<Bn254>::deserialize_compressed(&mut cursor)
        .map_err(|_| "canonical proof")?;
    if !cursor.is_empty() {
        return Err("proof trailing bytes");
    }
    Ok(proof)
}
fn expected_public(public_json: &[u8], input_json: &[u8], q1: &[u8]) -> Result<Vec<Fr>> {
    let public: Value = serde_json::from_slice(public_json).map_err(|_| "public JSON")?;
    let input: Value = serde_json::from_slice(input_json).map_err(|_| "input JSON")?;
    let values = public
        .as_array()
        .filter(|a| a.len() == 6)
        .ok_or("six public JSON fields")?;
    if input.as_object().filter(|o| o.len() == 14).is_none() {
        return Err("input keys");
    }
    let mut expected = Vec::new();
    for (name, value) in v3::PUBLIC_NAMES.iter().zip(values) {
        let decimal = value.as_str().ok_or("public decimal string")?;
        let scalar = Fr::from_str(decimal).map_err(|_| "public decimal field")?;
        if scalar.to_string() != decimal || input.get(*name) != Some(value) {
            return Err("exact input/public equality");
        }
        expected.push(scalar);
    }
    if q1.len() != 1918 || &q1[..4] != b"V3Q1" {
        return Err("Q1 shape");
    }
    let action: [u8; 32] = q1[1212..1244].try_into().map_err(|_| "action width")?;
    let mut canonical_action = [0; 32];
    expected[4]
        .serialize_compressed(&mut canonical_action[..])
        .map_err(|_| "action scalar")?;
    canonical_action.reverse();
    if action != canonical_action {
        return Err("Q1 action mismatch");
    }
    for (index, start) in [(0, 1822), (1, 1854), (5, 1886)] {
        let mut canonical = [0; 32];
        expected[index]
            .serialize_compressed(&mut canonical[..])
            .map_err(|_| "Q1 scalar")?;
        if q1[start..start + 32] != canonical {
            return Err("Q1 public mismatch");
        }
    }
    Ok(expected)
}
fn identity() -> v3::Identity {
    v3::Identity {
        circuit: program_vk::CIRCUIT_ID,
        package: program_vk::PACKAGE_ID,
        schema: program_vk::SEMANTIC_SCHEMA_ID,
        profile: program_vk::PROFILE_ID,
        ordinary_vk_digest: program_vk::ORDINARY_VK_DIGEST,
    }
}
fn adapter(vk_bytes: &[u8]) -> Result<v3::Verifier> {
    let expected_sha: String = program_vk::ORDINARY_VK_FILE_SHA256
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if vk_bytes.len() != 456
        || sha(vk_bytes) != expected_sha
        || vk_bytes[224..232] != 7u64.to_le_bytes()
    {
        return Err("pinned seven-IC ordinary VK");
    }
    let mut cursor = vk_bytes;
    let vk = ordinary::VerifyingKey::<Bn254>::deserialize_compressed(&mut cursor)
        .map_err(|_| "canonical ordinary VK")?;
    if !cursor.is_empty() {
        return Err("VK trailing bytes");
    }
    v3::Verifier::new(vk, identity()).map_err(|_| "adapter identity")
}
fn verify_join(
    proof_bytes: &[u8],
    public_bytes: &[u8],
    expected: &[Fr],
    vk: &[u8],
) -> Result<[u8; 448]> {
    let fields = public_values(public_bytes)?;
    if fields != expected {
        return Err("qualification publics differ from pinned fixture");
    }
    let proof = proof(proof_bytes)?;
    let verifier = adapter(vk)?;
    let encoded = verifier
        .encode(&proof, &fields, identity())
        .map_err(|_| "adapter encode")?;
    let flat: Vec<_> = encoded.inputs.iter().flatten().copied().collect();
    let decoded = verifier
        .decode(&encoded.proof, &flat, identity())
        .map_err(|_| "adapter decode")?;
    let mut roundtrip = Vec::new();
    decoded
        .serialize_compressed(&mut roundtrip)
        .map_err(|_| "proof roundtrip")?;
    if roundtrip != proof_bytes {
        return Err("proof roundtrip mismatch");
    }
    verifier
        .verify_solana(&encoded.proof, &flat, identity())
        .map_err(|_| "adapter native verifier")?;
    verify(&encoded.inputs, &encoded.proof).map_err(|_| "program host verifier")?;
    // Valid canonical changed statements must fail both component verifier paths.
    for index in 0..6 {
        let mut wrong = fields.clone();
        wrong[index] += Fr::ONE;
        if verifier.encode(&proof, &wrong, identity()).is_ok() {
            return Err("changed public accepted");
        }
        let mut wrong_inputs = encoded.inputs;
        let mut word = [0; 32];
        wrong[index]
            .serialize_compressed(&mut word[..])
            .map_err(|_| "changed public")?;
        word.reverse();
        wrong_inputs[index] = word;
        if verify(&wrong_inputs, &encoded.proof).is_ok() {
            return Err("host changed public accepted");
        }
    }
    // Negating C preserves curve/subgroup membership while invalidating this proof.
    let mut wrong_proof = proof.clone();
    wrong_proof.c = -wrong_proof.c;
    if verifier.encode(&wrong_proof, &fields, identity()).is_ok() {
        return Err("changed proof accepted");
    }
    let mut wire_wrong = encoded.proof;
    let mut y = ark_bn254::Fq::from_be_bytes_mod_order(&wire_wrong[224..256]);
    y = -y;
    y.serialize_compressed(&mut wire_wrong[224..256])
        .map_err(|_| "C coordinate")?;
    wire_wrong[224..256].reverse();
    if verify(&encoded.inputs, &wire_wrong).is_ok() {
        return Err("host changed proof accepted");
    }
    let mut wire = [0; 448];
    wire[..192].copy_from_slice(&flat);
    wire[192..].copy_from_slice(&encoded.proof);
    Ok(wire)
}

#[test]
fn raw_public_format_rejects_vec_prefix_wrong_width_and_noncanonical_fields() {
    assert!(public_values(&[0; 192]).is_ok());
    for width in [0, 191, 193, 200] {
        assert!(public_values(&vec![0; width]).is_err());
    }
    assert!(public_values(&[255; 192]).is_err());
    assert!(proof(&[0; 127]).is_err());
    assert!(proof(&[0; 129]).is_err());
}
#[test]
fn request_public_input_binding_rejects_substitution_and_noncanonical_decimal() {
    let public = serde_json::json!(["0", "0", "0", "0", "0", "0"]);
    let mut input = serde_json::Map::new();
    for name in v3::PUBLIC_NAMES {
        input.insert(name.into(), serde_json::json!("0"));
    }
    for name in [
        "layout",
        "slot",
        "tbs",
        "issuerModulus",
        "issuerSignature",
        "holderSignature",
        "siblings",
        "pathIndices",
    ] {
        input.insert(name.into(), serde_json::json!("0"));
    }
    let mut q1 = vec![0; 1918];
    q1[..4].copy_from_slice(b"V3Q1");
    let p = serde_json::to_vec(&public).unwrap();
    let i = serde_json::to_vec(&input).unwrap();
    assert!(expected_public(&p, &i, &q1).is_ok());
    for index in [1212, 1822, 1854, 1886] {
        q1[index] ^= 1;
        assert!(expected_public(&p, &i, &q1).is_err());
        q1[index] ^= 1;
    }
    input.insert("actionHash".into(), serde_json::json!("1"));
    assert!(expected_public(&p, &serde_json::to_vec(&input).unwrap(), &q1).is_err());
    let noncanonical = br#"["00","0","0","0","0","0"]"#;
    assert!(expected_public(noncanonical, &i, &q1).is_err());
}
#[test]
fn existing_public_corpus_checks_real_adapter_and_program_host_join() {
    // Public retained corpus only, distinct from the ignored request-bound gate.
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../program/tests/data");
    let proof = fs::read(base.join("v3-credential-0-full-base.ark-proof")).unwrap();
    let public = fs::read(base.join("v3-credential-0-full-base.ark-public")).unwrap();
    let vk = fs::read(base.join("v3-ordinary.ark-vk")).unwrap();
    assert_eq!(public.len(), 200);
    assert_eq!(&public[..8], &6u64.to_le_bytes());
    let fields = public_values(&public[8..]).unwrap();
    assert!(verify_join(&proof, &public[8..], &fields, &vk).is_ok());
    let mut wrong = fields;
    wrong[4] += Fr::ONE;
    assert!(verify_join(&proof, &public[8..], &wrong, &vk).is_err());
}
#[test]
fn private_reader_rejects_public_mode_and_hardlinks() {
    let dir = std::env::temp_dir().join(format!("v3-host-private-{}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let dir = fs::canonicalize(dir).unwrap();
    let path = dir.join("fixture");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.write_all(b"fixture").unwrap();
    assert!(private(&path, 7, Some(7)).is_ok());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(private(&path, 7, Some(7)).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let link = dir.join("link");
    fs::hard_link(&path, &link).unwrap();
    assert!(private(&path, 7, Some(7)).is_err());
    fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(private(&link, 7, Some(7)).is_err());
    assert!(private(&path, 6, Some(7)).is_err());
    assert!(private(&path, 7, Some(6)).is_err());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
#[ignore = "explicit private request-bound training proof fixture required"]
fn private_request_bound_full_passes_adapter_and_program_host() {
    let fixture =
        PathBuf::from(std::env::var_os("M2_V3_HOST_FIXTURE").expect("private fixture required"));
    directory(&fixture).expect("private fixture directory");
    let receipt_bytes = private(&fixture.join("training-receipt.json"), 16384, None).unwrap();
    let expected_sha = std::env::var("M2_V3_HOST_RECEIPT_SHA256").expect("receipt SHA required");
    assert!(
        expected_sha.len() == 64
            && expected_sha
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert!(
        sha(&receipt_bytes) == expected_sha,
        "pinned training receipt"
    );
    let receipt: Value = serde_json::from_slice(&receipt_bytes).expect("training receipt JSON");
    assert!(
        receipt["schema"] == "v3-request-bound-training-input-v1"
            && receipt["training_only"] == true
            && receipt["live_state_authenticated"] == false
            && receipt["proof_created"] == false
    );
    let q1 = private(&fixture.join("request.bin"), 1918, Some(1918)).unwrap();
    let input = private(&fixture.join("input.json"), 65536, None).unwrap();
    let public_json = private(&fixture.join("public.json"), 1024, None).unwrap();
    for (name, bytes) in [
        ("request.bin", &q1),
        ("input.json", &input),
        ("public.json", &public_json),
    ] {
        assert!(
            receipt["artifact_sha256"][name].as_str() == Some(sha(bytes).as_str()),
            "pinned fixture artifact"
        );
    }
    let expected =
        expected_public(&public_json, &input, &q1).expect("exact request/public/input equality");
    let proof = private(&fixture.join("full-ordinary.proof"), 128, Some(128)).unwrap();
    let public = private(&fixture.join("full-public-le.bin"), 192, Some(192)).unwrap();
    let setup = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../artifacts/dynark/part5/v3-development-setup-001");
    let vk = private(
        &setup.canonicalize().unwrap().join("ordinary.vk"),
        456,
        Some(456),
    )
    .unwrap();
    let wire =
        verify_join(&proof, &public, &expected, &vk).expect("private training adapter/host join");
    let output = fixture.join("full-solana-wire.bin");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&output)
        .expect("fresh private wire output");
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .unwrap();
    file.write_all(&wire).unwrap();
    file.sync_all().unwrap();
    assert!(
        private(&output, 448, Some(448)).unwrap() == wire,
        "private wire output identity"
    );
    // No serialized values are printed. Execute/live authorization remain separate.
}

#[test]
#[ignore = "explicit private request-bound Anchor proof and changed-root fixture required"]
fn private_request_bound_anchor_passes_adapter_and_program_host() {
    let base_fixture = PathBuf::from(
        std::env::var_os("M2_V3_ANCHOR_BASE_FIXTURE").expect("private base fixture required"),
    );
    let fixture = PathBuf::from(
        std::env::var_os("M2_V3_ANCHOR_FIXTURE").expect("private near fixture required"),
    );
    let proof_dir = PathBuf::from(
        std::env::var_os("M2_V3_ANCHOR_PROOF_DIR").expect("private proof directory required"),
    );
    directory(&base_fixture).expect("private base fixture directory");
    directory(&fixture).expect("private near fixture directory");
    directory(&proof_dir).expect("private proof directory");
    let receipt_bytes = private(&fixture.join("training-receipt.json"), 16384, None).unwrap();
    let receipt_sha = std::env::var("M2_V3_ANCHOR_RECEIPT_SHA256").expect("near receipt SHA");
    assert_eq!(sha(&receipt_bytes), receipt_sha, "pinned near receipt");
    let receipt: Value = serde_json::from_slice(&receipt_bytes).expect("near receipt JSON");
    assert!(
        receipt["schema"] == "v3-request-bound-near-training-input-v1"
            && receipt["training_only"] == true
            && receipt["live_state_authenticated"] == false
            && receipt["proof_created"] == false
    );
    let base_receipt_bytes =
        private(&base_fixture.join("training-receipt.json"), 16384, None).unwrap();
    let base_receipt_sha =
        std::env::var("M2_V3_ANCHOR_BASE_RECEIPT_SHA256").expect("base receipt SHA");
    assert_eq!(
        sha(&base_receipt_bytes),
        base_receipt_sha,
        "pinned base receipt"
    );
    let base_receipt: Value =
        serde_json::from_slice(&base_receipt_bytes).expect("base receipt JSON");
    assert!(
        base_receipt["schema"] == "v3-request-bound-training-input-v1"
            && base_receipt["training_only"] == true
            && base_receipt["proof_created"] == false
    );
    let report_bytes = private(&proof_dir.join("proof-report.json"), 65536, None).unwrap();
    let report_sha = std::env::var("M2_V3_ANCHOR_PROOF_REPORT_SHA256").expect("proof report SHA");
    assert_eq!(
        sha(&report_bytes),
        report_sha,
        "pinned ordinary proof report"
    );
    let report: Value = serde_json::from_slice(&report_bytes).expect("proof report JSON");
    assert!(
        report["schema"] == "credential-v3-request-bound-anchor-proof-v1"
            && report["passed"] == true
            && report["mode"] == "anchor-request-bound"
            && report["application_verified"] == false
            && report["old_base_full_rejected_at_near_publics"] == true
    );
    let q1 = private(&fixture.join("request.bin"), 1918, Some(1918)).unwrap();
    let input = private(&fixture.join("input.json"), 65536, None).unwrap();
    let public_json = private(&fixture.join("public.json"), 1024, None).unwrap();
    for (name, bytes) in [
        ("request.bin", &q1),
        ("input.json", &input),
        ("public.json", &public_json),
    ] {
        assert_eq!(
            receipt["artifact_sha256"][name].as_str(),
            Some(sha(bytes).as_str()),
            "pinned near artifact"
        );
    }
    let expected =
        expected_public(&public_json, &input, &q1).expect("near request/public/input equality");
    let base_request = private(&base_fixture.join("request.bin"), 1918, Some(1918)).unwrap();
    let base_input = private(&base_fixture.join("input.json"), 65536, None).unwrap();
    let base_public_json = private(&base_fixture.join("public.json"), 1024, None).unwrap();
    for (name, bytes) in [
        ("request.bin", &base_request),
        ("input.json", &base_input),
        ("public.json", &base_public_json),
    ] {
        assert_eq!(
            base_receipt["artifact_sha256"][name].as_str(),
            Some(sha(bytes).as_str())
        );
    }
    let base_expected = expected_public(&base_public_json, &base_input, &base_request)
        .expect("base request/public/input equality");
    assert_ne!(base_expected[0], expected[0], "changed root");
    assert_eq!(
        &base_expected[1..],
        &expected[1..],
        "same issuer, validity, action and policy"
    );
    assert_eq!(
        report["application_stage_pins"]["base_root"].as_str(),
        Some(base_expected[0].to_string().as_str()),
        "proof report base root"
    );
    assert_eq!(
        report["application_stage_pins"]["near_root"].as_str(),
        Some(expected[0].to_string().as_str()),
        "proof report near root"
    );
    assert_eq!(
        report["application_stage_pins"]["action_hash"].as_str(),
        Some(expected[4].to_string().as_str()),
        "proof report exact action"
    );
    let proof = private(
        &proof_dir.join("request_bound_training_anchor_near.proof"),
        128,
        Some(128),
    )
    .unwrap();
    let public = private(
        &proof_dir.join("request_bound_training_anchor_near-public.bin"),
        200,
        Some(200),
    )
    .unwrap();
    let setup = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../artifacts/dynark/part5/v3-development-setup-001");
    let vk = private(
        &setup.canonicalize().unwrap().join("ordinary.vk"),
        456,
        Some(456),
    )
    .unwrap();
    let wire = verify_join(&proof, &public, &expected, &vk)
        .expect("near Anchor adapter and program host verification");
    let full_proof = private(
        &proof_dir.join("request_bound_training_full_base.proof"),
        128,
        Some(128),
    )
    .unwrap();
    let full_public = private(
        &proof_dir.join("request_bound_training_full_base-public.bin"),
        200,
        Some(200),
    )
    .unwrap();
    let full_wire = verify_join(&full_proof, &full_public, &base_expected, &vk)
        .expect("base Full adapter and program host verification");
    let base_output = base_fixture.join("full-solana-wire.bin");
    let mut base_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&base_output)
        .expect("fresh private Full wire output");
    base_file
        .set_permissions(fs::Permissions::from_mode(0o600))
        .unwrap();
    base_file.write_all(&full_wire).unwrap();
    base_file.sync_all().unwrap();
    assert_eq!(private(&base_output, 448, Some(448)).unwrap(), full_wire);
    let output = fixture.join("anchor-solana-wire.bin");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&output)
        .expect("fresh private Anchor wire output");
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .unwrap();
    file.write_all(&wire).unwrap();
    file.sync_all().unwrap();
    assert_eq!(private(&output, 448, Some(448)).unwrap(), wire);
}

#[test]
#[ignore = "explicit private request-bound R1 Full proof and finalized fixture required"]
fn private_request_bound_full_near_passes_adapter_and_program_host() {
    let fixture = PathBuf::from(
        std::env::var_os("M2_V3_FULL_NEAR_FIXTURE").expect("private R1 fixture required"),
    );
    let proof_dir = PathBuf::from(
        std::env::var_os("M2_V3_FULL_NEAR_PROOF_DIR").expect("private R1 proof directory required"),
    );
    directory(&fixture).unwrap();
    directory(&proof_dir).unwrap();
    let receipt_bytes = private(&fixture.join("training-receipt.json"), 16384, None).unwrap();
    assert_eq!(
        sha(&receipt_bytes),
        std::env::var("M2_V3_FULL_NEAR_RECEIPT_SHA256").unwrap()
    );
    let receipt: Value = serde_json::from_slice(&receipt_bytes).unwrap();
    assert!(
        receipt["schema"] == "v3-request-bound-near-training-input-v1"
            && receipt["training_only"] == true
            && receipt["proof_created"] == false
    );
    let report_bytes = private(&proof_dir.join("proof-report.json"), 65536, None).unwrap();
    assert_eq!(
        sha(&report_bytes),
        std::env::var("M2_V3_FULL_NEAR_PROOF_REPORT_SHA256").unwrap()
    );
    let report: Value = serde_json::from_slice(&report_bytes).unwrap();
    assert!(
        report["schema"] == "credential-v3-request-bound-full-proof-v1"
            && report["mode"] == "full-request-bound"
            && report["passed"] == true
            && report["application_verified"] == false
            && report["counts"]["proofs"] == 3
            && report["counts"]["ordinary_checks"] == 23
    );
    let q1 = private(&fixture.join("request.bin"), 1918, Some(1918)).unwrap();
    let input = private(&fixture.join("input.json"), 65536, None).unwrap();
    let public_json = private(&fixture.join("public.json"), 1024, None).unwrap();
    for (name, bytes) in [
        ("request.bin", &q1),
        ("input.json", &input),
        ("public.json", &public_json),
    ] {
        assert_eq!(
            receipt["artifact_sha256"][name].as_str(),
            Some(sha(bytes).as_str())
        );
    }
    let expected = expected_public(&public_json, &input, &q1).unwrap();
    assert_eq!(
        report["application_stage_pins"]["near_root"].as_str(),
        Some(expected[0].to_string().as_str())
    );
    assert_eq!(
        report["application_stage_pins"]["action_hash"].as_str(),
        Some(expected[4].to_string().as_str())
    );
    let proof = private(
        &proof_dir.join("request_bound_training_full_near.proof"),
        128,
        Some(128),
    )
    .unwrap();
    let public = private(
        &proof_dir.join("request_bound_training_full_near-public.bin"),
        200,
        Some(200),
    )
    .unwrap();
    let setup = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../artifacts/dynark/part5/v3-development-setup-001");
    let vk = private(
        &setup.canonicalize().unwrap().join("ordinary.vk"),
        456,
        Some(456),
    )
    .unwrap();
    let wire = verify_join(&proof, &public, &expected, &vk)
        .expect("R1 Full adapter and program host verification");
    let output = fixture.join("full-near-solana-wire.bin");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&output)
        .expect("fresh private R1 Full wire output");
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .unwrap();
    file.write_all(&wire).unwrap();
    file.sync_all().unwrap();
    assert_eq!(private(&output, 448, Some(448)).unwrap(), wire);
}

#[test]
#[ignore = "explicit matched request-bound proof and private fixtures required"]
fn private_matched_k1_wires_pass_adapter_and_program_host() {
    let mode = std::env::var("M2_V3_MATCHED_MODE").expect("matched mode");
    assert!(matches!(mode.as_str(), "matched-full-k1" | "matched-anchor-k1"));
    let base = PathBuf::from(std::env::var_os("M2_V3_MATCHED_BASE").expect("base fixture"));
    let near = PathBuf::from(std::env::var_os("M2_V3_MATCHED_NEAR").expect("near fixture"));
    let proofs = PathBuf::from(std::env::var_os("M2_V3_MATCHED_PROOFS").expect("proof directory"));
    for path in [&base, &near, &proofs] {
        directory(path).expect("owner-only fixture directory");
    }
    let report_bytes = private(&proofs.join("proof-report.json"), 65536, None).unwrap();
    assert_eq!(
        sha(&report_bytes),
        std::env::var("M2_V3_MATCHED_REPORT_SHA256").expect("proof report SHA")
    );
    let report: Value = serde_json::from_slice(&report_bytes).unwrap();
    assert!(
        report["schema"] == "credential-v3-matched-k1-proof-v1"
            && report["mode"] == mode
            && report["passed"] == true
            && report["application_verified"] == false
            && report["qualification_extras_executed"] == false
            && report["counts"]["proofs"] == 2
            && report["counts"]["ordinary_checks"] == 16
    );
    let setup = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../artifacts/dynark/part5/v3-development-setup-001");
    let vk = private(&setup.canonicalize().unwrap().join("ordinary.vk"), 456, Some(456)).unwrap();
    for (fixture, suffix, proof_name, wire_name) in [
        (&base, "base", "request_bound_training_full_base", "full-solana-wire.bin"),
        (&near, "near", if mode == "matched-full-k1" {
            "request_bound_training_full_near"
        } else {
            "request_bound_training_anchor_near"
        }, if mode == "matched-full-k1" {
            "full-near-solana-wire.bin"
        } else {
            "anchor-solana-wire.bin"
        }),
    ] {
        let receipt_bytes = private(&fixture.join("training-receipt.json"), 16384, None).unwrap();
        let receipt: Value = serde_json::from_slice(&receipt_bytes).unwrap();
        assert_eq!(receipt["schema"], if suffix == "base" {
            "v3-request-bound-training-input-v1"
        } else {
            "v3-request-bound-near-training-input-v1"
        });
        let q1 = private(&fixture.join("request.bin"), 1918, Some(1918)).unwrap();
        let input = private(&fixture.join("input.json"), 65536, None).unwrap();
        let public_json = private(&fixture.join("public.json"), 1024, None).unwrap();
        for (name, bytes) in [
            ("request.bin", &q1),
            ("input.json", &input),
            ("public.json", &public_json),
        ] {
            assert_eq!(receipt["artifact_sha256"][name].as_str(), Some(sha(bytes).as_str()));
        }
        let expected = expected_public(&public_json, &input, &q1).unwrap();
        assert_eq!(report["application_stage_pins"][if suffix == "base" {
            "base_root"
        } else {
            "near_root"
        }], expected[0].to_string());
        assert_eq!(report["application_stage_pins"]["action_hash"], expected[4].to_string());
        let proof = private(&proofs.join(format!("{proof_name}.proof")), 128, Some(128)).unwrap();
        let public = private(&proofs.join(format!("{proof_name}-public.bin")), 200, Some(200)).unwrap();
        let wire = verify_join(&proof, &public, &expected, &vk).unwrap();
        let output = fixture.join(wire_name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&output)
            .unwrap();
        file.write_all(&wire).unwrap();
        file.sync_all().unwrap();
        assert_eq!(private(&output, 448, Some(448)).unwrap(), wire);
    }
}

#[test]
#[ignore = "explicit private cumulative proof and final request fixture required"]
fn private_campaign_final_wire_passes_adapter_and_program_host() {
    let mode = std::env::var("M2_V3_CAMPAIGN_MODE").expect("campaign proof mode");
    let (kind, suffix) = mode
        .strip_prefix("campaign-")
        .and_then(|value| value.rsplit_once("-k"))
        .expect("campaign mode shape");
    assert!(matches!(kind, "full" | "anchor" | "coalesced-full"));
    let count = match suffix {
        "0" => 0,
        "1" => 1,
        "2" => 2,
        "5" => 5,
        "10" => 10,
        _ => panic!("registered campaign count required"),
    };
    let fixture = PathBuf::from(
        std::env::var_os("M2_V3_CAMPAIGN_FINAL_FIXTURE").expect("final private fixture"),
    );
    let packet_path = PathBuf::from(
        std::env::var_os("M2_V3_CAMPAIGN_PACKET").expect("private proof packet"),
    );
    let proofs = PathBuf::from(
        std::env::var_os("M2_V3_CAMPAIGN_PROOFS").expect("private proof directory"),
    );
    for path in [&fixture, &proofs, packet_path.parent().expect("packet parent")] {
        directory(path).expect("canonical owner0700 private directory");
    }
    let receipt_bytes = private(&fixture.join("training-receipt.json"), 16384, None).unwrap();
    assert_eq!(
        sha(&receipt_bytes),
        std::env::var("M2_V3_CAMPAIGN_FINAL_RECEIPT_SHA256").expect("final receipt SHA")
    );
    let receipt: Value = serde_json::from_slice(&receipt_bytes).expect("final receipt JSON");
    assert!(receipt["training_only"] == true && receipt["proof_created"] == false);
    let q1 = private(&fixture.join("request.bin"), 1918, Some(1918)).unwrap();
    let input = private(&fixture.join("input.json"), 65536, None).unwrap();
    let public_json = private(&fixture.join("public.json"), 1024, None).unwrap();
    for (name, bytes) in [
        ("request.bin", &q1),
        ("input.json", &input),
        ("public.json", &public_json),
    ] {
        assert_eq!(receipt["artifact_sha256"][name].as_str(), Some(sha(bytes).as_str()));
    }
    let expected = expected_public(&public_json, &input, &q1)
        .expect("exact final request/input/public equality");

    let packet_bytes = private(&packet_path, 262144, None).unwrap();
    let packet_sha = std::env::var("M2_V3_CAMPAIGN_PACKET_SHA256").expect("packet SHA");
    assert_eq!(sha(&packet_bytes), packet_sha, "pinned proof packet");
    let packet: Value = serde_json::from_slice(&packet_bytes).expect("proof packet JSON");
    assert_eq!(
        packet["schema"],
        if kind == "coalesced-full" {
            "credential-v3-cumulative-coalesced-request-v1"
        } else {
            "credential-v3-cumulative-request-v1"
        }
    );
    assert!(
        packet["synthetic_only"] == false
            && packet["application_verified"] == false
            && packet["cohort"] == "cumulative-training-v1"
            && packet["update_count"].as_u64() == Some(count)
    );
    let final_case = if kind == "coalesced-full" {
        &packet["final"]
    } else {
        let pairs = packet["pairs"].as_array().expect("campaign pairs");
        assert_eq!(pairs.len(), count.max(1) as usize);
        let last = pairs.last().unwrap();
        assert_eq!(last["name"], format!("request_bound_training_r{count}"));
        &last["near"]
    };
    assert_eq!(final_case["root_version"].as_u64(), Some(count));
    assert_eq!(
        final_case["input_path"].as_str(),
        fixture.join("input.json").to_str()
    );
    assert_eq!(
        final_case["public_path"].as_str(),
        fixture.join("public.json").to_str()
    );
    assert_eq!(final_case["input_sha256"].as_str(), Some(sha(&input).as_str()));
    assert_eq!(
        final_case["public_sha256"].as_str(),
        Some(sha(&public_json).as_str())
    );

    let report_bytes = private(&proofs.join("proof-report.json"), 65536, None).unwrap();
    assert_eq!(
        sha(&report_bytes),
        std::env::var("M2_V3_CAMPAIGN_REPORT_SHA256").expect("proof report SHA")
    );
    let report: Value = serde_json::from_slice(&report_bytes).expect("proof report JSON");
    let proof_count = if kind == "coalesced-full" { 1 } else { count + 1 };
    let cross_root_checks = if kind == "coalesced-full" { 0 } else { 2 * count };
    assert!(
        report["schema"] == "credential-v3-cumulative-proof-v1"
            && report["mode"] == mode
            && report["cohort"] == packet["cohort"]
            && report["update_count"].as_u64() == Some(count)
            && report["packet_sha256"].as_str() == Some(packet_sha.as_str())
            && report["passed"] == true
            && report["application_verified"] == false
            && report["admitted"] == false
            && report["counts"]["proofs"].as_u64() == Some(proof_count)
            && report["counts"]["positive_checks"].as_u64() == Some(proof_count)
            && report["counts"]["altered_public_checks"].as_u64() == Some(6 * proof_count)
            && report["counts"]["cross_root_checks"].as_u64() == Some(cross_root_checks)
            && report["counts"]["ordinary_checks"].as_u64()
                == Some(7 * proof_count + cross_root_checks)
    );
    let checkpoints = report["checkpoints"].as_array().expect("proof checkpoints");
    assert_eq!(checkpoints.len(), proof_count as usize);
    let last = checkpoints.last().unwrap();
    assert_eq!(last["generation"].as_u64(), Some(count));
    assert_eq!(
        last["proof_kind"],
        if kind == "coalesced-full" {
            "coalesced-full"
        } else if kind == "anchor" && count > 0 {
            "anchor"
        } else {
            "full"
        }
    );
    assert_eq!(report["application_stage_pins"], packet["application_stage"]);
    assert_eq!(
        report["application_stage_pins_authority"],
        "caller-supplied; external finalized-state verification required"
    );
    assert_eq!(
        report["application_stage_pins"]["near_root"],
        expected[0].to_string()
    );
    assert_eq!(
        report["application_stage_pins"]["action_hash"],
        expected[4].to_string()
    );
    if count == 0 {
        assert_eq!(report["application_stage_pins"]["base_root"], expected[0].to_string());
    } else {
        assert_ne!(report["application_stage_pins"]["base_root"], expected[0].to_string());
    }
    for name in [
        "freeze_receipt_sha256",
        "history_receipt_sha256",
        "root_schedule_sha256",
    ] {
        assert_eq!(report[name], packet[name]);
    }

    let proof_name = if kind == "coalesced-full" {
        format!("request_bound_training_coalesced_full_r{count}")
    } else if kind == "anchor" && count > 0 {
        format!("request_bound_training_anchor_r{count}")
    } else {
        format!("request_bound_training_full_r{count}")
    };
    let proof = private(&proofs.join(format!("{proof_name}.proof")), 128, Some(128)).unwrap();
    let public = private(
        &proofs.join(format!("{proof_name}-public.bin")),
        200,
        Some(200),
    )
    .unwrap();
    let setup = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../artifacts/dynark/part5/v3-development-setup-001");
    let vk = private(
        &setup.canonicalize().unwrap().join("ordinary.vk"),
        456,
        Some(456),
    )
    .unwrap();
    assert_eq!(report["ordinary_vk_file_sha256"], sha(&vk));
    let wire = verify_join(&proof, &public, &expected, &vk)
        .expect("final campaign ordinary proof/adapter/program host join");
    let output = fixture.join(format!("{mode}-solana-wire.bin"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&output)
        .expect("fresh private campaign wire output");
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .unwrap();
    file.write_all(&wire).unwrap();
    file.sync_all().unwrap();
    assert_eq!(private(&output, 448, Some(448)).unwrap(), wire);

    // The cumulative R0 proof is available for Full and Anchor campaigns and
    // is needed by the protected-effect host to reject stale-base execution.
    // Coalesced campaigns intentionally produce only their final proof.
    if kind != "coalesced-full" && count > 0 {
        let base_fixture = PathBuf::from(
            std::env::var_os("M2_V3_CAMPAIGN_BASE_FIXTURE")
                .expect("private cumulative base fixture"),
        );
        directory(&base_fixture).expect("canonical owner0700 base fixture directory");
        let base_receipt_bytes =
            private(&base_fixture.join("training-receipt.json"), 16384, None).unwrap();
        assert_eq!(
            sha(&base_receipt_bytes),
            std::env::var("M2_V3_CAMPAIGN_BASE_RECEIPT_SHA256").expect("base receipt SHA")
        );
        let base_receipt: Value =
            serde_json::from_slice(&base_receipt_bytes).expect("base receipt JSON");
        assert!(
            base_receipt["schema"] == "v3-request-bound-training-input-v1"
                && base_receipt["training_only"] == true
                && base_receipt["proof_created"] == false
        );
        let base_request = private(&base_fixture.join("request.bin"), 1918, Some(1918)).unwrap();
        let base_input = private(&base_fixture.join("input.json"), 65536, None).unwrap();
        let base_public_json = private(&base_fixture.join("public.json"), 1024, None).unwrap();
        for (name, bytes) in [
            ("request.bin", &base_request),
            ("input.json", &base_input),
            ("public.json", &base_public_json),
        ] {
            assert_eq!(
                base_receipt["artifact_sha256"][name].as_str(),
                Some(sha(bytes).as_str())
            );
        }
        let base_expected = expected_public(&base_public_json, &base_input, &base_request)
            .expect("base request/public/input equality");
        assert_eq!(
            report["application_stage_pins"]["base_root"],
            base_expected[0].to_string(),
            "proof report base root"
        );
        assert_ne!(base_expected[0], expected[0], "stale R0 root differs from final");
        assert_eq!(&base_expected[1..], &expected[1..], "same cumulative action");

        let base_proof = private(
            &proofs.join("request_bound_training_full_r0.proof"),
            128,
            Some(128),
        )
        .unwrap();
        let base_public = private(
            &proofs.join("request_bound_training_full_r0-public.bin"),
            200,
            Some(200),
        )
        .unwrap();
        let base_wire = verify_join(&base_proof, &base_public, &base_expected, &vk)
            .expect("base R0 Full ordinary proof/adapter/program host join");
        let base_output = base_fixture.join("campaign-full-k0-solana-wire.bin");
        let mut base_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&base_output)
            .expect("fresh private campaign base wire output");
        base_file
            .set_permissions(fs::Permissions::from_mode(0o600))
            .unwrap();
        base_file.write_all(&base_wire).unwrap();
        base_file.sync_all().unwrap();
        assert_eq!(private(&base_output, 448, Some(448)).unwrap(), base_wire);
    }
    // Caller-supplied stage pins do not establish a finalized application effect.
}
