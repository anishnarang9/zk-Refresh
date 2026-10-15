//! Public-only verifier boundary. Corpus credential_0/full_base is a Full proof
//! for action12345, not a finalized application request or queue-effect fixture.
//! Ark proof128/public200/VK456 are source-pinned below. Runtime Execute stays
//! closed. Canonical decompression happens only when ROOT runs this host test.
use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::{Groth16Verifier, Groth16Verifyingkey},
};
use solana_program::{hash::hash, program_error::ProgramError, pubkey::Pubkey};
use zk_fresh_program::{
    application_runtime_v2,
    application_runtime_v3::verify,
    application_v3::{AppError, PREFIX},
    generated_vk as v1, generated_vk_v2 as v2, generated_vk_v3 as v3, process_instruction,
    FIELD_MODULUS,
};

// Public source: artifacts/dynark/part5/v3-full-corpus-001/credential_0_full_base*
// and artifacts/dynark/part5/v3-development-setup-001/ordinary.vk. No secret data.
const RAW_PROOF: &[u8] = include_bytes!("data/v3-credential-0-full-base.ark-proof");
const RAW_PUBLIC: &[u8] = include_bytes!("data/v3-credential-0-full-base.ark-public");
const RAW_VK: &[u8] = include_bytes!("data/v3-ordinary.ark-vk");
const PROOF_SHA: &str = "e7249b26863515c475042b96af2256843057c7c43e4f25319c9a82527a9b0e90";
const PUBLIC_SHA: &str = "cb19d40c4f24a67fde62710a5eb5fc019e3d037b592d6f2243fdc9186d138f9b";
const VK_SHA: &str = "87edb4608c2140f3c7fddc8503e49b68931cda973711ce2c831bd44f1b98a875";
const TAGGED_VK: &str = "2f9b770ff51ac399619a3127ddb32efad67697402f10c4549441a3578e4f9a4e";
const NAMES: [&str; 6] = [
    "root",
    "issuerHash",
    "notBefore",
    "notAfter",
    "actionHash",
    "policyHash",
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|n| format!("{n:02x}")).collect()
}
fn word(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);
    std::array::from_fn(|n| u8::from_str_radix(&hex[n * 2..n * 2 + 2], 16).unwrap())
}
fn fq() -> [u8; 32] {
    word("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47")
}
fn scalar(n: u64) -> [u8; 32] {
    let mut b = [0; 32];
    b[24..].copy_from_slice(&n.to_be_bytes());
    b
}
fn checked_sources() {
    for (raw, len, sha) in [
        (RAW_PROOF, 128, PROOF_SHA),
        (RAW_PUBLIC, 200, PUBLIC_SHA),
        (RAW_VK, 456, VK_SHA),
    ] {
        assert_eq!(raw.len(), len);
        assert_eq!(hex(&hash(raw).to_bytes()), sha);
    }
}
fn public_values(bytes: &[u8]) -> Option<[[u8; 32]; 6]> {
    if bytes.len() != 200 || bytes[..8] != 6u64.to_le_bytes() {
        return None;
    }
    let mut public = [[0; 32]; 6];
    for (value, raw) in public.iter_mut().zip(bytes[8..].chunks_exact(32)) {
        value.copy_from_slice(raw);
        value.reverse();
        if *value >= FIELD_MODULUS {
            return None;
        }
    }
    Some(public)
}
fn g1(raw: &[u8]) -> [u8; 64] {
    let mut compressed: [u8; 32] = raw.try_into().unwrap();
    // Ark compressed LE32 including flags -> Solana compressed BE32.
    compressed.reverse();
    decompress_g1(&compressed).unwrap()
}
fn g2(raw: &[u8]) -> [u8; 128] {
    let mut compressed: [u8; 64] = raw.try_into().unwrap();
    // Reverse the WHOLE compressed Fq2 word (not each32-byte limb). The installed
    // Solana decompressor returns canonical x.c1,x.c0,y.c1,y.c0 BE components.
    compressed.reverse();
    decompress_g2(&compressed).unwrap()
}
fn negate_y(point: &mut [u8]) {
    assert_eq!(point.len(), 64);
    let y: [u8; 32] = point[32..].try_into().unwrap();
    assert!(y < fq());
    if y == [0; 32] {
        return;
    }
    let modulus = fq();
    let mut negative = [0; 32];
    let mut borrow = 0u16;
    for n in (0..32).rev() {
        let value = modulus[n] as u16;
        let sub = y[n] as u16 + borrow;
        negative[n] = value.wrapping_sub(sub) as u8;
        borrow = u16::from(value < sub);
    }
    assert_eq!(borrow, 0);
    point[32..].copy_from_slice(&negative);
}
fn encoded() -> ([[u8; 32]; 6], [u8; 256]) {
    checked_sources();
    let public = public_values(RAW_PUBLIC).unwrap();
    let mut proof = [0; 256];
    proof[..64].copy_from_slice(&g1(&RAW_PROOF[..32]));
    negate_y(&mut proof[..64]);
    proof[64..192].copy_from_slice(&g2(&RAW_PROOF[32..96]));
    proof[192..].copy_from_slice(&g1(&RAW_PROOF[96..]));
    // Schema order is fixed, public Fr words are canonical BE32 without reduction.
    assert_eq!(
        NAMES,
        [
            "root",
            "issuerHash",
            "notBefore",
            "notAfter",
            "actionHash",
            "policyHash"
        ]
    );
    assert_eq!(public[2], scalar(0x6955b900));
    assert_eq!(public[3], scalar(0x6d40fe80));
    assert_eq!(public[4], scalar(12345));
    assert_ne!(public[0], public[1]);
    assert_ne!(public[5], [0; 32]);
    for coordinate in proof.chunks_exact(32) {
        assert!(coordinate < fq().as_slice());
    }
    (public, proof)
}
fn expected_key() -> (Groth16Verifyingkey<'static>, Vec<[u8; 64]>) {
    // Return the four fixed points separately from IC, avoiding leaking test memory.
    // The caller attaches its local seven-point IC vector before native verification.
    checked_sources();
    assert_eq!(&RAW_VK[224..232], &7u64.to_le_bytes());
    let fixed = Groth16Verifyingkey {
        nr_pubinputs: 6,
        vk_alpha_g1: g1(&RAW_VK[..32]),
        vk_beta_g2: g2(&RAW_VK[32..96]),
        vk_gamme_g2: g2(&RAW_VK[96..160]),
        vk_delta_g2: g2(&RAW_VK[160..224]),
        vk_ic: &[],
    };
    let ic = RAW_VK[232..].chunks_exact(32).map(g1).collect::<Vec<_>>();
    assert_eq!(ic.len(), 7);
    (fixed, ic)
}
fn tagged(key: &Groth16Verifyingkey) -> [u8; 32] {
    let mut b = b"dynark-solana-adapter/ordinary-vk/v2".to_vec();
    b.extend(6u32.to_be_bytes());
    b.extend(7u32.to_be_bytes());
    b.extend(key.vk_alpha_g1);
    b.extend(key.vk_beta_g2);
    b.extend(key.vk_gamme_g2);
    b.extend(key.vk_delta_g2);
    for point in key.vk_ic {
        b.extend(point);
    }
    hash(&b).to_bytes()
}
fn native(key: &Groth16Verifyingkey, inputs: &[[u8; 32]; 6], proof: &[u8; 256]) -> bool {
    Groth16Verifier::new(
        proof[..64].try_into().unwrap(),
        proof[64..192].try_into().unwrap(),
        proof[192..].try_into().unwrap(),
        inputs,
        key,
    )
    .and_then(|mut v| v.verify())
    .is_ok()
}

#[test]
fn v3_embedded_key_accepts_actual_six_public_corpus_full_proof() {
    let (inputs, proof) = encoded();
    let (fixed, ic) = expected_key();
    let independently_decoded = Groth16Verifyingkey {
        vk_ic: &ic,
        ..fixed
    };
    assert!(
        native(&independently_decoded, &inputs, &proof),
        "canonical public corpus proof must verify with its independently decoded ordinary key"
    );
    assert!(native(&v3::VERIFYING_KEY, &inputs, &proof));
    assert_eq!(verify(&inputs, &proof), Ok(()));
}

#[test]
fn v3_embedded_key_is_exact_seven_ic_public_ordinary_vk_and_separate_identity() {
    let (fixed, ic) = expected_key();
    let expected = Groth16Verifyingkey {
        vk_ic: &ic,
        ..fixed
    };
    assert_eq!(v3::VERIFYING_KEY, expected);
    assert_eq!(
        (
            v3::VERIFYING_KEY.nr_pubinputs,
            v3::VERIFYING_KEY.vk_ic.len()
        ),
        (6, 7)
    );
    assert_eq!(hex(&tagged(&expected)), TAGGED_VK);
    assert_eq!(tagged(&v3::VERIFYING_KEY), v3::ORDINARY_VK_DIGEST);
    assert_eq!(hex(&v3::ORDINARY_VK_FILE_SHA256), VK_SHA);
    assert_ne!(v3::ORDINARY_VK_DIGEST, v3::ORDINARY_VK_FILE_SHA256);
    assert_ne!(v3::ORDINARY_VK_DIGEST, v3::ENGINE_EXTENDED_VK_DIGEST);
}

#[test]
fn v3_verifier_rejects_each_changed_public_field() {
    let (inputs, proof) = encoded();
    for n in 0..6 {
        let mut changed = inputs;
        for byte in changed[n].iter_mut().rev() {
            let (next, carry) = byte.overflowing_add(1);
            *byte = next;
            if !carry {
                break;
            }
        }
        assert!(changed[n] < FIELD_MODULUS);
        assert!(
            verify(&changed, &proof).is_err(),
            "altered public field {n} admitted"
        );
    }
}

#[test]
fn v3_verifier_rejects_valid_curve_proof_changes_and_wrong_g2_order() {
    let (inputs, proof) = encoded();
    let mut changed = proof;
    negate_y(&mut changed[192..]);
    assert_ne!(changed, proof);
    assert!(verify(&inputs, &changed).is_err());
    let mut changed = proof;
    negate_y(&mut changed[..64]);
    assert!(verify(&inputs, &changed).is_err());
    let mut swapped = proof;
    for offset in [64, 128] {
        swapped[offset..offset + 32].copy_from_slice(&proof[offset + 32..offset + 64]);
        swapped[offset + 32..offset + 64].copy_from_slice(&proof[offset..offset + 32]);
    }
    assert!(verify(&inputs, &swapped).is_err());
}

#[test]
fn v3_verifier_rejects_noncanonical_fields_coordinates_and_infinity() {
    let (inputs, proof) = encoded();
    for n in 0..6 {
        for noncanonical in [FIELD_MODULUS, [255; 32]] {
            let mut bad = inputs;
            bad[n] = noncanonical;
            assert!(verify(&bad, &proof).is_err());
        }
    }
    for n in 0..8 {
        let mut bad = proof;
        bad[n * 32..n * 32 + 32].copy_from_slice(&fq());
        assert!(verify(&inputs, &bad).is_err());
    }
    for (start, end) in [(0, 64), (64, 192), (192, 256)] {
        let mut infinity = proof;
        infinity[start..end].fill(0);
        assert!(verify(&inputs, &infinity).is_err());
    }
}

#[test]
fn v3_raw_public_codec_rejects_wrong_count_length_and_noncanonical_words() {
    checked_sources();
    assert!(public_values(RAW_PUBLIC).is_some());
    for length in [0, 8, 192, 199] {
        assert!(public_values(&RAW_PUBLIC[..length]).is_none());
    }
    let mut extra = RAW_PUBLIC.to_vec();
    extra.push(0);
    assert!(public_values(&extra).is_none());
    for count in [0u64, 5, 7, u64::MAX] {
        let mut bad = RAW_PUBLIC.to_vec();
        bad[..8].copy_from_slice(&count.to_le_bytes());
        assert!(public_values(&bad).is_none());
    }
    let mut bad = RAW_PUBLIC.to_vec();
    let mut modulus_le = FIELD_MODULUS;
    modulus_le.reverse();
    bad[8..40].copy_from_slice(&modulus_le);
    assert!(public_values(&bad).is_none());
}

#[test]
fn v3_corpus_is_not_v1_or_v2_and_runtime_execute_remains_unavailable() {
    let (inputs, proof) = encoded();
    for legacy in [&v1::VERIFYING_KEY, &v2::VERIFYING_KEY] {
        assert_eq!((legacy.nr_pubinputs, legacy.vk_ic.len()), (5, 6));
        assert!(
            !native(legacy, &inputs, &proof),
            "five-field key accepted six-field statement"
        );
    }
    let five: [[u8; 32]; 5] = inputs[..5].try_into().unwrap();
    assert!(application_runtime_v2::verify(&five, &proof).is_err());
    assert!(zk_fresh_program::verify_proof(&five, &proof).is_err());
    let mut wire = vec![PREFIX, 7];
    for input in inputs {
        wire.extend(input);
    }
    wire.extend(proof);
    assert_eq!(wire.len(), 450);
    assert_eq!(
        process_instruction(&Pubkey::new_from_array([12; 32]), &[], &wire),
        Err(ProgramError::from(AppError::Unavailable))
    );
}
