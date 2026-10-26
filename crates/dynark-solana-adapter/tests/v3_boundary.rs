//! Synthetic six-field ABI tests only: no setup, proving or profile admission.
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::{short_weierstrass::SWCurveConfig, AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, PrimeField};
use dynark_solana_adapter::{v3, Error};
use sha2::{Digest, Sha256};
fn key() -> ordinary::VerifyingKey<Bn254> {
    ordinary::VerifyingKey {
        alpha_g1: G1Affine::generator(),
        beta_g2: G2Affine::generator(),
        gamma_g2: G2Affine::generator(),
        delta_g2: G2Affine::generator(),
        gamma_abc_g1: vec![G1Affine::generator(); 7],
    }
}
fn be<F: PrimeField>(x: F) -> [u8; 32] {
    let b = x.into_bigint().to_bytes_be();
    let mut out = [0; 32];
    out[32 - b.len()..].copy_from_slice(&b);
    out
}
fn preimage(k: &ordinary::VerifyingKey<Bn254>, tag: &[u8], public: u32) -> Vec<u8> {
    let mut b = tag.to_vec();
    b.extend(public.to_be_bytes());
    b.extend((k.gamma_abc_g1.len() as u32).to_be_bytes());
    b.extend(be(k.alpha_g1.x));
    b.extend(be(k.alpha_g1.y));
    for g in [k.beta_g2, k.gamma_g2, k.delta_g2] {
        for f in [g.x.c1, g.x.c0, g.y.c1, g.y.c0] {
            b.extend(be(f))
        }
    }
    for g in &k.gamma_abc_g1 {
        if g.is_zero() {
            b.extend([0; 64])
        } else {
            b.extend(be(g.x));
            b.extend(be(g.y))
        }
    }
    b
}
fn identity() -> v3::Identity {
    v3::Identity {
        circuit: [1; 32],
        package: [2; 32],
        schema: [3; 32],
        profile: [4; 32],
        ordinary_vk_digest: v3::ordinary_vk_digest(&key()).unwrap(),
    }
}
fn public() -> Vec<u8> {
    (0..6).flat_map(|i| be(Fr::from(i as u64))).collect()
}
fn proof_wire() -> [u8; 256] {
    let mut p = [0; 256];
    p[..32].copy_from_slice(&be(Fq::from(1)));
    p[32..64].copy_from_slice(&be(-Fq::from(2)));
    let g = G2Affine::generator();
    for (b, f) in p[64..192]
        .chunks_exact_mut(32)
        .zip([g.x.c1, g.x.c0, g.y.c1, g.y.c0])
    {
        b.copy_from_slice(&be(f))
    }
    p[192..224].copy_from_slice(&be(Fq::from(1)));
    p[224..].copy_from_slice(&be(Fq::from(2)));
    p
}
#[test]
fn six_field_contract_is_explicit_and_separate_from_five_field_tag() {
    assert_eq!(v3::PUBLIC_INPUTS, 6);
    assert_eq!(v3::PUBLIC_BYTES, 192);
    assert_eq!(v3::WIRE_BYTES, 448);
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
    assert_eq!(
        dynark_solana_adapter::ORDINARY_VK_TAG,
        b"dynark-solana-adapter/ordinary-vk/v1"
    );
}
#[test]
fn six_field_parser_preserves_order_and_rejects_five_fields_trailing_and_noncanonical() {
    let p = public();
    let values = v3::canonical_public_values(&p).unwrap();
    assert_eq!(values, std::array::from_fn(|i| Fr::from(i as u64)));
    for n in [0, 32, 160, 191] {
        assert_eq!(v3::canonical_public_values(&p[..n]), Err(Error::Length))
    }
    let mut extra = p.clone();
    extra.push(0);
    assert_eq!(v3::canonical_public_values(&extra), Err(Error::Length));
    for i in 0..6 {
        let mut bad = p.clone();
        bad[i * 32..(i + 1) * 32].copy_from_slice(&Fr::MODULUS.to_bytes_be());
        assert_eq!(v3::canonical_public_values(&bad), Err(Error::Field));
    }
}
#[test]
fn six_public_digest_matches_independent_coordinate_preimage_and_domain_counts() {
    let k = key();
    let bytes = preimage(&k, b"dynark-solana-adapter/ordinary-vk/v2", 6);
    assert_eq!(bytes.len(), v3::ORDINARY_VK_TAG.len() + 8 + 896);
    let expected: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(
        expected,
        [
            182, 44, 137, 32, 234, 214, 15, 234, 167, 124, 17, 143, 199, 200, 241, 132, 38, 21,
            215, 230, 124, 224, 104, 190, 124, 245, 170, 44, 183, 19, 40, 51
        ]
    );
    assert_eq!(v3::ordinary_vk_digest(&k), Ok(expected));
    assert_ne!(
        expected,
        <[u8; 32]>::from(Sha256::digest(preimage(
            &k,
            b"dynark-solana-adapter/ordinary-vk/v1",
            6
        )))
    );
    assert_ne!(
        expected,
        <[u8; 32]>::from(Sha256::digest(preimage(
            &k,
            b"dynark-solana-adapter/ordinary-vk/v2",
            5
        )))
    );
    let mut changed = k;
    changed.gamma_abc_g1[6] = G1Affine::generator()
        .mul_bigint(Fr::from(2u64).into_bigint())
        .into_affine();
    assert_ne!(v3::ordinary_vk_digest(&changed), Ok(expected));
}
#[test]
fn seven_ic_required_and_only_constant_identity_allowed() {
    for n in [0, 5, 6, 8] {
        let mut k = key();
        k.gamma_abc_g1.resize(n, G1Affine::generator());
        assert_eq!(v3::ordinary_vk_digest(&k), Err(Error::Schema));
    }
    let mut k = key();
    k.gamma_abc_g1[0] = G1Affine::identity();
    assert!(v3::ordinary_vk_digest(&k).is_ok());
    for i in 1..7 {
        let mut k = key();
        k.gamma_abc_g1[i] = G1Affine::identity();
        assert_eq!(v3::ordinary_vk_digest(&k), Err(Error::Point));
    }
    for i in 0..4 {
        let mut k = key();
        match i {
            0 => k.alpha_g1 = G1Affine::identity(),
            1 => k.beta_g2 = G2Affine::identity(),
            2 => k.gamma_g2 = G2Affine::identity(),
            _ => k.delta_g2 = G2Affine::identity(),
        };
        assert_eq!(v3::ordinary_vk_digest(&k), Err(Error::Point));
    }
}
#[test]
fn key_digest_checks_off_curve_and_subgroup_before_pairing() {
    let mut k = key();
    k.alpha_g1 = G1Affine::new_unchecked(Fq::ONE, Fq::ONE);
    assert_eq!(v3::ordinary_vk_digest(&k), Err(Error::Point));
    let outsider = (0u64..64)
        .find_map(|i| {
            let x = Fq2::new(Fq::from(i), Fq::ONE);
            let y = (x.square() * x + ark_bn254::g2::Config::COEFF_B).sqrt()?;
            let g = G2Affine::new_unchecked(x, y);
            (!g.is_in_correct_subgroup_assuming_on_curve()).then_some(g)
        })
        .unwrap();
    k = key();
    k.beta_g2 = outsider;
    assert_eq!(v3::ordinary_vk_digest(&k), Err(Error::Point));
}
#[test]
fn verifier_rejects_wrong_key_and_all_manifest_identity_substitutions() {
    let id = identity();
    let mut bad = id;
    bad.ordinary_vk_digest[0] ^= 1;
    assert!(matches!(v3::Verifier::new(key(), bad), Err(Error::Key)));
    let v = v3::Verifier::new(key(), id).unwrap();
    for i in 0..5 {
        let mut bad = id;
        match i {
            0 => bad.circuit[0] ^= 1,
            1 => bad.package[0] ^= 1,
            2 => bad.schema[0] ^= 1,
            3 => bad.profile[0] ^= 1,
            _ => bad.ordinary_vk_digest[0] ^= 1,
        };
        assert_eq!(
            v.decode(&proof_wire(), &public(), bad),
            Err(Error::Identity)
        );
    }
}
#[test]
fn verifier_rejects_noncanonical_points_infinity_and_old_wire_before_proof_work() {
    let id = identity();
    let v = v3::Verifier::new(key(), id).unwrap();
    let proof = proof_wire();
    for n in [0, 64, 255] {
        assert_eq!(v.decode(&proof[..n], &public(), id), Err(Error::Length));
    }
    let mut trailing = proof.to_vec();
    trailing.push(0);
    assert_eq!(v.decode(&trailing, &public(), id), Err(Error::Length));
    assert_eq!(v.decode(&proof, &public()[..160], id), Err(Error::Length));
    for (a, b) in [(0, 64), (64, 192), (192, 256)] {
        let mut zero = proof;
        zero[a..b].fill(0);
        assert_eq!(v.decode(&zero, &public(), id), Err(Error::Point));
    }
    for i in 0..8 {
        let mut p = proof;
        p[i * 32..(i + 1) * 32].copy_from_slice(&Fq::MODULUS.to_bytes_be());
        assert_eq!(v.decode(&p, &public(), id), Err(Error::Field));
    }
}
#[test]
fn six_field_synthetic_points_do_not_claim_a_valid_profile_proof() {
    let id = identity();
    let v = v3::Verifier::new(key(), id).unwrap();
    assert_eq!(v.decode(&proof_wire(), &public(), id), Err(Error::Proof));
    let p = ordinary::Proof::<Bn254> {
        a: G1Affine::generator(),
        b: G2Affine::generator(),
        c: G1Affine::generator(),
    };
    assert_eq!(v.encode(&p, &[Fr::ONE; 5], id), Err(Error::Schema));
}
#[test]
fn five_field_api_and_v1_key_digest_stay_separate_and_unchanged() {
    let mut k = key();
    assert_eq!(
        dynark_solana_adapter::ordinary_vk_digest(&k),
        Err(Error::Schema)
    );
    k.gamma_abc_g1.pop();
    assert_eq!(v3::ordinary_vk_digest(&k), Err(Error::Schema));
    let expected: [u8; 32] =
        Sha256::digest(preimage(&k, b"dynark-solana-adapter/ordinary-vk/v1", 5)).into();
    assert_eq!(
        expected,
        [
            183, 22, 87, 44, 17, 176, 110, 251, 61, 131, 118, 163, 246, 32, 154, 139, 232, 66, 3,
            95, 157, 79, 58, 139, 66, 189, 194, 137, 247, 167, 215, 117
        ]
    );
    assert_eq!(dynark_solana_adapter::ordinary_vk_digest(&k), Ok(expected));
}
