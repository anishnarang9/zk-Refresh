use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::{short_weierstrass::SWCurveConfig, AffineRepr};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::CanonicalSerialize;
use dynark_bn254::{public_schema_digest, Anchor, AnchorBinding, CircuitDescriptor, Limits, PublicPackage, Reduction, Transition, UpdatingMaterial};
use dynark_solana_adapter::{ordinary_vk_digest, Error, Identity, Verifier, ORDINARY_VK_TAG};
use sha2::{Digest, Sha256};
use rand::rngs::OsRng;
use std::sync::OnceLock;

fn package() -> &'static PublicPackage {
    static P: OnceLock<PublicPackage> = OnceLock::new();
    P.get_or_init(|| {
        let a: Vec<_> = (6..11).map(|j| vec![(Fr::ONE, j)]).collect();
        let c: Vec<_> = (1..6).map(|j| vec![(Fr::ONE, j)]).collect();
        let m = ConstraintMatrices { num_instance_variables: 6, num_witness_variables: 5,
            num_constraints: 5, a_num_non_zero: 5, b_num_non_zero: 5, c_num_non_zero: 5,
            a: a.clone(), b: a, c };
        let pk = dynark::Groth16::<Bn254>::groth16_setup_dynark(m.clone(), &mut OsRng).unwrap().0;
        let names = ["root", "issuerHash", "notBefore", "notAfter", "actionHash"].map(str::to_owned).to_vec();
        let d = CircuitDescriptor { r1cs_artifact_digest: [1;32], witness_executable_digest: [2;32],
            profile_digest: [3;32], public_schema_digest: public_schema_digest(&names),
            public_schema: names, reduction: Reduction::Original };
        let id = PublicPackage::inspect_identity(&m, &d, &pk).unwrap();
        PublicPackage::new(m, d, pk, id).unwrap()
    })
}
fn assignment(root: u64) -> Vec<Fr> {
    let w = [root, 3, 4, 5, 6];
    std::iter::once(Fr::ONE).chain(w.map(|n| Fr::from(n*n))).chain(w.map(Fr::from)).collect()
}
fn identity() -> Identity {
    let p = package();
    let names = ["root", "issuerHash", "notBefore", "notAfter", "actionHash"].map(str::to_owned);
    Identity { circuit: p.identity().circuit_digest, package: p.identity().package_digest,
        schema: public_schema_digest(&names), ordinary_vk_digest: ordinary_vk_digest(&p.ordinary_verifying_key()).unwrap() }
}
fn verifier() -> Verifier { Verifier::new(package().ordinary_verifying_key(), identity()).unwrap() }
fn proof() -> ordinary::Proof<Bn254> {
    let z = assignment(2);
    let bytes: Vec<_> = z.iter().map(|v| { let mut b = [0;32]; v.serialize_compressed(&mut b[..]).unwrap(); b }).collect();
    let validated = package().validate_assignment(&bytes, &z[1..6]).unwrap();
    dynark_bn254::prove(package(), &validated, 0, &mut OsRng).unwrap().proof
}
fn wire() -> (Verifier, dynark_solana_adapter::Encoded) {
    let v = verifier(); let e = v.encode(&proof(), &assignment(2)[1..6], identity()).unwrap(); (v,e)
}
fn inputs(e: &dynark_solana_adapter::Encoded) -> Vec<u8> { e.inputs.concat() }
fn be<F: PrimeField>(x: F) -> [u8;32] {
    let b = x.into_bigint().to_bytes_be(); let mut out=[0;32]; out[32-b.len()..].copy_from_slice(&b); out
}
#[test]
fn full_proof_roundtrips_and_matches_actual_solana_abi() {
    let p = proof(); let v=verifier(); let e=v.encode(&p,&assignment(2)[1..6],identity()).unwrap();
    assert_eq!(&e.proof[..32], &be(p.a.x)); assert_eq!(&e.proof[32..64], &be(-p.a.y));
    assert_eq!(&e.proof[64..96], &be(p.b.x.c1)); assert_eq!(&e.proof[96..128], &be(p.b.x.c0));
    assert_eq!(&e.proof[128..160], &be(p.b.y.c1)); assert_eq!(&e.proof[160..192], &be(p.b.y.c0));
    assert_eq!(&e.proof[192..224], &be(p.c.x)); assert_eq!(&e.proof[224..], &be(p.c.y));
    assert_eq!(e.inputs[0],be(Fr::from(4))); assert_eq!(v.decode(&e.proof,&inputs(&e),identity()).unwrap(),p);
    v.verify_solana(&e.proof,&inputs(&e),identity()).unwrap();
}
#[test]
fn independently_randomized_full_and_engine_refreshed_proofs_pass_both_verifiers() {
    let p=package(); let z=assignment(2); let target=assignment(3); let limits=Limits::small();
    let b: Vec<_>=z.iter().map(|v| { let mut b=[0;32]; v.serialize_compressed(&mut b[..]).unwrap(); b }).collect();
    let uk=UpdatingMaterial::prepare(p,limits).unwrap();
    let anchor=Anchor::create(p,&uk,p.validate_assignment(&b,&z[1..6]).unwrap(),AnchorBinding::new(p,[7;32],[8;32],0),limits,&mut OsRng).unwrap();
    let mut delta=Vec::new();
    for (i,(a,b)) in z.iter().zip(&target).enumerate() { if a!=b {let mut bytes=[0;32]; (*b-*a).serialize_compressed(&mut bytes[..]).unwrap(); delta.push((i,bytes));} }
    let transition=Transition::new(p,anchor.binding(),1,&delta,&target[1..6],limits).unwrap();
    let refreshed=anchor.update(p,&uk,&transition,limits,&mut OsRng).unwrap();
    let v=verifier(); let encoded=v.encode(&refreshed.proof,&refreshed.public_values,identity()).unwrap();
    v.decode(&encoded.proof,&inputs(&encoded),identity()).unwrap();
    v.verify_solana(&encoded.proof,&inputs(&encoded),identity()).unwrap();
}
#[test]
fn every_public_value_and_public_order_is_bound() {
    let (v,e)=wire();
    for i in 0..5 {let mut changed=inputs(&e); changed[i*32+31]^=1; assert!(v.decode(&e.proof,&changed,identity()).is_err());}
    let mut changed=inputs(&e); changed[..64].rotate_left(32); assert!(v.decode(&e.proof,&changed,identity()).is_err());
}
#[test]
fn exact_wire_width_rejects_truncation_and_trailing_bytes() {
    let (v,e)=wire(); let public=inputs(&e);
    for n in [0,63,127,255] {assert_eq!(v.decode(&e.proof[..n],&public,identity()),Err(Error::Length));}
    let mut extra=e.proof.to_vec(); extra.push(0); assert_eq!(v.decode(&extra,&public,identity()),Err(Error::Length));
    assert_eq!(v.decode(&e.proof,&public[..159],identity()),Err(Error::Length));
    let mut extra=public; extra.push(0); assert_eq!(v.decode(&e.proof,&extra,identity()),Err(Error::Length));
}
#[test]
fn scalar_and_base_modulus_are_rejected_without_modular_reduction() {
    let (v,e)=wire(); let mut public=inputs(&e); public[..32].copy_from_slice(&Fr::MODULUS.to_bytes_be());
    assert_eq!(v.decode(&e.proof,&public,identity()),Err(Error::Field));
    for offset in (0..256).step_by(32) {let mut proof=e.proof; proof[offset..offset+32].copy_from_slice(&Fq::MODULUS.to_bytes_be()); assert_eq!(v.decode(&proof,&inputs(&e),identity()),Err(Error::Field));}
}
#[test]
fn identity_circuit_package_schema_and_key_must_all_match() {
    let (v,e)=wire();
    for n in 0..4 {let mut id=identity(); match n {0=>id.circuit[0]^=1,1=>id.package[0]^=1,2=>id.schema[0]^=1,_=>id.ordinary_vk_digest[0]^=1}; assert_eq!(v.decode(&e.proof,&inputs(&e),id),Err(Error::Identity));}
    let mut id=identity(); id.ordinary_vk_digest[0]^=1; assert!(matches!(Verifier::new(package().ordinary_verifying_key(),id),Err(Error::Key)));
}
#[test]
fn wrong_key_and_wrong_number_of_public_inputs_fail() {
    let mut key=package().ordinary_verifying_key(); key.gamma_abc_g1.swap(1,2);
    let mut id=identity(); id.ordinary_vk_digest=ordinary_vk_digest(&key).unwrap();
    let wrong=Verifier::new(key,id).unwrap(); let (_,e)=wire();
    assert!(wrong.decode(&e.proof,&inputs(&e),id).is_err());
    let v=verifier(); assert_eq!(v.encode(&proof(),&assignment(2)[1..5],identity()),Err(Error::Schema));
    let mut key=package().ordinary_verifying_key(); key.gamma_abc_g1.pop(); let id=identity();
    assert!(matches!(Verifier::new(key,id),Err(Error::Schema)));
}
#[test]
fn off_curve_infinity_and_non_subgroup_points_are_rejected() {
    let v=verifier(); let public=assignment(2); let mut p=proof();
    p.a=G1Affine::identity(); assert_eq!(v.encode(&p,&public[1..6],identity()),Err(Error::Point));
    p=proof(); p.c=G1Affine::new_unchecked(Fq::ONE,Fq::ONE); assert_eq!(v.encode(&p,&public[1..6],identity()),Err(Error::Point));
    let outsider=(0u64..64).find_map(|i| {let x=Fq2::new(Fq::from(i),Fq::ONE); let y=(x.square()*x+ark_bn254::g2::Config::COEFF_B).sqrt()?; let g=G2Affine::new_unchecked(x,y); (!g.is_in_correct_subgroup_assuming_on_curve()).then_some(g)}).expect("finite G2 outsider fixture");
    p=proof(); p.b=outsider; assert_eq!(v.encode(&p,&public[1..6],identity()),Err(Error::Point));
    let (_,mut e)=wire(); e.proof[..64].fill(0); assert_eq!(v.decode(&e.proof,&inputs(&e),identity()),Err(Error::Point));
}
#[test]
fn wrong_a_sign_and_fq2_order_cannot_be_admitted() {
    let p=proof(); let v=verifier(); let e=v.encode(&p,&assignment(2)[1..6],identity()).unwrap();
    let mut a=e.proof; a[32..64].copy_from_slice(&be(p.a.y)); assert!(v.decode(&a,&inputs(&e),identity()).is_err());
    let mut b=e.proof; b[64..128].rotate_left(32); b[128..192].rotate_left(32); assert!(v.decode(&b,&inputs(&e),identity()).is_err());
}

fn generator_key() -> ordinary::VerifyingKey<Bn254> {
    ordinary::VerifyingKey {
        alpha_g1: G1Affine::generator(), beta_g2: G2Affine::generator(),
        gamma_g2: G2Affine::generator(), delta_g2: G2Affine::generator(),
        gamma_abc_g1: vec![G1Affine::generator(); 6],
    }
}
#[test]
fn ordinary_vk_digest_matches_independent_solana_coordinate_preimage() {
    let key=generator_key();
    assert_eq!(ORDINARY_VK_TAG,b"dynark-solana-adapter/ordinary-vk/v1");
    let mut preimage=b"dynark-solana-adapter/ordinary-vk/v1".to_vec();
    preimage.extend(5u32.to_be_bytes()); preimage.extend(6u32.to_be_bytes());
    preimage.extend(be(key.alpha_g1.x)); preimage.extend(be(key.alpha_g1.y));
    for g in [key.beta_g2,key.gamma_g2,key.delta_g2] {
        for f in [g.x.c1,g.x.c0,g.y.c1,g.y.c0] {preimage.extend(be(f));}
    }
    for g in &key.gamma_abc_g1 {preimage.extend(be(g.x));preimage.extend(be(g.y));}
    assert_eq!(preimage.len(), ORDINARY_VK_TAG.len()+8+832);
    let expected: [u8;32]=Sha256::digest(&preimage).into();
    assert_eq!(ordinary_vk_digest(&key),Ok(expected));
    let mut no_tag=preimage.clone(); no_tag.drain(..ORDINARY_VK_TAG.len());
    assert_ne!(expected,<[u8;32]>::from(Sha256::digest(no_tag)));
    let mut negated=key.clone(); negated.alpha_g1=-negated.alpha_g1;
    assert_ne!(ordinary_vk_digest(&key),ordinary_vk_digest(&negated));
    let mut reordered=package().ordinary_verifying_key(); let original=ordinary_vk_digest(&reordered);
    reordered.gamma_abc_g1.swap(0,1); assert_ne!(original,ordinary_vk_digest(&reordered));
}
#[test]
fn ordinary_vk_digest_rejects_invalid_points_and_non_five_public_schema() {
    for len in [0,5,7] {let mut k=generator_key(); k.gamma_abc_g1.resize(len,G1Affine::generator()); assert_eq!(ordinary_vk_digest(&k),Err(Error::Schema));}
    for slot in [0,2,3,4,5,6] {let mut k=generator_key(); if slot==0 {k.alpha_g1=G1Affine::identity();} else {k.gamma_abc_g1[slot-1]=G1Affine::identity();} assert_eq!(ordinary_vk_digest(&k),Err(Error::Point));}
    for slot in 0..3 {let mut k=generator_key(); match slot {0=>k.beta_g2=G2Affine::identity(),1=>k.gamma_g2=G2Affine::identity(),_=>k.delta_g2=G2Affine::identity()}; assert_eq!(ordinary_vk_digest(&k),Err(Error::Point));}
    let mut k=generator_key(); k.alpha_g1=G1Affine::new_unchecked(Fq::ONE,Fq::ONE);
    assert_eq!(ordinary_vk_digest(&k),Err(Error::Point));
}

#[test]
fn zero_constant_column_produces_only_identity_ic0_with_valid_ordinary_and_solana_proofs() {
    use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
    let key=package().ordinary_verifying_key();
    assert!(key.gamma_abc_g1[0].is_zero(), "constant column is identically zero");
    assert!(key.alpha_g1.is_on_curve() && !key.alpha_g1.is_zero());
    for g in [&key.beta_g2,&key.gamma_g2,&key.delta_g2] {
        assert!(!g.is_zero() && g.is_on_curve() && g.is_in_correct_subgroup_assuming_on_curve());
    }
    for g in &key.gamma_abc_g1[1..] {
        assert!(!g.is_zero() && g.is_on_curve() && g.is_in_correct_subgroup_assuming_on_curve());
    }
    let proof=proof(); let public=assignment(2);
    assert!(ordinary::Groth16::<Bn254>::verify_proof(&ordinary::prepare_verifying_key(&key),&proof,&public[1..6]).unwrap());
    let pack_g1=|g: G1Affine| -> [u8;64] {
        if g.is_zero() {return [0;64];}
        let mut bytes=[0;64];bytes[..32].copy_from_slice(&be(g.x));bytes[32..].copy_from_slice(&be(g.y));bytes
    };
    let pack_g2=|g: G2Affine| -> [u8;128] {
        let mut bytes=[0;128]; for (b,f) in bytes.chunks_exact_mut(32).zip([g.x.c1,g.x.c0,g.y.c1,g.y.c0]) {b.copy_from_slice(&be(f));} bytes
    };
    let ic:Vec<_>=key.gamma_abc_g1.iter().copied().map(pack_g1).collect();
    assert_eq!(ic[0],[0;64]);
    let wire_key=Groth16Verifyingkey {nr_pubinputs:5,vk_alpha_g1:pack_g1(key.alpha_g1),vk_beta_g2:pack_g2(key.beta_g2),vk_gamme_g2:pack_g2(key.gamma_g2),vk_delta_g2:pack_g2(key.delta_g2),vk_ic:&ic};
    let a=pack_g1(-proof.a);let b=pack_g2(proof.b);let c=pack_g1(proof.c);
    let inputs:[[u8;32];5]=std::array::from_fn(|i|be(public[i+1]));
    Groth16Verifier::new(&a,&b,&c,&inputs,&wire_key).unwrap().verify().unwrap();
}
#[test]
fn adapter_admits_valid_matching_key_with_only_identity_constant_ic() {
    let key=package().ordinary_verifying_key();
    assert!(key.gamma_abc_g1[0].is_zero());
    assert!(ordinary_vk_digest(&key).is_ok(), "IC0 identity does not erase any public coefficient");
    let mut bad=key.clone(); bad.gamma_abc_g1[0]=G1Affine::new_unchecked(Fq::ONE,Fq::ONE);
    assert_eq!(ordinary_vk_digest(&bad),Err(Error::Point));
    let v=verifier(); let p=proof(); let encoded=v.encode(&p,&assignment(2)[1..6],identity()).unwrap();
    v.verify_solana(&encoded.proof,&inputs(&encoded),identity()).unwrap();
}
