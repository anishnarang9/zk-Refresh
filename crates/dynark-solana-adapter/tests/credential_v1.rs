//! Bounded accepted-v1 artifact replay/export. No setup, witness generation or proving.
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use dynark_bn254::public_schema_digest;
use dynark_solana_adapter::{ordinary_vk_digest, Identity, Verifier};
use sha2::{Digest, Sha256};
use std::{fs::{File, OpenOptions}, io::{Read, Write}, os::unix::fs::{OpenOptionsExt, PermissionsExt}, path::Path};

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
fn digest(value: &str) -> [u8;32] {
    assert_eq!(value.len(),64); std::array::from_fn(|i|u8::from_str_radix(&value[2*i..2*i+2],16).unwrap())
}
fn authenticated(path: &Path, len: u64, expected: &str) -> Vec<u8> {
    assert!(len<=4096);let f=File::open(path).unwrap();assert_eq!(f.metadata().unwrap().len(),len);
    let mut data=Vec::new();f.take(len+1).read_to_end(&mut data).unwrap();assert_eq!(data.len() as u64,len);
    assert_eq!(hex(&Sha256::digest(&data)),expected);data
}
fn decode<T: CanonicalDeserialize>(data: &[u8]) -> T {
    let mut cursor=std::io::Cursor::new(data);let value=T::deserialize_compressed(&mut cursor).unwrap();assert_eq!(cursor.position() as usize,data.len());value
}
fn prefix_from_authenticated_public_uk(path: &Path) -> Vec<u8> {
    let mut f=File::open(path).unwrap();assert_eq!(f.metadata().unwrap().len(),427_598_901);
    let mut hash=Sha256::new();let mut prefix=Vec::new();let mut bytes=[0u8;32768];let mut total=0u64;
    loop {let n=f.read(&mut bytes).unwrap();if n==0{break;}total+=n as u64;assert!(total<=427_598_901);hash.update(&bytes[..n]);
        let take=n.min(4096-prefix.len());prefix.extend_from_slice(&bytes[..take]);}
    assert_eq!(total,427_598_901);assert_eq!(hex(&hash.finalize()),"ab377a3a727a1a716c180ac184f50f3057ceaf2c80d6ccb4334881ed0ab5a5ff");prefix
}
fn be<F: PrimeField>(value:F)->[u8;32] {let bytes=value.into_bigint().to_bytes_be();let mut b=[0;32];b[32-bytes.len()..].copy_from_slice(&bytes);b}
fn g1(p:G1Affine)->[u8;64] {if p.is_zero(){return [0;64];}let mut b=[0;64];b[..32].copy_from_slice(&be(p.x));b[32..].copy_from_slice(&be(p.y));b}
fn g2(p:G2Affine)->[u8;128] {let mut b=[0;128];for (c,v) in b.chunks_exact_mut(32).zip([p.x.c1,p.x.c0,p.y.c1,p.y.c0]) {c.copy_from_slice(&be(v));}b}
fn write_new(out:&Path,name:&str,bytes:&[u8]) {let mut f=OpenOptions::new().write(true).create_new(true).mode(0o600).open(out.join(name)).unwrap();f.write_all(bytes).unwrap();f.sync_all().unwrap();}

#[test]
#[ignore = "ROOT-reviewed accepted-v1 public-artifact replay/export; reads 427MB public UK by streaming"]
fn accepted_v1_manifest_binding_and_full_refreshed_native_solana_export() {
    let root=Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../artifacts/dynark/phase-1/near-e2-v1"));
    let output=std::env::var("M5_V1_OUTPUT").expect("fresh protected output directory required");let out=Path::new(&output);
    assert!(out.is_absolute() && out.is_dir());assert_eq!(out.metadata().unwrap().permissions().mode()&0o777,0o700);assert_eq!(std::fs::read_dir(out).unwrap().count(),0);
    let vk_bytes=authenticated(&root.join("ordinary-vk.bin"),424,"cfbb4e50cf30611c91d779448dfd0632cdf837046662b730eb6b7926d4a6d8cc");
    let vk:ordinary::VerifyingKey<Bn254>=decode(&vk_bytes);
    let prefix=prefix_from_authenticated_public_uk(&root.join("updating-key.bin"));
    let extended=dynark::VerifyingKey::<Bn254>::deserialize_compressed(&prefix[..]).unwrap();
    assert_eq!(extended.num_constraints,648156);assert_eq!(extended.num_instance,6);assert_eq!(extended.num_witness,643557);
    let mut canonical=Vec::new();extended.serialize_compressed(&mut canonical).unwrap();let mut h=Sha256::new();h.update(b"dynark-bn254/vk/v1");h.update(&canonical);
    assert_eq!(hex(&h.finalize()),"1ae0864ab3bdbe39f912734ba8c11c65c02d3a9b3d56d8204fb00ddac57ab642");
    let derived=ordinary::VerifyingKey::<Bn254>{alpha_g1:extended.alpha_g1,beta_g2:extended.beta_g2,gamma_g2:extended.gamma_g2,delta_g2:extended.delta_g2,gamma_abc_g1:extended.t_v_g1};
    assert_eq!(derived,vk,"exact ordinary key must derive from accepted extended key");
    let ordinary_digest=ordinary_vk_digest(&vk).unwrap();
    let names=["root","issuerHash","notBefore","notAfter","actionHash"].map(str::to_owned);
    let id=Identity{circuit:digest("4ed8bc9915ac836bbeda833480fba8a5dea9cf58c198b1668c460743552b7e1e"),package:digest("57cea7ff53a711f8fbb2e8f256a21a852d087564c49df70b6065c6994765c0d5"),schema:public_schema_digest(&names),ordinary_vk_digest:ordinary_digest};
    let verifier=Verifier::new(vk.clone(),id).unwrap();
    let cases=[("full","initial-proof.bin","bb3c171f79e60bfc6eac58a274bb1c5bbd9745f22bb5b2c6d6f0a7e5bdc5efc5","before-public-inputs.bin","595c1af5bc3ada00fc66b2ff9c8fac90ba59d584979c11f25e940afd43f8b82f"),
        ("refreshed","updated-proof.bin","bec8fbb880f9b9b5caec928f77db1587021a3d9c82f7b7a5ad2703cd13fa4248","after-public-inputs.bin","5982747632dc30febb0430cf39cb395017dc9299728034e1fca6915fab826dea")];
    for (name,pf,ph,xf,xh) in cases {
        let p:ordinary::Proof<Bn254>=decode(&authenticated(&root.join(pf),128,ph));let x:Vec<Fr>=decode(&authenticated(&root.join(xf),168,xh));assert_eq!(x.len(),5);
        let encoded=verifier.encode(&p,&x,id).unwrap();let public=encoded.inputs.concat();verifier.verify_solana(&encoded.proof,&public,id).unwrap();
        let mut wire=public.clone();wire.extend(encoded.proof);assert_eq!(wire.len(),416);write_new(out,&format!("{name}.wire"),&wire);
        for i in 0..5 {let mut changed=public.clone();changed[i*32+31]^=1;assert!(verifier.verify_solana(&encoded.proof,&changed,id).is_err());}
        if name=="full" {wire[159]^=1;write_new(out,"wrong-public.wire",&wire);}
    }
    let ic:Vec<_>=vk.gamma_abc_g1.iter().copied().map(g1).collect();
    let source=format!("// Matching credential-v1 Original development VK; not the original snarkjs zkey.\nuse groth16_solana::groth16::Groth16Verifyingkey;\npub const VERIFYING_KEY: Groth16Verifyingkey<'static> = Groth16Verifyingkey {{ nr_pubinputs:5, vk_alpha_g1:{:?}, vk_beta_g2:{:?}, vk_gamme_g2:{:?}, vk_delta_g2:{:?}, vk_ic:&{:?} }};\n",g1(vk.alpha_g1),g2(vk.beta_g2),g2(vk.gamma_g2),g2(vk.delta_g2),ic);
    write_new(out,"generated_vk.rs",source.as_bytes());
    let manifest=format!("{{\n  \"schema\":1,\n  \"scope\":\"credential-v1 Original development local-verifier gate\",\n  \"circuit\":\"{}\",\n  \"package\":\"{}\",\n  \"schema_digest\":\"{}\",\n  \"engine_extended_vk_digest\":\"1ae0864ab3bdbe39f912734ba8c11c65c02d3a9b3d56d8204fb00ddac57ab642\",\n  \"ordinary_vk_digest\":\"{}\",\n  \"ordinary_vk_file_sha256\":\"cfbb4e50cf30611c91d779448dfd0632cdf837046662b730eb6b7926d4a6d8cc\",\n  \"authenticated_uk_sha256\":\"ab377a3a727a1a716c180ac184f50f3057ceaf2c80d6ccb4334881ed0ab5a5ff\",\n  \"ordinary_vk_tag\":\"dynark-solana-adapter/ordinary-vk/v1\",\n  \"generated_vk_source_sha256\":\"{}\",\n  \"authority\":\"candidate; requires ROOT review and pinning before M2 admission\"\n}}\n",hex(&id.circuit),hex(&id.package),hex(&id.schema),hex(&ordinary_digest),hex(&Sha256::digest(source.as_bytes())));
    write_new(out,"candidate-manifest.json",manifest.as_bytes());
}
