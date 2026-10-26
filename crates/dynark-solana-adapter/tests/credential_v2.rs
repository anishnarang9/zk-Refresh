//! ROOT-pinned, verification-only v2 artifact gate. Does not run setup or proving.
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_serialize::CanonicalDeserialize;
use dynark_solana_adapter::{ordinary_vk_digest, Identity, Verifier};
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use sha2::{Digest, Sha256};
use std::{fs::{File, OpenOptions}, io::{Read, Write}, os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt}, path::Path};

const SETUP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../artifacts/dynark/pre-part5/credential-v2-dev-development-setup-001");
const PROOFS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../artifacts/dynark/pre-part5/credential-v2-dev-development-proof-001");
const CIRCUIT: &str = "da0ad2e5e92f3879951ac3e56e077967eb5fcf6a9814839d680037d620ae9146";
const PACKAGE: &str = "04d5ad5776bea03ee014790f54c2572adde796f4d8caeacb88f8a54b0e98b6eb";
const EXTENDED_VK: &str = "b2678dbd6c04cfb536826cf26156ac5a046c1cdfe3734ea936f79e5d5f2a3a06";
const SEMANTIC_SCHEMA: &str = "de111be59b7a21f5e9aa757506a9ec679d892d6342c88729b6b7997c8b472611";

fn hex(bytes: &[u8])->String {bytes.iter().map(|b|format!("{b:02x}")).collect()}
fn unhex(text:&str)->[u8;32] {
    assert!(text.len()==64 && text.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)),"canonical lowercase SHA256 required");
    std::array::from_fn(|i|u8::from_str_radix(&text[2*i..2*i+2],16).unwrap())
}
fn pin(name:&str)->String {let value=std::env::var(name).unwrap_or_else(|_|panic!("missing ROOT pin {name}"));unhex(&value);value}
fn read_pinned(path:&Path, expected:&str, exact:Option<u64>, cap:u64, owner:u32)->Vec<u8> {
    let stat=std::fs::symlink_metadata(path).unwrap();assert!(stat.is_file()&&!stat.file_type().is_symlink());
    assert_eq!(stat.uid(),owner);assert_eq!(stat.permissions().mode()&0o777,0o600);assert!(stat.len()<=cap);
    if let Some(length)=exact {assert_eq!(stat.len(),length);}
    let file=File::open(path).unwrap();let opened=file.metadata().unwrap();assert_eq!((opened.dev(),opened.ino(),opened.len()),(stat.dev(),stat.ino(),stat.len()));
    let mut bytes=Vec::new();file.take(cap+1).read_to_end(&mut bytes).unwrap();assert!(bytes.len() as u64<=cap);assert_eq!(bytes.len() as u64,stat.len());
    assert_eq!(hex(&Sha256::digest(&bytes)),expected,"ROOT artifact pin mismatch");bytes
}
fn decode<T:CanonicalDeserialize>(bytes:&[u8])->T {let mut c=std::io::Cursor::new(bytes);let value=T::deserialize_compressed(&mut c).unwrap();assert_eq!(c.position() as usize,bytes.len());value}
fn be<F:PrimeField>(value:F)->[u8;32] {let bytes=value.into_bigint().to_bytes_be();let mut out=[0;32];out[32-bytes.len()..].copy_from_slice(&bytes);out}
fn g1(point:G1Affine)->[u8;64] {if point.is_zero(){return [0;64];}let mut out=[0;64];out[..32].copy_from_slice(&be(point.x));out[32..].copy_from_slice(&be(point.y));out}
fn g2(point:G2Affine)->[u8;128] {let mut out=[0;128];for (b,v) in out.chunks_exact_mut(32).zip([point.x.c1,point.x.c0,point.y.c1,point.y.c0]){b.copy_from_slice(&be(v));}out}
fn native(vk:&ordinary::VerifyingKey<Bn254>,proof:&[u8;256],public:&[[u8;32];5])->bool {
    let ic:Vec<_>=vk.gamma_abc_g1.iter().copied().map(g1).collect();
    let key=Groth16Verifyingkey{nr_pubinputs:5,vk_alpha_g1:g1(vk.alpha_g1),vk_beta_g2:g2(vk.beta_g2),vk_gamme_g2:g2(vk.gamma_g2),vk_delta_g2:g2(vk.delta_g2),vk_ic:&ic};
    let a=proof[..64].try_into().unwrap();let b=proof[64..192].try_into().unwrap();let c=proof[192..].try_into().unwrap();
    Groth16Verifier::new(a,b,c,public,&key).unwrap().verify().is_ok()
}
fn write_new(root:&Path,name:&str,bytes:&[u8]) {let mut f=OpenOptions::new().create_new(true).write(true).mode(0o600).open(root.join(name)).unwrap();f.write_all(bytes).unwrap();f.sync_all().unwrap();}

#[test]
#[ignore = "Requires successful ROOT-reviewed v2 proof qualification and explicit ROOT artifact pins"]
fn root_pinned_v2_full_anchor_ordinary_and_native_solana_gate() {
    assert_eq!(std::env::var("M5_V2_APPROVAL_SCOPE").unwrap(),"credential-v2-dev-full-anchor-local-verifier-only");
    assert_eq!(pin("M5_V2_CIRCUIT"),CIRCUIT);assert_eq!(pin("M5_V2_PACKAGE"),PACKAGE);
    assert_eq!(pin("M5_V2_EXTENDED_VK"),EXTENDED_VK);assert_eq!(pin("M5_V2_SEMANTIC_SCHEMA"),SEMANTIC_SCHEMA);
    let setup_pin=pin("M5_V2_SETUP_MANIFEST_SHA256");let report_pin=pin("M5_V2_PROOF_REPORT_SHA256");
    let vk_pin=pin("M5_V2_ORDINARY_VK_FILE_SHA256");let expected_ordinary=pin("M5_V2_ORDINARY_VK_DIGEST");
    let full_pin=pin("M5_V2_FULL_PROOF_SHA256");let full_public_pin=pin("M5_V2_FULL_PUBLIC_SHA256");
    let anchor_pin=pin("M5_V2_ANCHOR_PROOF_SHA256");let anchor_public_pin=pin("M5_V2_ANCHOR_PUBLIC_SHA256");
    let output=std::env::var("M5_V2_OUTPUT").unwrap();let out=Path::new(&output);assert!(out.is_absolute());
    let stat=std::fs::symlink_metadata(out).unwrap();assert!(stat.is_dir()&&!stat.file_type().is_symlink());assert_eq!(stat.permissions().mode()&0o777,0o700);
    assert_eq!(std::fs::read_dir(out).unwrap().count(),0);let owner=stat.uid();
    // ROOT must approve these exact manifests as passed and bind the named package before supplying pins.
    // Hash authentication is deliberate; this test does not reinterpret JSON or self-admit a setup.
    read_pinned(&Path::new(SETUP).join("setup-manifest.json"),&setup_pin,None,65536,owner);
    read_pinned(&Path::new(PROOFS).join("proof-report.json"),&report_pin,None,65536,owner);
    let vk_bytes=read_pinned(&Path::new(SETUP).join("ordinary.vk"),&vk_pin,Some(424),424,owner);
    let proof_vk=read_pinned(&Path::new(PROOFS).join("ordinary.vk"),&vk_pin,Some(424),424,owner);assert_eq!(proof_vk,vk_bytes);
    let vk:ordinary::VerifyingKey<Bn254>=decode(&vk_bytes);assert_eq!(ordinary_vk_digest(&vk).unwrap(),unhex(&expected_ordinary));
    let id=Identity{circuit:unhex(CIRCUIT),package:unhex(PACKAGE),schema:unhex(SEMANTIC_SCHEMA),ordinary_vk_digest:unhex(&expected_ordinary)};
    let verifier=Verifier::new(vk.clone(),id).unwrap();let pvk=ordinary::prepare_verifying_key(&vk);
    let cases=[("full","full-after.proof",full_pin,"full-after-public.bin",full_public_pin),("anchor","anchor-after.proof",anchor_pin,"anchor-after-public.bin",anchor_public_pin)];
    let mut statements=Vec::new();
    for (label,pf,ph,xf,xh) in cases {
        let proof:ordinary::Proof<Bn254>=decode(&read_pinned(&Path::new(PROOFS).join(pf),&ph,Some(128),128,owner));
        let public:Vec<Fr>=decode(&read_pinned(&Path::new(PROOFS).join(xf),&xh,Some(168),168,owner));assert_eq!(public.len(),5);
        assert!(ordinary::Groth16::<Bn254>::verify_proof(&pvk,&proof,&public).unwrap());
        let encoded=verifier.encode(&proof,&public,id).unwrap();assert!(native(&vk,&encoded.proof,&encoded.inputs));
        verifier.verify_solana(&encoded.proof,&encoded.inputs.concat(),id).unwrap();
        for i in 0..5 {
            let mut changed=public.clone();changed[i]+=Fr::ONE;
            assert!(!ordinary::Groth16::<Bn254>::verify_proof(&pvk,&proof,&changed).unwrap());
            let wrong: [[u8;32];5]=std::array::from_fn(|j|be(changed[j]));
            assert!(!native(&vk,&encoded.proof,&wrong),"native Solana independently rejects wrong public");
            assert!(verifier.decode(&encoded.proof,&wrong.concat(),id).is_err());
        }
        let mut wire=encoded.inputs.concat();wire.extend(encoded.proof);write_new(out,&format!("v2-{label}.wire"),&wire);statements.push(public);
    }
    assert_eq!(statements[0],statements[1],"Full and Anchor must prove the same target statement");
    let ic:Vec<_>=vk.gamma_abc_g1.iter().copied().map(g1).collect();
    let source=format!("// credential-v2-dev Original matching development VK only.\nuse groth16_solana::groth16::Groth16Verifyingkey;\npub const VERIFYING_KEY:Groth16Verifyingkey<'static>=Groth16Verifyingkey{{nr_pubinputs:5,vk_alpha_g1:{:?},vk_beta_g2:{:?},vk_gamme_g2:{:?},vk_delta_g2:{:?},vk_ic:&{:?}}};\n",g1(vk.alpha_g1),g2(vk.beta_g2),g2(vk.gamma_g2),g2(vk.delta_g2),ic);
    write_new(out,"v2-generated_vk.rs",source.as_bytes());
    let report=format!("{{\"scope\":\"v2 development native verification only\",\"passed\":true,\"proofs\":2,\"independent_ordinary_positive\":2,\"independent_native_solana_positive\":2,\"independent_ordinary_wrong_public\":10,\"independent_native_solana_wrong_public\":10,\"setup_manifest_sha256\":\"{setup_pin}\",\"proof_report_sha256\":\"{report_pin}\",\"package\":\"{PACKAGE}\",\"semantic_schema\":\"{SEMANTIC_SCHEMA}\",\"engine_extended_vk_digest\":\"{EXTENDED_VK}\",\"ordinary_vk_file_sha256\":\"{vk_pin}\",\"ordinary_vk_digest\":\"{expected_ordinary}\",\"generated_vk_source_sha256\":\"{}\",\"sbf_executed\":false,\"admitted\":false}}\n",hex(&Sha256::digest(source.as_bytes())));
    write_new(out,"v2-native-verifier-report.json",report.as_bytes());
}

#[test]
#[ignore = "Candidate digest measurement from ROOT-pinned setup; does not admit the package"]
fn measure_root_pinned_v2_ordinary_vk_candidate_digest() {
    let setup_pin=pin("M5_V2_SETUP_MANIFEST_SHA256");let vk_pin=pin("M5_V2_ORDINARY_VK_FILE_SHA256");
    let root=Path::new(SETUP);let stat=std::fs::symlink_metadata(root).unwrap();assert!(stat.is_dir()&&!stat.file_type().is_symlink());assert_eq!(stat.permissions().mode()&0o777,0o700);
    read_pinned(&root.join("setup-manifest.json"),&setup_pin,None,65536,stat.uid());
    let vk:ordinary::VerifyingKey<Bn254>=decode(&read_pinned(&root.join("ordinary.vk"),&vk_pin,Some(424),424,stat.uid()));
    let digest=ordinary_vk_digest(&vk).unwrap();
    println!("{{\"scope\":\"candidate ordinary VK digest measurement only\",\"ordinary_vk_file_sha256\":\"{vk_pin}\",\"ordinary_vk_digest\":\"{}\",\"setup_manifest_sha256\":\"{setup_pin}\",\"admitted\":false}}",hex(&digest));
}
