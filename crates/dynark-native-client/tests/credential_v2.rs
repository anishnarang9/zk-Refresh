//! Opt-in real fixed-template v2 development integration. ROOT serializes the
//! enclosing workload-tree supervisor; ordinary cargo test never runs this gate.
use ark_bn254::{Bn254, Fr};
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use dynark_bn254::{
    import, public_schema_digest, CircuitDescriptor, Limits, PublicPackage, Reduction,
};
use dynark_native_client::*;
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, File},
    io::{Cursor, Read},
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const BASE: &str = "/Users/anishnarang/Zk-refresh/artifacts/dynark/pre-part5";
const CORPUS_SHA: &str = "e5a25009f9b966fea3bdde9965242526720a9d27adf1b4f5219452b5c636e152";
const EXTRACT: &str = r#"
const fs=require('node:fs'),crypto=require('node:crypto');
const [corpusPath,output]=process.argv.slice(1);
const bytes=fs.readFileSync(corpusPath);
if(bytes.length>2*1024*1024 || crypto.createHash('sha256').update(bytes).digest('hex')!=='e5a25009f9b966fea3bdde9965242526720a9d27adf1b4f5219452b5c636e152')process.exit(2);
const corpus=JSON.parse(bytes.toString('utf8'));
if(corpus.schema!=='credential-v2-dev-witness-corpus-v1'||corpus.synthetic_only!==true||corpus.source_keys_serialized!==false)process.exit(2);
const found=corpus.cases.filter(item=>item.name==='valid_base');
if(found.length!==1)process.exit(2);
const input=Buffer.from(JSON.stringify(found[0].inputs));
if(!input.length||input.length>65536)process.exit(2);
fs.writeFileSync(output,input,{flag:'wx',mode:0o600});
"#;

fn digest(value: &str) -> Digest {
    decode_digest(value).expect("public digest encoding")
}
fn pinned_read(path: &Path, expected: &str, exact: u64, private: bool, owner: u32) -> Vec<u8> {
    assert!(
        path.is_absolute() && fs::canonicalize(path).unwrap() == path,
        "artifact path"
    );
    let meta = fs::symlink_metadata(path).unwrap();
    assert!(
        meta.is_file() && meta.len() == exact,
        "artifact type and size"
    );
    if private {
        assert!(
            meta.uid() == owner && meta.permissions().mode() & 0o777 == 0o600,
            "private artifact authority"
        );
    }
    let file = File::open(path).unwrap();
    let opened = file.metadata().unwrap();
    assert!(
        (opened.dev(), opened.ino(), opened.len()) == (meta.dev(), meta.ino(), meta.len()),
        "artifact changed at open"
    );
    let mut bytes = Vec::new();
    file.take(exact + 1).read_to_end(&mut bytes).unwrap();
    assert!(
        bytes.len() as u64 == exact && <[u8; 32]>::from(Sha256::digest(&bytes)) == digest(expected),
        "artifact digest"
    );
    bytes
}
fn limits() -> import::ImportLimits {
    import::ImportLimits {
        operation: Limits {
            max_domain: 1_048_576,
            max_assignment: V2_COORDINATES,
            max_matrix_entries: 4_500_000,
            max_delta_entries: 8192,
            max_pair_work: 11_000_000,
            max_allocation_bytes: 4 * 1024 * 1024 * 1024,
        },
        max_file_bytes: 192 * 1024 * 1024,
        max_section_bytes: 160 * 1024 * 1024,
        max_sections: 3,
        max_row_entries: 4096,
    }
}
struct PrivateRun(PathBuf);
impl Drop for PrivateRun {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct FixtureTarget {
    binding: WitnessBinding,
    input: Vec<u8>,
    publics: Vec<FieldBytes>,
}
impl AuthenticatedTarget for FixtureTarget {
    fn binding(&self) -> &WitnessBinding {
        &self.binding
    }
    fn input(&self) -> &[u8] {
        &self.input
    }
    fn public_values(&self) -> &[FieldBytes] {
        &self.publics
    }
    fn authorize(&self, _: u64) -> Result<(), ClientError> {
        Ok(())
    }
}
struct CorruptCandidate(Vec<u8>);
impl WitnessGenerator for CorruptCandidate {
    fn generate(
        &mut self,
        _: &[u8],
        _: &[u8],
        _: &[u8],
        incremental: bool,
        control: &OperationControl,
    ) -> Result<(Vec<u8>, WitnessMode), ClientError> {
        control.check()?;
        assert!(!incremental, "v2 never requests incremental");
        Ok((self.0.clone(), WitnessMode::Full))
    }
}
struct ExactGenerator {
    native: NativeV2FullWitnessGenerator,
    oracle: Vec<u8>,
    calls: usize,
}
impl WitnessGenerator for ExactGenerator {
    fn generate(
        &mut self,
        before: &[u8],
        witness: &[u8],
        input: &[u8],
        incremental: bool,
        control: &OperationControl,
    ) -> Result<(Vec<u8>, WitnessMode), ClientError> {
        assert!(!incremental, "v2 Full-only lane");
        let (bytes, mode) = self
            .native
            .generate(before, witness, input, incremental, control)?;
        assert!(bytes == self.oracle, "complete v2 witness equality");
        assert!(mode == WitnessMode::Full, "v2 Full mode");
        self.calls += 1;
        Ok((bytes, mode))
    }
}
fn stage(name: &str, start: Instant) {
    println!(
        "{{\"stage\":\"{name}\",\"elapsed_ms\":{:.3}}}",
        start.elapsed().as_secs_f64() * 1000.0
    );
}

#[test]
#[ignore = "ROOT-owned bounded real v2 Full witness/relation/proof integration grant required"]
fn native_v2_full_exact_witness_relation_and_randomized_proofs() {
    assert!(
        std::env::var("M2_V2_APPROVAL_SCOPE").as_deref() == Ok("native-v2-full-002"),
        "exact ROOT execution scope"
    );
    let start = Instant::now();
    let control = OperationControl::new(start + Duration::from_secs(570));
    let manifest = V2FullManifest::accepted_development().unwrap();
    let parent = PathBuf::from(std::env::var("M2_PRIVATE_ROOT").expect("ROOT private root"));
    let meta = fs::symlink_metadata(&parent).unwrap();
    assert!(
        parent.is_absolute()
            && fs::canonicalize(&parent).unwrap() == parent
            && meta.is_dir()
            && meta.permissions().mode() & 0o777 == 0o700,
        "private root"
    );
    let owner = meta.uid();
    let work = parent.join(format!("native-v2-full-002-{}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&work).unwrap();
    let run = PrivateRun(work);
    let generations = run.0.join("generations");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&generations)
        .unwrap();
    let node_path = PathBuf::from(std::env::var("M2_NODE").expect("ROOT Node runtime"));
    let runtime = PinnedFile::new(
        &node_path,
        digest(&std::env::var("M2_NODE_SHA256").expect("ROOT Node SHA256")),
        128 * 1024 * 1024,
    )
    .unwrap();
    let base = Path::new(BASE);
    let compile = base.join("credential-v2-dev-compile-002");
    let setup = base.join("credential-v2-dev-development-setup-001");
    let r1cs = compile.join("credential.r1cs");
    let r1cs_pin = PinnedFile::new(
        &r1cs,
        digest("ae7d802e9d62d6475fbcc312472b66f583f761c0d74dec223c733f4348bfc009"),
        166490376,
    )
    .unwrap();
    drop(r1cs_pin);
    pinned_read(
        &setup.join("setup-manifest.json"),
        "878503eb2e182f4cb53b481ef5f3961ec81725f7546d472c0fe14e5f94ee6f53",
        1585,
        true,
        owner,
    );
    let profile = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/credential-v2-dev/profile.json")
        .canonicalize()
        .unwrap();
    PinnedFile::new(profile, manifest.profile, 65536).unwrap();
    let corpus = base.join("credential-v2-dev-witness-corpus-001/corpus.json");
    PinnedFile::new(&corpus, digest(CORPUS_SHA), 379681).unwrap();
    let input_path = run.0.join("input.json");
    let status = Command::new(&node_path)
        .arg("-e")
        .arg(EXTRACT)
        .arg(&corpus)
        .arg(&input_path)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "pinned synthetic input extraction");
    control.check().unwrap();
    let input_meta = fs::symlink_metadata(&input_path).unwrap();
    assert!(
        input_meta.is_file()
            && input_meta.uid() == owner
            && input_meta.permissions().mode() & 0o777 == 0o600
            && input_meta.len() <= 65536,
        "private synthetic input"
    );
    let input = fs::read(&input_path).unwrap();
    let oracle = pinned_read(
        &base.join("credential-v2-dev-witness-qualification-002/valid_base.wtns"),
        "5fcc72b635701ac05f4b0b23da2f0e89a0821f561ed742b1f214a9cb4fde392a",
        V2_WITNESS_BYTES as u64,
        true,
        owner,
    );
    let fields = parse_canonical_v2_wtns(&oracle).unwrap();
    let publics = fields[1..6].to_vec();
    drop(fields);
    let mut action = publics[4];
    action.reverse();
    let target = FixtureTarget {
        binding: WitnessBinding {
            package: manifest.native.package,
            profile: manifest.profile,
            credential: [1; 32],
            credential_version: 1,
            action,
            issuer: [2; 32],
            target: RootTarget {
                root: publics[0],
                version: 1,
                issuer_version: 1,
                policy_version: 1,
            },
            mapping: [0; 32],
            generation: 1,
        },
        input,
        publics,
    };
    // These identity labels are synthetic adapter capabilities, not evidence of
    // authenticated registry/status or application admission.
    let pk_bytes = pinned_read(
        &setup.join("development.pk"),
        "260c42276f6780cb6845f45efe41101db27c78e64d5e871e52f98b54ed141fc9",
        156612277,
        true,
        owner,
    );
    let names = ["root", "issuerHash", "notBefore", "notAfter", "actionHash"]
        .map(str::to_owned)
        .to_vec();
    let descriptor = CircuitDescriptor {
        r1cs_artifact_digest: digest(
            "ae7d802e9d62d6475fbcc312472b66f583f761c0d74dec223c733f4348bfc009",
        ),
        witness_executable_digest: digest(V2_WASM_HEX),
        profile_digest: manifest.profile,
        public_schema_digest: public_schema_digest(&names),
        public_schema: names,
        reduction: Reduction::Original,
    };
    // `PublicPackage::new` below performs full key Valid::check, dimensional,
    // degeneracy and exact identity validation. Skip the redundant first
    // subgroup pass only for these already SHA256-pinned setup bytes; the
    // decoded key never leaves this function or authorizes work before new().
    let matrices = import::read_r1cs(&r1cs, limits()).unwrap();
    let mut cursor = Cursor::new(&pk_bytes);
    let pk = CanonicalDeserialize::deserialize_compressed_unchecked(&mut cursor).unwrap();
    assert!(
        cursor.position() as usize == pk_bytes.len(),
        "PK trailing bytes"
    );
    let package = PublicPackage::new(matrices, descriptor, pk, manifest.native.package).unwrap();
    manifest.check_package(&package).unwrap();
    drop(pk_bytes);
    control.check().unwrap();
    stage("package_import", start);
    let vk_bytes = pinned_read(
        &setup.join("ordinary.vk"),
        "52b614e3a8560ae8b5dc246bc197944a95072b8784b5a2c9c84c740f119925e3",
        424,
        true,
        owner,
    );
    let mut package_vk = Vec::new();
    package
        .ordinary_verifying_key()
        .serialize_compressed(&mut package_vk)
        .unwrap();
    assert!(package_vk == vk_bytes, "exact matching ordinary VK");
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let worker = PinnedFile::new(
        here.join("workers/v2_full_worker.cjs"),
        Sha256::digest(include_bytes!("../workers/v2_full_worker.cjs")).into(),
        65536,
    )
    .unwrap();
    let native = NativeV2FullWitnessGenerator::new(
        WorkerRunner::pinned(runtime, worker),
        PinnedFile::new(
            compile.join("credential_js/credential.wasm"),
            digest(V2_WASM_HEX),
            8395299,
        )
        .unwrap(),
        PinnedFile::new(
            compile.join("credential_js/witness_calculator.js"),
            digest(V2_CALCULATOR_HEX),
            10356,
        )
        .unwrap(),
        &generations,
    )
    .unwrap();
    let mut generator = ExactGenerator {
        native,
        oracle,
        calls: 0,
    };
    let t = Instant::now();
    let context = WitnessContext::open_v2(
        package.clone(),
        manifest,
        &target,
        &mut generator,
        0,
        &control,
    )
    .unwrap();
    assert!(generator.calls == 1, "one complete native generation");
    stage("full_witness_and_relation", t);
    let mut corrupt = generator.oracle.clone();
    let offset = 76 + 32 * 6;
    let value = Fr::deserialize_compressed(&corrupt[offset..offset + 32]).unwrap() + Fr::ONE;
    value
        .serialize_compressed(&mut corrupt[offset..offset + 32])
        .unwrap();
    let bad = WitnessContext::open_v2(
        package.clone(),
        manifest,
        &target,
        &mut CorruptCandidate(corrupt),
        0,
        &control,
    );
    assert!(
        matches!(bad, Err(ClientError::Relation)),
        "corrupt candidate rejected by complete relation"
    );
    let pvk = ordinary::prepare_verifying_key(&package.ordinary_verifying_key());
    let t = Instant::now();
    let first = context
        .prove_full(&target, &mut rand::rngs::OsRng, 0, &control)
        .unwrap();
    let second = context
        .prove_full(&target, &mut rand::rngs::OsRng, 0, &control)
        .unwrap();
    stage("two_randomized_full_proofs", t);
    assert!(
        first.v2_manifest() == Some(manifest) && first.binding() == &target.binding,
        "proof context binding"
    );
    let mut a = Vec::new();
    let mut b = Vec::new();
    first.proof().serialize_compressed(&mut a).unwrap();
    second.proof().serialize_compressed(&mut b).unwrap();
    assert!(a != b, "fresh randomized proof bytes");
    for proof in [&first, &second] {
        assert!(
            ordinary::Groth16::<Bn254>::verify_proof(&pvk, proof.proof(), proof.public_values())
                .unwrap(),
            "independent ordinary verification"
        );
        for index in 0..5 {
            let mut wrong = proof.public_values().to_vec();
            wrong[index] += Fr::ONE;
            assert!(
                !ordinary::Groth16::<Bn254>::verify_proof(&pvk, proof.proof(), &wrong).unwrap(),
                "altered public rejected"
            );
        }
    }
    first
        .ensure_submission_current(&target, 0, &control)
        .unwrap();
    assert!(
        fs::read_dir(&generations).unwrap().next().is_none(),
        "private worker cleanup"
    );
    control.check().unwrap();
    stage("complete_native_v2_full_gate", start);
    println!("{{\"scope\":\"native-v2-full-002\",\"full_witnesses\":1,\"complete_output_equalities\":1,\"corrupt_relations_rejected\":1,\"full_proofs\":2,\"independent_ordinary_positive\":2,\"independent_wrong_public\":10,\"application_effect_executed\":false}}");
}

#[test]
fn bad_pk_file_pin_fails_before_any_decode() {
    let parent = fs::canonicalize(std::env::temp_dir()).unwrap();
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = parent.join(format!(
        "native-v2-pin-test-{}-{suffix}",
        std::process::id()
    ));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let run = PrivateRun(directory);
    let path = run.0.join("candidate.pk");
    fs::write(&path, b"not a key").unwrap();
    let result = std::panic::catch_unwind(|| pinned_read(&path, &"00".repeat(32), 9, false, 0));
    assert!(
        result.is_err(),
        "bad-pinned bytes must fail before key decoding"
    );
}
