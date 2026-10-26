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

const BASE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../artifacts/dynark/pre-part5");
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

// Request-bound integration uses the existing standard signer/input builder;
// the state capability is a ROOT-pinned local test snapshot. Execution-current
// source/root binding is rechecked by the actual queue program after restart.
struct FinalizedPlanState {
    binding: WitnessBinding,
    issuer_hash: FieldBytes,
    slot: u16,
    siblings: [FieldBytes; 10],
    not_before: u64,
    not_after: u64,
    deadline: u64,
}
impl AuthenticatedV2State for FinalizedPlanState {
    fn binding(&self) -> &WitnessBinding {
        &self.binding
    }
    fn issuer_hash(&self) -> FieldBytes {
        self.issuer_hash
    }
    fn slot(&self) -> u16 {
        self.slot
    }
    fn siblings(&self) -> &[FieldBytes; 10] {
        &self.siblings
    }
    fn authorize(&self, now: u64) -> Result<(), ClientError> {
        if now < self.not_before || now > self.not_after || now > self.deadline {
            return Err(ClientError::Expired);
        }
        Ok(())
    }
}
const FINALIZED_PLAN_PREP: &str = r#"
import hashlib,json,os,stat,sys,types
from pathlib import Path
helper,helper_pin,plan_path,credential_path,context_path,output=sys.argv[1:]
source=Path(helper).read_bytes()
if hashlib.sha256(source).hexdigest()!=helper_pin:raise ValueError('helper identity')
m=types.ModuleType('prepare');m.__file__=helper
exec(compile(source,helper,'exec'),m.__dict__)
plan_bytes=m.pinned(Path(plan_path),'783c1c8c9110e41e1cf3d1cd79d6bb10c07c79f81aa3d17774b60fb6f7bd4c4b',16384,True)
p=json.loads(plan_bytes)
context=json.loads(m.pinned(Path(context_path),'0ee2fb693640dfcd430af7cb59a2162e35902f35a4c97c39eb067c074925cb4d',65536))
expected=p['expected_inputs']
if len(expected)!=5 or any(len(x)!=32 or any(type(y)is not int or not 0<=y<256 for y in x)for x in expected):raise ValueError('public width')
expected=list(map(bytes,expected));fr=21888242871839275222246405745257275088548364400416034343698204186575808495617
if any(int.from_bytes(x,'big')>=fr for x in expected):raise ValueError('public field')
# Independently encode the frozen action-v2 contract (two relevant accounts).
preimage=b'DYNARK-WORK-REQUEST'+bytes([2])+b''.join(bytes(p[k])for k in ['genesis','program','config','policy_id'])
preimage+=(1).to_bytes(4,'big')+bytes.fromhex(context['circuit_id'])+bytes(p['nonce'])+bytes(p['recipient'])
preimage+=(1).to_bytes(2,'big')+len(p['payload']).to_bytes(4,'big')+hashlib.sha256(bytes(p['payload'])).digest()
preimage+=bytes([2])+bytes(p['request'])+bytes([2])+bytes(p['queue'])+bytes([2])+p['deadline'].to_bytes(8,'big')
action=(int.from_bytes(hashlib.sha256(preimage).digest(),'big')%fr).to_bytes(32,'big')
if action!=expected[4] or action.hex()!='204adc0e5bc8095de0e3d5d768f1ca596267148fd3ca130c0290e5976015cdb0':raise ValueError('action mismatch')
if m.read_bound(Path(plan_path).parent/'action-preimage.bin',4096,True)!=preimage:raise ValueError('preimage mismatch')
if m.pinned(Path(plan_path).parent/'action-hash.be','bb74656de01e8e453dd22e2e6bff6701bbf76351d3c3b537661307dde7ac45d1',32,True)!=action:raise ValueError('action bytes')
for i,key in enumerate(['root','issuer_hash','not_before','not_after']):
    if int.from_bytes(expected[i],'big')!=int(context[key]):raise ValueError('prepared context mismatch')
private=m.private_root(Path(credential_path));profile,_=m.sources()
from cryptography.hazmat.primitives import serialization
issuer=serialization.load_pem_private_key(m.read_bound(private/'issuer.synthetic.pem',8192,True),None)
modulus=issuer.public_key().public_numbers().n
certificate=m.read_bound(private/'certificate.synthetic.der',4096,True)
parsed=profile.admit_certificate(certificate,modulus)
registry=json.loads(m.read_bound(private/'registry.synthetic.json',65536,True))
metadata=b'RQV1'+b''.join(expected)+hashlib.sha256(parsed['tbs']).digest()+modulus.to_bytes(256,'big')
metadata+=registry['slot'].to_bytes(2,'big')+b''.join(x.to_bytes(32,'little')for x in registry['siblings'])+p['deadline'].to_bytes(8,'big')
m.write_new(Path(output),metadata,0o600)
"#;
fn current_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn new_private(path: &Path, bytes: &[u8]) {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn scalar_be<F: ark_ff::PrimeField>(value: F) -> [u8; 32] {
    use ark_ff::BigInteger;
    let bytes = value.into_bigint().to_bytes_be();
    let mut word = [0; 32];
    word[32 - bytes.len()..].copy_from_slice(&bytes);
    word
}
/// Exact existing adapter convention, confined to this reviewable integration
/// export: publics BE, -A G1, B Fq2 c1/c0, C G1. Ordinary proof verification
/// happens before export; actual loaded program independently checks this wire.
fn export_five_field_wire(proof: &ProofResult) -> Vec<u8> {
    assert!(proof.public_values().len() == 5, "five-field v2 schema");
    let mut wire = Vec::with_capacity(416);
    for value in proof.public_values() {
        wire.extend(scalar_be(*value));
    }
    let a = -proof.proof().a;
    let b = proof.proof().b;
    let c = proof.proof().c;
    for value in [a.x, a.y, b.x.c1, b.x.c0, b.y.c1, b.y.c0, c.x, c.y] {
        wire.extend(scalar_be(value));
    }
    assert!(wire.len() == 416, "v2 exact wire length");
    wire
}
#[test]
#[ignore = "ROOT-granted exact finalized-request Full proof; private synthetic keys and resource supervisor required"]
fn native_v2_finalized_request_full_proof_wire() {
    assert!(
        std::env::var("M2_V2_APPROVAL_SCOPE").as_deref() == Ok("native-v2-request-full-001"),
        "fresh exact action scope"
    );
    let start = Instant::now();
    let control = OperationControl::new(start + Duration::from_secs(570));
    stage("request_gate_begin", start);
    let output =
        PathBuf::from(std::env::var("M2_PRIVATE_ROOT").expect("ROOT fresh private output"));
    let meta = fs::symlink_metadata(&output).unwrap();
    assert!(
        output.is_absolute()
            && fs::canonicalize(&output).unwrap() == output
            && meta.is_dir()
            && meta.permissions().mode() & 0o777 == 0o700,
        "private output authority"
    );
    assert!(
        fs::read_dir(&output).unwrap().next().is_none(),
        "fresh output only"
    );
    let owner = meta.uid();
    let operations = output.join("operations");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&operations)
        .unwrap();
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo = here.join("../..").canonicalize().unwrap();
    let python = PathBuf::from(std::env::var("M2_PYTHON").unwrap());
    let python_pin = PinnedFile::new(
        &python,
        digest(&std::env::var("M2_PYTHON_SHA256").unwrap()),
        128 * 1024 * 1024,
    )
    .unwrap();
    let helper = here.join("tests/support/prepare_v2_context.py");
    let helper_hash: Digest =
        Sha256::digest(include_bytes!("support/prepare_v2_context.py")).into();
    let helper_hex: String = helper_hash.iter().map(|b| format!("{b:02x}")).collect();
    let plan =
        repo.join("artifacts/dynark/part5/application-v2-local-runtime-001/private/plan.json");
    let credential =
        repo.join("artifacts/dynark/part5/application-v2-synthetic-context-001-private");
    let context_path = repo.join("results/dynark/part5/application-v2-public-context-001.json");
    let metadata_path = output.join("request-context.bin");
    stage("plan_and_credential_import_begin", start);
    let status = Command::new(&python)
        .arg("-c")
        .arg(FINALIZED_PLAN_PREP)
        .arg(helper)
        .arg(helper_hex)
        .arg(&plan)
        .arg(&credential)
        .arg(context_path)
        .arg(&metadata_path)
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(
        status.success(),
        "exact finalized request/context admission"
    );
    control.check().unwrap();
    let mut metadata = fs::read(&metadata_path).unwrap();
    assert!(
        metadata.len() == 782 && &metadata[..4] == b"RQV1",
        "private context protocol"
    );
    let expected_be: [[u8; 32]; 5] =
        std::array::from_fn(|i| metadata[4 + i * 32..36 + i * 32].try_into().unwrap());
    let mut native_publics = expected_be;
    for field in &mut native_publics {
        field.reverse();
    }
    let manifest = V2FullManifest::accepted_development().unwrap();
    let state = FinalizedPlanState {
        binding: WitnessBinding {
            package: manifest.native.package,
            profile: manifest.profile,
            credential: metadata[164..196].try_into().unwrap(),
            credential_version: 1,
            action: expected_be[4],
            issuer: plan_account_issuer(&plan, &python),
            target: RootTarget {
                root: native_publics[0],
                version: 0,
                issuer_version: 1,
                policy_version: 1,
            },
            mapping: [0; 32],
            generation: 1,
        },
        issuer_hash: native_publics[1],
        slot: u16::from_be_bytes(metadata[452..454].try_into().unwrap()),
        siblings: std::array::from_fn(|i| metadata[454 + i * 32..486 + i * 32].try_into().unwrap()),
        not_before: u64::from_be_bytes(expected_be[2][24..].try_into().unwrap()),
        not_after: u64::from_be_bytes(expected_be[3][24..].try_into().unwrap()),
        deadline: u64::from_be_bytes(metadata[774..782].try_into().unwrap()),
    };
    let modulus: [u8; 256] = metadata[196..452].try_into().unwrap();
    metadata.fill(0);
    fs::remove_file(metadata_path).unwrap();
    stage("plan_and_credential_import_done", start);
    let input_worker_pin = PinnedFile::new(
        here.join("workers/v2_input_worker.py"),
        Sha256::digest(include_bytes!("../workers/v2_input_worker.py")).into(),
        65536,
    )
    .unwrap();
    let make_input_worker =
        || V2InputWorker::new(python_pin.clone(), input_worker_pin.clone(), &operations).unwrap();
    let key_path = credential.join("holder.synthetic.pem");
    let mut key_bytes = fs::read(&key_path).unwrap();
    let key_digest: Digest = Sha256::digest(&key_bytes).into();
    key_bytes.fill(0);
    let key = PinnedFile::new(key_path, key_digest, 8192).unwrap();
    let mut signer = LocalSyntheticV2HolderSigner::new(make_input_worker(), key).unwrap();
    let mut input_builder = V2AuthenticatedInputBuilder::new(make_input_worker());
    let mut certificate = fs::read(credential.join("certificate.synthetic.der")).unwrap();
    stage("holder_sign_and_input_begin", start);
    let target = input_builder
        .build(
            &certificate,
            &modulus,
            &state,
            &mut signer,
            current_unix(),
            &control,
        )
        .unwrap();
    certificate.fill(0);
    assert!(
        target.public_values() == native_publics,
        "six distinct bindings map to exact five v2 publics"
    );
    stage("holder_sign_and_input_done", start);
    let artifacts = Path::new(BASE);
    let setup = artifacts.join("credential-v2-dev-development-setup-001");
    let compile = artifacts.join("credential-v2-dev-compile-002");
    pinned_read(
        &setup.join("setup-manifest.json"),
        "878503eb2e182f4cb53b481ef5f3961ec81725f7546d472c0fe14e5f94ee6f53",
        1585,
        true,
        owner,
    );
    let r1cs = compile.join("credential.r1cs");
    PinnedFile::new(
        &r1cs,
        digest("ae7d802e9d62d6475fbcc312472b66f583f761c0d74dec223c733f4348bfc009"),
        166490376,
    )
    .unwrap();
    stage("pk_read_and_hash_begin", start);
    let pk_bytes = pinned_read(
        &setup.join("development.pk"),
        "260c42276f6780cb6845f45efe41101db27c78e64d5e871e52f98b54ed141fc9",
        156612277,
        true,
        owner,
    );
    stage("pk_read_and_hash_done", start);
    stage("r1cs_import_begin", start);
    let matrices = import::read_r1cs(&r1cs, limits()).unwrap();
    stage("r1cs_import_done", start);
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
    stage("pk_decode_begin", start);
    let mut cursor = Cursor::new(&pk_bytes);
    // Exact hash-pinned artifact; PublicPackage::new immediately checks the full
    // key, all identity commitments, dimensions and degenerate denominators.
    let pk = CanonicalDeserialize::deserialize_compressed_unchecked(&mut cursor).unwrap();
    assert!(
        cursor.position() as usize == pk_bytes.len(),
        "PK trailing bytes"
    );
    stage("pk_decode_done", start);
    stage("package_validation_begin", start);
    let package = PublicPackage::new(matrices, descriptor, pk, manifest.native.package).unwrap();
    manifest.check_package(&package).unwrap();
    drop(pk_bytes);
    control.check().unwrap();
    stage("package_validation_done", start);
    let vk_bytes = pinned_read(
        &setup.join("ordinary.vk"),
        "52b614e3a8560ae8b5dc246bc197944a95072b8784b5a2c9c84c740f119925e3",
        424,
        true,
        owner,
    );
    let mut actual_vk = Vec::new();
    package
        .ordinary_verifying_key()
        .serialize_compressed(&mut actual_vk)
        .unwrap();
    assert!(actual_vk == vk_bytes, "exact matching ordinary VK");
    let node = PinnedFile::new(
        PathBuf::from(std::env::var("M2_NODE").unwrap()),
        digest(&std::env::var("M2_NODE_SHA256").unwrap()),
        128 * 1024 * 1024,
    )
    .unwrap();
    let full_worker = PinnedFile::new(
        here.join("workers/v2_full_worker.cjs"),
        Sha256::digest(include_bytes!("../workers/v2_full_worker.cjs")).into(),
        65536,
    )
    .unwrap();
    let mut generator = NativeV2FullWitnessGenerator::new(
        WorkerRunner::pinned(node, full_worker),
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
        &operations,
    )
    .unwrap();
    stage("full_witness_relation_begin", start);
    let witness = WitnessContext::open_v2(
        package.clone(),
        manifest,
        &target,
        &mut generator,
        current_unix(),
        &control,
    )
    .unwrap();
    stage("full_witness_relation_done", start);
    stage("full_proof_begin", start);
    let proof = witness
        .prove_full(&target, &mut rand::rngs::OsRng, current_unix(), &control)
        .unwrap();
    stage("full_proof_done", start);
    assert!(
        proof.v2_manifest() == Some(manifest) && proof.binding() == target.binding(),
        "exact proof context"
    );
    let pvk = ordinary::prepare_verifying_key(&package.ordinary_verifying_key());
    assert!(
        ordinary::Groth16::<Bn254>::verify_proof(&pvk, proof.proof(), proof.public_values())
            .unwrap(),
        "independent ordinary proof"
    );
    for index in 0..5 {
        let mut wrong = proof.public_values().to_vec();
        wrong[index] += Fr::ONE;
        assert!(
            !ordinary::Groth16::<Bn254>::verify_proof(&pvk, proof.proof(), &wrong).unwrap(),
            "altered public rejected"
        );
    }
    stage("wire_export_begin", start);
    let wire = export_five_field_wire(&proof);
    assert!(
        wire[..160] == expected_be.concat(),
        "exact finalized request five-field wire"
    );
    let mut ordinary_proof = Vec::new();
    proof
        .proof()
        .serialize_compressed(&mut ordinary_proof)
        .unwrap();
    let mut ordinary_public = Vec::new();
    proof
        .public_values()
        .to_vec()
        .serialize_compressed(&mut ordinary_public)
        .unwrap();
    proof
        .ensure_submission_current(&target, current_unix(), &control)
        .unwrap();
    new_private(&output.join("full.wire"), &wire);
    new_private(&output.join("ordinary.proof"), &ordinary_proof);
    new_private(&output.join("ordinary-public.bin"), &ordinary_public);
    new_private(&output.join("ordinary.vk"), &vk_bytes);
    let wire_hash: Digest = Sha256::digest(&wire).into();
    let wire_hex: String = wire_hash.iter().map(|b| format!("{b:02x}")).collect();
    let report=format!("{{\"schema\":\"native-v2-request-full-001\",\"passed\":true,\"full_proofs\":1,\"ordinary_positive\":1,\"ordinary_wrong_public\":5,\"plan_sha256\":\"783c1c8c9110e41e1cf3d1cd79d6bb10c07c79f81aa3d17774b60fb6f7bd4c4b\",\"action_be\":\"204adc0e5bc8095de0e3d5d768f1ca596267148fd3ca130c0290e5976015cdb0\",\"wire_sha256\":\"{wire_hex}\",\"application_executed\":false,\"authenticated_source\":\"ROOT-pinned local test snapshot; execution checks onchain state\"}}\n");
    new_private(&output.join("proof-report.json"), report.as_bytes());
    assert!(
        fs::read_dir(&operations).unwrap().next().is_none(),
        "private child cleanup"
    );
    control.check().unwrap();
    stage("wire_export_done", start);
}
fn plan_account_issuer(plan: &Path, python: &Path) -> Digest {
    // Public account identifier from the same exact independently pinned plan.
    let script="import hashlib,json,sys; b=open(sys.argv[1],'rb').read(); assert hashlib.sha256(b).hexdigest()=='783c1c8c9110e41e1cf3d1cd79d6bb10c07c79f81aa3d17774b60fb6f7bd4c4b'; sys.stdout.buffer.write(bytes(json.loads(b)['issuer_account']))";
    let result = Command::new(python)
        .arg("-c")
        .arg(script)
        .arg(plan)
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .unwrap();
    assert!(
        result.status.success() && result.stdout.len() == 32,
        "pinned issuer enrollment account"
    );
    result.stdout.try_into().unwrap()
}
