//! Opt-in tiny synthetic signer/input integration; no package or proving work.
use dynark_native_client::*;
use sha2::{Digest as _, Sha256};
use std::{
    cell::Cell,
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
struct PrivateRun(PathBuf);
impl Drop for PrivateRun {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct State {
    binding: WitnessBinding,
    issuer: FieldBytes,
    siblings: [FieldBytes; 10],
    status: Cell<Result<(), ClientError>>,
}
impl AuthenticatedV2State for State {
    fn binding(&self) -> &WitnessBinding {
        &self.binding
    }
    fn issuer_hash(&self) -> FieldBytes {
        self.issuer
    }
    fn slot(&self) -> u16 {
        7
    }
    fn siblings(&self) -> &[FieldBytes; 10] {
        &self.siblings
    }
    fn authorize(&self, _: u64) -> Result<(), ClientError> {
        self.status.get()
    }
}
const FIXTURE: &str = r#"
import hashlib,json,sys,types
from pathlib import Path
helper,output,expected=sys.argv[1:]
source=Path(helper).read_bytes()
if hashlib.sha256(source).hexdigest()!=expected:raise ValueError('test source')
m=types.ModuleType('prepare');m.__file__=helper
exec(compile(source,helper,'exec'),m.__dict__)
out=Path(output);private=out/'credential';context=out/'context.json'
c=m.prepare(private,context)
p,w=m.sources()
cert=(private/'certificate.synthetic.der').read_bytes()
issuer=m.read_bound(private/'issuer.synthetic.pem',8192,True)
from cryptography.hazmat.primitives import serialization
modulus=serialization.load_pem_private_key(issuer,None).public_key().public_numbers().n
parsed=p.admit_certificate(cert,modulus)
meta=int(c['root']).to_bytes(32,'little')+int(c['issuer_hash']).to_bytes(32,'little')+hashlib.sha256(parsed['tbs']).digest()
meta+=int(c['not_before']).to_bytes(8,'big')
m.write_new(out/'metadata.bin',meta,0o600)
m.write_new(out/'issuer-modulus.be',modulus.to_bytes(256,'big'),0o600)
"#;
fn pin(path: PathBuf, maximum: u64) -> PinnedFile {
    let bytes = fs::read(&path).unwrap();
    PinnedFile::new(path, Sha256::digest(&bytes).into(), maximum).unwrap()
}
#[test]
#[ignore = "ROOT-approved pinned Python runtime required; tiny signer/input integration only"]
fn local_synthetic_signer_builds_bound_v2_input_and_fails_closed() {
    let control = OperationControl::new(Instant::now() + Duration::from_secs(20));
    let base = fs::canonicalize(std::env::temp_dir()).unwrap();
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = base.join(format!("v2-native-input-{}-{suffix}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let run = PrivateRun(root);
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let python = PathBuf::from(std::env::var("M2_PYTHON").expect("pinned Python path"));
    let runtime = PinnedFile::new(
        &python,
        decode_digest(&std::env::var("M2_PYTHON_SHA256").expect("Python pin")).unwrap(),
        128 * 1024 * 1024,
    )
    .unwrap();
    let helper = here.join("tests/support/prepare_v2_context.py");
    let helper_digest: Digest =
        Sha256::digest(include_bytes!("support/prepare_v2_context.py")).into();
    let helper_hex: String = helper_digest.iter().map(|b| format!("{b:02x}")).collect();
    let status = Command::new(&python)
        .arg("-c")
        .arg(FIXTURE)
        .arg(helper)
        .arg(&run.0)
        .arg(helper_hex)
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "synthetic fixture preparation");
    control.check().unwrap();
    let metadata = fs::read(run.0.join("metadata.bin")).unwrap();
    assert!(metadata.len() == 104);
    let root: FieldBytes = metadata[..32].try_into().unwrap();
    let issuer: FieldBytes = metadata[32..64].try_into().unwrap();
    let credential: Digest = metadata[64..96].try_into().unwrap();
    let now = u64::from_be_bytes(metadata[96..104].try_into().unwrap()) + 1;
    let manifest = V2FullManifest::accepted_development().unwrap();
    let mut action = [0; 32];
    action[31] = 30;
    let state = State {
        binding: WitnessBinding {
            package: manifest.native.package,
            profile: manifest.profile,
            credential,
            credential_version: 1,
            action,
            issuer: [8; 32],
            target: RootTarget {
                root,
                version: 1,
                issuer_version: 1,
                policy_version: 1,
            },
            mapping: [0; 32],
            generation: 1,
        },
        issuer,
        siblings: std::array::from_fn(|i| {
            let mut b = [0; 32];
            b[0] = (17 + i) as u8;
            b
        }),
        status: Cell::new(Ok(())),
    };
    let worker = pin(here.join("workers/v2_input_worker.py"), 65536);
    let work = run.0.join("operations");
    fs::DirBuilder::new().mode(0o700).create(&work).unwrap();
    let make_worker = || V2InputWorker::new(runtime.clone(), worker.clone(), &work).unwrap();
    let key_path = run.0.join("credential/holder.synthetic.pem");
    let key = pin(key_path.clone(), 8192);
    let mut signer = LocalSyntheticV2HolderSigner::new(make_worker(), key).unwrap();
    let mut builder = V2AuthenticatedInputBuilder::new(make_worker());
    let certificate = fs::read(run.0.join("credential/certificate.synthetic.der")).unwrap();
    let modulus: [u8; 256] = fs::read(run.0.join("issuer-modulus.be"))
        .unwrap()
        .try_into()
        .unwrap();
    let target = builder
        .build(&certificate, &modulus, &state, &mut signer, now, &control)
        .unwrap();
    assert!(
        target.binding() == state.binding()
            && target.public_values()[0] == root
            && target.public_values()[1] == issuer,
        "exact authenticated target"
    );
    assert!(
        target.public_values()[4][0] == 30 && target.public_values()[4][1..] == [0; 31],
        "single endian conversion"
    );
    assert!(
        !target.input().is_empty() && target.input().len() < 65536,
        "canonical input bound"
    );
    target.authorize(now).unwrap();
    state.status.set(Err(ClientError::Revoked));
    assert_eq!(target.authorize(now), Err(ClientError::Revoked));
    drop(target);
    state.status.set(Ok(()));
    let cancelled = OperationControl::new(Instant::now() + Duration::from_secs(1));
    cancelled.cancel();
    assert!(matches!(
        builder.build(&certificate, &modulus, &state, &mut signer, now, &cancelled),
        Err(ClientError::Cancelled)
    ));
    fs::write(&key_path, b"changed synthetic key").unwrap();
    assert_eq!(
        signer.sign_action(action, &control),
        Err(ClientError::Identity)
    );
    assert!(
        fs::read_dir(&work).unwrap().next().is_none(),
        "private operation cleanup"
    );
}
