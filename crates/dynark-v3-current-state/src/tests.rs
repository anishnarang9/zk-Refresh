//! Synthetic deployment bytes only. No signature or application admission claim.
use super::*;
use sha2::{Digest, Sha256};
use solana_program::{bpf_loader_upgradeable::{self, UpgradeableLoaderState}, clock::Clock, sysvar};
use std::sync::{Arc, Mutex};
use zk_fresh_program::{application_runtime_v3::config_address, application_v3::Config, generated_vk_v3 as identity};

fn key(n: u8) -> Pubkey { Pubkey::new_from_array([n; 32]) }
fn field(n: u8) -> [u8; 32] { let mut b = [0; 32]; b[31] = n; b }

struct ScriptedTransport {
    expected: FinalizedRequest,
    response: Mutex<Option<FinalizedBatch>>,
    genesis: [u8; 32],
    calls: Arc<Mutex<Vec<&'static str>>>,
}
impl Transport for ScriptedTransport {
    fn genesis(&self) -> Result<[u8; 32], Error> {
        self.calls.lock().unwrap().push("genesis");
        Ok(self.genesis)
    }
    fn finalized_accounts(&self, request: &FinalizedRequest) -> Result<FinalizedBatch, Error> {
        assert_eq!(request, &self.expected, "finalized request/pin contract changed");
        self.calls.lock().unwrap().push("finalized_accounts");
        self.response.lock().unwrap().take().ok_or(Error::Transport)
    }
}

struct Fixture { pins: DeploymentPins, batch: FinalizedBatch, genesis: [u8; 32] }

fn fixture() -> Fixture {
    let program = key(11);
    let programdata = Pubkey::find_program_address(&[program.as_ref()], &bpf_loader_upgradeable::id()).0;
    let config = Config {
        admin: key(12), seed: [13; 32], publisher: key(14), genesis: [15; 32],
        policy_id: field(16), policy_version: 1,
        circuit_id: identity::CIRCUIT_ID, package_id: identity::PACKAGE_ID,
        schema_id: identity::SEMANTIC_SCHEMA_ID, profile_id: identity::PROFILE_ID,
        ordinary_vk_digest: identity::ORDINARY_VK_DIGEST,
        root: field(17), root_version: 0, eligibility_epoch: 2, enabled: true,
    };
    let config_key = config_address(&program, &config.admin, &config.seed).0;
    let config_bytes = config.encode();
    assert_eq!(Config::decode(&config_bytes).unwrap(), config);
    // Public synthetic image, deliberately not a real executable/deployment.
    let elf = b"\x7fELFsynthetic-v3-deployment-vector-v1";
    let program_bytes = bincode::serialize(&UpgradeableLoaderState::Program { programdata_address: programdata }).unwrap();
    let mut programdata_bytes = bincode::serialize(&UpgradeableLoaderState::ProgramData {
        slot: 40, upgrade_authority_address: Some(key(18)),
    }).unwrap();
    programdata_bytes.resize(UpgradeableLoaderState::size_of_programdata_metadata(), 0);
    programdata_bytes.extend(elf);
    let clock = Clock { slot: 100, epoch_start_timestamp: 800, epoch: 3, leader_schedule_epoch: 4, unix_timestamp: 1000 };
    let pins = DeploymentPins {
        endpoint: "http://127.0.0.1:8899".into(), genesis: config.genesis,
        program, programdata, config: config_key, admin: config.admin, seed: config.seed,
        elf_sha256: Sha256::digest(elf).into(), elf_length: elf.len(),
        upgrade_authority: Some(key(18)), minimum_finalized_slot: 90,
        maximum_clock_age_seconds: 5,
    };
    Fixture { pins, genesis: config.genesis, batch: FinalizedBatch {
        context_slot: 100,
        accounts: vec![
            Account { key: program, owner: bpf_loader_upgradeable::id(), executable: true, bytes: program_bytes },
            Account { key: programdata, owner: bpf_loader_upgradeable::id(), executable: false, bytes: programdata_bytes },
            Account { key: config_key, owner: program, executable: false, bytes: config_bytes },
            Account { key: sysvar::clock::id(), owner: sysvar::id(), executable: false, bytes: bincode::serialize(&clock).unwrap() },
        ],
    }}
}

fn run(f: Fixture, now: i64) -> (Result<VerifiedDeployment, Error>, Vec<&'static str>) {
    let expected = FinalizedRequest {
        keys: vec![f.pins.program, f.pins.programdata, f.pins.config, sysvar::clock::id()],
        commitment: Commitment::Finalized, minimum_context_slot: f.pins.minimum_finalized_slot,
    };
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = ScriptedTransport {
        expected,
        response: Mutex::new(Some(f.batch)), genesis: f.genesis, calls: calls.clone(),
    };
    // Only this private module can inject a scripted transport. Production has
    // no public transport trait or constructor accepting account JSON.
    let verifier = ConfiguredVerifier { pins: f.pins, transport: Box::new(transport) };
    let result = verifier.verify_deployment(now);
    let trace = calls.lock().unwrap().clone();
    (result, trace)
}

#[test]
fn finalized_deployment_pda_gate() {
    let f = fixture();
    let expected_program = f.pins.program;
    let expected_config = f.pins.config;
    let (result, trace) = run(f, 1002);
    assert_eq!(trace, vec!["genesis", "finalized_accounts"]);
    assert_eq!(result.as_ref().map(|v| v.finalized_slot()), Ok(100));
    let checked = result.unwrap();
    assert_eq!(checked.program(), &expected_program);
    assert_eq!(checked.config(), &expected_config);
}

type Mutation = fn(&mut Fixture);
fn rejects(cases: &[(&str, Mutation, Error)]) {
    for (name, mutate, expected) in cases {
        let mut f = fixture(); mutate(&mut f);
        assert_eq!(run(f, 1002).0.err(), Some(*expected), "{name}");
    }
}
fn config_mutate(f: &mut Fixture, mutate: fn(&mut Config)) {
    let mut c = Config::decode(&f.batch.accounts[2].bytes).unwrap();
    mutate(&mut c); f.batch.accounts[2].bytes = c.encode();
}
fn clock_mutate(f: &mut Fixture, mutate: fn(&mut Clock)) {
    let mut c: Clock = bincode::deserialize(&f.batch.accounts[3].bytes).unwrap();
    mutate(&mut c); f.batch.accounts[3].bytes = bincode::serialize(&c).unwrap();
}

#[test]
fn rejects_wrong_genesis_loader_linkage_and_elf() {
    rejects(&[
        ("RPC genesis", |f| f.genesis[0] ^= 1, Error::Deployment),
        ("programdata PDA pin", |f| f.pins.programdata = key(50), Error::Deployment),
        ("program owner", |f| f.batch.accounts[0].owner = key(50), Error::Deployment),
        ("program executable", |f| f.batch.accounts[0].executable = false, Error::Deployment),
        ("program trailing", |f| f.batch.accounts[0].bytes.push(0), Error::Deployment),
        ("program loader tag", |f| f.batch.accounts[0].bytes = bincode::serialize(&UpgradeableLoaderState::Uninitialized).unwrap(), Error::Deployment),
        ("programdata link", |f| f.batch.accounts[0].bytes = bincode::serialize(&UpgradeableLoaderState::Program { programdata_address: key(50) }).unwrap(), Error::Deployment),
        ("programdata owner", |f| f.batch.accounts[1].owner = key(50), Error::Deployment),
        ("programdata executable", |f| f.batch.accounts[1].executable = true, Error::Deployment),
        ("short metadata", |f| f.batch.accounts[1].bytes.truncate(44), Error::Deployment),
        ("programdata loader tag", |f| f.batch.accounts[1].bytes[0] = 1, Error::Deployment),
        ("invalid authority option", |f| f.batch.accounts[1].bytes[12] = 2, Error::Deployment),
        ("wrong authority", |f| f.pins.upgrade_authority = Some(key(50)), Error::Deployment),
        ("wrong image hash", |f| f.pins.elf_sha256[0] ^= 1, Error::Deployment),
        ("wrong image length", |f| f.pins.elf_length += 1, Error::Deployment),
        ("image corruption", |f| *f.batch.accounts[1].bytes.last_mut().unwrap() ^= 1, Error::Deployment),
        ("zero image bound", |f| f.pins.elf_length = 0, Error::Deployment),
        ("oversized image bound", |f| f.pins.elf_length = 4 * 1024 * 1024 + 1, Error::Deployment),
        ("future deployment slot", |f| f.batch.accounts[1].bytes[4..12].copy_from_slice(&101u64.to_le_bytes()), Error::Deployment),
    ]);
}

#[test]
fn rejects_wrong_config_pda_owner_codec_and_identities() {
    rejects(&[
        ("config pin PDA", |f| f.pins.config = key(50), Error::Deployment),
        ("admin pin", |f| f.pins.admin = key(50), Error::Deployment),
        ("seed pin", |f| f.pins.seed[0] ^= 1, Error::Deployment),
        ("config owner", |f| f.batch.accounts[2].owner = key(50), Error::Account),
        ("config executable", |f| f.batch.accounts[2].executable = true, Error::Account),
        ("config short", |f| { f.batch.accounts[2].bytes.pop(); }, Error::Account),
        ("config trailing", |f| f.batch.accounts[2].bytes.push(0), Error::Account),
        ("config discriminator", |f| f.batch.accounts[2].bytes[0] ^= 1, Error::Account),
        ("config genesis", |f| config_mutate(f, |c| c.genesis[0] ^= 1), Error::Deployment),
        ("config admin", |f| config_mutate(f, |c| c.admin = key(50)), Error::Deployment),
        ("config seed", |f| config_mutate(f, |c| c.seed[0] ^= 1), Error::Deployment),
        ("circuit", |f| config_mutate(f, |c| c.circuit_id[0] ^= 1), Error::Account),
        ("package", |f| config_mutate(f, |c| c.package_id[0] ^= 1), Error::Account),
        ("schema", |f| config_mutate(f, |c| c.schema_id[0] ^= 1), Error::Account),
        ("profile", |f| config_mutate(f, |c| c.profile_id[0] ^= 1), Error::Account),
        ("VK", |f| config_mutate(f, |c| c.ordinary_vk_digest[0] ^= 1), Error::Account),
        ("noncanonical root", |f| config_mutate(f, |c| c.root = [255;32]), Error::Account),
    ]);
}

#[test]
fn rejects_wrong_batch_context_account_order_and_roles() {
    rejects(&[
        ("context below floor", |f| f.batch.context_slot = 89, Error::Finality),
        ("zero context", |f| { f.batch.context_slot = 0; f.pins.minimum_finalized_slot = 0; }, Error::Finality),
        ("missing account", |f| { f.batch.accounts.pop(); }, Error::Account),
        ("extra account", |f| f.batch.accounts.push(Account { key:key(50),owner:key(51),executable:false,bytes:vec![] }), Error::Account),
        ("wrong order", |f| f.batch.accounts.swap(0,1), Error::Account),
        ("wrong account key", |f| f.batch.accounts[2].key = key(50), Error::Account),
        ("clock owner", |f| f.batch.accounts[3].owner = key(50), Error::Clock),
        ("clock executable", |f| f.batch.accounts[3].executable = true, Error::Clock),
        ("clock truncated", |f| { f.batch.accounts[3].bytes.pop(); }, Error::Clock),
        ("clock trailing", |f| f.batch.accounts[3].bytes.push(0), Error::Clock),
        ("clock slot", |f| clock_mutate(f, |c| c.slot = 99), Error::Clock),
        ("clock future", |f| clock_mutate(f, |c| c.unix_timestamp = 1003), Error::Clock),
        ("clock negative", |f| clock_mutate(f, |c| c.unix_timestamp = -1), Error::Clock),
        ("clock stale", |f| clock_mutate(f, |c| c.unix_timestamp = 996), Error::Clock),
        ("unbounded clock age", |f| f.pins.maximum_clock_age_seconds = 301, Error::Clock),
        ("zero clock age", |f| f.pins.maximum_clock_age_seconds = 0, Error::Clock),
    ]);
    assert_eq!(run(fixture(), -1).0.err(), Some(Error::Clock));
    assert!(run(fixture(), 1005).0.is_ok(), "configured maximum age is inclusive");
    assert_eq!(run(fixture(), 1006).0.err(), Some(Error::Clock));
}

#[test]
fn immutable_authority_none_and_reserved_metadata_bytes() {
    let mut f = fixture(); f.pins.upgrade_authority = None;
    let metadata = bincode::serialize(&UpgradeableLoaderState::ProgramData { slot: 40, upgrade_authority_address: None }).unwrap();
    let n = UpgradeableLoaderState::size_of_programdata_metadata();
    let image = f.batch.accounts[1].bytes[n..].to_vec();
    f.batch.accounts[1].bytes = metadata;
    f.batch.accounts[1].bytes.resize(n, 0);
    f.batch.accounts[1].bytes.extend(image);
    // None consumes fewer than45 metadata bytes; prior authority bytes can
    // remain reserved. They are not ELF bytes or an authority when tag=None.
    f.batch.accounts[1].bytes[n-1] = 1;
    assert!(run(f,1002).0.is_ok());
}

#[test]
fn public_constructor_remains_closed_even_with_coherent_pins() {
    assert_eq!(ConfiguredVerifier::new(fixture().pins).err(), Some(Error::Unavailable));
}

// Next tests-first slice: chain-current state only, as of a finalized context.
// No detached signature, holder proof, path, action-execution or real RPC claim.
use zk_fresh_program::{application_runtime_v3 as runtime, application_v3::{
    Issuer, PublisherHead, Queue, RelevantMeta, Request, RequestState, QUEUE_CAPACITY,
}};

struct CurrentFixture { deployment: Fixture, selection: CurrentSelection }

fn current_fixture() -> CurrentFixture {
    let mut f = fixture();
    let c = Config::decode(&f.batch.accounts[2].bytes).unwrap();
    let selection = CurrentSelection { issuer_hash: field(21), creator: key(22), nonce: [23;32], publisher: c.publisher };
    let issuer_key = runtime::issuer_address(&f.pins.program, &f.pins.config, &selection.issuer_hash).0;
    let head_key = runtime::publisher_head_address(&f.pins.program, &f.pins.config, &issuer_key, &c.publisher).0;
    let request_key = runtime::request_address(&f.pins.program, &f.pins.config, &selection.creator, &selection.nonce).0;
    let queue_key = runtime::queue_address(&f.pins.program, &f.pins.config).0;
    let mut aki = [0;32]; aki[..20].fill(24);
    let issuer = Issuer {
        config: f.pins.config, issuer_hash: selection.issuer_hash,
        profile_id: c.profile_id, profile_version: 3, aki, source: key(25), enabled: true,
        sequence: 7, digest: [26;32], observed_at: 990, expires_at: 1100,
        bound_root: c.root, bound_root_version: c.root_version,
        bound_source_sequence: 7, bound_source_digest: [26;32],
        enrollment_version: 1, evidence_digest: [27;32],
        observed_config_epoch: c.eligibility_epoch, status_valid: true,
        eligibility_epoch: 3, observed_issuer_epoch: 3,
    };
    let head = PublisherHead {
        config: f.pins.config, issuer: issuer_key, publisher: c.publisher,
        publication_sequence: 2, envelope_digest: [28;32], previous_publication_digest: [29;32],
        root: c.root, root_version: c.root_version, source_sequence: issuer.sequence, source_digest: issuer.digest,
        config_epoch: c.eligibility_epoch, issuer_epoch: issuer.eligibility_epoch, committed_at: 995,
    };
    let request = Request {
        config: f.pins.config, creator: selection.creator, nonce: selection.nonce,
        issuer_hash: selection.issuer_hash, recipient: key(30), request_type: 1, deadline: 1200,
        payload_len: 3, uploaded: 3, metas_uploaded: 2, state: RequestState::Finalized,
        metas: vec![RelevantMeta { key: request_key, flags: 2, owner: f.pins.program },
            RelevantMeta { key: queue_key, flags: 2, owner: f.pins.program }], payload: vec![1,2,3],
    };
    let queue = Queue::new(f.pins.config);
    // Freeze valid owning-program codecs before the intended final RED. These
    // modeled facts are synthetic, not signatures or transaction-history proof.
    assert_eq!(Issuer::decode(&issuer.encode()).unwrap(), issuer);
    assert_eq!(PublisherHead::decode(&head.encode()).unwrap(), head);
    assert_eq!(Request::decode(&request.encode()).unwrap(), request);
    assert_eq!(Queue::decode(&queue.encode()).unwrap(), queue);
    assert_eq!(request.metas[0].key, request_key);
    assert_eq!(request.metas[1].key, queue_key);
    assert!(request.metas.iter().all(|m|m.flags==2 && m.owner==f.pins.program));
    for (key, bytes) in [(issuer_key, issuer.encode()), (head_key, head.encode()),
        (request_key, request.encode()), (queue_key, queue.encode())] {
        f.batch.accounts.push(Account { key, owner: f.pins.program, executable: false, bytes });
    }
    CurrentFixture { deployment: f, selection }
}

fn run_current(f: CurrentFixture, now: i64) -> (Result<AuthenticatedV3Current, Error>, Vec<&'static str>) {
    let p = &f.deployment.pins;
    let issuer = runtime::issuer_address(&p.program, &p.config, &f.selection.issuer_hash).0;
    let expected = FinalizedRequest { keys: vec![p.program,p.programdata,p.config,sysvar::clock::id(),
        issuer, runtime::publisher_head_address(&p.program,&p.config,&issuer,&f.selection.publisher).0,
        runtime::request_address(&p.program,&p.config,&f.selection.creator,&f.selection.nonce).0,
        runtime::queue_address(&p.program,&p.config).0],
        commitment: Commitment::Finalized, minimum_context_slot: p.minimum_finalized_slot };
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = ScriptedTransport { expected, response: Mutex::new(Some(f.deployment.batch)),
        genesis: f.deployment.genesis, calls: calls.clone() };
    let verifier = ConfiguredVerifier { pins: f.deployment.pins, transport: Box::new(transport) };
    let result = verifier.verify_current(&f.selection, now);
    let trace = calls.lock().unwrap().clone();
    (result,trace)
}

#[test]
fn finalized_chain_current_gate() {
    let (result,trace) = run_current(current_fixture(),1002);
    assert_eq!(trace,vec!["genesis","finalized_accounts"],"must refresh deployment and current state in ONE batch");
    assert_eq!(result.as_ref().map(|v|v.finalized_slot()),Ok(100),
        "intentional RED: chain-current capability mint remains Unavailable");
}

fn issuer_mutate(f: &mut CurrentFixture, mutate: fn(&mut Issuer)) {
    let a = &mut f.deployment.batch.accounts[4];
    let mut value = Issuer::decode(&a.bytes).unwrap(); mutate(&mut value); a.bytes=value.encode();
}
fn head_mutate(f: &mut CurrentFixture, mutate: fn(&mut PublisherHead)) {
    let a = &mut f.deployment.batch.accounts[5];
    let mut value = PublisherHead::decode(&a.bytes).unwrap(); mutate(&mut value); a.bytes=value.encode();
}
fn request_mutate(f: &mut CurrentFixture, mutate: fn(&mut Request)) {
    let a = &mut f.deployment.batch.accounts[6];
    let mut value = Request::decode(&a.bytes).unwrap(); mutate(&mut value); a.bytes=value.encode();
}
fn queue_mutate(f: &mut CurrentFixture, mutate: fn(&mut Queue)) {
    let a = &mut f.deployment.batch.accounts[7];
    let mut value = Queue::decode(&a.bytes).unwrap(); mutate(&mut value); a.bytes=value.encode();
}
type CurrentMutation = fn(&mut CurrentFixture);
fn current_rejects(cases: &[(&str,CurrentMutation)]) {
    for (name,mutate) in cases {
        let mut f = current_fixture(); mutate(&mut f);
        let error = run_current(f,1002).0.err();
        assert!(matches!(error,Some(Error::Deployment|Error::Finality|Error::Account|Error::Clock)),
            "{name}: must reject by actual validation, not the Unavailable stub: {error:?}");
    }
}

#[test]
fn current_rejects_issuer_source_lifecycle_and_expiry_mismatches() {
    current_rejects(&[
        ("disabled config",|f|config_mutate(&mut f.deployment,|c|c.enabled=false)),
        ("issuer config",|f|issuer_mutate(f,|i|i.config=key(50))),
        ("issuer hash",|f|issuer_mutate(f,|i|i.issuer_hash=field(50))),
        ("disabled issuer",|f|issuer_mutate(f,|i|i.enabled=false)),
        ("inactive source",|f|issuer_mutate(f,|i|i.status_valid=false)),
        ("zero source sequence",|f|issuer_mutate(f,|i|i.sequence=0)),
        ("zero source digest",|f|issuer_mutate(f,|i|i.digest=[0;32])),
        ("future observation",|f|issuer_mutate(f,|i|i.observed_at=1003)),
        ("expired source",|f|issuer_mutate(f,|i|i.expires_at=1001)),
        ("exact expiry",|f|issuer_mutate(f,|i|i.expires_at=1002)),
        ("observed config epoch",|f|issuer_mutate(f,|i|i.observed_config_epoch=1)),
        ("observed issuer epoch",|f|issuer_mutate(f,|i|i.observed_issuer_epoch=2)),
        ("head issuer epoch",|f|head_mutate(f,|h|h.issuer_epoch=2)),
        ("head config epoch",|f|head_mutate(f,|h|h.config_epoch=1)),
        ("bound source seq",|f|issuer_mutate(f,|i|i.bound_source_sequence=6)),
        ("bound source digest",|f|issuer_mutate(f,|i|i.bound_source_digest=[50;32])),
    ]);
}

#[test]
fn current_rejects_head_root_publisher_and_commitment_mismatches() {
    current_rejects(&[
        ("head config",|f|head_mutate(f,|h|h.config=key(50))),
        ("head issuer",|f|head_mutate(f,|h|h.issuer=key(50))),
        ("head publisher",|f|head_mutate(f,|h|h.publisher=key(50))),
        ("head root",|f|head_mutate(f,|h|h.root=field(50))),
        ("head root version",|f|head_mutate(f,|h|h.root_version=1)),
        ("bound root",|f|issuer_mutate(f,|i|i.bound_root=field(50))),
        ("bound root version",|f|issuer_mutate(f,|i|i.bound_root_version=1)),
        ("head source seq",|f|head_mutate(f,|h|h.source_sequence=6)),
        ("head source digest",|f|head_mutate(f,|h|h.source_digest=[50;32])),
        ("missing envelope digest",|f|head_mutate(f,|h|h.envelope_digest=[0;32])),
        ("replayed envelope",|f|head_mutate(f,|h|h.envelope_digest=h.previous_publication_digest)),
        ("invalid predecessor",|f|head_mutate(f,|h|h.previous_publication_digest=[0;32])),
        ("future commit",|f|head_mutate(f,|h|h.committed_at=1003)),
        ("commit before observation",|f|head_mutate(f,|h|h.committed_at=989)),
    ]);
}

#[test]
fn current_rejects_request_queue_and_nonreplay_failures() {
    current_rejects(&[
        ("request config",|f|request_mutate(f,|r|r.config=key(50))),
        ("request issuer",|f|request_mutate(f,|r|r.issuer_hash=field(50))),
        ("request creator",|f|request_mutate(f,|r|r.creator=key(50))),
        ("request nonce",|f|request_mutate(f,|r|r.nonce=[50;32])),
        ("request staging",|f|request_mutate(f,|r|r.state=RequestState::Staging)),
        ("request cancelled",|f|request_mutate(f,|r|r.state=RequestState::Cancelled)),
        ("request consumed",|f|request_mutate(f,|r|r.state=RequestState::Consumed)),
        ("request expired",|f|request_mutate(f,|r|r.deadline=1001)),
        ("request partial upload",|f|request_mutate(f,|r|r.uploaded=2)),
        ("request partial metas",|f|request_mutate(f,|r|r.metas_uploaded=1)),
        ("request first meta PDA",|f|request_mutate(f,|r|r.metas[0].key=key(50))),
        ("request second meta PDA",|f|request_mutate(f,|r|r.metas[1].key=key(50))),
        ("request metas order",|f|request_mutate(f,|r|r.metas.swap(0,1))),
        ("request first meta flags",|f|request_mutate(f,|r|r.metas[0].flags=0)),
        ("request second meta flags",|f|request_mutate(f,|r|r.metas[1].flags=3)),
        ("request first meta owner",|f|request_mutate(f,|r|r.metas[0].owner=key(50))),
        ("request second meta owner",|f|request_mutate(f,|r|r.metas[1].owner=key(50))),
        ("queue config",|f|queue_mutate(f,|q|q.config=key(50))),
        ("queue replay",|f|{let request=f.deployment.batch.accounts[6].key; let a=&mut f.deployment.batch.accounts[7];let mut q=Queue::decode(&a.bytes).unwrap();q.entries.push(request);a.bytes=q.encode();}),
        ("queue capacity",|f|queue_mutate(f,|q|q.entries=(100..100+QUEUE_CAPACITY).map(|n|key(n as u8)).collect())),
    ]);
}

#[test]
fn current_rejects_account_order_deployment_and_finality_failures() {
    current_rejects(&[
        ("wrong genesis",|f|f.deployment.genesis=[50;32]),
        ("changed ELF",|f|*f.deployment.batch.accounts[1].bytes.last_mut().unwrap()^=1),
        ("context below floor",|f|f.deployment.batch.context_slot=89),
        ("clock context mismatch",|f|clock_mutate(&mut f.deployment,|c|c.slot=99)),
        ("clock stale",|f|clock_mutate(&mut f.deployment,|c|c.unix_timestamp=996)),
        ("issuer wrong owner",|f|f.deployment.batch.accounts[4].owner=key(50)),
        ("head wrong owner",|f|f.deployment.batch.accounts[5].owner=key(50)),
        ("request wrong owner",|f|f.deployment.batch.accounts[6].owner=key(50)),
        ("queue wrong owner",|f|f.deployment.batch.accounts[7].owner=key(50)),
        ("issuer executable",|f|f.deployment.batch.accounts[4].executable=true),
        ("missing head",|f|{f.deployment.batch.accounts.remove(5);}),
        ("wrong order",|f|f.deployment.batch.accounts.swap(4,5)),
        ("wrong issuer PDA",|f|f.deployment.batch.accounts[4].key=key(50)),
        ("wrong head PDA",|f|f.deployment.batch.accounts[5].key=key(50)),
        ("wrong request PDA",|f|f.deployment.batch.accounts[6].key=key(50)),
        ("wrong queue PDA",|f|f.deployment.batch.accounts[7].key=key(50)),
        ("head trailing bytes",|f|f.deployment.batch.accounts[5].bytes.push(0)),
        ("request truncated",|f|{f.deployment.batch.accounts[6].bytes.pop();}),
    ]);
}

#[test]
fn current_source_expiry_minus_one_accepts_and_old_batch_cannot_be_reused() {
    let mut f=current_fixture(); issuer_mutate(&mut f,|i|i.expires_at=1003);
    assert_eq!(run_current(f,1002).0.as_ref().map(|v|v.finalized_slot()),Ok(100));
    // A second call must perform a fresh read. The one-shot private transport
    // has no second response and must fail, rather than reuse a cached batch.
    let f=current_fixture(); let p=&f.deployment.pins;
    let expected=FinalizedRequest {keys:f.deployment.batch.accounts.iter().map(|a|a.key).collect(),
        commitment:Commitment::Finalized,minimum_context_slot:p.minimum_finalized_slot};
    let calls=Arc::new(Mutex::new(Vec::new()));
    let verifier=ConfiguredVerifier {pins:f.deployment.pins,transport:Box::new(ScriptedTransport {
        expected,response:Mutex::new(Some(f.deployment.batch)),genesis:f.deployment.genesis,calls,
    })};
    assert!(verifier.verify_current(&f.selection,1002).is_ok());
    assert_eq!(verifier.verify_current(&f.selection,1002).err(),Some(Error::Transport));
}
