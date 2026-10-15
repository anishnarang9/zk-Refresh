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
