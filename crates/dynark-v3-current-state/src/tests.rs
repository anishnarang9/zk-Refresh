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

#[test]
fn finalized_deployment_pda_gate() {
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
    let expected = FinalizedRequest {
        keys: vec![program, programdata, config_key, sysvar::clock::id()],
        commitment: Commitment::Finalized, minimum_context_slot: 90,
    };
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = ScriptedTransport {
        expected,
        response: Mutex::new(Some(FinalizedBatch {
            context_slot: 100,
            accounts: vec![
                Account { key: program, owner: bpf_loader_upgradeable::id(), executable: true, bytes: program_bytes },
                Account { key: programdata, owner: bpf_loader_upgradeable::id(), executable: false, bytes: programdata_bytes },
                Account { key: config_key, owner: program, executable: false, bytes: config_bytes },
                Account { key: sysvar::clock::id(), owner: sysvar::id(), executable: false, bytes: bincode::serialize(&clock).unwrap() },
            ],
        })),
        genesis: config.genesis, calls: calls.clone(),
    };
    // Only this private module can inject a scripted transport. Production has
    // no public transport trait or constructor accepting account JSON.
    let verifier = ConfiguredVerifier { pins, transport: Box::new(transport) };
    let result = verifier.verify_deployment(1002);
    assert_eq!(*calls.lock().unwrap(), vec!["genesis", "finalized_accounts"]);
    assert_eq!(result.as_ref().map(|v| v.finalized_slot()), Ok(100),
        "intentional RED: deployment/finality/PDA verification is unavailable");
}
