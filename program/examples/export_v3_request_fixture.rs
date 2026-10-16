//! Development request-fixture boundary. Export grants no authorization;
//! proof generation, CLI transport and live accounts are absent.
use solana_program::pubkey::Pubkey;
use zk_fresh_program::{
    application_runtime_v3 as addresses,
    application_v3::{action_hash, action_preimage, AppError, Config, Request, RequestState},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestFixture {
    pub program_id: Pubkey,
    pub config_bytes: Vec<u8>,
    pub request_bytes: Vec<u8>,
    pub public_inputs: [[u8; 32]; 6],
    pub now: i64,
    pub config_pda: Pubkey,
    pub issuer_pda: Pubkey,
    pub request_pda: Pubkey,
    pub queue_pda: Pubkey,
    pub publisher_head_pda: Pubkey,
    pub action_hash: [u8; 32],
    pub action_preimage: Vec<u8>,
}

/// Export only a canonical, finalized, unexpired request whose
/// immutable metas and six canonical BE publics match its derived identities.
/// These local checks establish no live issuer status or proof validity.
pub fn export_fixture(
    program_id: &Pubkey,
    config: &Config,
    request: &Request,
    public_inputs: &[[u8; 32]; 6],
    now: i64,
) -> Result<RequestFixture, AppError> {
    let config_bytes = config.encode();
    let request_bytes = request.encode();
    if Config::decode(&config_bytes)? != *config
        || Request::decode(&request_bytes)? != *request
    {
        return Err(AppError::State);
    }
    if !config.enabled {
        return Err(AppError::Policy);
    }
    if request.state != RequestState::Finalized {
        return Err(AppError::Consumed);
    }
    if now < 0 || now > request.deadline {
        return Err(AppError::Expired);
    }
    let config_pda = addresses::config_address(program_id, &config.admin, &config.seed).0;
    let issuer_pda = addresses::issuer_address(program_id, &config_pda, &request.issuer_hash).0;
    let request_pda = addresses::request_address(
        program_id, &config_pda, &request.creator, &request.nonce,
    ).0;
    let queue_pda = addresses::queue_address(program_id, &config_pda).0;
    let publisher_head_pda = addresses::publisher_head_address(
        program_id, &config_pda, &issuer_pda, &config.publisher,
    ).0;
    if request.config != config_pda
        || request.metas[0].key != request_pda
        || request.metas[1].key != queue_pda
        || request.metas[..2].iter().any(|meta| meta.flags != 2 || meta.owner != *program_id)
        || request.metas.iter().any(|meta| {
            [config_pda, issuer_pda, publisher_head_pda].contains(&meta.key)
        })
    {
        return Err(AppError::Accounts);
    }
    for input in public_inputs {
        zk_fresh_program::canonical(input).map_err(|_| AppError::Proof)?;
    }
    if public_inputs[0] != config.root
        || public_inputs[1] != request.issuer_hash
        || public_inputs[5] != config.policy_id
    {
        return Err(AppError::Policy);
    }
    zk_fresh_program::validate_times(&public_inputs[2], &public_inputs[3], now)
        .map_err(|_| AppError::Expired)?;
    let action_hash = action_hash(program_id, config, request)?;
    if public_inputs[4] != action_hash {
        return Err(AppError::Action);
    }
    Ok(RequestFixture {
        program_id: *program_id,
        config_bytes,
        request_bytes,
        public_inputs: *public_inputs,
        now,
        config_pda,
        issuer_pda,
        request_pda,
        queue_pda,
        publisher_head_pda,
        action_hash,
        action_preimage: action_preimage(program_id, config, request)?,
    })
}

#[allow(dead_code)] // This file is also imported as an integration-test module.
fn main() {
    eprintln!("development v3 request fixture export is unavailable");
    std::process::exit(1);
}
