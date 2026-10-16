//! Development request-fixture boundary. This scaffold emits nothing and grants
//! no authorization; proof generation, CLI transport and live accounts are absent.
use solana_program::pubkey::Pubkey;
use zk_fresh_program::application_v3::{AppError, Config, Request};

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

/// Intended to export only a canonical, finalized, unexpired request whose
/// immutable metas and six canonical BE publics match its derived identities.
/// Unavailable until validation and export are implemented and reviewed.
pub fn export_fixture(
    _program_id: &Pubkey,
    _config: &Config,
    _request: &Request,
    _public_inputs: &[[u8; 32]; 6],
    _now: i64,
) -> Result<RequestFixture, AppError> {
    Err(AppError::Unavailable)
}

#[allow(dead_code)] // This file is also imported as an integration-test module.
fn main() {
    eprintln!("development v3 request fixture export is unavailable");
    std::process::exit(1);
}
