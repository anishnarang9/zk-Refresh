//! Development request-fixture boundary. Export grants no authorization;
//! proof generation, CLI transport and live accounts are absent.
use solana_program::pubkey::Pubkey;
use zk_fresh_program::{
    application_runtime_v3 as addresses,
    application_v3::{
        action_hash, action_preimage, AppError, Config, Request, RequestState, CONFIG_LEN,
        REQUEST_LEN,
    },
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

/// Decode one exact V3F1 development fixture and export its checked V3F2 identities.
/// Public fields and the action hash retain their canonical big-endian encoding;
/// the transport timestamp and lengths use little endian.
pub fn export_fixture_from_wire(input: &[u8]) -> Result<Vec<u8>, AppError> {
    fn take<const N: usize>(remaining: &mut &[u8]) -> Result<[u8; N], AppError> {
        let bytes = remaining.get(..N).ok_or(AppError::Bounds)?;
        let value = bytes.try_into().map_err(|_| AppError::Bounds)?;
        *remaining = remaining.get(N..).ok_or(AppError::Bounds)?;
        Ok(value)
    }

    const INPUT_LEN: usize = 4 + 32 + 8 + 4 + 4 + 6 * 32 + CONFIG_LEN + REQUEST_LEN;
    if input.len() != INPUT_LEN {
        return Err(AppError::Bounds);
    }
    let mut remaining = input;
    if take::<4>(&mut remaining)? != *b"V3F1" {
        return Err(AppError::Version);
    }
    let program_id = Pubkey::new_from_array(take::<32>(&mut remaining)?);
    let now = i64::from_le_bytes(take::<8>(&mut remaining)?);
    let config_len = u32::from_le_bytes(take::<4>(&mut remaining)?);
    let request_len = u32::from_le_bytes(take::<4>(&mut remaining)?);
    if config_len != CONFIG_LEN as u32 || request_len != REQUEST_LEN as u32 {
        return Err(AppError::Bounds);
    }
    let mut public_inputs = [[0; 32]; 6];
    for field in &mut public_inputs {
        *field = take::<32>(&mut remaining)?;
    }
    let config_bytes = take::<CONFIG_LEN>(&mut remaining)?;
    let request_bytes = take::<REQUEST_LEN>(&mut remaining)?;
    if !remaining.is_empty() {
        return Err(AppError::Bounds);
    }
    let config = Config::decode(&config_bytes)?;
    let request = Request::decode(&request_bytes)?;
    if config.encode().as_slice() != config_bytes.as_slice()
        || request.encode().as_slice() != request_bytes.as_slice()
    {
        return Err(AppError::State);
    }
    let fixture = export_fixture(&program_id, &config, &request, &public_inputs, now)?;
    let preimage_len = u32::try_from(fixture.action_preimage.len())
        .map_err(|_| AppError::Bounds)?;
    let output_len = 200usize.checked_add(fixture.action_preimage.len())
        .ok_or(AppError::Bounds)?;
    let mut output = Vec::with_capacity(output_len);
    output.extend_from_slice(b"V3F2");
    for pda in [
        fixture.config_pda,
        fixture.issuer_pda,
        fixture.request_pda,
        fixture.queue_pda,
        fixture.publisher_head_pda,
    ] {
        output.extend_from_slice(pda.as_ref());
    }
    output.extend_from_slice(&fixture.action_hash);
    output.extend_from_slice(&preimage_len.to_le_bytes());
    output.extend_from_slice(&fixture.action_preimage);
    Ok(output)
}

#[allow(dead_code)] // This file is also imported as an integration-test module.
fn main() {
    eprintln!("development v3 request fixture export is unavailable");
    std::process::exit(1);
}
