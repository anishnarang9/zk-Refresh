//! Development request-fixture boundary with checked local CLI transport.
//! Export grants no authorization; proof generation and live account
//! authentication are absent.
use solana_program::pubkey::Pubkey;
use zk_fresh_program::{
    application_runtime_v3 as addresses,
    application_v3::{
        action_hash, action_preimage, AppError, Config, RelevantMeta, Request, RequestState,
        CONFIG_LEN, MAX_CHUNK, MAX_META_CHUNK, MAX_PAYLOAD, REQUEST_LEN,
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

/// Public request data for a local development fixture. No credential secrets,
/// signing keys, proof, or authenticated live account state are supplied here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPlan {
    pub program_id: Pubkey,
    pub config: Config,
    pub issuer_hash: [u8; 32],
    pub credential_not_before: [u8; 32],
    pub credential_not_after: [u8; 32],
    pub creator: Pubkey,
    pub nonce: [u8; 32],
    pub recipient: Pubkey,
    pub request_type: u16,
    pub deadline: i64,
    pub payload: Vec<u8>,
    pub now: i64,
}

/// Stage and finalize a request with the ordered writable request/queue metas,
/// validate its six public inputs, and serialize its exact V3F1 transport.
/// A successful build grants no authorization and establishes no proof validity.
pub fn build_request_fixture(plan: &RequestPlan) -> Result<(RequestFixture, Vec<u8>), AppError> {
    // Decode validates canonical config fields and all current generated VK
    // identity pins before any request allocation or action construction.
    if Config::decode(&plan.config.encode())? != plan.config {
        return Err(AppError::State);
    }
    if plan.payload.len() > MAX_PAYLOAD {
        return Err(AppError::Bounds);
    }
    let payload_len = u16::try_from(plan.payload.len()).map_err(|_| AppError::Bounds)?;
    let config_pda = addresses::config_address(
        &plan.program_id, &plan.config.admin, &plan.config.seed,
    ).0;
    let request_pda = addresses::request_address(
        &plan.program_id, &config_pda, &plan.creator, &plan.nonce,
    ).0;
    let queue_pda = addresses::queue_address(&plan.program_id, &config_pda).0;
    let metas = [request_pda, queue_pda].map(|key| RelevantMeta {
        key,
        flags: 2,
        owner: plan.program_id,
    });
    let mut request = Request {
        config: config_pda,
        creator: plan.creator,
        nonce: plan.nonce,
        issuer_hash: plan.issuer_hash,
        recipient: plan.recipient,
        request_type: plan.request_type,
        deadline: plan.deadline,
        payload_len,
        uploaded: 0,
        metas_uploaded: 0,
        state: RequestState::Staging,
        metas: vec![RelevantMeta {
            key: Pubkey::default(), flags: 0, owner: Pubkey::default(),
        }; metas.len()],
        payload: vec![0; plan.payload.len()],
    };
    for chunk in plan.payload.chunks(MAX_CHUNK) {
        request.upload(request.uploaded, chunk, plan.now)?;
    }
    for chunk in metas.chunks(MAX_META_CHUNK) {
        request.upload_metas(request.metas_uploaded, chunk, plan.now)?;
    }
    request.finalize(plan.now)?;
    let public_inputs = [
        plan.config.root,
        plan.issuer_hash,
        plan.credential_not_before,
        plan.credential_not_after,
        action_hash(&plan.program_id, &plan.config, &request)?,
        plan.config.policy_id,
    ];
    let fixture = export_fixture(
        &plan.program_id, &plan.config, &request, &public_inputs, plan.now,
    )?;
    let mut wire = Vec::with_capacity(
        4 + 32 + 8 + 4 + 4 + 6 * 32 + CONFIG_LEN + REQUEST_LEN,
    );
    wire.extend_from_slice(b"V3F1");
    wire.extend_from_slice(plan.program_id.as_ref());
    wire.extend_from_slice(&plan.now.to_le_bytes());
    wire.extend_from_slice(&(CONFIG_LEN as u32).to_le_bytes());
    wire.extend_from_slice(&(REQUEST_LEN as u32).to_le_bytes());
    for public in &fixture.public_inputs {
        wire.extend_from_slice(public);
    }
    wire.extend_from_slice(&fixture.config_bytes);
    wire.extend_from_slice(&fixture.request_bytes);
    Ok((fixture, wire))
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

/// Read one exact fixed-size V3F1 fixture before writing its checked V3F2 export.
/// Truncated or trailing input returns Bounds without writing; other transport
/// failures return Unavailable. A destination failure may leave partial output.
pub fn export_fixture_stream<R: std::io::Read, W: std::io::Write>(
    source: &mut R,
    destination: &mut W,
) -> Result<(), AppError> {
    const INPUT_LEN: usize = 4 + 32 + 8 + 4 + 4 + 6 * 32 + CONFIG_LEN + REQUEST_LEN;
    let mut input = [0; INPUT_LEN];
    source.read_exact(&mut input).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            AppError::Bounds
        } else {
            AppError::Unavailable
        }
    })?;
    let mut trailing = [0; 1];
    match source.read_exact(&mut trailing) {
        Ok(()) => return Err(AppError::Bounds),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(_) => return Err(AppError::Unavailable),
    }
    let output = export_fixture_from_wire(&input)?;
    destination.write_all(&output).map_err(|_| AppError::Unavailable)
}

#[allow(dead_code)] // This file is also imported as an integration-test module.
fn main() {
    let mut source = std::io::stdin().lock();
    let mut destination = std::io::stdout().lock();
    let result = export_fixture_stream(&mut source, &mut destination).and_then(|()| {
        std::io::Write::flush(&mut destination).map_err(|_| AppError::Unavailable)
    });
    if let Err(error) = result {
        eprintln!("development v3 request fixture export failed: {error:?}");
        std::process::exit(1);
    }
}
