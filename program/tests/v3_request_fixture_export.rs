#[path = "../examples/export_v3_request_fixture.rs"]
mod exporter;

use solana_program::pubkey::Pubkey;
use zk_fresh_program::{
    application_runtime_v3 as addresses,
    application_v3::{action_hash, action_preimage, Config, RelevantMeta, Request, RequestState, CONFIG_LEN, REQUEST_LEN},
    generated_vk_v3 as identity,
};

fn field(value: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    bytes
}

fn canonical_fixture() -> (Pubkey, Config, Request, [[u8; 32]; 6], i64) {
    // 2026-10-15 00:00:00 UTC: use the certificate era, not toy epoch times.
    let now = 1_792_022_400;
    let program = Pubkey::new_from_array([42; 32]);
    let config = Config {
        admin: Pubkey::new_from_array([18; 32]),
        seed: [7; 32],
        publisher: Pubkey::new_from_array([19; 32]),
        genesis: [1; 32],
        policy_id: field(2),
        policy_version: 1,
        circuit_id: identity::CIRCUIT_ID,
        package_id: identity::PACKAGE_ID,
        schema_id: identity::SEMANTIC_SCHEMA_ID,
        profile_id: identity::PROFILE_ID,
        ordinary_vk_digest: identity::ORDINARY_VK_DIGEST,
        root: field(6),
        root_version: 0,
        eligibility_epoch: 0,
        enabled: true,
    };
    let config_pda = addresses::config_address(&program, &config.admin, &config.seed).0;
    let creator = Pubkey::new_from_array([20; 32]);
    let nonce = [11; 32];
    let request_pda = addresses::request_address(&program, &config_pda, &creator, &nonce).0;
    let queue_pda = addresses::queue_address(&program, &config_pda).0;
    let request = Request {
        config: config_pda,
        creator,
        nonce,
        issuer_hash: field(8),
        recipient: Pubkey::new_from_array([14; 32]),
        request_type: 1,
        deadline: now + 120,
        payload_len: 3,
        uploaded: 3,
        metas_uploaded: 2,
        state: RequestState::Finalized,
        metas: [request_pda, queue_pda]
            .into_iter()
            .map(|key| RelevantMeta { key, flags: 2, owner: program })
            .collect(),
        payload: b"abc".to_vec(),
    };
    // Establish valid source objects before reaching the intentionally missing exporter.
    assert_eq!(Config::decode(&config.encode()).unwrap(), config);
    assert_eq!(Request::decode(&request.encode()).unwrap(), request);
    let expected_action = action_hash(&program, &config, &request).unwrap();
    let publics = [
        config.root,
        request.issuer_hash,
        field((now - 60) as u64),
        field((now + 300) as u64),
        expected_action,
        config.policy_id,
    ];

    (program, config, request, publics, now)
}

#[test]
fn exports_canonical_request_fixture_with_exact_action_and_pdas() {
    let (program, config, request, publics, now) = canonical_fixture();
    let config_pda = addresses::config_address(&program, &config.admin, &config.seed).0;
    let request_pda = addresses::request_address(
        &program, &config_pda, &request.creator, &request.nonce,
    ).0;
    let queue_pda = addresses::queue_address(&program, &config_pda).0;
    let expected_action = publics[4];

    let exported = exporter::export_fixture(&program, &config, &request, &publics, now)
        .expect("valid request fixture must export; scaffold currently returns Unavailable");
    assert_eq!(exported.program_id, program);
    assert_eq!(exported.public_inputs, publics);
    assert_eq!(exported.now, now);
    assert_eq!(exported.config_bytes, config.encode());
    assert_eq!(exported.request_bytes, request.encode());
    let decoded_config = Config::decode(&exported.config_bytes).unwrap();
    let decoded_request = Request::decode(&exported.request_bytes).unwrap();
    assert_eq!(decoded_config, config);
    assert_eq!(decoded_request, request);
    assert_eq!(decoded_request.metas, request.metas);
    assert_eq!(exported.config_pda, config_pda);
    assert_eq!(exported.request_pda, request_pda);
    assert_eq!(exported.queue_pda, queue_pda);
    let issuer_pda = addresses::issuer_address(&program, &config_pda, &request.issuer_hash).0;
    assert_eq!(exported.issuer_pda, issuer_pda);
    assert_eq!(exported.publisher_head_pda,
        addresses::publisher_head_address(&program, &config_pda, &issuer_pda, &config.publisher).0);
    assert_eq!(exported.action_hash, expected_action);
    assert_eq!(action_hash(&program, &decoded_config, &decoded_request).unwrap(), publics[4]);
    assert_eq!(exported.action_preimage,
        action_preimage(&program, &decoded_config, &decoded_request).unwrap());
}

#[test]
fn exports_exact_request_fixture_wire_identities_and_byte_order() {
    let (program, config, request, publics, now) = canonical_fixture();
    let config_bytes = config.encode();
    let request_bytes = request.encode();
    assert_eq!(config_bytes.len(), CONFIG_LEN);
    assert_eq!(request_bytes.len(), REQUEST_LEN);

    let mut input = b"V3F1".to_vec();
    input.extend_from_slice(program.as_ref());
    input.extend_from_slice(&now.to_le_bytes());
    input.extend_from_slice(&(CONFIG_LEN as u32).to_le_bytes());
    input.extend_from_slice(&(REQUEST_LEN as u32).to_le_bytes());
    for public in &publics {
        input.extend_from_slice(public);
    }
    input.extend_from_slice(&config_bytes);
    input.extend_from_slice(&request_bytes);
    assert_eq!(input.len(), 4 + 32 + 8 + 4 + 4 + 6 * 32 + CONFIG_LEN + REQUEST_LEN);

    let output = exporter::export_fixture_from_wire(&input)
        .expect("canonical V3F1 fixture must export to V3F2");
    let config_pda = addresses::config_address(&program, &config.admin, &config.seed).0;
    let issuer_pda = addresses::issuer_address(&program, &config_pda, &request.issuer_hash).0;
    let request_pda = addresses::request_address(
        &program, &config_pda, &request.creator, &request.nonce,
    ).0;
    let queue_pda = addresses::queue_address(&program, &config_pda).0;
    let publisher_head_pda = addresses::publisher_head_address(
        &program, &config_pda, &issuer_pda, &config.publisher,
    ).0;
    let preimage = action_preimage(&program, &config, &request).unwrap();

    assert_eq!(&output[..4], b"V3F2");
    for (index, pda) in [config_pda, issuer_pda, request_pda, queue_pda, publisher_head_pda]
        .iter().enumerate()
    {
        let offset = 4 + index * 32;
        assert_eq!(&output[offset..offset + 32], pda.as_ref());
    }
    assert_eq!(&output[164..196], &publics[4]);
    let preimage_len = u32::from_le_bytes(output[196..200].try_into().unwrap()) as usize;
    assert_eq!(preimage_len, preimage.len());
    assert_eq!(&output[200..], preimage.as_slice());
    assert_eq!(output.len(), 200 + preimage_len);
}
