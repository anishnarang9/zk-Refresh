#[path = "../examples/export_v3_request_fixture.rs"]
mod exporter;

use solana_program::pubkey::Pubkey;
use zk_fresh_program::{
    application_runtime_v3 as addresses,
    application_v3::{action_hash, action_preimage, Config, RelevantMeta, Request, RequestState},
    generated_vk_v3 as identity,
};

fn field(value: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    bytes
}

#[test]
fn exports_canonical_request_fixture_with_exact_action_and_pdas() {
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
