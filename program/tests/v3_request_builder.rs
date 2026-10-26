#[path = "../examples/export_v3_request_fixture.rs"]
mod exporter;

use solana_program::pubkey::Pubkey;
use zk_fresh_program::{
    application_runtime_v3 as addresses,
    application_v3::{
        action_hash, action_preimage, Config, RelevantMeta, Request, RequestState, CONFIG_LEN,
        MAX_CHUNK, MAX_META_CHUNK, REQUEST_LEN,
    },
    generated_vk_v3 as identity,
};

fn field(value: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    bytes
}

#[test]
fn builds_public_request_plan_through_staging_and_exports_exact_wire() {
    let now = 1_792_108_800i64;
    let plan = exporter::RequestPlan {
        program_id: Pubkey::new_from_array([63; 32]),
        config: Config {
            admin: Pubkey::new_from_array([64; 32]),
            seed: [65; 32],
            publisher: Pubkey::new_from_array([66; 32]),
            genesis: [67; 32],
            policy_id: field(103),
            policy_version: 7,
            circuit_id: identity::CIRCUIT_ID,
            package_id: identity::PACKAGE_ID,
            schema_id: identity::SEMANTIC_SCHEMA_ID,
            profile_id: identity::PROFILE_ID,
            ordinary_vk_digest: identity::ORDINARY_VK_DIGEST,
            root: field(107),
            root_version: 11,
            eligibility_epoch: 3,
            enabled: true,
        },
        issuer_hash: field(109),
        credential_not_before: field((now - 3600) as u64),
        credential_not_after: field((now + 86400) as u64),
        creator: Pubkey::new_from_array([68; 32]),
        nonce: [69; 32],
        recipient: Pubkey::new_from_array([70; 32]),
        request_type: 1,
        deadline: now + 240,
        payload: (0..777).map(|index| (index % 251) as u8).collect(),
        now,
    };
    let config_pda = addresses::config_address(
        &plan.program_id, &plan.config.admin, &plan.config.seed,
    ).0;
    let request_pda = addresses::request_address(
        &plan.program_id, &config_pda, &plan.creator, &plan.nonce,
    ).0;
    let queue_pda = addresses::queue_address(&plan.program_id, &config_pda).0;
    let issuer_pda = addresses::issuer_address(
        &plan.program_id, &config_pda, &plan.issuer_hash,
    ).0;
    let publisher_head_pda = addresses::publisher_head_address(
        &plan.program_id, &config_pda, &issuer_pda, &plan.config.publisher,
    ).0;
    let metas: Vec<_> = [request_pda, queue_pda].into_iter()
        .map(|key| RelevantMeta { key, flags: 2, owner: plan.program_id }).collect();
    let mut expected = Request {
        config: config_pda,
        creator: plan.creator,
        nonce: plan.nonce,
        issuer_hash: plan.issuer_hash,
        recipient: plan.recipient,
        request_type: plan.request_type,
        deadline: plan.deadline,
        payload_len: plan.payload.len() as u16,
        uploaded: 0,
        metas_uploaded: 0,
        state: RequestState::Staging,
        metas: vec![RelevantMeta { key: Pubkey::default(), flags: 0, owner: Pubkey::default() }; 2],
        payload: vec![0; plan.payload.len()],
    };
    assert!(plan.payload.len() > MAX_CHUNK);
    for chunk in plan.payload.chunks(MAX_CHUNK) {
        expected.upload(expected.uploaded, chunk, now).unwrap();
    }
    for chunk in metas.chunks(MAX_META_CHUNK) {
        expected.upload_metas(expected.metas_uploaded, chunk, now).unwrap();
    }
    expected.finalize(now).unwrap();
    let action = action_hash(&plan.program_id, &plan.config, &expected).unwrap();
    let publics: [[u8; 32]; 6] = [plan.config.root, plan.issuer_hash, plan.credential_not_before,
        plan.credential_not_after, action, plan.config.policy_id];

    let (built, wire): (exporter::RequestFixture, Vec<u8>) =
        exporter::build_request_fixture(&plan).expect("valid public request plan must build");
    assert_eq!(built.program_id, plan.program_id);
    assert_eq!(built.now, now);
    assert_eq!(Config::decode(&built.config_bytes).unwrap(), plan.config);
    assert_eq!(Request::decode(&built.request_bytes).unwrap(), expected);
    assert_eq!(built.public_inputs, publics);
    assert_eq!(built.action_hash, action);
    let preimage = action_preimage(&plan.program_id, &plan.config, &expected).unwrap();
    assert_eq!(built.action_preimage, preimage);
    let pdas = [config_pda, issuer_pda, request_pda, queue_pda, publisher_head_pda];
    assert_eq!([built.config_pda, built.issuer_pda, built.request_pda,
        built.queue_pda, built.publisher_head_pda], pdas);

    let mut expected_wire = b"V3F1".to_vec();
    expected_wire.extend_from_slice(plan.program_id.as_ref());
    expected_wire.extend_from_slice(&now.to_le_bytes());
    expected_wire.extend_from_slice(&(CONFIG_LEN as u32).to_le_bytes());
    expected_wire.extend_from_slice(&(REQUEST_LEN as u32).to_le_bytes());
    for public in &publics { expected_wire.extend_from_slice(public); }
    expected_wire.extend_from_slice(&plan.config.encode());
    expected_wire.extend_from_slice(&expected.encode());
    assert_eq!(wire.len(), 2874);
    assert_eq!(wire, expected_wire);
    let mut expected_export = b"V3F2".to_vec();
    for pda in pdas { expected_export.extend_from_slice(pda.as_ref()); }
    expected_export.extend_from_slice(&action);
    expected_export.extend_from_slice(&(preimage.len() as u32).to_le_bytes());
    expected_export.extend_from_slice(&preimage);
    assert_eq!(exporter::export_fixture_from_wire(&wire).unwrap(), expected_export);
}
