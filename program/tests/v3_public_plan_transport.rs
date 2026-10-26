#[path = "../examples/export_v3_request_fixture.rs"]
mod exporter;

use solana_program::pubkey::Pubkey;
use zk_fresh_program::{
    application_v3::{Config, MAX_PAYLOAD},
    generated_vk_v3 as identity,
};

fn field(value: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    bytes
}

fn valid_plan() -> exporter::RequestPlan {
    let now = 1_792_108_800i64;
    exporter::RequestPlan {
        program_id: Pubkey::new_from_array([131; 32]),
        config: Config {
            admin: Pubkey::new_from_array([132; 32]),
            seed: [133; 32],
            publisher: Pubkey::new_from_array([134; 32]),
            genesis: [135; 32],
            policy_id: field(223),
            policy_version: 7,
            circuit_id: identity::CIRCUIT_ID,
            package_id: identity::PACKAGE_ID,
            schema_id: identity::SEMANTIC_SCHEMA_ID,
            profile_id: identity::PROFILE_ID,
            ordinary_vk_digest: identity::ORDINARY_VK_DIGEST,
            root: field(227),
            root_version: 11,
            eligibility_epoch: 3,
            enabled: true,
        },
        issuer_hash: field(229),
        credential_not_before: field((now - 3600) as u64),
        credential_not_after: field((now + 86400) as u64),
        creator: Pubkey::new_from_array([136; 32]),
        nonce: [137; 32],
        recipient: Pubkey::new_from_array([138; 32]),
        request_type: 1,
        deadline: now + 240,
        payload: (0..777).map(|index| (index % 251) as u8).collect(),
        now,
    }
}


fn wire(plan: &exporter::RequestPlan) -> Vec<u8> {
    let mut bytes = b"V3P1".to_vec();
    bytes.extend_from_slice(plan.program_id.as_ref());
    bytes.extend_from_slice(&plan.now.to_le_bytes());
    bytes.extend_from_slice(&(plan.config.encode().len() as u32).to_le_bytes());
    bytes.extend_from_slice(&plan.config.encode());
    for value in [plan.issuer_hash, plan.credential_not_before, plan.credential_not_after] {
        bytes.extend_from_slice(&value);
    }
    for value in [plan.creator.as_ref(), &plan.nonce, plan.recipient.as_ref()] {
        bytes.extend_from_slice(value);
    }
    bytes.extend_from_slice(&plan.request_type.to_le_bytes());
    bytes.extend_from_slice(&plan.deadline.to_le_bytes());
    bytes.extend_from_slice(&(plan.payload.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&plan.payload);
    assert_eq!(bytes.len(), 633 + plan.payload.len());
    bytes
}

fn transport(bytes: &[u8]) -> Result<Vec<u8>, zk_fresh_program::application_v3::AppError> {
    let mut output = Vec::new();
    let result = exporter::build_request_fixture_stream(&mut std::io::Cursor::new(bytes), &mut output);
    if result.is_err() { assert!(output.is_empty()); }
    result.map(|()| output)
}

#[test]
fn accepts_public_values_as_data_and_exports_ordered_request_queue_action() {
    for variation in 0..2 {
        let mut plan = valid_plan();
        plan.config.root = field(987 + variation);
        plan.issuer_hash = field(765 + variation);
        plan.config.policy_id = field(543 + variation);
        plan.credential_not_before = field((plan.now - 300 - variation as i64) as u64);
        plan.credential_not_after = field((plan.now + 900 + variation as i64) as u64);
        let output = transport(&wire(&plan)).unwrap();
        let (fixture, expected) = exporter::build_request_fixture(&plan).unwrap();
        assert_eq!(output.len(), 2874);
        assert_eq!(output, expected);
        assert_eq!(&output[52..84], &plan.config.root);
        assert_eq!(&output[84..116], &plan.issuer_hash);
        assert_eq!(&output[116..148], &plan.credential_not_before);
        assert_eq!(&output[148..180], &plan.credential_not_after);
        assert_eq!(&output[212..244], &plan.config.policy_id);
        let request = zk_fresh_program::application_v3::Request::decode(&fixture.request_bytes).unwrap();
        assert_eq!(request.metas[0].key, fixture.request_pda);
        assert_eq!(request.metas[1].key, fixture.queue_pda);
        let f2 = exporter::export_fixture_from_wire(&output).unwrap();
        assert_eq!(&f2[164..196], &fixture.action_hash);
    }
}

#[test]
fn changed_nonce_payload_policy_changes_action_and_stale_public_action_is_rejected() {
    let plan = valid_plan();
    let baseline = transport(&wire(&plan)).unwrap();
    let changes: [fn(&mut exporter::RequestPlan); 3] = [
        |p| p.nonce[0] ^= 1, |p| p.payload[0] ^= 1,
        |p| p.config.policy_id = field(311),
    ];
    for change in changes {
        let mut changed = plan.clone();
        change(&mut changed);
        let mut output = transport(&wire(&changed)).unwrap();
        assert_ne!(&output[180..212], &baseline[180..212]);
        output[180..212].copy_from_slice(&baseline[180..212]);
        assert!(exporter::export_fixture_from_wire(&output).is_err());
    }
    let mut output = baseline;
    let request_offset = 244 + zk_fresh_program::application_v3::CONFIG_LEN;
    let mut request = zk_fresh_program::application_v3::Request::decode(&output[request_offset..]).unwrap();
    request.metas.swap(0, 1);
    output[request_offset..].copy_from_slice(&request.encode());
    assert!(exporter::export_fixture_from_wire(&output).is_err());
}

#[test]
fn rejects_malformed_truncated_trailing_and_oversized_frames_without_output() {
    let input = wire(&valid_plan());
    for len in [0, 3, 47, 428, 632, 633, input.len() - 1] {
        assert!(transport(&input[..len]).is_err(), "truncated length {len}");
    }
    let mut altered = input.clone();
    altered[0] ^= 1;
    assert!(transport(&altered).is_err());
    let mut altered = input.clone();
    altered[44..48].copy_from_slice(&380u32.to_le_bytes());
    assert!(transport(&altered).is_err());
    let mut altered = input.clone();
    altered.push(0);
    assert!(transport(&altered).is_err());
    let mut altered = input;
    altered[631..633].copy_from_slice(&1025u16.to_le_bytes());
    altered.resize(633 + 1025, 0);
    assert!(transport(&altered).is_err());
    let mut maximum = valid_plan();
    maximum.payload.resize(MAX_PAYLOAD, 19);
    assert_eq!(transport(&wire(&maximum)).unwrap().len(), 2874);
}

#[test]
fn rejects_all_wrong_config_pins_and_noncanonical_publics() {
    let changes: [fn(&mut exporter::RequestPlan); 8] = [
        |p| p.config.circuit_id[0] ^= 1,
        |p| p.config.package_id[0] ^= 1,
        |p| p.config.schema_id[0] ^= 1,
        |p| p.config.profile_id[0] ^= 1,
        |p| p.config.ordinary_vk_digest[0] ^= 1,
        |p| p.issuer_hash = [255; 32],
        |p| p.config.root = [255; 32],
        |p| p.config.policy_id = [255; 32],
    ];
    for change in changes {
        let mut plan = valid_plan();
        change(&mut plan);
        assert!(transport(&wire(&plan)).is_err());
    }
}
