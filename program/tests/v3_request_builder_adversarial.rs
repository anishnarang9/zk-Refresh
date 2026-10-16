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

#[test]
fn root_only_change_updates_first_public_and_preserves_action() {
    let mut plan = valid_plan();
    let (before, _) = exporter::build_request_fixture(&plan).unwrap();
    plan.config.root = field(233);
    let (after, _) = exporter::build_request_fixture(&plan).unwrap();
    let mut expected = before.public_inputs;
    expected[0] = plan.config.root;
    assert_ne!(before.public_inputs[0], after.public_inputs[0]);
    assert_eq!(after.public_inputs, expected);
    assert_eq!(before.action_hash, after.action_hash);
    assert_eq!(before.action_preimage, after.action_preimage);
}

#[test]
fn issuer_only_change_updates_second_public_and_issuer_pda_but_preserves_action() {
    let mut plan = valid_plan();
    let (before, _) = exporter::build_request_fixture(&plan).unwrap();
    plan.issuer_hash = field(239);
    let (after, _) = exporter::build_request_fixture(&plan).unwrap();
    let mut expected = before.public_inputs;
    expected[1] = plan.issuer_hash;
    assert_ne!(before.public_inputs[1], after.public_inputs[1]);
    assert_eq!(after.public_inputs, expected);
    assert_ne!(before.issuer_pda, after.issuer_pda);
    assert_eq!(before.action_hash, after.action_hash);
    assert_eq!(before.action_preimage, after.action_preimage);
}

#[test]
fn action_bound_changes_produce_different_actions() {
    let (baseline, _) = exporter::build_request_fixture(&valid_plan()).unwrap();
    let cases: [(&str, fn(&mut exporter::RequestPlan)); 3] = [
        ("payload", |plan| plan.payload[0] ^= 1),
        ("nonce", |plan| plan.nonce[0] ^= 1),
        ("policy", |plan| plan.config.policy_id = field(241)),
    ];
    for (name, mutate) in cases {
        let mut plan = valid_plan();
        mutate(&mut plan);
        let (changed, _) = exporter::build_request_fixture(&plan).unwrap();
        assert_ne!(baseline.action_hash, changed.action_hash, "{name}");
        assert_eq!(changed.public_inputs[4], changed.action_hash, "{name}");
    }
}

#[test]
fn wrong_generated_identities_and_oversized_payload_are_rejected() {
    let cases: [(&str, fn(&mut exporter::RequestPlan)); 3] = [
        ("package", |plan| plan.config.package_id[0] ^= 1),
        ("profile", |plan| plan.config.profile_id[0] ^= 1),
        ("payload size", |plan| plan.payload.resize(MAX_PAYLOAD + 1, 0)),
    ];
    for (name, mutate) in cases {
        let mut plan = valid_plan();
        mutate(&mut plan);
        assert!(exporter::build_request_fixture(&plan).is_err(), "{name}");
    }
}
