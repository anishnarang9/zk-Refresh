use solana_sdk::{
    hash::Hash,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use zk_fresh_benchmark::solana::queue_v2::*;
fn plan() -> QueuePlan {
    let mut p = QueuePlan {
        genesis: [1; 32],
        program: [12; 32],
        config: [13; 32],
        queue: [16; 32],
        request: [15; 32],
        issuer_account: [17; 32],
        admin: [18; 32],
        publisher: [19; 32],
        source: [20; 32],
        seed: [21; 32],
        nonce: [11; 32],
        recipient: [14; 32],
        policy_id: [2; 32],
        deadline: 500,
        payload: b"abc".to_vec(),
        expected_inputs: [[0; 32]; 5],
    };
    p.expected_inputs[0][31] = 6;
    p.expected_inputs[1][31] = 8;
    p.expected_inputs[2][31] = 90;
    p.expected_inputs[3][30..].copy_from_slice(&600u16.to_be_bytes());
    p.expected_inputs[4] = p.action_hash().unwrap();
    p
}
#[test]
fn independent_action_vector_and_finalized_account_layout_match_frozen_contract() {
    let p = plan();
    assert_eq!(p.action_preimage().unwrap().len(), 361);
    assert_eq!(
        hex::encode(p.action_hash().unwrap()),
        "29bef8a2c27a0cc3a4281e604a782581bcd214c9b9e9999eeb36910af36344ef"
    );
    let b = p.finalized_request().unwrap();
    assert_eq!(b.len(), 2249);
    assert_eq!(&b[..8], b"DYNREQ02");
    assert_eq!(b[183], 1);
    assert_eq!(&b[1225..1228], b"abc");
    assert_eq!(&b[185..217], &p.request);
}
#[test]
fn fixture_import_rejects_component_action12345_and_altered_application_proof() {
    let p = plan();
    let mut wire = vec![];
    for f in p.expected_inputs {
        wire.extend(f)
    }
    wire.extend([1; 256]);
    assert!(p.check_wire(&wire).is_ok());
    wire[159] ^= 1;
    assert!(p.check_wire(&wire).is_err());
    wire[..160].fill(0);
    wire[158..160].copy_from_slice(&12345u16.to_be_bytes());
    assert!(p.check_wire(&wire).is_err());
    assert!(p.check_wire(&wire[..415]).is_err());
}
#[test]
fn loopback_gate_rejects_external_rpc_and_ambiguous_urls() {
    assert!(check_loopback("http://127.0.0.1:18999").is_ok());
    for u in [
        "https://127.0.0.1:18999",
        "http://example.com:18999",
        "http://127.0.0.1:18999/path",
        "http://u@127.0.0.1:18999",
        "http://127.0.0.1:18999/?x=1",
    ] {
        assert!(check_loopback(u).is_err(), "{u}");
    }
}
#[test]
fn exact_execute_transaction_fits_packet_and_binds_only_ordered_relevant_accounts() {
    let mut p = plan();
    let payer = Keypair::new();
    p.admin = payer.pubkey().to_bytes();
    let mut wire = vec![];
    for f in p.expected_inputs {
        wire.extend(f)
    }
    wire.extend([1; 256]);
    let ix = p.execute_instruction(&wire).unwrap();
    assert_eq!(ix.data.len(), 418);
    assert_eq!(ix.accounts.len(), 4);
    assert_eq!(ix.accounts[2].pubkey, Pubkey::new_from_array(p.request));
    assert_eq!(ix.accounts[3].pubkey, Pubkey::new_from_array(p.queue));
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        Hash::new_unique(),
    );
    assert!(bincode::serialize(&tx).unwrap().len() <= 1232);
}
#[test]
#[ignore = "ROOT-pinned actual application ELF and supervised loopback validator required"]
fn root_pinned_queue_v2_prepare() {
    prepare_from_env().unwrap();
}
#[test]
#[ignore = "ROOT-pinned fresh exact-action Full proof and same persistent local ledger required"]
fn root_pinned_queue_v2_execute() {
    execute_from_env().unwrap();
}
