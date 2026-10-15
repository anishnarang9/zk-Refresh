#![allow(deprecated)]
use solana_program::{hash::hashv, pubkey::Pubkey, system_program};
use zk_fresh_program::*;

fn field(n: u64) -> [u8; 32] {
    let mut b = [0; 32];
    b[24..].copy_from_slice(&n.to_be_bytes());
    b
}
fn registry(policy: u8) -> Registry {
    Registry::new(
        Pubkey::new_unique(),
        [7; 32],
        field(8),
        field(1),
        policy,
        300,
        1000,
        254,
    )
    .unwrap()
}

#[test]
fn parses_exact_wire_lengths_and_input_order() {
    let mut bytes = vec![0];
    bytes.extend([7; 32]);
    bytes.extend(field(8));
    bytes.extend(field(1));
    bytes.push(1);
    bytes.extend(300u64.to_le_bytes());
    assert!(matches!(
        Instruction::parse(&bytes),
        Ok(Instruction::Initialize {
            policy: 1,
            max_age: 300,
            ..
        })
    ));
    bytes.push(0);
    assert_eq!(
        Instruction::parse(&bytes),
        Err(FreshError::InvalidInstruction)
    );
    let mut auth = vec![2];
    for i in 1..=5 {
        auth.extend(field(i));
    }
    auth.extend([9; 256]);
    auth.extend([10; 32]);
    auth.extend([11; 32]);
    match Instruction::parse(&auth).unwrap() {
        Instruction::Authorize {
            inputs,
            proof,
            action_id,
            recipient,
        } => {
            assert_eq!(inputs[4], field(5));
            assert_eq!(proof, [9; 256]);
            assert_eq!(action_id, [10; 32]);
            assert_eq!(recipient, [11; 32]);
        }
        _ => panic!(),
    }
    assert_eq!(Instruction::parse(&[]), Err(FreshError::InvalidInstruction));
}
#[test]
fn rejects_noncanonical_field_elements() {
    assert_eq!(canonical(&field(1)), Ok(()));
    assert_eq!(
        canonical(&FIELD_MODULUS),
        Err(FreshError::NonCanonicalField)
    );
    assert_eq!(canonical(&[255; 32]), Err(FreshError::NonCanonicalField));
}
#[test]
fn enforces_credential_interval_and_u64_encoding() {
    assert_eq!(validate_times(&field(1000), &field(1100), 1000), Ok(()));
    assert_eq!(
        validate_times(&field(1000), &field(1100), 999),
        Err(FreshError::NotYetValid)
    );
    assert_eq!(validate_times(&field(1000), &field(1100), 1100), Ok(()));
    assert_eq!(
        validate_times(&field(1000), &field(1100), 1101),
        Err(FreshError::CredentialExpired)
    );
    assert_eq!(
        validate_times(&field(1100), &field(1000), 1050),
        Err(FreshError::InvalidTime)
    );
    let mut huge = field(1000);
    huge[0] = 1;
    assert_eq!(
        validate_times(&huge, &field(1100), 1050),
        Err(FreshError::InvalidTime)
    );
    assert_eq!(
        validate_times(&field(0), &field(1100), -1),
        Err(FreshError::InvalidTime)
    );
}
#[test]
fn strict_policy_rejects_previous_roots() {
    let mut r = registry(0);
    r.update(field(2), 0, 1001).unwrap();
    assert_eq!(
        r.accepted_root(&field(1), 1002),
        Err(FreshError::RootNotAccepted)
    );
    assert_eq!(r.accepted_root(&field(2), 1002), Ok(1));
}
#[test]
fn historical_policy_keeps_original_activation_time() {
    let mut r = registry(1);
    r.update(field(2), 0, 1100).unwrap();
    assert_eq!(r.accepted_root(&field(1), 1300), Ok(0));
    assert_eq!(
        r.accepted_root(&field(1), 1301),
        Err(FreshError::RootExpired)
    );
    assert_eq!(r.accepted_root(&field(2), 1301), Ok(1));
    assert_eq!(
        r.accepted_root(&field(2), 1099),
        Err(FreshError::InvalidTime)
    );
}
#[test]
fn bounds_history_and_checks_expected_version_without_mutation() {
    let mut r = registry(1);
    let original = r.encode();
    assert_eq!(r.update(field(2), 9, 1001), Err(FreshError::InvalidVersion));
    assert_eq!(r.encode(), original);
    for version in 0..128 {
        r.update(field(version + 2), version, 1000).unwrap();
    }
    assert_eq!(
        r.accepted_root(&field(1), 1000),
        Err(FreshError::RootNotAccepted)
    );
    assert_eq!(r.accepted_root(&field(2), 1000), Ok(1));
    assert!(r.encode().len() < 10240);
    assert_eq!(Registry::decode(&r.encode()).unwrap().encode(), r.encode());
}
#[test]
fn rejects_bad_policy_and_max_age() {
    assert!(Registry::new(
        Pubkey::new_unique(),
        [0; 32],
        field(1),
        field(2),
        2,
        300,
        1000,
        1
    )
    .is_err());
    assert!(Registry::new(
        Pubkey::new_unique(),
        [0; 32],
        field(1),
        field(2),
        0,
        301,
        1000,
        1
    )
    .is_err());
    assert!(Registry::new(
        Pubkey::new_unique(),
        [0; 32],
        field(1),
        field(2),
        0,
        0,
        1000,
        1
    )
    .is_err());
}
#[test]
fn action_digest_matches_domain_and_modular_reduction() {
    let program = Pubkey::new_from_array([1; 32]);
    let registry = Pubkey::new_from_array([2; 32]);
    let recipient = [3; 32];
    let action = [4; 32];
    let hash = hashv(&[
        b"zk-fresh-action-v1",
        program.as_ref(),
        registry.as_ref(),
        &1u64.to_le_bytes(),
        &recipient,
        &action,
    ])
    .to_bytes();
    assert_eq!(
        hash,
        [
            19, 4, 88, 108, 152, 210, 163, 73, 33, 84, 237, 207, 86, 195, 128, 162, 189, 27, 9,
            196, 140, 175, 178, 65, 103, 93, 243, 182, 78, 143, 187, 8
        ]
    );
    assert_eq!(
        action_digest(&program, &registry, &recipient, &action),
        [
            19, 4, 88, 108, 152, 210, 163, 73, 33, 84, 237, 207, 86, 195, 128, 162, 189, 27, 9,
            196, 140, 175, 178, 65, 103, 93, 243, 182, 78, 143, 187, 8
        ]
    );
    assert_eq!(
        action_digest(&program, &registry, &recipient, &[5; 32]),
        [
            31, 134, 241, 183, 58, 100, 116, 169, 203, 103, 55, 166, 190, 249, 52, 140, 202, 192,
            20, 87, 7, 160, 94, 119, 249, 176, 53, 35, 188, 5, 65, 89
        ]
    );
}
#[test]
fn receipt_replay_is_rejected_but_prefunding_is_allowed() {
    let program = Pubkey::new_unique();
    assert_eq!(
        check_receipt_unused(&program, &program, 152),
        Err(FreshError::AlreadyUsed)
    );
    assert_eq!(
        check_receipt_unused(&program, &system_program::id(), 0),
        Ok(())
    );
    assert!(check_receipt_unused(&program, &Pubkey::new_unique(), 0).is_err());
}

#[test]
fn strict_current_root_has_no_max_age() {
    let r = registry(0);
    assert_eq!(r.accepted_root(&field(1), 1301), Ok(0));
}

#[test]
fn historical_current_root_expires_after_max_age() {
    let r = registry(1);
    assert_eq!(r.accepted_root(&field(1), 1300), Ok(0));
    assert_eq!(
        r.accepted_root(&field(1), 1301),
        Err(FreshError::RootExpired)
    );
}

#[test]
fn both_policies_reject_root_before_activation() {
    for policy in [0, 1] {
        let r = registry(policy);
        assert_eq!(
            r.accepted_root(&field(1), 999),
            Err(FreshError::InvalidTime)
        );
    }
}
