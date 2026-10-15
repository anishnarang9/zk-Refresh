#![allow(deprecated)]
use solana_program::{
    account_info::AccountInfo,
    clock::Clock,
    program_error::ProgramError,
    program_stubs::{set_syscall_stubs, SyscallStubs},
    pubkey::Pubkey,
};
use zk_fresh_program::{application_v2::*, process_instruction};
struct FixedClock;
impl SyscallStubs for FixedClock {
    fn sol_get_clock_sysvar(&self, p: *mut u8) -> u64 {
        unsafe {
            std::ptr::write_unaligned(
                p.cast::<Clock>(),
                Clock {
                    unix_timestamp: 100,
                    ..Clock::default()
                },
            )
        };
        0
    }
}
fn f(x: u8) -> [u8; 32] {
    let mut b = [0; 32];
    b[31] = x;
    b
}
#[test]
fn runtime_rejects_unauthorized_root_and_status_without_state_writes() {
    let old = set_syscall_stubs(Box::new(FixedClock));
    let program = Pubkey::new_unique();
    let admin = Pubkey::new_unique();
    let publisher = Pubkey::new_unique();
    let source = Pubkey::new_unique();
    let rogue = Pubkey::new_unique();
    let seed = [1; 32];
    let config_key =
        Pubkey::find_program_address(&[b"dyn-config-v2", admin.as_ref(), &seed], &program).0;
    let issuer_key =
        Pubkey::find_program_address(&[b"dyn-issuer-v2", config_key.as_ref(), &f(8)], &program).0;
    let c = Config {
        admin,
        seed,
        publisher,
        genesis: [2; 32],
        policy_id: [3; 32],
        policy_version: 1,
        circuit_id: [4; 32],
        package_id: [5; 32],
        schema_id: [6; 32],
        root: f(7),
        root_version: 0,
        enabled: true,
    };
    let i = Issuer {
        config: config_key,
        issuer_hash: f(8),
        profile_id: [4; 32],
        profile_version: 2,
        aki: {
            let mut a = [0; 32];
            for (j, b) in a[..20].iter_mut().enumerate() {
                *b = 0xa0 + j as u8;
            }
            a
        },
        source,
        enabled: true,
        sequence: 0,
        digest: [0; 32],
        observed_at: 0,
        expires_at: 0,
    };
    let mut cb = c.encode();
    let mut ib = i.encode();
    let cb0 = cb.clone();
    let ib0 = ib.clone();
    let mut rd = [];
    let mut l1 = 0;
    let mut l2 = 0;
    let mut l3 = 0;
    let a = AccountInfo::new(&rogue, true, false, &mut l1, &mut rd, &program, false, 0);
    let ca = AccountInfo::new(
        &config_key,
        false,
        true,
        &mut l2,
        &mut cb,
        &program,
        false,
        0,
    );
    let ia = AccountInfo::new(
        &issuer_key,
        false,
        true,
        &mut l3,
        &mut ib,
        &program,
        false,
        0,
    );
    let mut publish = vec![PREFIX, 2];
    publish.extend(0u64.to_be_bytes());
    publish.extend(f(9));
    assert_eq!(
        process_instruction(&program, &[a.clone(), ca.clone()], &publish),
        Err(ProgramError::from(AppError::Authority))
    );
    let mut observe = vec![PREFIX, 3];
    observe.extend(0u64.to_be_bytes());
    observe.extend(1u64.to_be_bytes());
    observe.extend([1; 32]);
    observe.extend(100i64.to_be_bytes());
    observe.extend(400i64.to_be_bytes());
    assert_eq!(
        process_instruction(&program, &[a, ca.clone(), ia.clone()], &observe),
        Err(ProgramError::from(AppError::Authority))
    );
    assert_eq!(ca.try_borrow_data().unwrap().as_ref(), cb0);
    assert_eq!(ia.try_borrow_data().unwrap().as_ref(), ib0);
    set_syscall_stubs(old);
}

fn ai(
    key: Pubkey,
    owner: Pubkey,
    signer: bool,
    writable: bool,
    data: Vec<u8>,
) -> AccountInfo<'static> {
    AccountInfo::new(
        Box::leak(Box::new(key)),
        signer,
        writable,
        Box::leak(Box::new(1)),
        Box::leak(data.into_boxed_slice()),
        Box::leak(Box::new(owner)),
        false,
        0,
    )
}
fn fixture() -> (
    Pubkey,
    Config,
    Issuer,
    Request,
    Vec<AccountInfo<'static>>,
    Vec<u8>,
) {
    use zk_fresh_program::application_runtime_v2::*;
    let program = Pubkey::new_unique();
    let admin = Pubkey::new_unique();
    let seed = [1; 32];
    let config = config_address(&program, &admin, &seed).0;
    let c = Config {
        admin,
        seed,
        publisher: Pubkey::new_unique(),
        genesis: [2; 32],
        policy_id: [3; 32],
        policy_version: 1,
        circuit_id: CIRCUIT_ID,
        package_id: PACKAGE_ID,
        schema_id: SCHEMA_ID,
        root: f(7),
        root_version: 0,
        enabled: true,
    };
    let creator = Pubkey::new_unique();
    let nonce = [4; 32];
    let req = request_address(&program, &config, &creator, &nonce).0;
    let queue = queue_address(&program, &config).0;
    let mut i = Issuer {
        config,
        issuer_hash: f(8),
        profile_id: PROFILE_ID,
        profile_version: 2,
        aki: {
            let mut a = [0; 32];
            for (j, b) in a[..20].iter_mut().enumerate() {
                *b = 0xa0 + j as u8;
            }
            a
        },
        source: Pubkey::new_unique(),
        enabled: true,
        sequence: 0,
        digest: [0; 32],
        observed_at: 0,
        expires_at: 0,
    };
    i.observe(0, 1, [1; 32], 99, 399, 100).unwrap();
    let issuer = issuer_address(&program, &config, &i.issuer_hash).0;
    let mut r = Request {
        config,
        creator,
        nonce,
        issuer_hash: i.issuer_hash,
        recipient: Pubkey::new_unique(),
        request_type: 1,
        deadline: 500,
        payload_len: 3,
        uploaded: 0,
        metas_uploaded: 2,
        state: RequestState::Staging,
        metas: vec![
            RelevantMeta {
                key: req,
                flags: 2,
                owner: program,
            },
            RelevantMeta {
                key: queue,
                flags: 2,
                owner: program,
            },
        ],
        payload: vec![0; 3],
    };
    r.upload(0, b"abc").unwrap();
    r.finalize(100).unwrap();
    let accounts = vec![
        ai(config, program, false, false, c.encode()),
        ai(issuer, program, false, false, i.encode()),
        ai(req, program, false, true, r.encode()),
        ai(queue, program, false, true, Queue::new(config).encode()),
    ];
    let inputs = [
        c.root,
        i.issuer_hash,
        f(90),
        f(200),
        action_hash(&program, &c, &r).unwrap(),
    ];
    let mut wire = vec![PREFIX, 7];
    for p in inputs {
        wire.extend(p)
    }
    wire.extend([0; 256]);
    (program, c, i, r, accounts, wire)
}
#[test]
fn execute_rejects_current_state_substitution_replay_and_bad_proof_without_writes() {
    let old = set_syscall_stubs(Box::new(FixedClock));
    let (program, c, i, r, accounts, wire) = fixture();
    let originals: Vec<_> = accounts
        .iter()
        .map(|a| a.try_borrow_data().unwrap().to_vec())
        .collect();
    let run = |a: &[AccountInfo], w: &[u8]| process_instruction(&program, a, w);
    assert_eq!(run(&accounts, &wire), Err(AppError::Proof.into()));
    let mut changed = wire.clone();
    changed[33] ^= 1;
    assert_eq!(
        run(&accounts, &changed),
        Err(zk_fresh_program::FreshError::RootNotAccepted.into())
    );
    changed = wire.clone();
    changed[2 + 4 * 32 + 31] ^= 1;
    assert_eq!(run(&accounts, &changed), Err(AppError::Action.into()));
    let mut bad = accounts.clone();
    bad[2].is_writable = false;
    assert_eq!(run(&bad, &wire), Err(AppError::Privileges.into()));
    bad = accounts.clone();
    bad.swap(2, 3);
    assert!(run(&bad, &wire).is_err());
    bad = accounts.clone();
    bad[2].owner = Box::leak(Box::new(Pubkey::new_unique()));
    assert_eq!(run(&bad, &wire), Err(AppError::Owner.into()));
    bad = accounts.clone();
    bad[3] = bad[2].clone();
    assert_eq!(run(&bad, &wire), Err(AppError::Accounts.into()));
    let mut disabled = i.clone();
    disabled.enabled = false;
    accounts[1]
        .try_borrow_mut_data()
        .unwrap()
        .copy_from_slice(&disabled.encode());
    assert_eq!(run(&accounts, &wire), Err(AppError::Policy.into()));
    let mut stale = i.clone();
    stale.observed_at = 1;
    stale.expires_at = 99;
    accounts[1]
        .try_borrow_mut_data()
        .unwrap()
        .copy_from_slice(&stale.encode());
    assert_eq!(run(&accounts, &wire), Err(AppError::Status.into()));
    accounts[1]
        .try_borrow_mut_data()
        .unwrap()
        .copy_from_slice(&i.encode());
    let mut consumed = r.clone();
    consumed.state = RequestState::Consumed;
    accounts[2]
        .try_borrow_mut_data()
        .unwrap()
        .copy_from_slice(&consumed.encode());
    assert_eq!(run(&accounts, &wire), Err(AppError::Consumed.into()));
    accounts[2]
        .try_borrow_mut_data()
        .unwrap()
        .copy_from_slice(&r.encode());
    let mut wrong = c.clone();
    wrong.package_id[0] ^= 1;
    accounts[0]
        .try_borrow_mut_data()
        .unwrap()
        .copy_from_slice(&wrong.encode());
    assert_eq!(run(&accounts, &wire), Err(AppError::Policy.into()));
    accounts[0]
        .try_borrow_mut_data()
        .unwrap()
        .copy_from_slice(&c.encode());
    for (a, b) in accounts.iter().zip(originals) {
        assert_eq!(a.try_borrow_data().unwrap().as_ref(), b)
    }
    set_syscall_stubs(old);
}
#[test]
fn finalized_request_rejects_creator_mutation_and_cancellation_stops_execution() {
    let old = set_syscall_stubs(Box::new(FixedClock));
    let (program, _, _, r, accounts, wire) = fixture();
    let wrong = ai(Pubkey::new_unique(), program, true, false, vec![]);
    assert_eq!(
        process_instruction(
            &program,
            &[wrong, accounts[0].clone(), accounts[2].clone()],
            &[PREFIX, 9]
        ),
        Err(AppError::Authority.into())
    );
    let creator = ai(r.creator, program, true, false, vec![]);
    let mut upload = vec![PREFIX, 6];
    upload.extend(0u16.to_be_bytes());
    upload.extend(1u16.to_be_bytes());
    upload.push(9);
    assert_eq!(
        process_instruction(
            &program,
            &[creator.clone(), accounts[0].clone(), accounts[2].clone()],
            &upload
        ),
        Err(AppError::State.into())
    );
    process_instruction(
        &program,
        &[creator, accounts[0].clone(), accounts[2].clone()],
        &[PREFIX, 9],
    )
    .unwrap();
    assert_eq!(
        Request::decode(&accounts[2].try_borrow_data().unwrap())
            .unwrap()
            .state,
        RequestState::Cancelled
    );
    assert_eq!(
        process_instruction(&program, &accounts, &wire),
        Err(AppError::Consumed.into())
    );
    set_syscall_stubs(old);
}
#[test]
fn canonical_proof_rejects_infinity_and_noncanonical_coordinate_before_pairing() {
    use zk_fresh_program::application_runtime_v2::verify;
    assert_eq!(verify(&[f(1); 5], &[0; 256]), Err(AppError::Proof.into()));
    assert_eq!(verify(&[f(1); 5], &[255; 256]), Err(AppError::Proof.into()));
    assert_eq!(
        verify(&[zk_fresh_program::FIELD_MODULUS; 5], &[1; 256]),
        Err(AppError::Proof.into())
    );
}

#[test]
fn enrollment_rejects_any_aki_outside_exact_signed_v2_profile_before_creation() {
    let (program, c, i, _, accounts, _) = fixture();
    let admin = ai(c.admin, program, true, true, vec![]);
    let mut target = accounts[1].clone();
    target.is_writable = true;
    let system = ai(
        solana_program::system_program::id(),
        solana_program::system_program::id(),
        false,
        false,
        vec![],
    );
    let mut enroll = vec![PREFIX, 1];
    enroll.extend(i.issuer_hash);
    enroll.extend(i.profile_id);
    enroll.extend(i.profile_version.to_be_bytes());
    enroll.extend([9; 32]);
    enroll.extend(i.source.as_ref());
    assert_eq!(
        process_instruction(
            &program,
            &[admin, accounts[0].clone(), target, system],
            &enroll
        ),
        Err(AppError::Policy.into())
    );
}

#[test]
fn authenticated_publication_advances_distinct_root_and_source_versions() {
    let old = set_syscall_stubs(Box::new(FixedClock));
    let (program, c, i, _, accounts, _) = fixture();
    let publisher = ai(c.publisher, program, true, false, vec![]);
    let source = ai(i.source, program, true, false, vec![]);
    let mut ca = accounts[0].clone();
    ca.is_writable = true;
    let mut ia = accounts[1].clone();
    ia.is_writable = true;
    let mut publish = vec![PREFIX, 2];
    publish.extend(0u64.to_be_bytes());
    publish.extend(f(9));
    process_instruction(&program, &[publisher.clone(), ca.clone()], &publish).unwrap();
    assert_eq!(
        Config::decode(&ca.try_borrow_data().unwrap())
            .unwrap()
            .root_version,
        1
    );
    assert_eq!(
        Issuer::decode(&ia.try_borrow_data().unwrap())
            .unwrap()
            .sequence,
        1
    );
    assert_eq!(
        process_instruction(&program, &[publisher, ca.clone()], &publish),
        Err(AppError::Version.into())
    );
    let mut observe = vec![PREFIX, 3];
    observe.extend(1u64.to_be_bytes());
    observe.extend(2u64.to_be_bytes());
    observe.extend([2; 32]);
    observe.extend(100i64.to_be_bytes());
    observe.extend(400i64.to_be_bytes());
    process_instruction(
        &program,
        &[source.clone(), ca.clone(), ia.clone()],
        &observe,
    )
    .unwrap();
    assert_eq!(
        Issuer::decode(&ia.try_borrow_data().unwrap())
            .unwrap()
            .sequence,
        2
    );
    assert_eq!(
        Config::decode(&ca.try_borrow_data().unwrap())
            .unwrap()
            .root_version,
        1
    );
    assert_eq!(
        process_instruction(&program, &[source, ca, ia], &observe),
        Err(AppError::Version.into())
    );
    set_syscall_stubs(old);
}
