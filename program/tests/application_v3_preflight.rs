//! Synthetic noncryptographic preflight fixtures only. No proof, verifier, CPI,
//! state transition or queue authorization is established by these tests.
//! Actual metas: config RO, issuer RO, publisher-head RO, request W, queue W,
//! then exactly the ordered relevant extras. Every account appears once.
#![allow(deprecated)]
use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};
use zk_fresh_program::{
    application_preflight_v3::check,
    application_runtime_v3 as runtime,
    application_v3::{
        action_hash, action_preimage, AppError, Authority, Config, Issuer, PublisherHead,
        PublisherHeadBinding, Queue, RelevantMeta, Request, RequestState, PREFIX, QUEUE_CAPACITY,
    },
    generated_vk_v3 as identity, process_instruction, FIELD_MODULUS,
};
fn key(n: u8) -> Pubkey {
    Pubkey::new_from_array([n; 32])
}
fn field(n: u64) -> [u8; 32] {
    let mut b = [0; 32];
    b[24..].copy_from_slice(&n.to_be_bytes());
    b
}
fn actor(key: Pubkey) -> Authority {
    Authority {
        key,
        is_signer: true,
    }
}
fn account(k: Pubkey, owner: Pubkey, writable: bool, data: Vec<u8>) -> AccountInfo<'static> {
    AccountInfo::new(
        Box::leak(Box::new(k)),
        false,
        writable,
        Box::leak(Box::new(1)),
        Box::leak(data.into_boxed_slice()),
        Box::leak(Box::new(owner)),
        false,
        0,
    )
}
fn replace(a: &AccountInfo, bytes: Vec<u8>) {
    *a.try_borrow_mut_data().unwrap() = Box::leak(bytes.into_boxed_slice());
}
fn snapshot(a: &[AccountInfo]) -> Vec<(Pubkey, u64, Vec<u8>)> {
    a.iter()
        .map(|x| {
            (
                *x.owner,
                x.lamports(),
                x.try_borrow_data().unwrap().to_vec(),
            )
        })
        .collect()
}
fn rejection(x: &Fixture, accounts: &[AccountInfo], inputs: &[[u8; 32]; 6], now: i64) {
    let before = snapshot(accounts);
    assert!(
        check(&x.program, accounts, inputs, now).is_err(),
        "invalid noncryptographic preflight admitted"
    );
    assert_eq!(
        snapshot(accounts),
        before,
        "non-authorizing preflight mutated account state"
    );
}
struct Fixture {
    program: Pubkey,
    accounts: Vec<AccountInfo<'static>>,
}
impl Fixture {
    fn new() -> Self {
        let program = key(12);
        let c = Config {
            admin: key(18),
            seed: [7; 32],
            publisher: key(19),
            genesis: [1; 32],
            policy_id: field(5),
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
        let ck = runtime::config_address(&program, &c.admin, &c.seed).0;
        let mut aki = [0; 32];
        aki[..20].fill(8);
        let mut i =
            Issuer::enroll(ck, &c, actor(c.admin), field(8), aki, key(20), 1, [8; 32]).unwrap();
        i.observe(
            &c,
            actor(i.source),
            0,
            0,
            0,
            1,
            [41; 32],
            true,
            100,
            300,
            100,
        )
        .unwrap();
        let ik = runtime::issuer_address(&program, &ck, &i.issuer_hash).0;
        let (i, h) = PublisherHead::prepare_bind(
            ck,
            ik,
            &c,
            &i,
            actor(c.publisher),
            None,
            &PublisherHeadBinding {
                expected_config_epoch: 0,
                expected_issuer_epoch: 0,
                expected_root: c.root,
                expected_root_version: 0,
                expected_source_sequence: 1,
                expected_source_digest: i.digest,
                expected_publication_sequence: 0,
                expected_publication_digest: [0; 32],
                next_publication_sequence: 1,
                envelope_digest: [91; 32],
            },
            100,
        )
        .unwrap();
        let creator = key(21);
        let nonce = [11; 32];
        let rk = runtime::request_address(&program, &ck, &creator, &nonce).0;
        let qk = runtime::queue_address(&program, &ck).0;
        let hk = runtime::publisher_head_address(&program, &ck, &ik, &c.publisher).0;
        let r = Request {
            config: ck,
            creator,
            nonce,
            issuer_hash: i.issuer_hash,
            recipient: key(22),
            request_type: 1,
            deadline: 200,
            payload_len: 4,
            uploaded: 4,
            metas_uploaded: 3,
            state: RequestState::Finalized,
            metas: vec![
                RelevantMeta {
                    key: rk,
                    owner: program,
                    flags: 2,
                },
                RelevantMeta {
                    key: qk,
                    owner: program,
                    flags: 2,
                },
                RelevantMeta {
                    key: key(31),
                    owner: key(50),
                    flags: 0,
                },
            ],
            payload: b"work".to_vec(),
        };
        Self {
            program,
            accounts: vec![
                account(ck, program, false, c.encode()),
                account(ik, program, false, i.encode()),
                account(hk, program, false, h.encode()),
                account(rk, program, true, r.encode()),
                account(qk, program, true, Queue::new(ck).encode()),
                account(key(31), key(50), false, vec![]),
            ],
        }
    }
    fn c(&self) -> Config {
        Config::decode(&self.accounts[0].try_borrow_data().unwrap()).unwrap()
    }
    fn i(&self) -> Issuer {
        Issuer::decode(&self.accounts[1].try_borrow_data().unwrap()).unwrap()
    }
    fn h(&self) -> PublisherHead {
        PublisherHead::decode(&self.accounts[2].try_borrow_data().unwrap()).unwrap()
    }
    fn r(&self) -> Request {
        Request::decode(&self.accounts[3].try_borrow_data().unwrap()).unwrap()
    }
    fn inputs(&self) -> [[u8; 32]; 6] {
        let c = self.c();
        let r = self.r();
        [
            c.root,
            r.issuer_hash,
            field(100),
            field(200),
            action_hash(&self.program, &c, &r).unwrap(),
            c.policy_id,
        ]
    }
    fn success(&self, now: i64, inputs: &[[u8; 32]; 6]) {
        let before = snapshot(&self.accounts);
        assert_eq!(check(&self.program, &self.accounts, inputs, now), Ok(()));
        assert_eq!(snapshot(&self.accounts), before);
    }
}
fn independent_action(program: &Pubkey, c: &Config, r: &Request) -> Vec<u8> {
    let mut b = b"DYNARK-WORK-REQUEST".to_vec();
    b.push(2);
    b.extend(c.genesis);
    b.extend(program.to_bytes());
    b.extend(r.config.to_bytes());
    b.extend(c.policy_id);
    b.extend(c.policy_version.to_be_bytes());
    b.extend(c.circuit_id);
    b.extend(r.nonce);
    b.extend(r.recipient.to_bytes());
    b.extend(r.request_type.to_be_bytes());
    b.extend((r.payload.len() as u32).to_be_bytes());
    b.extend(solana_program::hash::hash(&r.payload).to_bytes());
    b.push(r.metas.len() as u8);
    for m in &r.metas {
        b.extend(m.key.to_bytes());
        b.push(m.flags);
    }
    b.extend(r.deadline.to_be_bytes());
    b
}
fn reduced_hash(bytes: &[u8]) -> [u8; 32] {
    let mut h = solana_program::hash::hash(bytes).to_bytes();
    while h >= FIELD_MODULUS {
        let mut borrow = 0u16;
        for n in (0..32).rev() {
            let value = h[n] as u16;
            let sub = FIELD_MODULUS[n] as u16 + borrow;
            h[n] = value.wrapping_sub(sub) as u8;
            borrow = u16::from(value < sub);
        }
    }
    h
}

#[test]
fn preflight_v3_exact_current_six_field_request_passes_without_authorizing_execute() {
    let x = Fixture::new();
    let inputs = x.inputs();
    let before = snapshot(&x.accounts);
    let preimage = independent_action(&x.program, &x.c(), &x.r());
    assert_eq!(
        action_preimage(&x.program, &x.c(), &x.r()),
        Ok(preimage.clone())
    );
    assert_eq!(inputs[4], reduced_hash(&preimage));
    assert_eq!(
        (x.accounts[3].key, x.accounts[4].key),
        (&x.r().metas[0].key, &x.r().metas[1].key)
    );
    // Even this exact public statement and actual account plan has no proof.
    let mut wire = vec![PREFIX, 7];
    for input in inputs {
        wire.extend(input);
    }
    wire.extend([0; 256]);
    assert_eq!(wire.len(), 450);
    assert_eq!(
        process_instruction(&x.program, &x.accounts, &wire),
        Err(ProgramError::from(AppError::Unavailable))
    );
    assert_eq!(snapshot(&x.accounts), before);
    assert_eq!(
        check(&x.program, &x.accounts, &inputs, 110),
        Ok(()),
        "exact v3 current-state preflight must pass without proof authorization"
    );
    assert_eq!(snapshot(&x.accounts), before);
    // Every declared extra privilege is compared with the actual account flags.
    for flags in 0..=3 {
        let mut r = x.r();
        r.metas[2].flags = flags;
        replace(&x.accounts[3], r.encode());
        let mut actual = x.accounts.clone();
        actual[5].is_signer = flags & 1 != 0;
        actual[5].is_writable = flags & 2 != 0;
        assert_eq!(check(&x.program, &actual, &x.inputs(), 110), Ok(()));
    }
    for meta_count in [2, 16] {
        let mut boundary = Fixture::new();
        let mut r = boundary.r();
        r.metas.truncate(2);
        boundary.accounts.truncate(5);
        for n in 2..meta_count {
            r.metas.push(RelevantMeta {
                key: key(80 + n),
                owner: key(50),
                flags: 0,
            });
            boundary
                .accounts
                .push(account(key(80 + n), key(50), false, vec![]));
        }
        r.metas_uploaded = meta_count;
        replace(&boundary.accounts[3], r.encode());
        assert_eq!(boundary.accounts.len(), 3 + meta_count as usize);
        boundary.success(110, &boundary.inputs());
    }
}

#[test]
fn preflight_v3_missing_or_legacy_only_head_cannot_authorize() {
    for case in 0..5 {
        let x = Fixture::new();
        let inputs = x.inputs();
        // The fixture issuer already has a valid legacy root/source binding.
        assert_eq!(x.i().binding_current(&x.c()), Ok(()));
        let mut actual = x.accounts.clone();
        match case {
            0 => {
                actual.remove(2);
            }
            1 => {
                replace(&actual[2], vec![]);
                actual[2].assign(&solana_program::system_program::id());
            }
            2 => replace(&actual[2], vec![0; 280]),
            3 => {
                let mut h = x.h();
                h.source_sequence = 2;
                replace(&actual[2], h.encode());
            }
            4 => {
                let mut h = x.h();
                h.root_version = 1;
                replace(&actual[2], h.encode());
            }
            _ => unreachable!(),
        }
        rejection(&x, &actual, &inputs, 110);
    }
}

#[test]
fn preflight_v3_fixed_and_relevant_account_aliases_and_privileges_fail_unchanged() {
    for index in 0..6 {
        for mutation in 0..4 {
            let x = Fixture::new();
            let inputs = x.inputs();
            let mut a = x.accounts.clone();
            match mutation {
                0 => a[index].is_signer = !a[index].is_signer,
                1 => a[index].is_writable = !a[index].is_writable,
                2 => a[index].key = Box::leak(Box::new(key(61))),
                3 => a[index].assign(&key(61)),
                _ => unreachable!(),
            }
            rejection(&x, &a, &inputs, 110);
        }
    }
    for (one, two) in [(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (0, 5)] {
        let x = Fixture::new();
        let inputs = x.inputs();
        let mut a = x.accounts.clone();
        a.swap(one, two);
        rejection(&x, &a, &inputs, 110);
        a[two] = a[one].clone();
        rejection(&x, &a, &inputs, 110);
    }
    for fixed in 0..3 {
        let x = Fixture::new();
        let mut r = x.r();
        let mut a = x.accounts.clone();
        // Stored and actual lists agree on the collision; full-list uniqueness
        // must still reject fixed accounts appearing as relevant extras.
        r.metas[2] = RelevantMeta {
            key: *a[fixed].key,
            owner: *a[fixed].owner,
            flags: 0,
        };
        replace(&a[3], r.encode());
        a[5] = a[fixed].clone();
        rejection(&x, &a, &x.inputs(), 110);
    }
    let x = Fixture::new();
    let inputs = x.inputs();
    let mut extra = x.accounts.clone();
    extra.push(account(key(62), key(50), false, vec![]));
    rejection(&x, &extra, &inputs, 110);
    for count in 0..5 {
        rejection(&x, &x.accounts[..count], &inputs, 110);
    }
    let mut too_many = x.accounts.clone();
    for n in 0..14 {
        too_many.push(account(key(80 + n), key(50), false, vec![]));
    }
    assert_eq!(too_many.len(), 20);
    rejection(&x, &too_many, &inputs, 110);
}

#[test]
fn preflight_v3_root_policy_issuer_and_action_inputs_are_exact() {
    for index in 0..6 {
        let x = Fixture::new();
        let mut inputs = x.inputs();
        inputs[index] = FIELD_MODULUS;
        rejection(&x, &x.accounts, &inputs, 110);
    }
    for index in [0, 1, 4, 5] {
        let x = Fixture::new();
        let mut inputs = x.inputs();
        inputs[index] = field(77);
        rejection(&x, &x.accounts, &inputs, 110);
    }
    for case in 0..5 {
        let x = Fixture::new();
        let inputs = x.inputs();
        let mut r = x.r();
        match case {
            0 => r.payload[0] ^= 1,
            1 => r.recipient = key(62),
            2 => r.deadline += 1,
            3 => {
                r.metas[2].flags = 1;
            }
            4 => {
                r.issuer_hash = field(9);
            }
            _ => unreachable!(),
        }
        replace(&x.accounts[3], r.encode());
        let mut actual = x.accounts.clone();
        if case == 3 {
            actual[5].is_signer = true;
        }
        rejection(&x, &actual, &inputs, 110);
    }
}

#[test]
fn preflight_v3_root_source_and_both_epoch_changes_invalidate_head() {
    for case in 0..13 {
        let x = Fixture::new();
        let mut c = x.c();
        let mut i = x.i();
        let mut h = x.h();
        match case {
            0 => c.publish(actor(c.publisher), 0, field(7)).unwrap(),
            1 => i
                .observe(
                    &c,
                    actor(i.source),
                    0,
                    0,
                    1,
                    2,
                    [42; 32],
                    true,
                    101,
                    300,
                    110,
                )
                .unwrap(),
            2 => {
                c.set_enabled(actor(c.admin), false).unwrap();
                c.set_enabled(actor(c.admin), true).unwrap();
                i.observe(
                    &c,
                    actor(i.source),
                    2,
                    0,
                    1,
                    2,
                    [42; 32],
                    true,
                    101,
                    300,
                    110,
                )
                .unwrap();
            }
            3 => {
                i.set_enabled(&c, actor(c.admin), false).unwrap();
                i.set_enabled(&c, actor(c.admin), true).unwrap();
                i.observe(
                    &c,
                    actor(i.source),
                    0,
                    2,
                    1,
                    2,
                    [42; 32],
                    true,
                    101,
                    300,
                    110,
                )
                .unwrap();
            }
            4 => {
                h.source_digest = [42; 32];
            }
            5 => h.publisher = key(62),
            6 => h.committed_at = 111,
            7 => h.committed_at = 99,
            8 => h.config = key(62),
            9 => h.issuer = key(62),
            10 => h.config_epoch = 1,
            11 => h.issuer_epoch = 1,
            12 => h.root = field(7),
            _ => unreachable!(),
        }
        // Restore legacy binding to isolate the additional mandatory current head.
        i.bind_current(
            &c,
            actor(c.publisher),
            c.eligibility_epoch,
            i.eligibility_epoch,
            c.root_version,
            i.sequence,
            110,
        )
        .unwrap();
        replace(&x.accounts[0], c.encode());
        replace(&x.accounts[1], i.encode());
        replace(&x.accounts[2], h.encode());
        rejection(&x, &x.accounts, &x.inputs(), 110);
    }
    for case in 0..5 {
        let x = Fixture::new();
        let inputs = x.inputs();
        let mut c = x.c();
        let mut i = x.i();
        match case {
            0 => c.enabled = false,
            1 => i.enabled = false,
            2 => i.status_valid = false,
            3 => i.observed_config_epoch = 1,
            4 => {
                i.eligibility_epoch = 2;
            }
            _ => unreachable!(),
        }
        replace(&x.accounts[0], c.encode());
        replace(&x.accounts[1], i.encode());
        rejection(&x, &x.accounts, &inputs, 110);
    }
}

#[test]
fn preflight_v3_source_expiry_exclusive_request_and_credential_deadlines_inclusive() {
    let x = Fixture::new();
    let inputs = x.inputs();
    x.success(100, &inputs);
    x.success(200, &inputs);
    for now in [-1, 99, 201] {
        rejection(&x, &x.accounts, &inputs, now);
    }
    let mut r = x.r();
    r.deadline = 400;
    replace(&x.accounts[3], r.encode());
    let mut later_inputs = x.inputs();
    later_inputs[3] = field(400);
    x.success(299, &later_inputs);
    rejection(&x, &x.accounts, &later_inputs, 300);
    for (before, after) in [(111, 200), (100, 109), (200, 100)] {
        let mut bad = x.inputs();
        bad[2] = field(before);
        bad[3] = field(after);
        rejection(&x, &x.accounts, &bad, 110);
    }
    let mut too_wide = x.inputs();
    too_wide[2] = [1; 32];
    rejection(&x, &x.accounts, &too_wide, 110);
    let mut expired = x.i();
    expired.expires_at = 109;
    replace(&x.accounts[1], expired.encode());
    rejection(&x, &x.accounts, &later_inputs, 110);
}

#[test]
fn preflight_v3_queue_capacity_replay_and_nonfinalized_states_fail_unchanged() {
    for state in [
        RequestState::Staging,
        RequestState::Cancelled,
        RequestState::Consumed,
    ] {
        let x = Fixture::new();
        let inputs = x.inputs();
        let mut r = x.r();
        r.state = state;
        replace(&x.accounts[3], r.encode());
        rejection(&x, &x.accounts, &inputs, 110);
    }
    for count in [QUEUE_CAPACITY - 1, QUEUE_CAPACITY] {
        let x = Fixture::new();
        let inputs = x.inputs();
        let q = Queue {
            config: *x.accounts[0].key,
            entries: (0..count).map(|n| key(80 + n as u8)).collect(),
        };
        replace(&x.accounts[4], q.encode());
        if count < QUEUE_CAPACITY {
            x.success(110, &inputs);
        } else {
            rejection(&x, &x.accounts, &inputs, 110);
        }
    }
    let x = Fixture::new();
    let inputs = x.inputs();
    let q = Queue {
        config: *x.accounts[0].key,
        entries: vec![*x.accounts[3].key],
    };
    replace(&x.accounts[4], q.encode());
    rejection(&x, &x.accounts, &inputs, 110);
    let mut r = x.r();
    r.uploaded -= 1;
    r.payload[3] = 0;
    replace(&x.accounts[3], r.encode());
    rejection(&x, &x.accounts, &inputs, 110);
}

#[test]
fn preflight_v3_identity_codec_owner_and_pda_cross_wiring_fails() {
    for index in 0..5 {
        for case in 0..4 {
            let x = Fixture::new();
            let inputs = x.inputs();
            let mut a = x.accounts.clone();
            match case {
                0 => a[index].executable = true,
                1 => {
                    let mut b = a[index].try_borrow_data().unwrap().to_vec();
                    b.pop();
                    replace(&a[index], b);
                }
                2 => {
                    let mut b = a[index].try_borrow_data().unwrap().to_vec();
                    b[7] = b'2';
                    replace(&a[index], b);
                }
                3 => a[index].key = Box::leak(Box::new(key(62))),
                _ => unreachable!(),
            }
            rejection(&x, &a, &inputs, 110);
        }
    }
    for case in 0..10 {
        let x = Fixture::new();
        let inputs = x.inputs();
        let mut c = x.c();
        let mut i = x.i();
        let mut r = x.r();
        match case {
            0 => c.circuit_id[0] ^= 1,
            1 => c.package_id[0] ^= 1,
            2 => c.schema_id[0] ^= 1,
            3 => c.profile_id[0] ^= 1,
            4 => c.ordinary_vk_digest[0] ^= 1,
            5 => i.config = key(62),
            6 => r.config = key(62),
            7 => r.nonce = [62; 32],
            8 => r.creator = key(62),
            9 => i.profile_version = 2,
            _ => unreachable!(),
        }
        replace(&x.accounts[0], c.encode());
        replace(&x.accounts[1], i.encode());
        replace(&x.accounts[3], r.encode());
        rejection(&x, &x.accounts, &inputs, 110);
    }
    let x = Fixture::new();
    let inputs = x.inputs();
    replace(
        &x.accounts[4],
        Queue {
            config: key(62),
            entries: vec![],
        }
        .encode(),
    );
    rejection(&x, &x.accounts, &inputs, 110);
    let mut foreign_program = x.program.to_bytes();
    foreign_program[0] ^= 1;
    assert!(check(
        &Pubkey::new_from_array(foreign_program),
        &x.accounts,
        &inputs,
        110
    )
    .is_err());
}
