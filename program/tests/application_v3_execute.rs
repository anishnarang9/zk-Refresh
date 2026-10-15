//! Tests-first negative Execute integration. All account state is synthetic and
//! the proof is deliberately invalid. No case authorizes a queue effect.
//!
//! POSITIVE FIXTURE DEPENDENCY: generate a fresh Full proof under the frozen v3
//! package for action_hash(actual program, exact finalized request), with its
//! matching root/issuer/times/policy public values. Retained corpus action12345
//! cannot be substituted: finding a request with that hash is a field-preimage
//! problem. Never replace the expected action with12345 to make a proof pass.
//! Once that public-only fixture exists, add successful exact queue append plus
//! request consumption, second/randomized-proof replay, restart, queue-full and
//! held-mutable-borrow atomicity tests. Actual unrelated/own leaf revocation
//! requires corresponding real membership witnesses/proofs. The tests below
//! cover persisted replay tombstones and source/root invalidation only.
#![allow(deprecated)]
use solana_program::{
    account_info::AccountInfo,
    clock::Clock,
    hash::hash,
    program_error::ProgramError,
    program_stubs::{set_syscall_stubs, SyscallStubs},
    pubkey::Pubkey,
};
use zk_fresh_program::{
    application_preflight_v3::check,
    application_runtime_v3 as runtime,
    application_v3::{
        action_hash, AppError, Authority, Config, Issuer, PublisherHead, PublisherHeadBinding,
        Queue, RelevantMeta, Request, RequestState, PREFIX, QUEUE_CAPACITY,
    },
    generated_vk_v3 as identity, process_instruction,
};

const NOW: i64 = 100;
fn key(n: u8) -> Pubkey {
    Pubkey::new_from_array([n; 32])
}
fn field(n: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&n.to_be_bytes());
    bytes
}
fn actor(key: Pubkey) -> Authority {
    Authority {
        key,
        is_signer: true,
    }
}
fn account(key: Pubkey, program: Pubkey, writable: bool, data: Vec<u8>) -> AccountInfo<'static> {
    AccountInfo::new(
        Box::leak(Box::new(key)),
        false,
        writable,
        Box::leak(Box::new(1)),
        Box::leak(data.into_boxed_slice()),
        Box::leak(Box::new(program)),
        false,
        0,
    )
}
fn replace(account: &AccountInfo, data: Vec<u8>) {
    *account.try_borrow_mut_data().unwrap() = Box::leak(data.into_boxed_slice());
}
fn snapshot(accounts: &[AccountInfo]) -> Vec<(Pubkey, u64, Vec<u8>)> {
    accounts
        .iter()
        .map(|a| {
            (
                *a.owner,
                a.lamports(),
                a.try_borrow_data().unwrap().to_vec(),
            )
        })
        .collect()
}
struct FixedClock;
impl SyscallStubs for FixedClock {
    fn sol_get_clock_sysvar(&self, destination: *mut u8) -> u64 {
        unsafe {
            std::ptr::write_unaligned(
                destination.cast::<Clock>(),
                Clock {
                    unix_timestamp: NOW,
                    ..Clock::default()
                },
            );
        }
        0
    }
}
struct ClockGuard(Option<Box<dyn SyscallStubs>>);
impl Drop for ClockGuard {
    fn drop(&mut self) {
        set_syscall_stubs(self.0.take().unwrap());
    }
}
struct Fixture {
    program: Pubkey,
    accounts: Vec<AccountInfo<'static>>,
    inputs: [[u8; 32]; 6],
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
            NOW - 1,
            300,
            NOW,
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
                expected_source_sequence: i.sequence,
                expected_source_digest: i.digest,
                expected_publication_sequence: 0,
                expected_publication_digest: [0; 32],
                next_publication_sequence: 1,
                envelope_digest: [91; 32],
            },
            NOW,
        )
        .unwrap();
        let creator = key(21);
        let nonce = [11; 32];
        let rk = runtime::request_address(&program, &ck, &creator, &nonce).0;
        let qk = runtime::queue_address(&program, &ck).0;
        let hk = runtime::publisher_head_address(&program, &ck, &ik, &c.publisher).0;
        let mut r = Request {
            config: ck,
            creator,
            nonce,
            issuer_hash: i.issuer_hash,
            recipient: key(22),
            request_type: 1,
            deadline: 200,
            payload_len: 4,
            uploaded: 4,
            metas_uploaded: 2,
            state: RequestState::Staging,
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
            ],
            payload: b"work".to_vec(),
        };
        r.finalize(NOW).unwrap();
        let inputs = [
            c.root,
            i.issuer_hash,
            field(100),
            field(200),
            action_hash(&program, &c, &r).unwrap(),
            c.policy_id,
        ];
        Self {
            program,
            inputs,
            accounts: vec![
                account(ck, program, false, c.encode()),
                account(ik, program, false, i.encode()),
                account(hk, program, false, h.encode()),
                account(rk, program, true, r.encode()),
                account(qk, program, true, Queue::new(ck).encode()),
            ],
        }
    }
    fn wire(&self) -> Vec<u8> {
        let mut wire = vec![PREFIX, 7];
        for value in self.inputs {
            wire.extend(value);
        }
        wire.extend([0; 256]); // Intentionally invalid; never an authorization fixture.
        wire
    }
    fn request(&self) -> Request {
        Request::decode(&self.accounts[3].try_borrow_data().unwrap()).unwrap()
    }
    fn config(&self) -> Config {
        Config::decode(&self.accounts[0].try_borrow_data().unwrap()).unwrap()
    }
    fn issuer(&self) -> Issuer {
        Issuer::decode(&self.accounts[1].try_borrow_data().unwrap()).unwrap()
    }
}

#[test]
fn execute_v3_integrates_current_state_rejections_without_appending_or_consuming() {
    let _clock = ClockGuard(Some(set_syscall_stubs(Box::new(FixedClock))));
    let mut mismatches = Vec::new();
    for (case, expected) in [
        ("invalid-proof", AppError::Proof),
        ("consumed", AppError::Consumed),
        ("queued-tombstone", AppError::Consumed),
        ("cancelled", AppError::Consumed),
        ("staging", AppError::Consumed),
        ("capacity", AppError::Capacity),
        ("disabled-config", AppError::Policy),
        ("inactive-source", AppError::Status),
        ("expired-source", AppError::Status),
        ("published-root", AppError::Binding),
        ("stale-head", AppError::Binding),
        ("policy", AppError::Policy),
        ("expired-request", AppError::Expired),
        ("changed-payload", AppError::Action),
        ("synthetic-corpus-action", AppError::Action),
    ] {
        let mut x = Fixture::new();
        // Establish that each negative case starts from structurally eligible,
        // finalized state. This grants no proof or queue authorization.
        assert_eq!(check(&x.program, &x.accounts, &x.inputs, NOW), Ok(()));
        match case {
            "consumed" | "cancelled" | "staging" | "expired-request" | "changed-payload" => {
                let mut r = x.request();
                match case {
                    "consumed" => r.state = RequestState::Consumed,
                    "cancelled" => r.state = RequestState::Cancelled,
                    "staging" => r.state = RequestState::Staging,
                    "expired-request" => r.deadline = NOW - 1,
                    _ => r.payload[0] ^= 1,
                }
                replace(&x.accounts[3], r.encode());
            }
            "queued-tombstone" | "capacity" => {
                let mut q = Queue::new(*x.accounts[0].key);
                q.entries = if case == "queued-tombstone" {
                    vec![*x.accounts[3].key]
                } else {
                    (0..QUEUE_CAPACITY).map(|n| key(100 + n as u8)).collect()
                };
                replace(&x.accounts[4], q.encode());
            }
            "disabled-config" | "published-root" => {
                let mut c = x.config();
                if case == "disabled-config" {
                    c.set_enabled(actor(c.admin), false).unwrap();
                } else {
                    c.publish(actor(c.publisher), 0, field(9)).unwrap();
                }
                replace(&x.accounts[0], c.encode());
            }
            "inactive-source" | "expired-source" => {
                let mut i = x.issuer();
                if case == "inactive-source" {
                    // An authenticated observation transition model, not own-leaf
                    // Merkle revocation or upstream envelope authentication.
                    i.observe(
                        &x.config(),
                        actor(i.source),
                        0,
                        0,
                        1,
                        2,
                        [42; 32],
                        false,
                        NOW,
                        300,
                        NOW,
                    )
                    .unwrap();
                } else {
                    i.expires_at = NOW;
                }
                replace(&x.accounts[1], i.encode());
            }
            "stale-head" => {
                let mut h =
                    PublisherHead::decode(&x.accounts[2].try_borrow_data().unwrap()).unwrap();
                h.source_digest = [42; 32];
                replace(&x.accounts[2], h.encode());
            }
            "policy" => x.inputs[5] = field(9),
            "synthetic-corpus-action" => x.inputs[4] = field(12345),
            _ => {}
        }
        let before = snapshot(&x.accounts);
        let result = process_instruction(&x.program, &x.accounts, &x.wire());
        assert_eq!(
            snapshot(&x.accounts),
            before,
            "{case}: failed Execute partially appended queue or consumed request"
        );
        if result != Err(ProgramError::from(expected)) {
            mismatches.push((case, result, expected));
        }
    }
    assert!(
        mismatches.is_empty(),
        "Execute must integrate preflight then proof verification; mismatches: {mismatches:?}"
    );
}

#[test]
fn retained_component_public_fixture_is_explicitly_not_a_request_bound_proof() {
    let raw = include_bytes!("data/v3-credential-0-full-base.ark-public");
    let sha: String = hash(raw)
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        sha,
        "cb19d40c4f24a67fde62710a5eb5fc019e3d037b592d6f2243fdc9186d138f9b"
    );
    assert_eq!(raw.len(), 200);
    assert_eq!(&raw[..8], &6u64.to_le_bytes());
    let mut corpus_action: [u8; 32] = raw[136..168].try_into().unwrap();
    corpus_action.reverse();
    assert_eq!(corpus_action, field(12345));
    assert_ne!(
        Fixture::new().inputs[4],
        corpus_action,
        "never use retained synthetic-action proof as positive authorization"
    );
}
