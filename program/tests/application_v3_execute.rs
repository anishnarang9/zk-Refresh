//! Host Execute integration using synthetic current-account state.
//! Default cases use deliberately invalid proofs and establish rejection behavior.
//! The ignored training join imports a genuine request-bound Full proof from
//! private storage, checks its exact finalized request, and exercises one queue
//! append, request consumption, replay and failure atomicity. It establishes no
//! deployment, live-state authentication or actual leaf-revocation evidence.
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
    account_with_owner(key, program, writable, data)
}
fn account_with_owner(
    key: Pubkey,
    owner: Pubkey,
    writable: bool,
    data: Vec<u8>,
) -> AccountInfo<'static> {
    AccountInfo::new(
        Box::leak(Box::new(key)),
        false,
        writable,
        Box::leak(Box::new(1)),
        Box::leak(data.into_boxed_slice()),
        Box::leak(Box::new(owner)),
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
fn full_snapshot(
    accounts: &[AccountInfo],
) -> Vec<(Pubkey, Pubkey, bool, bool, bool, u64, Vec<u8>)> {
    accounts
        .iter()
        .map(|a| {
            (
                *a.key,
                *a.owner,
                a.is_signer,
                a.is_writable,
                a.executable,
                a.lamports(),
                a.try_borrow_data().unwrap().to_vec(),
            )
        })
        .collect()
}
struct FixedClock {
    now: i64,
}
impl SyscallStubs for FixedClock {
    fn sol_get_clock_sysvar(&self, destination: *mut u8) -> u64 {
        unsafe {
            std::ptr::write_unaligned(
                destination.cast::<Clock>(),
                Clock {
                    unix_timestamp: self.now,
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
    let _clock = ClockGuard(Some(set_syscall_stubs(Box::new(FixedClock { now: NOW }))));
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
fn execute_v3_rejects_missing_disabled_and_stale_issuer_and_bad_account_views() {
    let _clock = ClockGuard(Some(set_syscall_stubs(Box::new(FixedClock { now: NOW }))));
    for (case, expected) in [
        ("missing-issuer", AppError::Accounts),
        ("disabled-issuer", AppError::Policy),
        ("stale-observation", AppError::Status),
        ("wrong-order", AppError::State),
        ("wrong-privilege", AppError::Privileges),
        ("wrong-owner", AppError::Owner),
    ] {
        let mut x = Fixture::new();
        match case {
            "missing-issuer" => {
                x.accounts.remove(1);
            }
            "disabled-issuer" => {
                let mut issuer = x.issuer();
                issuer
                    .set_enabled(&x.config(), actor(x.config().admin), false)
                    .unwrap();
                replace(&x.accounts[1], issuer.encode());
            }
            "stale-observation" => {
                let mut issuer = x.issuer();
                // Keep the issuer codec/admission state valid, then execute
                // after its signed status has expired.
                issuer.observed_at = 0;
                issuer.expires_at = 300;
                replace(&x.accounts[1], issuer.encode());
            }
            "wrong-order" => x.accounts.swap(1, 2),
            "wrong-privilege" => x.accounts[3].is_writable = false,
            "wrong-owner" => {
                let issuer_key = *x.accounts[1].key;
                let issuer_data = x.accounts[1].try_borrow_data().unwrap().to_vec();
                x.accounts[1] = account_with_owner(issuer_key, key(99), false, issuer_data);
            }
            _ => unreachable!(),
        }
        let clock_now = if case == "stale-observation" {
            301
        } else {
            NOW
        };
        set_syscall_stubs(Box::new(FixedClock { now: clock_now }));
        let before = full_snapshot(&x.accounts);
        assert_eq!(
            process_instruction(&x.program, &x.accounts, &x.wire()),
            Err(ProgramError::from(expected)),
            "{case}: Execute accepted invalid current account state"
        );
        assert_eq!(
            full_snapshot(&x.accounts),
            before,
            "{case}: rejected Execute changed account keys, metadata, or state"
        );
    }
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

// This opt-in join reads only private, ignored fixture files; no proof is embedded.
#[allow(dead_code)]
#[path = "../examples/export_v3_request_fixture.rs"]
mod request_exporter;

struct TrainingClock(i64);
impl SyscallStubs for TrainingClock {
    fn sol_get_clock_sysvar(&self, destination: *mut u8) -> u64 {
        unsafe {
            std::ptr::write_unaligned(
                destination.cast::<Clock>(),
                Clock {
                    unix_timestamp: self.0,
                    ..Clock::default()
                },
            );
        }
        0
    }
}

fn private_training_file(directory: &std::path::Path, name: &str, length: usize) -> Vec<u8> {
    use std::{
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    };
    let path = directory.join(name);
    let before = std::fs::symlink_metadata(&path).expect("private training metadata");
    assert!(before.is_file());
    assert_eq!(before.permissions().mode() & 0o7777, 0o600);
    assert_eq!(before.uid(), std::fs::metadata(directory).unwrap().uid());
    assert_eq!(before.nlink(), 1);
    assert_eq!(before.len(), length as u64);
    #[cfg(target_os = "macos")]
    let flags = 0x0100 | 0x0004;
    #[cfg(target_os = "linux")]
    let flags = 0x20000 | 0x0800;
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    compile_error!("private training fixture requires macOS or Linux");
    let identity = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.mode(),
            m.uid(),
            m.nlink(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(&path)
        .expect("private training handle");
    assert_eq!(identity(&file.metadata().unwrap()), identity(&before));
    let mut bytes = Vec::new();
    (&mut file)
        .take(length as u64 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes.len(), length);
    assert_eq!(identity(&file.metadata().unwrap()), identity(&before));
    assert_eq!(
        identity(&std::fs::symlink_metadata(path).unwrap()),
        identity(&before)
    );
    bytes
}

#[test]
#[ignore = "requires genuine private request-bound proof; run with --test-threads=1"]
fn request_bound_training_execute_appends_consumes_rejects_replay_and_rolls_back() {
    use std::os::unix::fs::PermissionsExt;
    let directory = std::path::PathBuf::from(
        std::env::var_os("M2_V3_HOST_FIXTURE").expect("private training fixture required"),
    );
    assert!(directory.is_absolute());
    assert_eq!(directory.canonicalize().unwrap(), directory);
    let info = std::fs::symlink_metadata(&directory).unwrap();
    assert!(info.is_dir());
    assert_eq!(info.permissions().mode() & 0o7777, 0o700);
    let f1 = private_training_file(&directory, "finalized-request.v3f1", 2874);
    let f2 = private_training_file(&directory, "finalized-request.v3f2", 561);
    let wire = private_training_file(&directory, "full-solana-wire.bin", 448);
    for (bytes, variable) in [
        (f1.as_slice(), "M2_V3_HOST_F1_SHA256"),
        (f2.as_slice(), "M2_V3_HOST_F2_SHA256"),
        (wire.as_slice(), "M2_V3_HOST_WIRE_SHA256"),
    ] {
        let expected = std::env::var(variable).expect("external fixture identity pin required");
        assert!(
            training_hash_matches(bytes, &expected),
            "private fixture identity mismatch"
        );
    }
    assert!(request_exporter::export_fixture_from_wire(&f1).unwrap() == f2);
    assert!(wire[..192] == f1[52..244]);
    let program = Pubkey::new_from_array(f1[4..36].try_into().unwrap());
    let now = i64::from_le_bytes(f1[36..44].try_into().unwrap());
    let c = Config::decode(&f1[244..625]).unwrap();
    let r = Request::decode(&f1[625..]).unwrap();
    let inputs: [[u8; 32]; 6] =
        std::array::from_fn(|index| wire[index * 32..(index + 1) * 32].try_into().unwrap());
    let proof: [u8; 256] = wire[192..].try_into().unwrap();
    let _clock = ClockGuard(Some(set_syscall_stubs(Box::new(TrainingClock(now)))));
    let construct = || {
        let ck = runtime::config_address(&program, &c.admin, &c.seed).0;
        let ik = runtime::issuer_address(&program, &ck, &r.issuer_hash).0;
        let mut aki = [0; 32];
        aki[..20].fill(8);
        let mut issuer = Issuer::enroll(
            ck,
            &c,
            actor(c.admin),
            r.issuer_hash,
            aki,
            key(20),
            1,
            [8; 32],
        )
        .unwrap();
        issuer
            .observe(
                &c,
                actor(issuer.source),
                c.eligibility_epoch,
                issuer.eligibility_epoch,
                0,
                1,
                [41; 32],
                true,
                now,
                now + 240,
                now,
            )
            .unwrap();
        let (issuer, head) = PublisherHead::prepare_bind(
            ck,
            ik,
            &c,
            &issuer,
            actor(c.publisher),
            None,
            &PublisherHeadBinding {
                expected_config_epoch: c.eligibility_epoch,
                expected_issuer_epoch: issuer.eligibility_epoch,
                expected_root: c.root,
                expected_root_version: c.root_version,
                expected_source_sequence: issuer.sequence,
                expected_source_digest: issuer.digest,
                expected_publication_sequence: 0,
                expected_publication_digest: [0; 32],
                next_publication_sequence: 1,
                envelope_digest: [91; 32],
            },
            now,
        )
        .unwrap();
        vec![
            account(ck, program, false, c.encode()),
            account(ik, program, false, issuer.encode()),
            account(
                runtime::publisher_head_address(&program, &ck, &ik, &c.publisher).0,
                program,
                false,
                head.encode(),
            ),
            account(
                runtime::request_address(&program, &ck, &r.creator, &r.nonce).0,
                program,
                true,
                r.encode(),
            ),
            account(
                runtime::queue_address(&program, &ck).0,
                program,
                true,
                Queue::new(ck).encode(),
            ),
        ]
    };
    let instruction = [vec![PREFIX, 7], wire].concat();
    let accounts = construct();
    assert_eq!(check(&program, &accounts, &inputs, now), Ok(()));
    assert_eq!(runtime::verify(&inputs, &proof), Ok(()));
    let before = snapshot(&accounts);
    let result = process_instruction(&program, &accounts, &instruction);
    assert_eq!(
        result,
        Ok(()),
        "genuine request-bound proof must reach queue effect"
    );
    let mut expected = before.clone();
    let mut consumed = r.clone();
    consumed.state = RequestState::Consumed;
    expected[3].2 = consumed.encode();
    let mut queued = Queue::new(*accounts[0].key);
    queued.entries.push(*accounts[3].key);
    expected[4].2 = queued.encode();
    assert!(
        snapshot(&accounts) == expected,
        "effect changed unrelated account bytes"
    );
    assert_eq!(
        process_instruction(&program, &accounts, &instruction),
        Err(ProgramError::from(AppError::Consumed))
    );
    assert!(snapshot(&accounts) == expected);

    // Reconstruct persisted bytes into fresh AccountInfos to model a host restart.
    let restarted = construct();
    replace(&restarted[3], expected[3].2.clone());
    replace(&restarted[4], expected[4].2.clone());
    assert_eq!(
        process_instruction(&program, &restarted, &instruction),
        Err(ProgramError::from(AppError::Consumed))
    );
    assert!(snapshot(&restarted) == expected);

    let rollback = construct();
    let before = snapshot(&rollback);
    let held = rollback[3].try_borrow_data().unwrap();
    assert_eq!(
        process_instruction(&program, &rollback, &instruction),
        Err(ProgramError::AccountBorrowFailed)
    );
    assert!(
        snapshot(&rollback) == before,
        "second destination borrow partially appended"
    );
    drop(held);

    let full = construct();
    let mut queue = Queue::new(*full[0].key);
    queue.entries = (0..QUEUE_CAPACITY)
        .map(|index| key(100 + index as u8))
        .collect();
    replace(&full[4], queue.encode());
    let before = snapshot(&full);
    assert_eq!(
        process_instruction(&program, &full, &instruction),
        Err(ProgramError::from(AppError::Capacity))
    );
    assert!(snapshot(&full) == before);
}

fn training_hash_matches(bytes: &[u8], expected: &str) -> bool {
    expected.len() == 64
        && expected
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && hash(bytes)
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
            == expected
}

#[test]
fn training_fixture_hash_pins_reject_substitution_and_malformed_digests() {
    let data = b"fixture identity";
    let expected: String = hash(data)
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(training_hash_matches(data, &expected));
    for changed in [
        "0".repeat(64),
        expected.to_uppercase(),
        expected[..63].to_owned(),
    ] {
        assert!(!training_hash_matches(data, &changed));
    }
    assert!(!training_hash_matches(b"substituted fixture", &expected));
}
