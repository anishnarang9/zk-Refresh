//! Tests-first signed issuer-status revision. No CPI, proof or Execute evidence.
//! Observe83: prefix/op[0..2], config epoch[2..10], issuer epoch[10..18],
//! expected sequence[18..26], next sequence[26..34], digest[34..66], active[66],
//! observed[67..75], expires[75..83]. Integers are BE; bool is exactly 0 or 1.
#![allow(deprecated)]
use solana_program::{
    account_info::AccountInfo,
    clock::Clock,
    entrypoint::ProgramResult,
    program_stubs::{set_syscall_stubs, SyscallStubs},
    pubkey::Pubkey,
    system_program,
};
use zk_fresh_program::{
    application_runtime_v3 as runtime,
    application_v3::{AppInstruction, Authority, Config, Issuer, PREFIX},
    generated_vk_v3 as identity, process_instruction,
};

fn field(n: u8) -> [u8; 32] {
    let mut b = [0; 32];
    b[31] = n;
    b
}
fn account(
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
fn actor(key: Pubkey) -> AccountInfo<'static> {
    account(key, system_program::id(), true, false, vec![])
}
struct Fixture {
    program: Pubkey,
    config: AccountInfo<'static>,
    issuer: AccountInfo<'static>,
}
impl Fixture {
    fn new() -> Self {
        let program = Pubkey::new_from_array([12; 32]);
        let c = Config {
            admin: Pubkey::new_from_array([18; 32]),
            seed: [7; 32],
            publisher: Pubkey::new_from_array([19; 32]),
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
        let i = Issuer::enroll(
            ck,
            &c,
            Authority {
                key: c.admin,
                is_signer: true,
            },
            field(8),
            aki,
            Pubkey::new_from_array([20; 32]),
            1,
            [8; 32],
        )
        .unwrap();
        let ik = runtime::issuer_address(&program, &ck, &i.issuer_hash).0;
        Self {
            program,
            config: account(ck, program, false, true, c.encode()),
            issuer: account(ik, program, false, true, i.encode()),
        }
    }
    fn c(&self) -> Config {
        Config::decode(&self.config.try_borrow_data().unwrap()).unwrap()
    }
    fn i(&self) -> Issuer {
        Issuer::decode(&self.issuer.try_borrow_data().unwrap()).unwrap()
    }
    fn ro_config(&self) -> AccountInfo<'static> {
        let mut a = self.config.clone();
        a.is_writable = false;
        a
    }
    fn observe(&self, wire: &[u8]) -> ProgramResult {
        process_instruction(
            &self.program,
            &[
                actor(self.i().source),
                self.ro_config(),
                self.issuer.clone(),
            ],
            wire,
        )
    }
    fn bind(&self, ce: u64, ie: u64, sequence: u64) -> ProgramResult {
        let mut b = vec![PREFIX, 11];
        for n in [ce, ie, self.c().root_version, sequence] {
            b.extend(n.to_be_bytes());
        }
        process_instruction(
            &self.program,
            &[
                actor(self.c().publisher),
                self.ro_config(),
                self.issuer.clone(),
            ],
            &b,
        )
    }
    fn toggle_config(&self, enabled: bool) {
        assert_eq!(
            process_instruction(
                &self.program,
                &[actor(self.c().admin), self.config.clone()],
                &[PREFIX, 10, u8::from(enabled)]
            ),
            Ok(())
        );
    }
    fn toggle_issuer(&self, enabled: bool) {
        assert_eq!(
            process_instruction(
                &self.program,
                &[actor(self.c().admin), self.ro_config(), self.issuer.clone()],
                &[PREFIX, 12, u8::from(enabled)]
            ),
            Ok(())
        );
    }
}
fn observe(ce: u64, ie: u64, expected: u64, next: u64, active: u8, time: i64) -> Vec<u8> {
    let mut b = vec![PREFIX, 3];
    for n in [ce, ie, expected, next] {
        b.extend(n.to_be_bytes());
    }
    b.extend([next as u8; 32]);
    b.push(active);
    b.extend(time.to_be_bytes());
    b.extend((time + 200).to_be_bytes());
    b
}
struct ClockStub;
impl SyscallStubs for ClockStub {
    fn sol_get_clock_sysvar(&self, p: *mut u8) -> u64 {
        unsafe {
            (p as *mut Clock).write(Clock {
                unix_timestamp: 110,
                ..Clock::default()
            });
        }
        0
    }
}
struct Restore(Option<Box<dyn SyscallStubs>>);
impl Restore {
    fn clock() -> Self {
        Self(Some(set_syscall_stubs(Box::new(ClockStub))))
    }
}
impl Drop for Restore {
    fn drop(&mut self) {
        set_syscall_stubs(self.0.take().unwrap());
    }
}

#[test]
fn v3_observe83_accepts_explicit_authenticated_inactive_bit() {
    let b = observe(2, 4, 6, 7, 0, 100);
    assert_eq!(b.len(), 83);
    assert_eq!(b[66], 0);
    assert_eq!(
        AppInstruction::parse(&b).is_ok(),
        true,
        "v3 Observe83 must accept the explicit signed inactive bit and both epochs"
    );
    let mut active = b;
    active[66] = 1;
    assert!(AppInstruction::parse(&active).is_ok());
}

#[test]
fn v3_observe_rejects_unsigned_status_and_epochless_legacy_wires() {
    let mut old82 = observe(0, 0, 0, 1, 1, 100);
    old82.remove(66);
    assert_eq!(old82.len(), 82);
    assert!(
        AppInstruction::parse(&old82).is_err(),
        "old Observe82 omits signed active"
    );
    let mut epochless67 = observe(0, 0, 0, 1, 1, 100);
    epochless67.drain(2..18);
    assert_eq!(epochless67.len(), 67);
    assert!(AppInstruction::parse(&epochless67).is_err());
    epochless67.remove(50);
    assert_eq!(epochless67.len(), 66);
    assert!(AppInstruction::parse(&epochless67).is_err());
}

#[test]
fn v3_observe83_rejects_every_truncation_invalid_bool_and_trailing_byte() {
    let b = observe(0, 0, 0, 1, 1, 100);
    for end in 0..83 {
        assert!(
            AppInstruction::parse(&b[..end]).is_err(),
            "accepted truncation {end}"
        );
    }
    for invalid in [2, 127, 255] {
        let mut bad = b.clone();
        bad[66] = invalid;
        assert!(AppInstruction::parse(&bad).is_err());
    }
    let mut trailing = b;
    trailing.push(0);
    assert!(AppInstruction::parse(&trailing).is_err());
}

#[test]
fn v3_authenticated_inactive_advances_negative_fact_and_requires_later_active_then_bind() {
    let _clock = Restore::clock();
    let x = Fixture::new();
    assert_eq!(x.observe(&observe(0, 0, 0, 1, 1, 100)), Ok(()));
    assert_eq!(x.bind(0, 0, 1), Ok(()));
    assert_eq!(x.i().binding_current(&x.c()), Ok(()));
    assert_eq!(
        x.observe(&observe(0, 0, 1, 2, 0, 101)),
        Ok(()),
        "authenticated negative fact must be recorded"
    );
    let negative = x.i();
    assert_eq!(negative.sequence, 2);
    assert_eq!(negative.digest, [2; 32]);
    assert_eq!((negative.observed_at, negative.expires_at), (101, 301));
    assert_eq!(
        (
            negative.observed_config_epoch,
            negative.observed_issuer_epoch
        ),
        (0, 0)
    );
    assert!(!negative.status_valid);
    assert!(negative.fresh(&x.c(), 110).is_err());
    assert!(negative.binding_current(&x.c()).is_err());
    assert!(x.bind(0, 0, 2).is_err());
    assert_eq!(
        x.i(),
        negative,
        "failed Bind must preserve negative observation"
    );
    for (expected, next) in [(1, 2), (2, 2), (2, 4)] {
        assert!(x.observe(&observe(0, 0, expected, next, 1, 102)).is_err());
        assert_eq!(x.i(), negative);
    }
    assert_eq!(x.observe(&observe(0, 0, 2, 3, 1, 102)), Ok(()));
    assert!(x.i().status_valid);
    assert_eq!(x.i().fresh(&x.c(), 110), Ok(()));
    assert!(
        x.i().binding_current(&x.c()).is_err(),
        "active observation does not implicitly rebind"
    );
    assert_eq!(x.bind(0, 0, 3), Ok(()));
    assert_eq!(x.i().binding_current(&x.c()), Ok(()));
}

#[test]
fn v3_inactive_and_active_observations_both_require_current_signed_epochs() {
    let _clock = Restore::clock();
    let x = Fixture::new();
    assert_eq!(x.observe(&observe(0, 0, 0, 1, 0, 100)), Ok(()));
    x.toggle_config(false);
    x.toggle_config(true);
    x.toggle_issuer(false);
    x.toggle_issuer(true);
    assert_eq!((x.c().eligibility_epoch, x.i().eligibility_epoch), (2, 2));
    let before = x.i();
    for active in [0, 1] {
        for (ce, ie) in [(0, 0), (0, 2), (2, 0)] {
            assert!(x.observe(&observe(ce, ie, 1, 2, active, 101)).is_err());
            assert_eq!(
                x.i(),
                before,
                "stale signed epoch must not advance the source fact"
            );
        }
    }
    assert_eq!(x.observe(&observe(2, 2, 1, 2, 0, 101)), Ok(()));
    assert!(x.i().fresh(&x.c(), 110).is_err());
    assert!(x.bind(2, 2, 2).is_err());
    assert_eq!(x.observe(&observe(2, 2, 2, 3, 1, 102)), Ok(()));
    assert!(x.bind(0, 2, 3).is_err());
    assert!(x.bind(2, 0, 3).is_err());
    assert_eq!(x.bind(2, 2, 3), Ok(()));
    assert_eq!(x.i().binding_current(&x.c()), Ok(()));
}

#[test]
fn v3_inactive_observation_still_requires_source_signature_fresh_time_and_nonzero_sequence() {
    let _clock = Restore::clock();
    let x = Fixture::new();
    let before = x.i();
    for (expected, next, time) in [(0, 0, 100), (0, 1, 111), (0, 1, -300)] {
        assert!(x.observe(&observe(0, 0, expected, next, 0, time)).is_err());
        assert_eq!(x.i(), before);
    }
    for wrong_key in [false, true] {
        let mut source = actor(if wrong_key { x.c().admin } else { x.i().source });
        source.is_signer = wrong_key;
        assert!(process_instruction(
            &x.program,
            &[source, x.ro_config(), x.issuer.clone()],
            &observe(0, 0, 0, 1, 0, 100)
        )
        .is_err());
        assert_eq!(x.i(), before);
    }
}
