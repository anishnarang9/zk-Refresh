//! Administrative runtime contract tests only. CPI allocation below is a host model,
//! not loaded-ELF allocation, transaction rollback or proof verification evidence.
#![allow(deprecated)]
use solana_program::{
    account_info::AccountInfo,
    clock::Clock,
    entrypoint::ProgramResult,
    instruction::Instruction,
    program_error::ProgramError,
    program_stubs::{set_syscall_stubs, SyscallStubs},
    pubkey::Pubkey,
    rent::Rent,
    system_program,
};
use std::sync::{
    atomic::{AtomicI64, Ordering},
    Arc, Mutex,
};
use zk_fresh_program::{
    application_runtime_v3 as runtime, application_v3::*, generated_vk_v3 as identity,
    process_instruction,
};
fn f(n: u8) -> [u8; 32] {
    let mut b = [0; 32];
    b[31] = n;
    b
}
fn ai(
    key: Pubkey,
    owner: Pubkey,
    signer: bool,
    writable: bool,
    data: Vec<u8>,
    lamports: u64,
    executable: bool,
) -> AccountInfo<'static> {
    AccountInfo::new(
        Box::leak(Box::new(key)),
        signer,
        writable,
        Box::leak(Box::new(lamports)),
        Box::leak(data.into_boxed_slice()),
        Box::leak(Box::new(owner)),
        executable,
        0,
    )
}
fn actor(key: Pubkey, writable: bool) -> AccountInfo<'static> {
    ai(
        key,
        system_program::id(),
        true,
        writable,
        vec![],
        1_000_000_000,
        false,
    )
}
fn fresh(key: Pubkey) -> AccountInfo<'static> {
    ai(key, system_program::id(), false, true, vec![], 0, false)
}
fn system() -> AccountInfo<'static> {
    ai(
        system_program::id(),
        Pubkey::new_unique(),
        false,
        false,
        vec![],
        0,
        true,
    )
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
struct Fixture {
    program: Pubkey,
    c: Config,
    i: Issuer,
    ca: AccountInfo<'static>,
    ia: AccountInfo<'static>,
}
fn fixture() -> Fixture {
    let program = Pubkey::new_from_array([12; 32]);
    let c = Config {
        admin: Pubkey::new_from_array([18; 32]),
        seed: [7; 32],
        publisher: Pubkey::new_from_array([19; 32]),
        genesis: [1; 32],
        policy_id: f(5),
        policy_version: 1,
        circuit_id: identity::CIRCUIT_ID,
        package_id: identity::PACKAGE_ID,
        schema_id: identity::SEMANTIC_SCHEMA_ID,
        profile_id: identity::PROFILE_ID,
        ordinary_vk_digest: identity::ORDINARY_VK_DIGEST,
        root: f(6),
        root_version: 0,
        eligibility_epoch: 0,
        enabled: true,
    };
    let config_key = runtime::config_address(&program, &c.admin, &c.seed).0;
    let i = Issuer::enroll(
        config_key,
        &c,
        Authority {
            key: c.admin,
            is_signer: true,
        },
        f(8),
        {
            let mut b = [0; 32];
            b[..20].fill(0xaa);
            b
        },
        Pubkey::new_from_array([20; 32]),
        1,
        [8; 32],
    )
    .unwrap();
    let issuer_key = runtime::issuer_address(&program, &config_key, &i.issuer_hash).0;
    Fixture {
        program,
        ca: ai(config_key, program, false, true, c.encode(), 1, false),
        ia: ai(issuer_key, program, false, true, i.encode(), 1, false),
        c,
        i,
    }
}
fn ro(a: &AccountInfo<'static>) -> AccountInfo<'static> {
    let mut a = a.clone();
    a.is_writable = false;
    a
}
fn publish(expected: u64, root: [u8; 32]) -> Vec<u8> {
    let mut b = vec![PREFIX, 2];
    b.extend(expected.to_be_bytes());
    b.extend(root);
    b
}
fn observe(ce: u64, ie: u64, expected: u64, next: u64, digest: u8, time: i64) -> Vec<u8> {
    let mut b = vec![PREFIX, 3];
    for n in [ce, ie, expected, next] {
        b.extend(n.to_be_bytes());
    }
    b.extend([digest; 32]);
    b.push(1); // Existing administrative cases explicitly authenticate active.
    b.extend(time.to_be_bytes());
    b.extend((time + 300).to_be_bytes());
    b
}
fn bind(ce: u64, ie: u64, root: u64, source: u64) -> Vec<u8> {
    let mut b = vec![PREFIX, 11];
    for n in [ce, ie, root, source] {
        b.extend(n.to_be_bytes());
    }
    b
}
fn enroll(i: &Issuer) -> Vec<u8> {
    let mut b = vec![PREFIX, 1];
    b.extend(i.issuer_hash);
    b.extend(i.aki);
    b.extend(i.source.to_bytes());
    b.extend(i.enrollment_version.to_be_bytes());
    b.extend(i.evidence_digest);
    b
}
fn initialize(c: &Config) -> Vec<u8> {
    let mut b = vec![PREFIX, 0];
    b.extend(c.seed);
    b.extend(c.publisher.to_bytes());
    b.extend(c.genesis);
    b.extend(c.policy_id);
    b.extend(c.policy_version.to_be_bytes());
    for x in [
        c.circuit_id,
        c.package_id,
        c.schema_id,
        c.profile_id,
        c.ordinary_vk_digest,
        c.root,
    ] {
        b.extend(x);
    }
    b
}
// These account lists are exact administrative metas. A signer may also be the
// writable fee payer. State PDAs are nonsigners; read-only config metas remain RO.
#[test]
fn runtime_v3_authorized_publish_uses_real_owned_pda_and_advances_current_root() {
    let x = fixture();
    let accounts = [actor(x.c.publisher, false), x.ca.clone()];
    assert_eq!(
        process_instruction(&x.program, &accounts, &publish(0, f(9))),
        Ok(())
    );
    let updated = Config::decode(&x.ca.try_borrow_data().unwrap()).unwrap();
    assert_eq!(updated.root, f(9));
    assert_eq!(updated.root_version, 1);
    assert_eq!(updated.eligibility_epoch, 0);
}
#[test]
fn runtime_v3_publish_rejects_owner_pda_signer_writable_and_predecessor_without_mutation() {
    for mode in 0..8 {
        let x = fixture();
        let mut publisher = actor(x.c.publisher, false);
        let mut config = x.ca.clone();
        match mode {
            0 => publisher.key = Box::leak(Box::new(x.c.admin)),
            1 => publisher.is_signer = false,
            2 => config.is_writable = false,
            3 => config.owner = Box::leak(Box::new(system_program::id())),
            4 => config.key = Box::leak(Box::new(Pubkey::new_unique())),
            5 => config.executable = true,
            6 => config.is_signer = true,
            _ => {}
        }
        let accounts = [publisher, config];
        let before = snapshot(&accounts);
        assert!(process_instruction(
            &x.program,
            &accounts,
            &publish(if mode == 7 { 1 } else { 0 }, f(9))
        )
        .is_err());
        assert_eq!(snapshot(&accounts), before);
    }
    let x = fixture();
    let accounts = [actor(x.c.publisher, false), x.ca.clone(), x.ca.clone()];
    let before = snapshot(&accounts);
    assert!(process_instruction(&x.program, &accounts, &publish(0, f(9))).is_err());
    assert_eq!(snapshot(&accounts), before);
}
struct ModelStubs {
    program: Pubkey,
    now: Arc<AtomicI64>,
    created: Arc<Mutex<Vec<(Pubkey, usize)>>>,
}
impl SyscallStubs for ModelStubs {
    fn sol_get_clock_sysvar(&self, p: *mut u8) -> u64 {
        unsafe {
            std::ptr::write_unaligned(
                p.cast::<Clock>(),
                Clock {
                    unix_timestamp: self.now.load(Ordering::SeqCst),
                    ..Clock::default()
                },
            );
        }
        0
    }
    fn sol_get_rent_sysvar(&self, p: *mut u8) -> u64 {
        unsafe {
            std::ptr::write_unaligned(p.cast::<Rent>(), Rent::default());
        }
        0
    }
    fn sol_invoke_signed(
        &self,
        ix: &Instruction,
        accounts: &[AccountInfo],
        seeds: &[&[&[u8]]],
    ) -> ProgramResult {
        // Model only fresh CreateAccount, exactly the case exercised below.
        if ix.program_id != system_program::id()
            || ix.data.len() != 52
            || ix.data[..4] != 0u32.to_le_bytes()
            || accounts.len() != 3
            || seeds.len() != 1
        {
            return Err(ProgramError::InvalidInstructionData);
        }
        let lamports = u64::from_le_bytes(ix.data[4..12].try_into().unwrap());
        let space = u64::from_le_bytes(ix.data[12..20].try_into().unwrap()) as usize;
        let owner = Pubkey::new_from_array(ix.data[20..52].try_into().unwrap());
        if owner != self.program
            || !matches!(space, CONFIG_LEN | ISSUER_LEN | QUEUE_LEN)
            || *accounts[1].owner != system_program::id()
            || accounts[1].data_len() != 0
            || accounts[1].lamports() != 0
        {
            return Err(ProgramError::InvalidAccountData);
        }
        let expected = Pubkey::create_program_address(seeds[0], &self.program)
            .map_err(|_| ProgramError::InvalidSeeds)?;
        if expected != *accounts[1].key {
            return Err(ProgramError::InvalidSeeds);
        }
        if accounts[0].lamports() < lamports {
            return Err(ProgramError::InsufficientFunds);
        }
        **accounts[0].try_borrow_mut_lamports()? -= lamports;
        **accounts[1].try_borrow_mut_lamports()? = lamports;
        *accounts[1].try_borrow_mut_data()? = Box::leak(vec![0; space].into_boxed_slice());
        accounts[1].assign(&owner);
        self.created.lock().unwrap().push((*accounts[1].key, space));
        Ok(())
    }
}
struct StubGuard(Option<Box<dyn SyscallStubs>>);
impl Drop for StubGuard {
    fn drop(&mut self) {
        if let Some(old) = self.0.take() {
            set_syscall_stubs(old);
        }
    }
}
fn model(program: Pubkey) -> (StubGuard, Arc<AtomicI64>, Arc<Mutex<Vec<(Pubkey, usize)>>>) {
    let now = Arc::new(AtomicI64::new(100));
    let created = Arc::new(Mutex::new(vec![]));
    let old = set_syscall_stubs(Box::new(ModelStubs {
        program,
        now: now.clone(),
        created: created.clone(),
    }));
    (StubGuard(Some(old)), now, created)
}
#[test]
fn runtime_v3_initialize_and_two_enrollments_use_exact_versioned_pdas_and_account_sizes() {
    let x = fixture();
    let (_guard, _now, created) = model(x.program);
    let ca = fresh(*x.ca.key);
    let queue = fresh(runtime::queue_address(&x.program, ca.key).0);
    let admin = actor(x.c.admin, true);
    let accounts = [admin.clone(), ca.clone(), queue.clone(), system()];
    assert_eq!(
        process_instruction(&x.program, &accounts, &initialize(&x.c)),
        Ok(())
    );
    assert_eq!(Config::decode(&ca.try_borrow_data().unwrap()).unwrap(), x.c);
    assert_eq!(
        Queue::decode(&queue.try_borrow_data().unwrap()).unwrap(),
        Queue::new(*ca.key)
    );
    assert_eq!(*ca.owner, x.program);
    assert_eq!(*queue.owner, x.program);
    for n in [8u8, 9] {
        let mut i = x.i.clone();
        i.issuer_hash = f(n);
        i.source = Pubkey::new_from_array([20 + n; 32]);
        i.aki[..20].fill(n);
        i.evidence_digest = [n; 32];
        let ia = fresh(runtime::issuer_address(&x.program, ca.key, &i.issuer_hash).0);
        let accounts = [admin.clone(), ro(&ca), ia.clone(), system()];
        assert_eq!(
            process_instruction(&x.program, &accounts, &enroll(&i)),
            Ok(())
        );
        assert_eq!(Issuer::decode(&ia.try_borrow_data().unwrap()).unwrap(), i);
        assert_eq!(*ia.owner, x.program);
        let before = snapshot(&accounts);
        assert!(process_instruction(&x.program, &accounts, &enroll(&i)).is_err());
        assert_eq!(snapshot(&accounts), before);
    }
    assert_eq!(
        created
            .lock()
            .unwrap()
            .iter()
            .map(|x| x.1)
            .collect::<Vec<_>>(),
        vec![CONFIG_LEN, QUEUE_LEN, ISSUER_LEN, ISSUER_LEN]
    );
}
#[test]
fn runtime_v3_creation_checks_all_accounts_before_any_cpi_or_application_write() {
    for mode in 0..7 {
        let x = fixture();
        let (_guard, _now, created) = model(x.program);
        let mut admin = actor(x.c.admin, true);
        let mut ca = fresh(*x.ca.key);
        let mut queue = fresh(runtime::queue_address(&x.program, ca.key).0);
        let mut sys = system();
        match mode {
            0 => admin.is_signer = false,
            1 => ca.key = Box::leak(Box::new(Pubkey::new_unique())),
            2 => queue.key = Box::leak(Box::new(Pubkey::new_unique())),
            3 => queue.owner = Box::leak(Box::new(x.program)),
            4 => sys.executable = false,
            5 => queue.is_writable = false,
            _ => sys.is_writable = true,
        }
        let accounts = [admin, ca, queue, sys];
        let before = snapshot(&accounts);
        assert!(process_instruction(&x.program, &accounts, &initialize(&x.c)).is_err());
        assert_eq!(snapshot(&accounts), before);
        assert!(created.lock().unwrap().is_empty());
    }
}
#[test]
fn runtime_v3_observe_bind_and_both_lifecycle_fences_require_actual_signed_authorities() {
    let x = fixture();
    let (_guard, now, _created) = model(x.program);
    let cfg = ro(&x.ca);
    let source = actor(x.i.source, false);
    let publisher = actor(x.c.publisher, false);
    let admin = actor(x.c.admin, false);
    for mut signer in [actor(x.c.admin, false), source.clone()] {
        if signer.key == source.key {
            signer.is_signer = false;
        }
        let accounts = [signer, cfg.clone(), x.ia.clone()];
        let before = snapshot(&accounts);
        assert!(process_instruction(&x.program, &accounts, &observe(0, 0, 0, 1, 1, 100)).is_err());
        assert_eq!(snapshot(&accounts), before);
    }
    assert_eq!(
        process_instruction(
            &x.program,
            &[source.clone(), cfg.clone(), x.ia.clone()],
            &observe(0, 0, 0, 1, 1, 100)
        ),
        Ok(())
    );
    assert_eq!(
        process_instruction(
            &x.program,
            &[publisher.clone(), cfg.clone(), x.ia.clone()],
            &bind(0, 0, 0, 1)
        ),
        Ok(())
    );
    let original = Issuer::decode(&x.ia.try_borrow_data().unwrap()).unwrap();
    assert_eq!(original.binding_current(&x.c), Ok(()));
    assert_eq!(
        process_instruction(
            &x.program,
            &[admin.clone(), cfg.clone(), x.ia.clone()],
            &[PREFIX, 12, 0]
        ),
        Ok(())
    );
    assert_eq!(
        process_instruction(
            &x.program,
            &[admin.clone(), cfg.clone(), x.ia.clone()],
            &[PREFIX, 12, 1]
        ),
        Ok(())
    );
    now.store(101, Ordering::SeqCst);
    let before = snapshot(&[x.ca.clone(), x.ia.clone()]);
    assert!(process_instruction(
        &x.program,
        &[source.clone(), cfg.clone(), x.ia.clone()],
        &observe(0, 0, 1, 2, 2, 101)
    )
    .is_err());
    assert_eq!(snapshot(&[x.ca.clone(), x.ia.clone()]), before);
    assert_eq!(
        process_instruction(
            &x.program,
            &[source.clone(), cfg.clone(), x.ia.clone()],
            &observe(0, 2, 1, 2, 2, 101)
        ),
        Ok(())
    );
    assert_eq!(
        process_instruction(
            &x.program,
            &[publisher.clone(), cfg.clone(), x.ia.clone()],
            &bind(0, 2, 0, 2)
        ),
        Ok(())
    );
    assert_eq!(
        process_instruction(&x.program, &[admin.clone(), x.ca.clone()], &[PREFIX, 10, 0]),
        Ok(())
    );
    assert_eq!(
        process_instruction(&x.program, &[admin, x.ca.clone()], &[PREFIX, 10, 1]),
        Ok(())
    );
    now.store(102, Ordering::SeqCst);
    let before = snapshot(&[x.ca.clone(), x.ia.clone()]);
    assert!(process_instruction(
        &x.program,
        &[source.clone(), cfg.clone(), x.ia.clone()],
        &observe(0, 2, 2, 3, 3, 102)
    )
    .is_err());
    assert_eq!(snapshot(&[x.ca.clone(), x.ia.clone()]), before);
    assert_eq!(
        process_instruction(
            &x.program,
            &[source, cfg.clone(), x.ia.clone()],
            &observe(2, 2, 2, 3, 3, 102)
        ),
        Ok(())
    );
    assert_eq!(
        process_instruction(
            &x.program,
            &[publisher, cfg, x.ia.clone()],
            &bind(2, 2, 0, 3)
        ),
        Ok(())
    );
    let c = Config::decode(&x.ca.try_borrow_data().unwrap()).unwrap();
    let i = Issuer::decode(&x.ia.try_borrow_data().unwrap()).unwrap();
    assert_eq!(i.binding_current(&c), Ok(()));
    assert_eq!((i.enrollment_version, i.sequence), (1, 3));
}
#[test]
fn runtime_v3_rejects_cross_config_issuer_and_wrong_privileges_without_mutation() {
    for mode in 0..7 {
        let x = fixture();
        let (_guard, _now, _created) = model(x.program);
        let mut cfg = ro(&x.ca);
        let mut issuer = x.ia.clone();
        match mode {
            0 => issuer.owner = Box::leak(Box::new(system_program::id())),
            1 => issuer.key = Box::leak(Box::new(Pubkey::new_unique())),
            2 => issuer.is_writable = false,
            3 => cfg.is_writable = true,
            4 => issuer.is_signer = true,
            5 => issuer.executable = true,
            _ => {
                let mut i = x.i.clone();
                i.config = Pubkey::new_unique();
                *issuer.try_borrow_mut_data().unwrap() = Box::leak(i.encode().into_boxed_slice());
            }
        }
        let accounts = [actor(x.i.source, false), cfg, issuer];
        let before = snapshot(&accounts);
        assert!(process_instruction(&x.program, &accounts, &observe(0, 0, 0, 1, 1, 100)).is_err());
        assert_eq!(snapshot(&accounts), before);
    }
}
#[test]
fn runtime_v3_execute_stays_unavailable_and_malformed_staging_accounts_do_not_mutate() {
    let x = fixture();
    let accounts = [x.ca.clone(), x.ia.clone()];
    let before = snapshot(&accounts);
    let mut execute = vec![PREFIX, 7];
    execute.extend([0; 448]);
    assert_eq!(
        process_instruction(&x.program, &accounts, &execute),
        Err(ProgramError::from(AppError::Unavailable))
    );
    assert_eq!(snapshot(&accounts), before);
    for data in [vec![PREFIX, 5], vec![PREFIX, 9]] {
        assert!(process_instruction(&x.program, &accounts, &data).is_err());
        assert_eq!(snapshot(&accounts), before);
    }
}
