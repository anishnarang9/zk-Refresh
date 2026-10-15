//! Tests-first publisher transaction commitment. Envelope digests are opaque raw
//! SHA256 identifiers; these tests do not authenticate detached JSON/Ed25519.
//! Head280: magic8, config32, issuer32, publisher32, publication_sequence8,
//! envelope_digest32, predecessor_digest32, root32, root_version8, source_sequence8,
//! source_digest32, config_epoch8, issuer_epoch8, committed_at8. Integers BE.
//! Bind179: 0x51,13,1; epochs8+8, root32, root_version8, source_sequence8,
//! source_digest32, expected_publication_sequence8/digest32, next_sequence8/digest32.
//! CPI below is a host model, not actual allocation/transaction rollback evidence.
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
    atomic::{AtomicI64, AtomicUsize, Ordering},
    Arc,
};
use zk_fresh_program::{
    application_runtime_v3 as runtime,
    application_v3::{AppError, AppInstruction, Authority, Config, Issuer, PREFIX},
    generated_vk_v3 as identity, process_instruction,
};
const HEAD_LEN: usize = 280;
fn key(n: u8) -> Pubkey {
    Pubkey::new_from_array([n; 32])
}
fn field(n: u8) -> [u8; 32] {
    let mut b = [0; 32];
    b[31] = n;
    b
}
fn ai(
    k: Pubkey,
    owner: Pubkey,
    signer: bool,
    writable: bool,
    data: Vec<u8>,
    lamports: u64,
) -> AccountInfo<'static> {
    AccountInfo::new(
        Box::leak(Box::new(k)),
        signer,
        writable,
        Box::leak(Box::new(lamports)),
        Box::leak(data.into_boxed_slice()),
        Box::leak(Box::new(owner)),
        false,
        0,
    )
}
fn replace(a: &AccountInfo, bytes: Vec<u8>) {
    *a.try_borrow_mut_data().unwrap() = Box::leak(bytes.into_boxed_slice());
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
fn unchanged_failure(program: &Pubkey, accounts: &[AccountInfo], wire: &[u8]) {
    let before = snapshot(accounts);
    assert!(process_instruction(program, accounts, wire).is_err());
    assert_eq!(
        snapshot(accounts),
        before,
        "failed publisher bind changed head/issuer/account state"
    );
}
#[derive(Clone)]
struct Claim {
    config_epoch: u64,
    issuer_epoch: u64,
    root: [u8; 32],
    root_version: u64,
    source_sequence: u64,
    source_digest: [u8; 32],
    expected_sequence: u64,
    expected_digest: [u8; 32],
    next_sequence: u64,
    digest: [u8; 32],
}
impl Claim {
    fn wire(&self) -> Vec<u8> {
        let mut b = vec![PREFIX, 13, 1];
        b.extend(self.config_epoch.to_be_bytes());
        b.extend(self.issuer_epoch.to_be_bytes());
        b.extend(self.root);
        b.extend(self.root_version.to_be_bytes());
        b.extend(self.source_sequence.to_be_bytes());
        b.extend(self.source_digest);
        b.extend(self.expected_sequence.to_be_bytes());
        b.extend(self.expected_digest);
        b.extend(self.next_sequence.to_be_bytes());
        b.extend(self.digest);
        b
    }
}
struct Fixture {
    program: Pubkey,
    config: AccountInfo<'static>,
    issuer: AccountInfo<'static>,
    head: AccountInfo<'static>,
    publisher: AccountInfo<'static>,
    system: AccountInfo<'static>,
}
impl Fixture {
    fn new(seed: u8, issuer_hash: u8) -> Self {
        let program = key(12);
        let c = Config {
            admin: key(18),
            seed: [seed; 32],
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
        aki[..20].fill(issuer_hash);
        let mut i = Issuer::enroll(
            ck,
            &c,
            Authority {
                key: c.admin,
                is_signer: true,
            },
            field(issuer_hash),
            aki,
            key(20),
            1,
            [8; 32],
        )
        .unwrap();
        i.observe(
            &c,
            Authority {
                key: i.source,
                is_signer: true,
            },
            0,
            0,
            0,
            1,
            [41; 32],
            true,
            100,
            300,
            110,
        )
        .unwrap();
        let ik = runtime::issuer_address(&program, &ck, &i.issuer_hash).0;
        let hk = Pubkey::find_program_address(
            &[
                b"dyn-pubhead-v3",
                ck.as_ref(),
                ik.as_ref(),
                c.publisher.as_ref(),
            ],
            &program,
        )
        .0;
        let mut system = ai(system_program::id(), key(60), false, false, vec![], 0);
        system.executable = true;
        Self {
            program,
            config: ai(ck, program, false, false, c.encode(), 1),
            issuer: ai(ik, program, false, true, i.encode(), 1),
            head: ai(hk, system_program::id(), false, true, vec![], 0),
            publisher: ai(
                c.publisher,
                system_program::id(),
                true,
                true,
                vec![],
                1_000_000_000,
            ),
            system,
        }
    }
    fn c(&self) -> Config {
        Config::decode(&self.config.try_borrow_data().unwrap()).unwrap()
    }
    fn i(&self) -> Issuer {
        Issuer::decode(&self.issuer.try_borrow_data().unwrap()).unwrap()
    }
    fn accounts(&self) -> Vec<AccountInfo<'static>> {
        vec![
            self.publisher.clone(),
            self.config.clone(),
            self.issuer.clone(),
            self.head.clone(),
            self.system.clone(),
        ]
    }
    fn claim(&self, expected: u64, previous: [u8; 32], digest: [u8; 32]) -> Claim {
        let c = self.c();
        let i = self.i();
        Claim {
            config_epoch: c.eligibility_epoch,
            issuer_epoch: i.eligibility_epoch,
            root: c.root,
            root_version: c.root_version,
            source_sequence: i.sequence,
            source_digest: i.digest,
            expected_sequence: expected,
            expected_digest: previous,
            next_sequence: expected.checked_add(1).unwrap(),
            digest,
        }
    }
    fn run(&self, claim: &Claim) -> ProgramResult {
        process_instruction(&self.program, &self.accounts(), &claim.wire())
    }
    fn expected_head(&self, claim: &Claim, now: i64) -> Vec<u8> {
        let mut b = b"DYNHEAD3".to_vec();
        b.extend(self.config.key.to_bytes());
        b.extend(self.issuer.key.to_bytes());
        b.extend(self.publisher.key.to_bytes());
        b.extend(claim.next_sequence.to_be_bytes());
        b.extend(claim.digest);
        b.extend(claim.expected_digest);
        b.extend(claim.root);
        b.extend(claim.root_version.to_be_bytes());
        b.extend(claim.source_sequence.to_be_bytes());
        b.extend(claim.source_digest);
        b.extend(claim.config_epoch.to_be_bytes());
        b.extend(claim.issuer_epoch.to_be_bytes());
        b.extend(now.to_be_bytes());
        assert_eq!(b.len(), HEAD_LEN);
        b
    }
    fn seed_existing(&self, claim: &Claim, now: i64) {
        self.head.assign(&self.program);
        replace(&self.head, self.expected_head(claim, now));
        let mut i = self.i();
        i.bind_current(
            &self.c(),
            Authority {
                key: self.c().publisher,
                is_signer: true,
            },
            claim.config_epoch,
            claim.issuer_epoch,
            claim.root_version,
            claim.source_sequence,
            now,
        )
        .unwrap();
        replace(&self.issuer, i.encode());
    }
}
struct Host {
    program: Pubkey,
    now: Arc<AtomicI64>,
    cpis: Arc<AtomicUsize>,
}
impl Host {
    fn derived(&self, target: &AccountInfo, seeds: &[&[&[u8]]]) -> ProgramResult {
        if seeds.len() != 1
            || seeds[0].len() != 5
            || seeds[0][0] != b"dyn-pubhead-v3"
            || Pubkey::create_program_address(seeds[0], &self.program)
                .map_err(|_| ProgramError::InvalidSeeds)?
                != *target.key
        {
            return Err(ProgramError::InvalidSeeds);
        }
        Ok(())
    }
    fn transfer(&self, payer: &AccountInfo, target: &AccountInfo, amount: u64) -> ProgramResult {
        let remaining = payer
            .lamports()
            .checked_sub(amount)
            .ok_or(ProgramError::InsufficientFunds)?;
        let funded = target
            .lamports()
            .checked_add(amount)
            .ok_or(ProgramError::InvalidAccountData)?;
        **payer.try_borrow_mut_lamports()? = remaining;
        **target.try_borrow_mut_lamports()? = funded;
        Ok(())
    }
}
impl SyscallStubs for Host {
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
        a: &[AccountInfo],
        seeds: &[&[&[u8]]],
    ) -> ProgramResult {
        if ix.program_id != system_program::id() || ix.data.len() < 4 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let opcode = u32::from_le_bytes(ix.data[..4].try_into().unwrap());
        match opcode {
            0 if ix.data.len() == 52 && a.len() == 3 => {
                self.derived(&a[1], seeds)?;
                if a[1].owner != &system_program::id()
                    || a[1].data_len() != 0
                    || a[1].lamports() != 0
                    || u64::from_le_bytes(ix.data[12..20].try_into().unwrap()) != HEAD_LEN as u64
                    || ix.data[20..52] != self.program.to_bytes()
                {
                    return Err(ProgramError::InvalidAccountData);
                }
                self.transfer(
                    &a[0],
                    &a[1],
                    u64::from_le_bytes(ix.data[4..12].try_into().unwrap()),
                )?;
                replace(&a[1], vec![0; HEAD_LEN]);
                a[1].assign(&self.program);
            }
            2 if ix.data.len() == 12 && a.len() == 3 && seeds.is_empty() => {
                if a[1].owner != &system_program::id() || a[1].data_len() != 0 {
                    return Err(ProgramError::InvalidAccountData);
                }
                self.transfer(
                    &a[0],
                    &a[1],
                    u64::from_le_bytes(ix.data[4..12].try_into().unwrap()),
                )?;
            }
            8 if ix.data.len() == 12 && a.len() == 2 => {
                self.derived(&a[0], seeds)?;
                if a[0].owner != &system_program::id()
                    || a[0].data_len() != 0
                    || u64::from_le_bytes(ix.data[4..12].try_into().unwrap()) != HEAD_LEN as u64
                {
                    return Err(ProgramError::InvalidAccountData);
                }
                replace(&a[0], vec![0; HEAD_LEN]);
            }
            1 if ix.data.len() == 36 && a.len() == 2 => {
                self.derived(&a[0], seeds)?;
                if a[0].owner != &system_program::id()
                    || a[0].data_len() != HEAD_LEN
                    || ix.data[4..36] != self.program.to_bytes()
                {
                    return Err(ProgramError::InvalidAccountData);
                }
                a[0].assign(&self.program);
            }
            _ => return Err(ProgramError::InvalidInstructionData),
        }
        self.cpis.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
struct Restore(Option<Box<dyn SyscallStubs>>);
impl Drop for Restore {
    fn drop(&mut self) {
        set_syscall_stubs(self.0.take().unwrap());
    }
}
fn host(program: Pubkey) -> (Restore, Arc<AtomicI64>, Arc<AtomicUsize>) {
    let now = Arc::new(AtomicI64::new(110));
    let cpis = Arc::new(AtomicUsize::new(0));
    let old = set_syscall_stubs(Box::new(Host {
        program,
        now: now.clone(),
        cpis: cpis.clone(),
    }));
    (Restore(Some(old)), now, cpis)
}

#[test]
fn publisher_v3_bind179_parser_accepts_signed_envelope_predecessor_and_context() {
    let x = Fixture::new(7, 8);
    let claim = x.claim(0, [0; 32], [91; 32]);
    let b = claim.wire();
    assert_eq!(b.len(), 179);
    assert_eq!(&b[..3], &[PREFIX, 13, 1]);
    assert_eq!(&b[19..51], &x.c().root);
    assert_eq!(&b[147..179], &[91; 32]);
    assert_eq!(
        AppInstruction::parse(&b).is_ok(),
        true,
        "v3 Bind179 must accept version1 signed publisher-head context and predecessor"
    );
}

#[test]
fn publisher_v3_bind179_rejects_truncation_trailing_version_and_noncanonical_root() {
    let x = Fixture::new(7, 8);
    let b = x.claim(0, [0; 32], [91; 32]).wire();
    for end in 0..179 {
        assert!(
            AppInstruction::parse(&b[..end]).is_err(),
            "accepted truncation{end}"
        );
    }
    let mut extra = b.clone();
    extra.push(0);
    assert!(AppInstruction::parse(&extra).is_err());
    for version in [0, 2, 255] {
        let mut bad = b.clone();
        bad[2] = version;
        assert!(AppInstruction::parse(&bad).is_err());
    }
    let mut v2 = b.clone();
    v2[0] = 0x50;
    assert!(AppInstruction::parse(&v2).is_err());
    let mut bad_root = b;
    bad_root[19..51].fill(255);
    assert!(AppInstruction::parse(&bad_root).is_err());
}

#[test]
fn publisher_v3_first_commit_atomically_allocates_exact_head_and_binds_issuer() {
    let x = Fixture::new(7, 8);
    let (_h, _now, cpis) = host(x.program);
    let claim = x.claim(0, [0; 32], [91; 32]);
    let config_before = snapshot(&[x.config.clone()]);
    let mut expected_issuer = x.i();
    expected_issuer.bound_root = claim.root;
    expected_issuer.bound_root_version = claim.root_version;
    expected_issuer.bound_source_sequence = claim.source_sequence;
    expected_issuer.bound_source_digest = claim.source_digest;
    assert!(x.i().binding_current(&x.c()).is_err());
    assert_eq!(x.run(&claim), Ok(()));
    assert_eq!(cpis.load(Ordering::SeqCst), 1);
    assert_eq!(x.head.owner, &x.program);
    assert_eq!(x.head.data_len(), HEAD_LEN);
    assert_eq!(
        *x.head.try_borrow_data().unwrap(),
        x.expected_head(&claim, 110).as_slice()
    );
    assert_eq!(
        *x.issuer.try_borrow_data().unwrap(),
        expected_issuer.encode().as_slice()
    );
    assert_eq!(x.i().binding_current(&x.c()), Ok(()));
    assert_eq!(snapshot(&[x.config.clone()]), config_before);
    unchanged_failure(&x.program, &x.accounts(), &claim.wire());
}

#[test]
fn publisher_v3_prefunded_empty_system_head_cannot_be_squatted() {
    let x = Fixture::new(7, 8);
    let (_h, _now, cpis) = host(x.program);
    **x.head.try_borrow_mut_lamports().unwrap() = 1;
    let claim = x.claim(0, [0; 32], [91; 32]);
    assert_eq!(x.run(&claim), Ok(()));
    assert_eq!(
        *x.head.try_borrow_data().unwrap(),
        x.expected_head(&claim, 110).as_slice()
    );
    assert_eq!(x.head.owner, &x.program);
    assert_eq!(cpis.load(Ordering::SeqCst), 3);
}

#[test]
fn publisher_v3_exact_accounts_owners_pdas_and_privileges_are_checked_before_allocation() {
    for case in 0..25 {
        let x = Fixture::new(7, 8);
        let (_h, _now, cpis) = host(x.program);
        let mut a = x.accounts();
        let claim = x.claim(0, [0; 32], [91; 32]);
        match case {
            0 => a[0].is_signer = false,
            1 => a[0].is_writable = false,
            2 => a[0].key = Box::leak(Box::new(x.c().admin)),
            3 => a[1].is_writable = true,
            4 => a[1].is_signer = true,
            5 => a[1].assign(&key(61)),
            6 => a[1].executable = true,
            7 => a[1].key = Box::leak(Box::new(key(61))),
            8 => replace(&a[1], vec![0; 380]),
            9 => a[2].is_writable = false,
            10 => a[2].is_signer = true,
            11 => a[2].assign(&key(61)),
            12 => a[2].executable = true,
            13 => a[2].key = Box::leak(Box::new(key(61))),
            14 => replace(&a[2], vec![0; 373]),
            15 => a[3].is_writable = false,
            16 => a[3].is_signer = true,
            17 => a[3].assign(&key(61)),
            18 => a[3].executable = true,
            19 => a[3].key = Box::leak(Box::new(key(61))),
            20 => replace(&a[3], vec![0]),
            21 => a[4].executable = false,
            22 => a[4].is_writable = true,
            23 => {
                let duplicate = a[1].clone();
                a.push(duplicate);
            }
            24 => a[3] = a[0].clone(),
            _ => unreachable!(),
        }
        unchanged_failure(&x.program, &a, &claim.wire());
        assert_eq!(
            cpis.load(Ordering::SeqCst),
            0,
            "invalid case{case} invoked CPI"
        );
    }
}

#[test]
fn publisher_v3_signed_context_and_predecessor_mismatches_leave_head_and_issuer_unchanged() {
    for case in 0..11 {
        let x = Fixture::new(7, 8);
        let (_h, _now, cpis) = host(x.program);
        let mut claim = x.claim(0, [0; 32], [91; 32]);
        match case {
            0 => claim.config_epoch = 1,
            1 => claim.issuer_epoch = 1,
            2 => claim.root = field(9),
            3 => claim.root_version = 1,
            4 => claim.source_sequence = 0,
            5 => claim.source_digest = [42; 32],
            6 => claim.expected_sequence = 1,
            7 => claim.expected_digest = [90; 32],
            8 => claim.next_sequence = 0,
            9 => claim.next_sequence = 2,
            10 => claim.digest = [0; 32],
            _ => unreachable!(),
        }
        unchanged_failure(&x.program, &x.accounts(), &claim.wire());
        assert_eq!(cpis.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn publisher_v3_existing_head_requires_exact_predecessor_checked_increment_and_non_decreasing_clock(
) {
    let x = Fixture::new(7, 8);
    let (_h, now, cpis) = host(x.program);
    let first = x.claim(0, [0; 32], [91; 32]);
    x.seed_existing(&first, 110);
    let next = x.claim(1, [91; 32], [92; 32]);
    for case in 0..7 {
        let mut bad = next.clone();
        match case {
            0 => bad.expected_sequence = 0,
            1 => bad.expected_digest = [90; 32],
            2 => bad.next_sequence = 1,
            3 => bad.next_sequence = 3,
            4 => bad.digest = [91; 32],
            5 => bad.digest = [0; 32],
            6 => {
                bad.expected_sequence = u64::MAX;
                bad.next_sequence = 0;
            }
            _ => unreachable!(),
        }
        unchanged_failure(&x.program, &x.accounts(), &bad.wire());
    }
    now.store(109, Ordering::SeqCst);
    unchanged_failure(&x.program, &x.accounts(), &next.wire());
    now.store(110, Ordering::SeqCst);
    assert_eq!(x.run(&next), Ok(()));
    assert_eq!(
        *x.head.try_borrow_data().unwrap(),
        x.expected_head(&next, 110).as_slice()
    );
    assert_eq!(
        cpis.load(Ordering::SeqCst),
        0,
        "existing head update must not allocate"
    );
    unchanged_failure(&x.program, &x.accounts(), &next.wire());
    // Real counter overflow in the stored predecessor, not only a caller mismatch.
    let mut bytes = x.head.try_borrow_data().unwrap().to_vec();
    bytes[104..112].copy_from_slice(&u64::MAX.to_be_bytes());
    replace(&x.head, bytes);
    let mut overflow = next;
    overflow.expected_sequence = u64::MAX;
    overflow.expected_digest = [92; 32];
    overflow.next_sequence = 0;
    overflow.digest = [93; 32];
    unchanged_failure(&x.program, &x.accounts(), &overflow.wire());
}

#[test]
fn publisher_v3_reused_malformed_or_wrong_stream_head_never_becomes_genesis() {
    for case in 0..12 {
        let x = Fixture::new(7, 8);
        let (_h, _now, cpis) = host(x.program);
        let first = x.claim(0, [0; 32], [91; 32]);
        x.seed_existing(&first, 110);
        let mut bytes = x.head.try_borrow_data().unwrap().to_vec();
        match case {
            0 => bytes.fill(0),
            1 => {
                bytes.pop();
            }
            2 => bytes.push(0),
            3 => bytes[..8].copy_from_slice(b"DYNHEAD2"),
            4 => bytes[8..40].copy_from_slice(key(61).as_ref()),
            5 => bytes[40..72].copy_from_slice(key(61).as_ref()),
            6 => bytes[72..104].copy_from_slice(key(61).as_ref()),
            7 => bytes[104..112].fill(0),
            8 => bytes[112..144].fill(0),
            9 => bytes[144..176].fill(90),
            10 => bytes[176..208].fill(255),
            11 => bytes[272..280].copy_from_slice(&(-1i64).to_be_bytes()),
            _ => unreachable!(),
        }
        replace(&x.head, bytes);
        unchanged_failure(
            &x.program,
            &x.accounts(),
            &x.claim(1, [91; 32], [92; 32]).wire(),
        );
        unchanged_failure(&x.program, &x.accounts(), &first.wire());
        assert_eq!(cpis.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn publisher_v3_multiple_issuers_configs_and_publishers_have_independent_head_streams() {
    let a = Fixture::new(7, 8);
    let b = Fixture::new(7, 9);
    let c = Fixture::new(8, 8);
    let (_h, _now, _cpis) = host(a.program);
    assert_eq!(a.config.key, b.config.key);
    assert_ne!(a.issuer.key, b.issuer.key);
    assert_ne!(a.head.key, b.head.key);
    assert_ne!(a.head.key, c.head.key);
    let other_publisher = Pubkey::find_program_address(
        &[
            b"dyn-pubhead-v3",
            a.config.key.as_ref(),
            a.issuer.key.as_ref(),
            key(25).as_ref(),
        ],
        &a.program,
    )
    .0;
    assert_ne!(*a.head.key, other_publisher);
    let claim = a.claim(0, [0; 32], [91; 32]);
    for foreign in [&b, &c] {
        let mut accounts = a.accounts();
        accounts[3] = foreign.head.clone();
        unchanged_failure(&a.program, &accounts, &claim.wire());
    }
    for x in [&a, &b, &c] {
        assert_eq!(x.run(&x.claim(0, [0; 32], [91; 32])), Ok(()));
    }
    let b_before = snapshot(&b.accounts());
    assert_eq!(a.run(&a.claim(1, [91; 32], [92; 32])), Ok(()));
    assert_eq!(snapshot(&b.accounts()), b_before);
}

#[test]
fn publisher_v3_current_active_fresh_source_and_both_recorded_epochs_are_mandatory() {
    for case in 0..9 {
        let x = Fixture::new(7, 8);
        let (_h, now, cpis) = host(x.program);
        let mut c = x.c();
        let mut i = x.i();
        match case {
            0 => c.enabled = false,
            1 => i.enabled = false,
            2 => i.status_valid = false,
            3 => c.eligibility_epoch = 2,
            4 => i.eligibility_epoch = 2,
            5 => now.store(301, Ordering::SeqCst),
            6 => now.store(300, Ordering::SeqCst),
            7 => now.store(-1, Ordering::SeqCst),
            8 => {
                i.sequence = 0;
                i.digest = [0; 32];
                i.observed_at = 0;
                i.expires_at = 0;
                i.status_valid = false;
            }
            _ => unreachable!(),
        }
        replace(&x.config, c.encode());
        replace(&x.issuer, i.encode());
        let claim = x.claim(0, [0; 32], [91; 32]);
        unchanged_failure(&x.program, &x.accounts(), &claim.wire());
        assert_eq!(cpis.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn publisher_v3_root_source_and_lifecycle_changes_require_new_exact_head_commitment() {
    let x = Fixture::new(7, 8);
    let (_h, now, _cpis) = host(x.program);
    let first = x.claim(0, [0; 32], [91; 32]);
    x.seed_existing(&first, 110);
    let old_next = x.claim(1, [91; 32], [92; 32]);
    let mut c = x.c();
    let mut i = x.i();
    c.publish(
        Authority {
            key: c.publisher,
            is_signer: true,
        },
        0,
        field(7),
    )
    .unwrap();
    c.set_enabled(
        Authority {
            key: c.admin,
            is_signer: true,
        },
        false,
    )
    .unwrap();
    c.set_enabled(
        Authority {
            key: c.admin,
            is_signer: true,
        },
        true,
    )
    .unwrap();
    i.set_enabled(
        &c,
        Authority {
            key: c.admin,
            is_signer: true,
        },
        false,
    )
    .unwrap();
    i.set_enabled(
        &c,
        Authority {
            key: c.admin,
            is_signer: true,
        },
        true,
    )
    .unwrap();
    i.observe(
        &c,
        Authority {
            key: i.source,
            is_signer: true,
        },
        2,
        2,
        1,
        2,
        [42; 32],
        true,
        111,
        310,
        111,
    )
    .unwrap();
    replace(&x.config, c.encode());
    replace(&x.issuer, i.encode());
    now.store(111, Ordering::SeqCst);
    unchanged_failure(&x.program, &x.accounts(), &old_next.wire());
    let current = x.claim(1, [91; 32], [92; 32]);
    assert_eq!(x.run(&current), Ok(()));
    assert_eq!(
        *x.head.try_borrow_data().unwrap(),
        x.expected_head(&current, 111).as_slice()
    );
    assert_eq!(x.i().binding_current(&x.c()), Ok(()));
}

#[test]
fn publisher_v3_old_bind_cannot_substitute_for_missing_publisher_head_and_execute_stays_closed() {
    let x = Fixture::new(7, 8);
    let (_h, _now, _cpis) = host(x.program);
    let mut old = vec![PREFIX, 11];
    for n in [0u64, 0, 0, 1] {
        old.extend(n.to_be_bytes());
    }
    assert_eq!(
        process_instruction(
            &x.program,
            &[x.publisher.clone(), x.config.clone(), x.issuer.clone()],
            &old
        ),
        Ok(())
    );
    assert_eq!(x.i().binding_current(&x.c()), Ok(()));
    assert_eq!(
        (x.head.data_len(), *x.head.owner),
        (0, system_program::id())
    );
    unchanged_failure(
        &x.program,
        &x.accounts(),
        &x.claim(1, [91; 32], [92; 32]).wire(),
    );
    let mut execute = vec![PREFIX, 7];
    execute.extend([0; 448]);
    assert_eq!(
        process_instruction(&x.program, &x.accounts(), &execute),
        Err(ProgramError::from(AppError::Unavailable))
    );
}

#[test]
fn publisher_v3_both_destination_borrows_must_succeed_before_either_account_write() {
    for held_head in [false, true] {
        let x = Fixture::new(7, 8);
        let (_h, _now, cpis) = host(x.program);
        x.seed_existing(&x.claim(0, [0; 32], [91; 32]), 110);
        let mut c = x.c();
        c.publish(
            Authority {
                key: c.publisher,
                is_signer: true,
            },
            0,
            field(7),
        )
        .unwrap();
        replace(&x.config, c.encode());
        let next = x.claim(1, [91; 32], [92; 32]);
        assert!(x.i().binding_current(&x.c()).is_err());
        // Immutable borrow still permits codec validation but blocks the commit
        // borrow. A stale issuer binding makes an early issuer write observable.
        let held = if held_head { &x.head } else { &x.issuer };
        let _borrow = held.try_borrow_data().unwrap();
        unchanged_failure(&x.program, &x.accounts(), &next.wire());
        assert_eq!(cpis.load(Ordering::SeqCst), 0);
    }
}
