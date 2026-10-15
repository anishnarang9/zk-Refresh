//! Tests-first v3 request staging. CPI is a fresh-CreateAccount host model only;
//! allocation/rollback still require a loaded ELF. No verifier or queue append.
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
    application_v3::{
        action_preimage, AppError, Authority, Config, Issuer, Queue, RelevantMeta, Request,
        RequestState, MAX_CHUNK, MAX_METAS, MAX_META_CHUNK, MAX_PAYLOAD, PREFIX, REQUEST_LEN,
    },
    generated_vk_v3 as identity, process_instruction,
};
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
fn authority(k: Pubkey, writable: bool) -> AccountInfo<'static> {
    ai(
        k,
        system_program::id(),
        true,
        writable,
        vec![],
        1_000_000_000,
    )
}
fn ro(a: &AccountInfo<'static>) -> AccountInfo<'static> {
    let mut x = a.clone();
    x.is_writable = false;
    x
}
fn replace_data(a: &AccountInfo, bytes: Vec<u8>) {
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
        "failure changed account bytes/owner/lamports"
    );
}
struct Fixture {
    program: Pubkey,
    config: AccountInfo<'static>,
    issuer: AccountInfo<'static>,
    request: AccountInfo<'static>,
    queue: AccountInfo<'static>,
    creator: AccountInfo<'static>,
}
impl Fixture {
    fn new(payload_len: u16, meta_count: usize, deadline: i64) -> Self {
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
        let i = Issuer::enroll(
            ck,
            &c,
            Authority {
                key: c.admin,
                is_signer: true,
            },
            field(8),
            aki,
            key(20),
            1,
            [8; 32],
        )
        .unwrap();
        let ik = runtime::issuer_address(&program, &ck, &i.issuer_hash).0;
        let creator = authority(key(21), true);
        let r = Request {
            config: ck,
            creator: *creator.key,
            nonce: [11; 32],
            issuer_hash: i.issuer_hash,
            recipient: key(22),
            request_type: 1,
            deadline,
            payload_len,
            uploaded: 0,
            metas_uploaded: 0,
            state: RequestState::Staging,
            metas: vec![
                RelevantMeta {
                    key: Pubkey::default(),
                    flags: 0,
                    owner: Pubkey::default()
                };
                meta_count
            ],
            payload: vec![0; payload_len as usize],
        };
        let rk = runtime::request_address(&program, &ck, creator.key, &r.nonce).0;
        let qk = runtime::queue_address(&program, &ck).0;
        Self {
            program,
            config: ai(ck, program, false, true, c.encode(), 1),
            issuer: ai(ik, program, false, false, i.encode(), 1),
            request: ai(rk, program, false, true, r.encode(), 1),
            queue: ai(qk, program, false, true, Queue::new(ck).encode(), 1),
            creator,
        }
    }
    fn r(&self) -> Request {
        Request::decode(&self.request.try_borrow_data().unwrap()).unwrap()
    }
    fn c(&self) -> Config {
        Config::decode(&self.config.try_borrow_data().unwrap()).unwrap()
    }
    fn accounts(&self) -> Vec<AccountInfo<'static>> {
        vec![self.creator.clone(), ro(&self.config), self.request.clone()]
    }
    fn run(&self, wire: &[u8]) -> ProgramResult {
        process_instruction(&self.program, &self.accounts(), wire)
    }
    fn metas(&self) -> Vec<RelevantMeta> {
        (0..self.r().metas.len())
            .map(|n| RelevantMeta {
                key: match n {
                    0 => *self.request.key,
                    1 => *self.queue.key,
                    _ => key(30 + n as u8),
                },
                flags: if n < 2 { 2 } else { 0 },
                owner: if n < 2 { self.program } else { key(50) },
            })
            .collect()
    }
    fn complete(&self) {
        let r = self.r();
        for (n, chunk) in vec![7; r.payload_len as usize]
            .chunks(MAX_CHUNK)
            .enumerate()
        {
            assert_eq!(self.run(&upload((n * MAX_CHUNK) as u16, chunk)), Ok(()));
        }
        for (n, chunk) in self.metas().chunks(MAX_META_CHUNK).enumerate() {
            assert_eq!(
                self.run(&upload_metas((n * MAX_META_CHUNK) as u8, chunk)),
                Ok(())
            );
        }
    }
    fn create_accounts(&self) -> Vec<AccountInfo<'static>> {
        let mut sys = ai(system_program::id(), key(60), false, false, vec![], 0);
        sys.executable = true;
        vec![
            self.creator.clone(),
            ro(&self.config),
            self.issuer.clone(),
            ai(
                *self.request.key,
                system_program::id(),
                false,
                true,
                vec![],
                0,
            ),
            sys,
        ]
    }
}
fn create(x: &Fixture) -> Vec<u8> {
    let r = x.r();
    let mut b = vec![PREFIX, 4];
    b.extend(r.nonce);
    b.extend(r.issuer_hash);
    b.extend(r.recipient.to_bytes());
    b.extend(r.request_type.to_be_bytes());
    b.extend(r.deadline.to_be_bytes());
    b.extend(r.payload_len.to_be_bytes());
    b.push(r.metas.len() as u8);
    b
}
fn upload(offset: u16, payload: &[u8]) -> Vec<u8> {
    let mut b = vec![PREFIX, 6];
    b.extend(offset.to_be_bytes());
    b.extend((payload.len() as u16).to_be_bytes());
    b.extend(payload);
    b
}
fn upload_metas(offset: u8, metas: &[RelevantMeta]) -> Vec<u8> {
    let mut b = vec![PREFIX, 8, offset, metas.len() as u8];
    for m in metas {
        b.extend(m.key.to_bytes());
        b.push(m.flags);
        b.extend(m.owner.to_bytes());
    }
    b
}
struct Host {
    program: Pubkey,
    now: Arc<AtomicI64>,
    created: Arc<AtomicUsize>,
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
        accounts: &[AccountInfo],
        seeds: &[&[&[u8]]],
    ) -> ProgramResult {
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
        if space != REQUEST_LEN
            || owner != self.program
            || accounts[1].owner != &system_program::id()
            || accounts[1].data_len() != 0
            || accounts[1].lamports() != 0
        {
            return Err(ProgramError::InvalidAccountData);
        }
        if Pubkey::create_program_address(seeds[0], &self.program)
            .map_err(|_| ProgramError::InvalidSeeds)?
            != *accounts[1].key
        {
            return Err(ProgramError::InvalidSeeds);
        }
        if accounts[0].lamports() < lamports {
            return Err(ProgramError::InsufficientFunds);
        }
        **accounts[0].try_borrow_mut_lamports()? -= lamports;
        **accounts[1].try_borrow_mut_lamports()? = lamports;
        *accounts[1].try_borrow_mut_data()? = Box::leak(vec![0; space].into_boxed_slice());
        accounts[1].assign(&owner);
        self.created.fetch_add(1, Ordering::SeqCst);
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
    let now = Arc::new(AtomicI64::new(100));
    let created = Arc::new(AtomicUsize::new(0));
    let old = set_syscall_stubs(Box::new(Host {
        program,
        now: now.clone(),
        created: created.clone(),
    }));
    (Restore(Some(old)), now, created)
}

#[test]
fn staging_v3_upload_payload_is_sequential_bounded_and_preserves_unwritten_bytes() {
    let x = Fixture::new(MAX_PAYLOAD as u16, 2, 100);
    let (_h, _now, _calls) = host(x.program);
    assert_eq!(
        x.run(&upload(0, &[7; MAX_CHUNK])),
        Ok(()),
        "authorized v3 staging payload upload must succeed"
    );
    assert_eq!(x.r().uploaded, MAX_CHUNK as u16);
    assert_eq!(&x.r().payload[..MAX_CHUNK], &[7; MAX_CHUNK]);
    assert!(x.r().payload[MAX_CHUNK..].iter().all(|b| *b == 0));
    for wire in [
        upload(0, &[9]),
        upload((MAX_CHUNK + 1) as u16, &[9]),
        upload(MAX_CHUNK as u16, &[]),
        upload(MAX_CHUNK as u16, &vec![9; MAX_CHUNK + 1]),
        upload(u16::MAX, &[9]),
    ] {
        unchanged_failure(&x.program, &x.accounts(), &wire);
    }
    assert_eq!(x.run(&upload(MAX_CHUNK as u16, &[8; MAX_CHUNK])), Ok(()));
    assert_eq!(x.r().uploaded, MAX_PAYLOAD as u16);
    unchanged_failure(&x.program, &x.accounts(), &upload(MAX_PAYLOAD as u16, &[9]));
    unchanged_failure(&x.program, &x.accounts(), &[PREFIX, 5]); // metas not complete
}

#[test]
fn staging_v3_create_uses_exact_pda_size_and_enabled_enrollment_without_live_binding() {
    let x = Fixture::new(4, 3, 100);
    let (_h, _now, calls) = host(x.program);
    let accounts = x.create_accounts();
    let before_config = snapshot(&accounts[1..3]);
    assert_eq!(
        process_instruction(&x.program, &accounts, &create(&x)),
        Ok(())
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(accounts[3].data_len(), REQUEST_LEN);
    assert_eq!(accounts[3].owner, &x.program);
    assert_eq!(
        Request::decode(&accounts[3].try_borrow_data().unwrap()),
        Ok(x.r())
    );
    assert_eq!(snapshot(&accounts[1..3]), before_config);
    assert_eq!(
        Queue::decode(&x.queue.try_borrow_data().unwrap())
            .unwrap()
            .entries
            .len(),
        0
    );
    unchanged_failure(&x.program, &accounts, &create(&x));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "existing request must never be reallocated"
    );
}

#[test]
fn staging_v3_create_rejects_bad_privileges_owners_pdas_associations_and_sizes_before_cpi() {
    for case in 0..24 {
        let x = Fixture::new(4, 2, 100);
        let (_h, _now, calls) = host(x.program);
        let mut a = x.create_accounts();
        match case {
            0 => a[0].is_signer = false,
            1 => a[0].is_writable = false,
            2 => a[1].is_writable = true,
            3 => a[1].is_signer = true,
            4 => a[1].assign(&key(61)),
            5 => a[1].key = Box::leak(Box::new(key(61))),
            6 => a[1].executable = true,
            7 => replace_data(&a[1], vec![0; 380]),
            8 => a[2].is_writable = true,
            9 => a[2].is_signer = true,
            10 => a[2].assign(&key(61)),
            11 => a[2].key = Box::leak(Box::new(key(61))),
            12 => a[2].executable = true,
            13 => replace_data(&a[2], vec![0; 373]),
            14 => {
                let mut i = Issuer::decode(&a[2].try_borrow_data().unwrap()).unwrap();
                i.config = key(61);
                replace_data(&a[2], i.encode());
            }
            15 => a[3].key = Box::leak(Box::new(key(61))),
            16 => a[3].is_writable = false,
            17 => a[3].is_signer = true,
            18 => a[3].assign(&key(61)),
            19 => replace_data(&a[3], vec![0]),
            20 => a[4].executable = false,
            21 => a[4].is_writable = true,
            22 => {
                let extra = a[1].clone();
                a.push(extra);
            }
            23 => a[3] = a[0].clone(),
            _ => unreachable!(),
        }
        unchanged_failure(&x.program, &a, &create(&x));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "invalid case {case} invoked CPI"
        );
    }
}

#[test]
fn staging_v3_create_rejects_disabled_or_mismatched_issuer_and_invalid_bounds() {
    for case in 0..9 {
        let x = Fixture::new(4, 2, 100);
        let (_h, _now, calls) = host(x.program);
        let a = x.create_accounts();
        let mut b = create(&x);
        match case {
            0 => {
                let mut c = x.c();
                c.enabled = false;
                replace_data(&a[1], c.encode());
            }
            1 => {
                let mut i = Issuer::decode(&a[2].try_borrow_data().unwrap()).unwrap();
                i.enabled = false;
                replace_data(&a[2], i.encode());
            }
            2 => b[34..66].copy_from_slice(&field(9)),
            3 => b[98..100].copy_from_slice(&2u16.to_be_bytes()),
            4 => b[100..108].copy_from_slice(&99i64.to_be_bytes()),
            5 => b[108..110].copy_from_slice(&((MAX_PAYLOAD + 1) as u16).to_be_bytes()),
            6 => b[110] = 1,
            7 => b[110] = (MAX_METAS + 1) as u8,
            8 => b[0] = 0x50,
            _ => unreachable!(),
        }
        unchanged_failure(&x.program, &a, &b);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn staging_v3_all_mutations_require_creator_and_exact_owned_writable_request_association() {
    for opcode in [6, 8, 5, 9] {
        for case in 0..16 {
            let x = Fixture::new(4, 3, 100);
            let (_h, _now, _calls) = host(x.program);
            // Each unmodified operation is admissible. In particular Finalize
            // must not fail merely because uploads are incomplete.
            if opcode == 5 {
                x.complete();
            }
            let operation = match opcode {
                6 => upload(0, &[7]),
                8 => upload_metas(0, &x.metas()[..1]),
                _ => vec![PREFIX, opcode],
            };
            let mut a = x.accounts();
            match case {
                0 => a[0].is_signer = false,
                1 => a[0].key = Box::leak(Box::new(key(61))),
                2 => a[1].is_writable = true,
                3 => a[1].assign(&key(61)),
                4 => a[1].key = Box::leak(Box::new(key(61))),
                5 => a[2].is_writable = false,
                6 => a[2].is_signer = true,
                7 => a[2].assign(&key(61)),
                8 => a[2].executable = true,
                9 => a[2].key = Box::leak(Box::new(key(61))),
                10 => replace_data(&a[2], vec![0; REQUEST_LEN - 1]),
                11 => {
                    let mut r = x.r();
                    r.config = key(61);
                    replace_data(&a[2], r.encode());
                }
                12 => {
                    let extra = a[1].clone();
                    a.push(extra);
                }
                13 => {
                    let mut bytes = a[2].try_borrow_data().unwrap().to_vec();
                    bytes[..8].copy_from_slice(b"DYNREQ02");
                    replace_data(&a[2], bytes);
                }
                14 => {
                    let mut r = x.r();
                    r.nonce = [62; 32];
                    replace_data(&a[2], r.encode());
                }
                15 => a[1].executable = true,
                _ => unreachable!(),
            }
            unchanged_failure(&x.program, &a, &operation);
        }
    }
}

#[test]
fn staging_v3_meta_uploads_are_sequential_bounded_and_reject_duplicates_without_partial_write() {
    let x = Fixture::new(0, MAX_METAS, 100);
    let (_h, _now, _calls) = host(x.program);
    let metas = x.metas();
    assert_eq!(x.run(&upload_metas(0, &metas[..4])), Ok(()));
    assert_eq!(x.r().metas_uploaded, 4);
    assert_eq!(&x.r().metas[..4], &metas[..4]);
    for wire in [
        upload_metas(0, &metas[4..5]),
        upload_metas(5, &metas[4..5]),
        upload_metas(4, &[]),
        upload_metas(4, &metas[4..9]),
        upload_metas(4, &[metas[4].clone(), metas[0].clone()]),
        upload_metas(4, &[metas[4].clone(), metas[4].clone()]),
    ] {
        unchanged_failure(&x.program, &x.accounts(), &wire);
    }
    let mut invalid = metas[4].clone();
    invalid.flags = 4;
    unchanged_failure(&x.program, &x.accounts(), &upload_metas(4, &[invalid]));
    for offset in [4, 8, 12] {
        assert_eq!(
            x.run(&upload_metas(
                offset,
                &metas[offset as usize..offset as usize + 4]
            )),
            Ok(())
        );
    }
    assert_eq!(x.r().metas, metas);
    unchanged_failure(
        &x.program,
        &x.accounts(),
        &upload_metas(16, &x.metas()[..1]),
    );
    assert_eq!(x.run(&[PREFIX, 5]), Ok(()));
}

#[test]
fn staging_v3_finalize_locks_exact_action_bytes_and_never_mutates_queue() {
    let x = Fixture::new(4, 3, 100);
    let (_h, _now, _calls) = host(x.program);
    let queue_before = snapshot(&[x.queue.clone()]);
    unchanged_failure(&x.program, &x.accounts(), &[PREFIX, 5]);
    x.complete();
    let mut expected = x.r();
    expected.state = RequestState::Finalized;
    let action_before = action_preimage(&x.program, &x.c(), &expected).unwrap();
    assert_eq!(x.run(&[PREFIX, 5]), Ok(()));
    assert_eq!(
        *x.request.try_borrow_data().unwrap(),
        expected.encode().as_slice()
    );
    assert_eq!(
        action_preimage(&x.program, &x.c(), &x.r()).unwrap(),
        action_before
    );
    assert_eq!(snapshot(&[x.queue.clone()]), queue_before);
    for wire in [
        upload(0, &[9]),
        upload_metas(0, &x.metas()),
        vec![PREFIX, 5],
    ] {
        unchanged_failure(&x.program, &x.accounts(), &wire);
    }
}

#[test]
fn staging_v3_finalize_rejects_changed_order_privileges_owner_and_authority_account_collisions() {
    for case in 0..8 {
        let x = Fixture::new(0, 3, 100);
        let (_h, _now, _calls) = host(x.program);
        let mut metas = x.metas();
        match case {
            0 => metas.swap(0, 1),
            1 => metas[0].flags = 3,
            2 => metas[1].flags = 0,
            3 => metas[0].owner = key(61),
            4 => metas[1].owner = key(61),
            5 => metas[2].key = *x.config.key,
            6 => metas[2].key = *x.issuer.key,
            7 => metas[0].key = key(61),
            _ => unreachable!(),
        }
        // Upload may reject invalid reserved metas early; if retained as preparatory
        // bytes, Finalize must reject them without changing the staged request.
        let before = snapshot(&x.accounts());
        if x.run(&upload_metas(0, &metas)).is_ok() {
            unchanged_failure(&x.program, &x.accounts(), &[PREFIX, 5]);
        } else {
            assert_eq!(snapshot(&x.accounts()), before);
        }
    }
}

#[test]
fn staging_v3_deadline_is_inclusive_then_cancel_remains_available_after_expiry_and_disable() {
    let x = Fixture::new(4, 3, 100);
    let (_h, now, _calls) = host(x.program);
    x.complete();
    assert_eq!(x.run(&[PREFIX, 5]), Ok(())); // now == deadline
    now.store(101, Ordering::SeqCst);
    let mut c = x.c();
    c.enabled = false;
    c.eligibility_epoch = 1;
    replace_data(&x.config, c.encode());
    let before = x.r();
    assert_eq!(x.run(&[PREFIX, 9]), Ok(()));
    let mut expected = before;
    expected.state = RequestState::Cancelled;
    assert_eq!(x.r(), expected);
    for wire in [
        vec![PREFIX, 9],
        vec![PREFIX, 5],
        upload(0, &[1]),
        upload_metas(0, &x.metas()),
    ] {
        unchanged_failure(&x.program, &x.accounts(), &wire);
    }
    let mut create_accounts = x.create_accounts();
    create_accounts[3] = x.request.clone();
    let mut reenabled = x.c();
    reenabled.enabled = true;
    reenabled.eligibility_epoch = 2;
    replace_data(&x.config, reenabled.encode());
    unchanged_failure(&x.program, &create_accounts, &create(&x));
}

#[test]
fn staging_v3_expired_uploads_and_finalize_reject_without_writes_but_partial_cancel_survives_codec()
{
    let x = Fixture::new(4, 3, 100);
    let (_h, now, _calls) = host(x.program);
    let fully_uploaded = Fixture::new(4, 3, 100);
    fully_uploaded.complete();
    assert_eq!(x.run(&upload(0, &[7, 8])), Ok(()));
    assert_eq!(x.run(&upload_metas(0, &x.metas()[..1])), Ok(()));
    now.store(101, Ordering::SeqCst);
    unchanged_failure(
        &fully_uploaded.program,
        &fully_uploaded.accounts(),
        &[PREFIX, 5],
    ); // All data present: only expiry prevents finalization.
    for wire in [
        upload(2, &[9, 9]),
        upload_metas(1, &x.metas()[1..]),
        vec![PREFIX, 5],
    ] {
        unchanged_failure(&x.program, &x.accounts(), &wire);
    }
    let mut expected = x.r();
    expected.state = RequestState::Cancelled;
    assert_eq!(x.run(&[PREFIX, 9]), Ok(()));
    assert_eq!(x.r(), expected);
    assert_eq!((x.r().uploaded, x.r().metas_uploaded), (2, 1));
    assert_eq!(x.r().payload, [7, 8, 0, 0]);
}

#[test]
fn staging_v3_disabled_after_create_can_finish_preparation_but_consumed_request_cannot_cancel() {
    let x = Fixture::new(4, 2, 100);
    let (_h, _now, _calls) = host(x.program);
    let mut c = x.c();
    c.enabled = false;
    c.eligibility_epoch = 1;
    replace_data(&x.config, c.encode());
    x.complete();
    assert_eq!(x.run(&[PREFIX, 5]), Ok(()));
    let mut consumed = x.r();
    consumed.state = RequestState::Consumed;
    replace_data(&x.request, consumed.encode());
    for wire in [
        vec![PREFIX, 9],
        vec![PREFIX, 5],
        upload(0, &[7]),
        upload_metas(0, &x.metas()),
    ] {
        unchanged_failure(&x.program, &x.accounts(), &wire);
    }
    let mut execute = vec![PREFIX, 7];
    execute.extend([0; 448]);
    let before = snapshot(&x.accounts());
    // Creator/config/request staging metas are not the complete Execute plan.
    assert_eq!(x.run(&execute), Err(ProgramError::from(AppError::Accounts)));
    assert_eq!(snapshot(&x.accounts()), before);
}
