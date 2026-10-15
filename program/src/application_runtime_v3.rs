//! V3 administrative runtime only. Request staging and Execute remain unavailable.
use crate::application_v3::{
    AppError, AppInstruction, Authority, Config, Issuer, Queue, CONFIG_LEN, ISSUER_LEN, QUEUE_LEN,
};
use solana_program::{
    account_info::AccountInfo, clock::Clock, entrypoint::ProgramResult,
    program_error::ProgramError, pubkey::Pubkey, system_program, sysvar::Sysvar,
};
pub fn config_address(program: &Pubkey, admin: &Pubkey, seed: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"dyn-config-v3", admin.as_ref(), seed], program)
}
pub fn issuer_address(program: &Pubkey, config: &Pubkey, issuer: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"dyn-issuer-v3", config.as_ref(), issuer], program)
}
pub fn request_address(
    program: &Pubkey,
    config: &Pubkey,
    creator: &Pubkey,
    nonce: &[u8; 32],
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"dyn-request-v3", config.as_ref(), creator.as_ref(), nonce],
        program,
    )
}
pub fn queue_address(program: &Pubkey, config: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"dyn-queue-v3", config.as_ref()], program)
}
// Administrative account contract (all state PDAs are nonsigners):
// 0 Initialize: admin signer+writable, config W, queue W, executable System RO.
// 1 Enroll: admin signer+writable, config RO, issuer W, executable System RO.
// 2 Publish: publisher signer, config W.
// 3 Observe: source signer, config RO, issuer W.
// 10 SetConfigEnabled: admin signer, config W.
// 11 BindCurrent: publisher signer, config RO, issuer W.
// 12 SetIssuerEnabled: admin signer, config RO, issuer W.
// Signer authorities may be writable fee payers. No request/proof handler exists.
fn count(accounts: &[AccountInfo], expected: usize) -> ProgramResult {
    if accounts.len() != expected {
        return Err(AppError::Accounts.into());
    }
    for (n, a) in accounts.iter().enumerate() {
        if accounts[..n].iter().any(|p| p.key == a.key) {
            return Err(AppError::Accounts.into());
        }
    }
    Ok(())
}
fn authority(a: &AccountInfo, key: &Pubkey) -> ProgramResult {
    if !a.is_signer || a.key != key {
        return Err(AppError::Authority.into());
    }
    Ok(())
}
fn role(a: &AccountInfo, writable: bool) -> ProgramResult {
    if a.is_signer || a.is_writable != writable {
        return Err(AppError::Privileges.into());
    }
    Ok(())
}
fn owned(program: &Pubkey, a: &AccountInfo, writable: bool) -> ProgramResult {
    if a.owner != program || a.executable {
        return Err(AppError::Owner.into());
    }
    role(a, writable)
}
fn fresh_account(program: &Pubkey, a: &AccountInfo) -> ProgramResult {
    role(a, true)?;
    if a.executable || a.owner != &system_program::id() {
        return Err(AppError::Owner.into());
    }
    // Existing program accounts are immutable enrollment/config identities. A
    // pre-funded System-owned empty PDA is handled by the existing allocator.
    if a.owner == program || a.data_len() != 0 {
        return Err(AppError::State.into());
    }
    Ok(())
}
fn system(a: &AccountInfo) -> ProgramResult {
    if a.key != &system_program::id() || !a.executable {
        return Err(AppError::Accounts.into());
    }
    role(a, false)
}
fn load_config(program: &Pubkey, a: &AccountInfo, writable: bool) -> Result<Config, ProgramError> {
    owned(program, a, writable)?;
    let c = Config::decode(&a.try_borrow_data()?)?;
    if config_address(program, &c.admin, &c.seed).0 != *a.key {
        return Err(AppError::Accounts.into());
    }
    Ok(c)
}
fn load_issuer(
    program: &Pubkey,
    config: &AccountInfo,
    a: &AccountInfo,
) -> Result<Issuer, ProgramError> {
    owned(program, a, true)?;
    let i = Issuer::decode(&a.try_borrow_data()?)?;
    if i.config != *config.key || issuer_address(program, config.key, &i.issuer_hash).0 != *a.key {
        return Err(AppError::Accounts.into());
    }
    Ok(i)
}
fn epochs(c: &Config, i: &Issuer, expected_config: u64, expected_issuer: u64) -> ProgramResult {
    if c.eligibility_epoch != expected_config || i.eligibility_epoch != expected_issuer {
        return Err(AppError::Version.into());
    }
    Ok(())
}
fn actor(a: &AccountInfo) -> Authority {
    Authority {
        key: *a.key,
        is_signer: a.is_signer,
    }
}
fn write(a: &AccountInfo, bytes: &[u8]) -> ProgramResult {
    let mut data = a.try_borrow_mut_data()?;
    if data.len() != bytes.len() {
        return Err(AppError::State.into());
    }
    data.copy_from_slice(bytes);
    Ok(())
}
pub fn process(program: &Pubkey, accounts: &[AccountInfo], bytes: &[u8]) -> ProgramResult {
    match AppInstruction::parse(bytes)? {
        AppInstruction::Initialize {
            seed,
            publisher,
            genesis,
            policy_id,
            policy_version,
            circuit_id,
            package_id,
            schema_id,
            profile_id,
            ordinary_vk_digest,
            root,
        } => {
            count(accounts, 4)?;
            let payer = &accounts[0];
            let ca = &accounts[1];
            let qa = &accounts[2];
            let sys = &accounts[3];
            authority(payer, payer.key)?;
            if !payer.is_writable {
                return Err(AppError::Privileges.into());
            }
            fresh_account(program, ca)?;
            fresh_account(program, qa)?;
            system(sys)?;
            if publisher == *payer.key || publisher == Pubkey::default() || genesis == [0; 32] {
                return Err(AppError::Policy.into());
            }
            let c = Config {
                admin: *payer.key,
                seed,
                publisher,
                genesis,
                policy_id,
                policy_version,
                circuit_id,
                package_id,
                schema_id,
                profile_id,
                ordinary_vk_digest,
                root,
                root_version: 0,
                eligibility_epoch: 0,
                enabled: true,
            };
            let cb = c.encode();
            Config::decode(&cb)?;
            let (expected, bump) = config_address(program, payer.key, &seed);
            let (expected_q, queue_bump) = queue_address(program, ca.key);
            if expected != *ca.key || expected_q != *qa.key {
                return Err(AppError::Accounts.into());
            }
            let qb = Queue::new(*ca.key).encode();
            // All account and semantic checks precede either CPI. Solana owns
            // transaction rollback if allocation/CPI fails; host model tests do
            // not establish that rollback or the loaded-ELF allocation result.
            crate::create_pda(
                program,
                payer,
                ca,
                sys,
                CONFIG_LEN,
                &[b"dyn-config-v3", payer.key.as_ref(), &seed, &[bump]],
            )?;
            crate::create_pda(
                program,
                payer,
                qa,
                sys,
                QUEUE_LEN,
                &[b"dyn-queue-v3", ca.key.as_ref(), &[queue_bump]],
            )?;
            owned(program, ca, true)?;
            owned(program, qa, true)?;
            let mut cd = ca.try_borrow_mut_data()?;
            let mut qd = qa.try_borrow_mut_data()?;
            if cd.len() != CONFIG_LEN || qd.len() != QUEUE_LEN {
                return Err(AppError::State.into());
            }
            // Both borrows and lengths are checked before the first data write.
            cd.copy_from_slice(&cb);
            qd.copy_from_slice(&qb);
        }
        AppInstruction::Enroll {
            issuer_hash,
            aki,
            source,
            enrollment_version,
            evidence_digest,
        } => {
            count(accounts, 4)?;
            let payer = &accounts[0];
            let ca = &accounts[1];
            let ia = &accounts[2];
            let sys = &accounts[3];
            let c = load_config(program, ca, false)?;
            authority(payer, &c.admin)?;
            if !payer.is_writable {
                return Err(AppError::Privileges.into());
            }
            fresh_account(program, ia)?;
            system(sys)?;
            if source == c.admin || source == c.publisher || source == Pubkey::default() {
                return Err(AppError::Policy.into());
            }
            let i = Issuer::enroll(
                *ca.key,
                &c,
                actor(payer),
                issuer_hash,
                aki,
                source,
                enrollment_version,
                evidence_digest,
            )?;
            let (expected, bump) = issuer_address(program, ca.key, &issuer_hash);
            if expected != *ia.key {
                return Err(AppError::Accounts.into());
            }
            let data = i.encode();
            Issuer::decode(&data)?;
            crate::create_pda(
                program,
                payer,
                ia,
                sys,
                ISSUER_LEN,
                &[b"dyn-issuer-v3", ca.key.as_ref(), &issuer_hash, &[bump]],
            )?;
            owned(program, ia, true)?;
            write(ia, &data)?;
        }
        AppInstruction::Publish { expected, root } => {
            count(accounts, 2)?;
            let mut c = load_config(program, &accounts[1], true)?;
            authority(&accounts[0], &c.publisher)?;
            c.publish(actor(&accounts[0]), expected, root)?;
            write(&accounts[1], &c.encode())?;
        }
        AppInstruction::Observe {
            expected_config_epoch,
            expected_issuer_epoch,
            expected,
            sequence,
            digest,
            observed,
            expires,
        } => {
            count(accounts, 3)?;
            let c = load_config(program, &accounts[1], false)?;
            let mut i = load_issuer(program, &accounts[1], &accounts[2])?;
            authority(&accounts[0], &i.source)?;
            epochs(&c, &i, expected_config_epoch, expected_issuer_epoch)?;
            // This frozen administrative wire records authenticated observation
            // validity only. It has no issuer-active bit. A separately reviewed
            // status revision is REQUIRED before any Execute handler is enabled.
            i.observe(
                &c,
                actor(&accounts[0]),
                expected_config_epoch,
                expected_issuer_epoch,
                expected,
                sequence,
                digest,
                observed,
                expires,
                Clock::get()?.unix_timestamp,
            )?;
            write(&accounts[2], &i.encode())?;
        }
        AppInstruction::SetConfigEnabled { enabled } => {
            count(accounts, 2)?;
            let mut c = load_config(program, &accounts[1], true)?;
            authority(&accounts[0], &c.admin)?;
            c.set_enabled(actor(&accounts[0]), enabled)?;
            write(&accounts[1], &c.encode())?;
        }
        AppInstruction::BindCurrent {
            expected_config_epoch,
            expected_issuer_epoch,
            root_version,
            source_sequence,
        } => {
            count(accounts, 3)?;
            let c = load_config(program, &accounts[1], false)?;
            let mut i = load_issuer(program, &accounts[1], &accounts[2])?;
            authority(&accounts[0], &c.publisher)?;
            epochs(&c, &i, expected_config_epoch, expected_issuer_epoch)?;
            i.bind_current(
                &c,
                actor(&accounts[0]),
                expected_config_epoch,
                expected_issuer_epoch,
                root_version,
                source_sequence,
                Clock::get()?.unix_timestamp,
            )?;
            write(&accounts[2], &i.encode())?;
        }
        AppInstruction::SetIssuerEnabled { enabled } => {
            count(accounts, 3)?;
            let c = load_config(program, &accounts[1], false)?;
            let mut i = load_issuer(program, &accounts[1], &accounts[2])?;
            authority(&accounts[0], &c.admin)?;
            i.set_enabled(&c, actor(&accounts[0]), enabled)?;
            write(&accounts[2], &i.encode())?;
        }
        // No proof verification, queue append, request staging, upload, finalize,
        // or cancellation exists in this slice. Parse bounds still apply.
        _ => return Err(AppError::Unavailable.into()),
    }
    Ok(())
}
