//! V3 administrative and request-staging runtime. Execute remains unavailable.
use crate::application_v3::{
    AppError, AppInstruction, Authority, Config, Issuer, PublisherHead, Queue, RelevantMeta,
    Request, RequestState, CONFIG_LEN, HEAD_LEN, ISSUER_LEN, QUEUE_LEN, REQUEST_LEN,
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
pub fn publisher_head_address(
    program: &Pubkey,
    config: &Pubkey,
    issuer: &Pubkey,
    publisher: &Pubkey,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            b"dyn-pubhead-v3",
            config.as_ref(),
            issuer.as_ref(),
            publisher.as_ref(),
        ],
        program,
    )
}
// Administrative account contract (all state PDAs are nonsigners):
// 0 Initialize: admin signer+writable, config W, queue W, executable System RO.
// 1 Enroll: admin signer+writable, config RO, issuer W, executable System RO.
// 2 Publish: publisher signer, config W.
// 3 Observe: source signer, config RO, issuer W.
// 4 Create: creator signer+writable, config RO, issuer RO, request W, executable System RO.
// 5/6/8/9 Finalize/Upload/UploadMetas/Cancel: creator signer, config RO, request W.
// 10 SetConfigEnabled: admin signer, config W.
// 11 BindCurrent: publisher signer, config RO, issuer W.
// 12 SetIssuerEnabled: admin signer, config RO, issuer W.
// 13/revision1 BindWithHead: publisher signer+writable, config RO, issuer W,
// head W, executable System RO. Same metas for initial allocation and updates.
// Signer authorities may be writable fee payers. Execute effects remain disabled.
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
    writable: bool,
) -> Result<Issuer, ProgramError> {
    owned(program, a, writable)?;
    let i = Issuer::decode(&a.try_borrow_data()?)?;
    if i.config != *config.key || issuer_address(program, config.key, &i.issuer_hash).0 != *a.key {
        return Err(AppError::Accounts.into());
    }
    Ok(i)
}
fn load_request(
    program: &Pubkey,
    config: &AccountInfo,
    a: &AccountInfo,
) -> Result<Request, ProgramError> {
    owned(program, a, true)?;
    let r = Request::decode(&a.try_borrow_data()?)?;
    if r.config != *config.key
        || request_address(program, config.key, &r.creator, &r.nonce).0 != *a.key
    {
        return Err(AppError::Accounts.into());
    }
    Ok(r)
}
fn finalized_metas(
    program: &Pubkey,
    config: &AccountInfo,
    request: &Pubkey,
    r: &Request,
) -> ProgramResult {
    let queue = queue_address(program, config.key).0;
    let issuer = issuer_address(program, config.key, &r.issuer_hash).0;
    if r.metas.len() < 2
        || r.metas[0].key != *request
        || r.metas[1].key != queue
        || r.metas[..2]
            .iter()
            .any(|m| m.flags != 2 || m.owner != *program)
    {
        return Err(AppError::Accounts.into());
    }
    for (index, m) in r.metas.iter().enumerate() {
        if m.key == *config.key
            || m.key == issuer
            || r.metas[..index].iter().any(|prior| prior.key == m.key)
        {
            return Err(AppError::Accounts.into());
        }
    }
    Ok(())
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
const FQ: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];
/// Six-field ordinary Groth16 verification only; this does not authorize an
/// application effect. Execute dispatch remains unavailable. The ABI is -A,
/// B(x.c1,x.c0,y.c1,y.c0), C with canonical BE Fq components. Curve/subgroup and
/// pairing checks are performed by groth16-solana and its BN254 syscalls.
pub fn verify(inputs: &[[u8; 32]; 6], proof: &[u8; 256]) -> ProgramResult {
    for input in inputs {
        crate::canonical(input).map_err(|_| AppError::Proof)?;
    }
    for point in [&proof[..64], &proof[64..192], &proof[192..]] {
        if point.iter().all(|byte| *byte == 0) {
            return Err(AppError::Proof.into());
        }
    }
    for coordinate in proof.chunks_exact(32) {
        if coordinate >= FQ.as_slice() {
            return Err(AppError::Proof.into());
        }
    }
    let key = &crate::generated_vk_v3::VERIFYING_KEY;
    if key.nr_pubinputs != 6 || key.vk_ic.len() != 7 {
        return Err(AppError::Proof.into());
    }
    let a = proof[..64].try_into().map_err(|_| AppError::Proof)?;
    let b = proof[64..192].try_into().map_err(|_| AppError::Proof)?;
    let c = proof[192..].try_into().map_err(|_| AppError::Proof)?;
    let mut verifier = groth16_solana::groth16::Groth16Verifier::new(a, b, c, inputs, key)
        .map_err(|_| AppError::Proof)?;
    verifier.verify().map_err(|_| AppError::Proof.into())
}

/// Private effect-only RED stub, intentionally disconnected from Execute.
/// Synthetic unit tests exercise commit mechanics without proving authorization.
/// A future caller must first authenticate current accounts and verify the real
/// request-bound proof. No public API or dispatch route bypasses that boundary.
#[allow(dead_code)]
fn apply_execute_effect(
    _request_account: &AccountInfo,
    _queue_account: &AccountInfo,
    _now: i64,
) -> ProgramResult {
    Err(AppError::Unavailable.into())
}

#[cfg(test)]
#[path = "application_runtime_v3/execute_effect_tests.rs"]
mod execute_effect_tests;

pub fn process(program: &Pubkey, accounts: &[AccountInfo], bytes: &[u8]) -> ProgramResult {
    let instruction = AppInstruction::parse(bytes)?;
    match instruction {
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
            active,
            observed,
            expires,
        } => {
            count(accounts, 3)?;
            let c = load_config(program, &accounts[1], false)?;
            let mut i = load_issuer(program, &accounts[1], &accounts[2], true)?;
            authority(&accounts[0], &i.source)?;
            epochs(&c, &i, expected_config_epoch, expected_issuer_epoch)?;
            // Preserve the authenticated active/negative fact exactly; neither
            // current epochs nor the source signature imply active status.
            i.observe(
                &c,
                actor(&accounts[0]),
                expected_config_epoch,
                expected_issuer_epoch,
                expected,
                sequence,
                digest,
                active,
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
            let mut i = load_issuer(program, &accounts[1], &accounts[2], true)?;
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
            let mut i = load_issuer(program, &accounts[1], &accounts[2], true)?;
            authority(&accounts[0], &c.admin)?;
            i.set_enabled(&c, actor(&accounts[0]), enabled)?;
            write(&accounts[2], &i.encode())?;
        }
        AppInstruction::Create {
            nonce,
            issuer_hash,
            recipient,
            request_type,
            deadline,
            payload_len,
            meta_count,
        } => {
            count(accounts, 5)?;
            let creator = &accounts[0];
            let ca = &accounts[1];
            let ia = &accounts[2];
            let ra = &accounts[3];
            let sys = &accounts[4];
            authority(creator, creator.key)?;
            if !creator.is_writable {
                return Err(AppError::Privileges.into());
            }
            let c = load_config(program, ca, false)?;
            let i = load_issuer(program, ca, ia, false)?;
            // Creation is preparatory, not authorization. Do not require current
            // status/binding/recorded epochs until the separate Execute gate.
            if !c.enabled
                || !i.enabled
                || i.profile_id != c.profile_id
                || i.issuer_hash != issuer_hash
            {
                return Err(AppError::Policy.into());
            }
            fresh_account(program, ra)?;
            system(sys)?;
            let now = Clock::get()?.unix_timestamp;
            if now < 0 || now > deadline {
                return Err(AppError::Expired.into());
            }
            let (expected, bump) = request_address(program, ca.key, creator.key, &nonce);
            if expected != *ra.key {
                return Err(AppError::Accounts.into());
            }
            let r = Request {
                config: *ca.key,
                creator: *creator.key,
                nonce,
                issuer_hash,
                recipient,
                request_type,
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
                    meta_count as usize
                ],
                payload: vec![0; payload_len as usize],
            };
            let data = r.encode();
            Request::decode(&data)?; // Exact bounded canonical account, before CPI.
            crate::create_pda(
                program,
                creator,
                ra,
                sys,
                REQUEST_LEN,
                &[
                    b"dyn-request-v3",
                    ca.key.as_ref(),
                    creator.key.as_ref(),
                    &nonce,
                    &[bump],
                ],
            )?;
            owned(program, ra, true)?;
            write(ra, &data)?;
        }
        AppInstruction::Upload { .. }
        | AppInstruction::UploadMetas { .. }
        | AppInstruction::Finalize
        | AppInstruction::Cancel => {
            count(accounts, 3)?;
            let creator = &accounts[0];
            let ca = &accounts[1];
            let ra = &accounts[2];
            load_config(program, ca, false)?;
            let mut r = load_request(program, ca, ra)?;
            authority(creator, &r.creator)?;
            // Preparatory uploads/finalization may finish after disable; live
            // eligibility is enforced by Execute. Cancel also survives expiry.
            match instruction {
                AppInstruction::Upload { offset, bytes } => {
                    r.upload(offset, &bytes, Clock::get()?.unix_timestamp)?
                }
                AppInstruction::UploadMetas { offset, metas } => {
                    r.upload_metas(offset, &metas, Clock::get()?.unix_timestamp)?
                }
                AppInstruction::Finalize => {
                    finalized_metas(program, ca, ra.key, &r)?;
                    r.finalize(Clock::get()?.unix_timestamp)?;
                }
                AppInstruction::Cancel => r.cancel()?,
                _ => unreachable!(),
            }
            write(ra, &r.encode())?;
        }
        AppInstruction::BindWithHead(binding) => {
            count(accounts, 5)?;
            let publisher = &accounts[0];
            let ca = &accounts[1];
            let ia = &accounts[2];
            let ha = &accounts[3];
            let sys = &accounts[4];
            let c = load_config(program, ca, false)?;
            let i = load_issuer(program, ca, ia, true)?;
            authority(publisher, &c.publisher)?;
            if !publisher.is_writable {
                return Err(AppError::Privileges.into());
            }
            system(sys)?;
            let (expected, bump) = publisher_head_address(program, ca.key, ia.key, &c.publisher);
            if expected != *ha.key {
                return Err(AppError::Accounts.into());
            }
            let previous = if ha.owner == program {
                owned(program, ha, true)?;
                Some(PublisherHead::decode(&ha.try_borrow_data()?)?)
            } else {
                // An empty System PDA may already hold donated rent. A malformed
                // program account is never interpreted as a genesis predecessor.
                fresh_account(program, ha)?;
                None
            };
            let (next_issuer, next_head) = PublisherHead::prepare_bind(
                *ca.key,
                *ia.key,
                &c,
                &i,
                actor(publisher),
                previous.as_ref(),
                &binding,
                Clock::get()?.unix_timestamp,
            )?;
            let ib = next_issuer.encode();
            let hb = next_head.encode();
            // Validate all values and destination access before any CPI/write.
            PublisherHead::decode(&hb)?;
            Issuer::decode(&ib)?;
            let mut idst = ia.try_borrow_mut_data()?;
            if idst.len() != ib.len() {
                return Err(AppError::State.into());
            }
            if previous.is_none() {
                let preflight = ha.try_borrow_mut_data()?;
                if !preflight.is_empty() {
                    return Err(AppError::State.into());
                }
                drop(preflight);
                // The trusted System CPI receives no issuer AccountInfo. Keep
                // its destination borrow until the final pair of writes.
                crate::create_pda(
                    program,
                    publisher,
                    ha,
                    sys,
                    HEAD_LEN,
                    &[
                        b"dyn-pubhead-v3",
                        ca.key.as_ref(),
                        ia.key.as_ref(),
                        c.publisher.as_ref(),
                        &[bump],
                    ],
                )?;
            }
            owned(program, ha, true)?;
            let mut hdst = ha.try_borrow_mut_data()?;
            if hdst.len() != hb.len() {
                return Err(AppError::State.into());
            }
            // Both mutable borrows/lengths are held/checked. Nothing fallible
            // follows the first write; Solana owns any earlier CPI rollback.
            idst.copy_from_slice(&ib);
            hdst.copy_from_slice(&hb);
        }
        AppInstruction::Execute { inputs, proof } => {
            let now = Clock::get()?.unix_timestamp;
            crate::application_preflight_v3::check(program, accounts, &inputs, now)?;
            verify(&inputs, &proof)?;
            // A valid statement still cannot authorize an effect until a real
            // request-bound Full proof and atomic append/consume tests exist.
            return Err(AppError::Unavailable.into());
        }
    }
    Ok(())
}
