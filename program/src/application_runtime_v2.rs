//! Onchain boundary for the five-public-input credential-v2-dev queue application.
//! This version deliberately cannot admit a successor circuit or six-input policy statement.
use crate::application_v2::*;
use solana_program::{
    account_info::AccountInfo, clock::Clock, entrypoint::ProgramResult,
    program_error::ProgramError, pubkey::Pubkey, sysvar::Sysvar,
};
const fn hex(s: &[u8; 64]) -> [u8; 32] {
    let mut b = [0; 32];
    let mut i = 0;
    while i < 32 {
        let x = s[i * 2];
        let y = s[i * 2 + 1];
        b[i] = ((if x <= b'9' { x - b'0' } else { x - b'a' + 10 }) << 4)
            | (if y <= b'9' { y - b'0' } else { y - b'a' + 10 });
        i += 1
    }
    b
}
pub const CIRCUIT_ID: [u8; 32] =
    hex(b"da0ad2e5e92f3879951ac3e56e077967eb5fcf6a9814839d680037d620ae9146");
pub const PACKAGE_ID: [u8; 32] =
    hex(b"04d5ad5776bea03ee014790f54c2572adde796f4d8caeacb88f8a54b0e98b6eb");
pub const SCHEMA_ID: [u8; 32] =
    hex(b"de111be59b7a21f5e9aa757506a9ec679d892d6342c88729b6b7997c8b472611");
pub const PROFILE_ID: [u8; 32] =
    hex(b"eb77028b2bd1e324c6ee74c40b43739ec2ce519014f6d04aebe2ca7f82aa1f68");
pub const PROFILE_VERSION: u32 = 2;
/// Fixed signed AKI20 followed by twelve zero bytes, never a digest or left padding.
pub const AKI: [u8; 32] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
pub fn config_address(program: &Pubkey, admin: &Pubkey, seed: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"dyn-config-v2", admin.as_ref(), seed], program)
}
pub fn issuer_address(program: &Pubkey, config: &Pubkey, issuer: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"dyn-issuer-v2", config.as_ref(), issuer], program)
}
pub fn request_address(
    program: &Pubkey,
    config: &Pubkey,
    creator: &Pubkey,
    nonce: &[u8; 32],
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"dyn-request-v2", config.as_ref(), creator.as_ref(), nonce],
        program,
    )
}
pub fn queue_address(program: &Pubkey, config: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"dyn-queue-v2", config.as_ref()], program)
}
fn owned(program: &Pubkey, a: &AccountInfo) -> ProgramResult {
    if a.owner != program || a.executable {
        return Err(AppError::Owner.into());
    }
    Ok(())
}
fn authority(a: &AccountInfo, key: &Pubkey) -> ProgramResult {
    if !a.is_signer || a.key != key {
        return Err(AppError::Authority.into());
    }
    Ok(())
}
fn writable(a: &AccountInfo) -> ProgramResult {
    if !a.is_writable {
        return Err(AppError::Privileges.into());
    }
    Ok(())
}
fn count(a: &[AccountInfo], n: usize) -> ProgramResult {
    if a.len() != n {
        return Err(AppError::Accounts.into());
    }
    unique(a)
}
fn unique(a: &[AccountInfo]) -> ProgramResult {
    for (i, x) in a.iter().enumerate() {
        if a[..i].iter().any(|y| x.key == y.key) {
            return Err(AppError::Accounts.into());
        }
    }
    Ok(())
}
fn load_config(program: &Pubkey, a: &AccountInfo) -> Result<Config, ProgramError> {
    owned(program, a)?;
    let c = Config::decode(&a.try_borrow_data()?)?;
    if config_address(program, &c.admin, &c.seed).0 != *a.key {
        return Err(AppError::Accounts.into());
    }
    Ok(c)
}
fn load_issuer(program: &Pubkey, c: &AccountInfo, a: &AccountInfo) -> Result<Issuer, ProgramError> {
    owned(program, a)?;
    let i = Issuer::decode(&a.try_borrow_data()?)?;
    if i.config != *c.key || issuer_address(program, c.key, &i.issuer_hash).0 != *a.key {
        return Err(AppError::Accounts.into());
    }
    Ok(i)
}
fn load_request(
    program: &Pubkey,
    c: &AccountInfo,
    a: &AccountInfo,
) -> Result<Request, ProgramError> {
    owned(program, a)?;
    let r = Request::decode(&a.try_borrow_data()?)?;
    if r.config != *c.key || request_address(program, c.key, &r.creator, &r.nonce).0 != *a.key {
        return Err(AppError::Accounts.into());
    }
    Ok(r)
}
fn load_queue(program: &Pubkey, c: &AccountInfo, a: &AccountInfo) -> Result<Queue, ProgramError> {
    owned(program, a)?;
    let q = Queue::decode(&a.try_borrow_data()?)?;
    if q.config != *c.key || queue_address(program, c.key).0 != *a.key {
        return Err(AppError::Accounts.into());
    }
    Ok(q)
}
fn write(a: &AccountInfo, bytes: &[u8]) -> ProgramResult {
    writable(a)?;
    let mut dst = a.try_borrow_mut_data()?;
    if dst.len() != bytes.len() {
        return Err(AppError::State.into());
    }
    dst.copy_from_slice(bytes);
    Ok(())
}
fn package(c: &Config) -> ProgramResult {
    if c.circuit_id != CIRCUIT_ID || c.package_id != PACKAGE_ID || c.schema_id != SCHEMA_ID {
        return Err(AppError::Policy.into());
    }
    Ok(())
}
fn profile(i: &Issuer) -> ProgramResult {
    if i.profile_id != PROFILE_ID || i.profile_version != PROFILE_VERSION || i.aki != AKI {
        return Err(AppError::Policy.into());
    }
    Ok(())
}
fn finalized_metas(program: &Pubkey, c: &AccountInfo, rkey: &Pubkey, r: &Request) -> ProgramResult {
    let queue = queue_address(program, c.key).0;
    let issuer = issuer_address(program, c.key, &r.issuer_hash).0;
    if r.metas.len() < 2
        || r.metas[0].key != *rkey
        || r.metas[1].key != queue
        || r.metas[0].flags != 2
        || r.metas[1].flags != 2
        || r.metas[0].owner != *program
        || r.metas[1].owner != *program
    {
        return Err(AppError::Accounts.into());
    }
    for (index, m) in r.metas.iter().enumerate() {
        if m.key == *c.key || m.key == issuer || r.metas[..index].iter().any(|p| p.key == m.key) {
            return Err(AppError::Accounts.into());
        }
    }
    Ok(())
}
/// Relevant actual accounts are request, queue, then extras, each exactly once.
pub fn validate_relevant(
    program: &Pubkey,
    config: &AccountInfo,
    request_key: &Pubkey,
    r: &Request,
    actual: &[AccountInfo],
) -> ProgramResult {
    finalized_metas(program, config, request_key, r)?;
    if actual.len() != r.metas.len() {
        return Err(AppError::Accounts.into());
    }
    for (meta, a) in r.metas.iter().zip(actual) {
        if meta.key != *a.key {
            return Err(AppError::Accounts.into());
        }
        if meta.owner != *a.owner {
            return Err(AppError::Owner.into());
        }
        if meta.flags != (a.is_signer as u8) | ((a.is_writable as u8) << 1) {
            return Err(AppError::Privileges.into());
        }
    }
    Ok(())
}
/// Performs every current-state and public statement check before curve operations.
pub fn validate_authorization(
    program: &Pubkey,
    c: &Config,
    i: &Issuer,
    r: &Request,
    inputs: &[[u8; 32]; 5],
    now: i64,
) -> ProgramResult {
    package(c)?;
    profile(i)?;
    if !c.enabled || !i.enabled || i.issuer_hash != r.issuer_hash || i.config != r.config {
        return Err(AppError::Policy.into());
    }
    if r.state != RequestState::Finalized {
        return Err(AppError::Consumed.into());
    }
    if now < 0 || now > r.deadline {
        return Err(AppError::Expired.into());
    }
    i.fresh(now)?;
    for input in inputs {
        crate::canonical(input).map_err(|_| AppError::Proof)?
    }
    if inputs[0] != c.root {
        return Err(crate::FreshError::RootNotAccepted.into());
    }
    if inputs[1] != i.issuer_hash {
        return Err(crate::FreshError::IssuerMismatch.into());
    }
    crate::validate_times(&inputs[2], &inputs[3], now)?;
    if inputs[4] != action_hash(program, c, r)? {
        return Err(AppError::Action.into());
    }
    Ok(())
}
const FQ: [u8; 32] = hex(b"30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47");
/// Canonical coordinates and non-infinity before pairing. The verifier/syscalls check curve validity.
pub fn verify(inputs: &[[u8; 32]; 5], proof: &[u8; 256]) -> ProgramResult {
    for input in inputs {
        crate::canonical(input).map_err(|_| AppError::Proof)?
    }
    for point in [&proof[..64], &proof[64..192], &proof[192..]] {
        if point.iter().all(|x| *x == 0) {
            return Err(AppError::Proof.into());
        }
    }
    for coord in proof.chunks_exact(32) {
        if coord >= FQ.as_slice() {
            return Err(AppError::Proof.into());
        }
    }
    let a = proof[..64].try_into().map_err(|_| AppError::Proof)?;
    let b = proof[64..192].try_into().map_err(|_| AppError::Proof)?;
    let c = proof[192..].try_into().map_err(|_| AppError::Proof)?;
    let mut verifier = groth16_solana::groth16::Groth16Verifier::new(
        a,
        b,
        c,
        inputs,
        &crate::generated_vk_v2::VERIFYING_KEY,
    )
    .map_err(|_| AppError::Proof)?;
    verifier.verify().map_err(|_| AppError::Proof.into())
}
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
            root,
        } => {
            count(accounts, 4)?;
            let admin = &accounts[0];
            let config = &accounts[1];
            let queue = &accounts[2];
            let system = &accounts[3];
            authority(admin, admin.key)?;
            writable(admin)?;
            writable(config)?;
            writable(queue)?;
            if publisher == *admin.key
                || publisher == Pubkey::default()
                || genesis == [0; 32]
                || policy_id == [0; 32]
                || policy_version == 0
            {
                return Err(AppError::Policy.into());
            }
            crate::canonical(&root)?;
            let c = Config {
                admin: *admin.key,
                seed,
                publisher,
                genesis,
                policy_id,
                policy_version,
                circuit_id,
                package_id,
                schema_id,
                root,
                root_version: 0,
                enabled: true,
            };
            package(&c)?;
            let (expected, bump) = config_address(program, admin.key, &seed);
            if expected != *config.key {
                return Err(AppError::Accounts.into());
            }
            let (expected_q, qb) = queue_address(program, config.key);
            if expected_q != *queue.key {
                return Err(AppError::Accounts.into());
            }
            crate::check_receipt_unused(program, config.owner, config.data_len())?;
            crate::check_receipt_unused(program, queue.owner, queue.data_len())?;
            crate::create_pda(
                program,
                admin,
                config,
                system,
                CONFIG_LEN,
                &[b"dyn-config-v2", admin.key.as_ref(), &seed, &[bump]],
            )?;
            crate::create_pda(
                program,
                admin,
                queue,
                system,
                QUEUE_LEN,
                &[b"dyn-queue-v2", config.key.as_ref(), &[qb]],
            )?;
            write(config, &c.encode())?;
            write(queue, &Queue::new(*config.key).encode())?;
        }
        AppInstruction::Enroll {
            issuer_hash,
            profile_id,
            profile_version,
            aki,
            source,
        } => {
            count(accounts, 4)?;
            let admin = &accounts[0];
            let ca = &accounts[1];
            let ia = &accounts[2];
            let system = &accounts[3];
            let c = load_config(program, ca)?;
            authority(admin, &c.admin)?;
            writable(admin)?;
            writable(ia)?;
            package(&c)?;
            crate::canonical(&issuer_hash)?;
            if source == c.admin
                || source == c.publisher
                || source == Pubkey::default()
                || issuer_hash == [0; 32]
                || aki == [0; 32]
            {
                return Err(AppError::Policy.into());
            }
            let i = Issuer {
                config: *ca.key,
                issuer_hash,
                profile_id,
                profile_version,
                aki,
                source,
                enabled: true,
                sequence: 0,
                digest: [0; 32],
                observed_at: 0,
                expires_at: 0,
            };
            profile(&i)?;
            let (expected, bump) = issuer_address(program, ca.key, &issuer_hash);
            if expected != *ia.key {
                return Err(AppError::Accounts.into());
            }
            crate::check_receipt_unused(program, ia.owner, ia.data_len())?;
            crate::create_pda(
                program,
                admin,
                ia,
                system,
                ISSUER_LEN,
                &[b"dyn-issuer-v2", ca.key.as_ref(), &issuer_hash, &[bump]],
            )?;
            write(ia, &i.encode())?;
        }
        AppInstruction::Publish { expected, root } => {
            count(accounts, 2)?;
            let mut c = load_config(program, &accounts[1])?;
            authority(&accounts[0], &c.publisher)?;
            writable(&accounts[1])?;
            c.publish(expected, root)?;
            write(&accounts[1], &c.encode())?
        }
        AppInstruction::Observe {
            expected,
            sequence,
            digest,
            observed,
            expires,
        } => {
            count(accounts, 3)?;
            load_config(program, &accounts[1])?;
            let mut i = load_issuer(program, &accounts[1], &accounts[2])?;
            authority(&accounts[0], &i.source)?;
            writable(&accounts[2])?;
            i.observe(
                expected,
                sequence,
                digest,
                observed,
                expires,
                Clock::get()?.unix_timestamp,
            )?;
            write(&accounts[2], &i.encode())?
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
            let system = &accounts[4];
            authority(creator, creator.key)?;
            writable(creator)?;
            writable(ra)?;
            let c = load_config(program, ca)?;
            package(&c)?;
            let i = load_issuer(program, ca, ia)?;
            profile(&i)?;
            if !c.enabled || !i.enabled || i.issuer_hash != issuer_hash {
                return Err(AppError::Policy.into());
            }
            if deadline < Clock::get()?.unix_timestamp {
                return Err(AppError::Expired.into());
            }
            let (expected, bump) = request_address(program, ca.key, creator.key, &nonce);
            if expected != *ra.key {
                return Err(AppError::Accounts.into());
            }
            crate::check_receipt_unused(program, ra.owner, ra.data_len())?;
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
            crate::create_pda(
                program,
                creator,
                ra,
                system,
                REQUEST_LEN,
                &[
                    b"dyn-request-v2",
                    ca.key.as_ref(),
                    creator.key.as_ref(),
                    &nonce,
                    &[bump],
                ],
            )?;
            write(ra, &r.encode())?;
        }
        AppInstruction::Upload { .. }
        | AppInstruction::UploadMetas { .. }
        | AppInstruction::Finalize
        | AppInstruction::Cancel => {
            count(accounts, 3)?;
            let creator = &accounts[0];
            let ca = &accounts[1];
            let ra = &accounts[2];
            load_config(program, ca)?;
            let mut r = load_request(program, ca, ra)?;
            authority(creator, &r.creator)?;
            writable(ra)?;
            match instruction {
                AppInstruction::Upload { offset, bytes } => r.upload(offset, &bytes)?,
                AppInstruction::UploadMetas { offset, metas } => r.upload_metas(offset, &metas)?,
                AppInstruction::Finalize => {
                    finalized_metas(program, ca, ra.key, &r)?;
                    r.finalize(Clock::get()?.unix_timestamp)?
                }
                AppInstruction::Cancel => {
                    if r.state != RequestState::Staging && r.state != RequestState::Finalized {
                        return Err(AppError::Consumed.into());
                    }
                    r.state = RequestState::Cancelled
                }
                _ => unreachable!(),
            };
            write(ra, &r.encode())?;
        }
        AppInstruction::SetEnabled { policy, issuer } => {
            count(accounts, 3)?;
            let mut c = load_config(program, &accounts[1])?;
            let mut i = load_issuer(program, &accounts[1], &accounts[2])?;
            authority(&accounts[0], &c.admin)?;
            writable(&accounts[1])?;
            writable(&accounts[2])?;
            c.enabled = policy;
            i.enabled = issuer;
            let mut cb = accounts[1].try_borrow_mut_data()?;
            let mut ib = accounts[2].try_borrow_mut_data()?;
            cb.copy_from_slice(&c.encode());
            ib.copy_from_slice(&i.encode());
        }
        AppInstruction::Execute { inputs, proof } => {
            if accounts.len() < 4 || accounts.len() > 2 + MAX_METAS {
                return Err(AppError::Accounts.into());
            }
            unique(accounts)?;
            if accounts[0].is_writable
                || accounts[0].is_signer
                || accounts[1].is_writable
                || accounts[1].is_signer
            {
                return Err(AppError::Privileges.into());
            }
            let c = load_config(program, &accounts[0])?;
            let i = load_issuer(program, &accounts[0], &accounts[1])?;
            let mut r = load_request(program, &accounts[0], &accounts[2])?;
            let mut q = load_queue(program, &accounts[0], &accounts[3])?;
            validate_relevant(program, &accounts[0], accounts[2].key, &r, &accounts[2..])?;
            let now = Clock::get()?.unix_timestamp;
            validate_authorization(program, &c, &i, &r, &inputs, now)?;
            // Capacity/replay checks occur before pairing and any account mutation.
            append(&mut q, &mut r, *accounts[2].key, now)?;
            verify(&inputs, &proof)?;
            // Borrow both accounts before either write; no fallible operation after the first write.
            let qb = q.encode();
            let rb = r.encode();
            let mut qdst = accounts[3].try_borrow_mut_data()?;
            let mut rdst = accounts[2].try_borrow_mut_data()?;
            if qdst.len() != qb.len() || rdst.len() != rb.len() {
                return Err(AppError::State.into());
            }
            qdst.copy_from_slice(&qb);
            rdst.copy_from_slice(&rb);
        }
    };
    Ok(())
}
