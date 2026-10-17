//! Non-authorizing structural/current-state preflight only. Even success cannot
//! establish a valid ordinary proof or authorize a queue append. Runtime Execute
//! independently verifies the proof before applying the queue effect.
use crate::{
    application_runtime_v3 as addresses,
    application_v3::{
        action_hash, AppError, Config, Issuer, PublisherHead, Queue, Request, RequestState,
        MAX_METAS, QUEUE_CAPACITY,
    },
};
use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult, pubkey::Pubkey};

fn owned_role(program: &Pubkey, account: &AccountInfo, writable: bool) -> ProgramResult {
    if account.owner != program || account.executable {
        return Err(AppError::Owner.into());
    }
    if account.is_signer || account.is_writable != writable {
        return Err(AppError::Privileges.into());
    }
    Ok(())
}

/// Check only the supplied account view and public statement. This function
/// authenticates no RPC finality, external time, network pin, source envelope or
/// ordinary proof. The runtime must supply its actual program/accounts and
/// Clock, then independently verify the proof before any application effect.
///
/// Exact ordered accounts: config RO, issuer RO, publisher head RO, request W,
/// queue W, then relevant extras. Fixed accounts are nonsigners. The immutable
/// relevant list starts with request/queue, each appearing exactly once.
pub fn check(
    program: &Pubkey,
    actual_accounts: &[AccountInfo],
    inputs: &[[u8; 32]; 6],
    now: i64,
) -> ProgramResult {
    if !(5..=3 + MAX_METAS).contains(&actual_accounts.len()) {
        return Err(AppError::Accounts.into());
    }
    for (index, account) in actual_accounts.iter().enumerate() {
        if actual_accounts[..index]
            .iter()
            .any(|prior| prior.key == account.key)
        {
            return Err(AppError::Accounts.into());
        }
    }
    for (index, account) in actual_accounts[..5].iter().enumerate() {
        owned_role(program, account, index >= 3)?;
    }
    let ca = &actual_accounts[0];
    let ia = &actual_accounts[1];
    let ha = &actual_accounts[2];
    let ra = &actual_accounts[3];
    let qa = &actual_accounts[4];
    // Each codec enforces its exact length, version discriminator, bounds and
    // canonical representation. Config additionally pins the shared v3 identities.
    let c = Config::decode(&ca.try_borrow_data()?)?;
    let i = Issuer::decode(&ia.try_borrow_data()?)?;
    let h = PublisherHead::decode(&ha.try_borrow_data()?)?;
    let r = Request::decode(&ra.try_borrow_data()?)?;
    let q = Queue::decode(&qa.try_borrow_data()?)?;
    if addresses::config_address(program, &c.admin, &c.seed).0 != *ca.key
        || addresses::issuer_address(program, ca.key, &i.issuer_hash).0 != *ia.key
        || addresses::publisher_head_address(program, ca.key, ia.key, &c.publisher).0 != *ha.key
        || addresses::request_address(program, ca.key, &r.creator, &r.nonce).0 != *ra.key
        || addresses::queue_address(program, ca.key).0 != *qa.key
        || i.config != *ca.key
        || h.config != *ca.key
        || h.issuer != *ia.key
        || h.publisher != c.publisher
        || r.config != *ca.key
        || q.config != *ca.key
    {
        return Err(AppError::Accounts.into());
    }
    let relevant = &actual_accounts[3..];
    if r.metas.len() != relevant.len()
        || r.metas[0].key != *ra.key
        || r.metas[1].key != *qa.key
        || r.metas[..2]
            .iter()
            .any(|meta| meta.flags != 2 || meta.owner != *program)
    {
        return Err(AppError::Accounts.into());
    }
    // Full-list uniqueness above excludes config/issuer/head collisions even if
    // both the stored relevant list and actual extras repeat that fixed account.
    for (meta, account) in r.metas.iter().zip(relevant) {
        if meta.key != *account.key {
            return Err(AppError::Accounts.into());
        }
        if meta.owner != *account.owner {
            return Err(AppError::Owner.into());
        }
        let flags = u8::from(account.is_signer) | (u8::from(account.is_writable) << 1);
        if meta.flags != flags {
            return Err(AppError::Privileges.into());
        }
    }
    for input in inputs {
        crate::canonical(input).map_err(|_| AppError::Proof)?;
    }
    if r.state != RequestState::Finalized || q.entries.contains(ra.key) {
        return Err(AppError::Consumed.into());
    }
    if q.entries.len() >= QUEUE_CAPACITY {
        return Err(AppError::Capacity.into());
    }
    if i.issuer_hash != r.issuer_hash {
        return Err(AppError::Policy.into());
    }
    // Includes enabled tuple, current recorded config/issuer epochs, nonzero
    // active source sequence, observed-time/max-age bounds and current binding.
    i.fresh(&c, now)?;
    i.binding_current(&c)?;
    if now >= i.expires_at {
        return Err(AppError::Status.into());
    }
    if h.root != c.root
        || h.root_version != c.root_version
        || h.source_sequence != i.sequence
        || h.source_digest != i.digest
        || h.config_epoch != c.eligibility_epoch
        || h.issuer_epoch != i.eligibility_epoch
        || h.committed_at < i.observed_at
        || h.committed_at > now
    {
        return Err(AppError::Binding.into());
    }
    if inputs[0] != c.root || inputs[1] != i.issuer_hash || inputs[5] != c.policy_id {
        return Err(AppError::Policy.into());
    }
    crate::validate_times(&inputs[2], &inputs[3], now)?;
    if now < 0 || now > r.deadline {
        return Err(AppError::Expired.into());
    }
    // action-v2 uses the actual program ID and the authenticated request.config
    // (the same config PDA that owns the root and is the registry scope).
    if inputs[4] != action_hash(program, &c, &r)? {
        return Err(AppError::Action.into());
    }
    Ok(())
}
