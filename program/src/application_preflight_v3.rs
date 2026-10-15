//! Non-authorizing structural/current-state preflight only. Even success cannot
//! establish a valid ordinary proof or authorize a queue append. Runtime Execute
//! remains unavailable until independent verifier/effect integration is reviewed.
use crate::application_v3::AppError;
use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult, pubkey::Pubkey};

pub fn check(
    _program: &Pubkey,
    _actual_accounts: &[AccountInfo],
    _inputs: &[[u8; 32]; 6],
    _now: i64,
) -> ProgramResult {
    Err(AppError::Unavailable.into())
}
