//! V3 PDA/dispatch boundary RED stubs. No verifier or state writes are enabled.
use crate::application_v3::AppError;
use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult, pubkey::Pubkey};
pub fn config_address(_program: &Pubkey, _admin: &Pubkey, _seed: &[u8; 32]) -> (Pubkey, u8) {
    (Pubkey::default(), 0)
}
pub fn issuer_address(_program: &Pubkey, _config: &Pubkey, _issuer: &[u8; 32]) -> (Pubkey, u8) {
    (Pubkey::default(), 0)
}
pub fn request_address(
    _program: &Pubkey,
    _config: &Pubkey,
    _creator: &Pubkey,
    _nonce: &[u8; 32],
) -> (Pubkey, u8) {
    (Pubkey::default(), 0)
}
pub fn queue_address(_program: &Pubkey, _config: &Pubkey) -> (Pubkey, u8) {
    (Pubkey::default(), 0)
}
pub fn process(_program: &Pubkey, _accounts: &[AccountInfo], _bytes: &[u8]) -> ProgramResult {
    Err(AppError::Unavailable.into())
}
