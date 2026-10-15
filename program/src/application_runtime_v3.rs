//! V3 PDA domains. Dispatch remains fail closed; no verifier or state writes are enabled.
use crate::application_v3::AppError;
use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult, pubkey::Pubkey};
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
pub fn process(_program: &Pubkey, _accounts: &[AccountInfo], _bytes: &[u8]) -> ProgramResult {
    Err(AppError::Unavailable.into())
}
