//! Tests-first finalized v3 deployment verifier scaffold; no authorization API.
//! JSON account records and user-implemented traits cannot mint capabilities.
#![allow(deprecated)]
use solana_program::pubkey::Pubkey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error { Unavailable, Transport, Deployment, Finality, Account, Clock }

/// Supplied by the trusted application/deployment configuration, never selected
/// from a credential or publisher envelope. HTTP support will be loopback-only;
/// remote transport requires an explicit reviewed TLS trust policy.
pub struct DeploymentPins {
    pub endpoint: String,
    pub genesis: [u8; 32],
    pub program: Pubkey,
    pub programdata: Pubkey,
    pub config: Pubkey,
    pub admin: Pubkey,
    pub seed: [u8; 32],
    pub elf_sha256: [u8; 32],
    pub elf_length: usize,
    pub upgrade_authority: Option<Pubkey>,
    pub minimum_finalized_slot: u64,
    pub maximum_clock_age_seconds: u64,
}

/// Deployment evidence only: cannot authorize a proof, request or operation.
pub struct VerifiedDeployment {
    program: Pubkey,
    config: Pubkey,
    finalized_slot: u64,
}
impl VerifiedDeployment {
    pub fn program(&self) -> &Pubkey { &self.program }
    pub fn config(&self) -> &Pubkey { &self.config }
    pub fn finalized_slot(&self) -> u64 { self.finalized_slot }
}

/// Reserved authorization capability. There is no minting path in this slice.
/// No public constructor, serde, Clone, Debug, From<JSON> or authority trait.
pub struct AuthenticatedV3Current { finalized_slot: u64 }
impl AuthenticatedV3Current {
    pub fn finalized_slot(&self) -> u64 { self.finalized_slot }
}

pub struct ConfiguredVerifier { pins: DeploymentPins, transport: Box<dyn Transport> }
impl ConfiguredVerifier {
    /// Concrete bounded HTTP transport is a later reviewed slice. No caller
    /// supplied implementation can substitute for that trusted transport.
    pub fn new(_pins: DeploymentPins) -> Result<Self, Error> { Err(Error::Unavailable) }

    /// RED stub: observes only the intended private transport requests. No
    /// genesis, loader, ELF, codec, PDA, context or clock validation exists yet.
    pub fn verify_deployment(&self, _local_unix: i64) -> Result<VerifiedDeployment, Error> {
        let _genesis = self.transport.genesis()?;
        let _batch = self.transport.finalized_accounts(&FinalizedRequest {
            keys: vec![self.pins.program, self.pins.programdata, self.pins.config, solana_program::sysvar::clock::id()],
            commitment: Commitment::Finalized,
            minimum_context_slot: self.pins.minimum_finalized_slot,
        })?;
        Err(Error::Unavailable)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Commitment { Finalized }
#[derive(Debug, PartialEq, Eq)]
struct FinalizedRequest { keys: Vec<Pubkey>, commitment: Commitment, minimum_context_slot: u64 }
#[allow(dead_code)]
struct Account { key: Pubkey, owner: Pubkey, executable: bool, bytes: Vec<u8> }
#[allow(dead_code)]
struct FinalizedBatch { context_slot: u64, accounts: Vec<Account> }
trait Transport {
    fn genesis(&self) -> Result<[u8; 32], Error>;
    fn finalized_accounts(&self, request: &FinalizedRequest) -> Result<FinalizedBatch, Error>;
}

#[cfg(test)]
mod tests;
