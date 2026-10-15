//! Tests-first finalized v3 deployment verifier scaffold; no authorization API.
//! JSON account records and user-implemented traits cannot mint capabilities.
#![allow(deprecated)]
use sha2::{Digest, Sha256};
use solana_program::{
    bpf_loader_upgradeable::{self, UpgradeableLoaderState},
    clock::Clock, pubkey::Pubkey, sysvar,
};
use zk_fresh_program::{application_runtime_v3::config_address, application_v3::Config};

const MAX_ELF_LENGTH: usize = 4 * 1024 * 1024;
const MAX_CLOCK_AGE_SECONDS: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error { Unavailable, Transport, Deployment, Finality, Account, Clock }

/// Publicly constructible pins are NOT an independent trust anchor. Verification
/// establishes only consistency relative to these pins; application deployment
/// policy must authenticate their provenance separately. HTTP will be loopback-only;
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

/// Deployment evidence relative to the supplied pins only. Cannot authorize a
/// proof, request or operation; no real RPC transport exists in this slice.
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

/// Reserved chain-current-state capability relative to separately trusted pins,
/// as of one finalized batch. No minting path exists in the RED scaffold. This
/// does NOT establish detached source/publisher signatures, holder proof, Merkle
/// membership, relevant-extra-account authentication, or execution authorization.
/// No public constructor, serde, Clone, Debug, From<JSON> or authority trait.
pub struct AuthenticatedV3Current { finalized_slot: u64 }
impl AuthenticatedV3Current {
    pub fn finalized_slot(&self) -> u64 { self.finalized_slot }
}

/// Address-discovery identifiers only, never current-state assertions. A future
/// checked implementation must match publisher to Config, issuer hash to Issuer
/// and request fields to their codecs/PDAs in the same finalized response.
pub struct CurrentSelection {
    pub issuer_hash: [u8;32],
    pub creator: Pubkey,
    pub nonce: [u8;32],
    pub publisher: Pubkey,
}

pub struct ConfiguredVerifier { pins: DeploymentPins, transport: Box<dyn Transport> }
impl ConfiguredVerifier {
    /// Concrete bounded HTTP transport is a later reviewed slice. No caller
    /// supplied implementation can substitute for that trusted transport.
    pub fn new(_pins: DeploymentPins) -> Result<Self, Error> { Err(Error::Unavailable) }

    /// Closed RED stub: request deployment+current accounts in ONE fresh batch,
    /// then reject. No decoding, validation, caching or capability minting occurs.
    /// GREEN must independently recheck deployment in this same context; calling
    /// verify_deployment first and mixing a later current batch is insufficient.
    pub fn verify_current(&self, selection: &CurrentSelection, _local_unix: i64)
        -> Result<AuthenticatedV3Current, Error>
    {
        use zk_fresh_program::application_runtime_v3 as runtime;
        let p=&self.pins;
        let issuer=runtime::issuer_address(&p.program,&p.config,&selection.issuer_hash).0;
        let _genesis=self.transport.genesis()?;
        let _batch=self.transport.finalized_accounts(&FinalizedRequest {
            keys:vec![p.program,p.programdata,p.config,sysvar::clock::id(),issuer,
                runtime::publisher_head_address(&p.program,&p.config,&issuer,&selection.publisher).0,
                runtime::request_address(&p.program,&p.config,&selection.creator,&selection.nonce).0,
                runtime::queue_address(&p.program,&p.config).0],
            commitment:Commitment::Finalized, minimum_context_slot:p.minimum_finalized_slot,
        })?;
        Err(Error::Unavailable)
    }

    /// Deployment-only checks against separately trusted pins and a private
    /// finalized transport. Does not authenticate source/publisher/action state.
    pub fn verify_deployment(&self, local_unix: i64) -> Result<VerifiedDeployment, Error> {
        let p = &self.pins;
        if p.elf_length < 4 || p.elf_length > MAX_ELF_LENGTH {
            return Err(Error::Deployment);
        }
        if local_unix < 0 || p.maximum_clock_age_seconds == 0
            || p.maximum_clock_age_seconds > MAX_CLOCK_AGE_SECONDS
        {
            return Err(Error::Clock);
        }
        let loader = bpf_loader_upgradeable::id();
        let expected_programdata = Pubkey::find_program_address(&[p.program.as_ref()], &loader).0;
        if p.programdata != expected_programdata
            || p.config != config_address(&p.program, &p.admin, &p.seed).0
        {
            return Err(Error::Deployment);
        }
        if self.transport.genesis()? != p.genesis { return Err(Error::Deployment); }
        let keys = vec![p.program, p.programdata, p.config, sysvar::clock::id()];
        // Avoid ambiguous role/account aliasing even under caller-chosen pins.
        for (i, key) in keys.iter().enumerate() {
            if keys[..i].contains(key) { return Err(Error::Account); }
        }
        let batch = self.transport.finalized_accounts(&FinalizedRequest {
            keys: keys.clone(),
            commitment: Commitment::Finalized,
            minimum_context_slot: p.minimum_finalized_slot,
        })?;
        if batch.context_slot == 0 || batch.context_slot < p.minimum_finalized_slot {
            return Err(Error::Finality);
        }
        if batch.accounts.len() != keys.len()
            || batch.accounts.iter().zip(&keys).any(|(a,k)| a.key != *k)
        {
            return Err(Error::Account);
        }
        let program = &batch.accounts[0];
        let programdata = &batch.accounts[1];
        let config = &batch.accounts[2];
        let clock = &batch.accounts[3];
        if program.owner != loader || !program.executable
            || programdata.owner != loader || programdata.executable
            || program.bytes.len() != UpgradeableLoaderState::size_of_program()
        {
            return Err(Error::Deployment);
        }
        match canonical_loader(&program.bytes, false)? {
            UpgradeableLoaderState::Program { programdata_address } if programdata_address == p.programdata => (),
            _ => return Err(Error::Deployment),
        }
        let metadata_len = UpgradeableLoaderState::size_of_programdata_metadata();
        if programdata.bytes.len() != metadata_len.checked_add(p.elf_length).ok_or(Error::Deployment)? {
            return Err(Error::Deployment);
        }
        match canonical_loader(&programdata.bytes[..metadata_len], true)? {
            UpgradeableLoaderState::ProgramData { slot, upgrade_authority_address }
                if slot <= batch.context_slot && upgrade_authority_address == p.upgrade_authority => (),
            _ => return Err(Error::Deployment),
        }
        let image = &programdata.bytes[metadata_len..];
        let digest: [u8;32] = Sha256::digest(image).into();
        if !image.starts_with(b"\x7fELF") || digest != p.elf_sha256 { return Err(Error::Deployment); }
        if config.owner != p.program || config.executable { return Err(Error::Account); }
        // Owning program codec validates exact length/magic/canonical fields and
        // the compiled profile/circuit/schema/package/ordinary-VK identities.
        let decoded = Config::decode(&config.bytes).map_err(|_| Error::Account)?;
        if decoded.admin != p.admin || decoded.seed != p.seed || decoded.genesis != p.genesis {
            return Err(Error::Deployment);
        }
        if clock.owner != sysvar::id() || clock.executable || clock.bytes.len() != 40 {
            return Err(Error::Clock);
        }
        let decoded: Clock = bincode::deserialize(&clock.bytes).map_err(|_| Error::Clock)?;
        if bincode::serialize(&decoded).map_err(|_| Error::Clock)? != clock.bytes
            || decoded.slot != batch.context_slot || decoded.unix_timestamp < 0
            || local_unix < decoded.unix_timestamp
            || u64::try_from(local_unix.checked_sub(decoded.unix_timestamp).ok_or(Error::Clock)?)
                .map_err(|_| Error::Clock)? > p.maximum_clock_age_seconds
        {
            return Err(Error::Clock);
        }
        Ok(VerifiedDeployment { program: p.program, config: p.config, finalized_slot: batch.context_slot })
    }
}

/// ProgramData with None authority consumes only13 of45 metadata bytes. Its
/// reserved suffix can retain prior authority bytes; it is neither authority nor
/// image data. Reencode and compare the consumed prefix, never hash that suffix
/// as ELF. Program accounts instead require exact full canonical bytes.
/// Callers bound input length before invoking the allocation-free state decoder.
fn canonical_loader(bytes: &[u8], padded: bool) -> Result<UpgradeableLoaderState, Error> {
    let state: UpgradeableLoaderState = bincode::deserialize(bytes).map_err(|_| Error::Deployment)?;
    let canonical = bincode::serialize(&state).map_err(|_| Error::Deployment)?;
    if padded {
        if !bytes.starts_with(&canonical) { return Err(Error::Deployment); }
    } else if canonical != bytes {
        return Err(Error::Deployment);
    }
    Ok(state)
}

#[derive(Debug, PartialEq, Eq)]
enum Commitment { Finalized }
#[derive(Debug, PartialEq, Eq)]
struct FinalizedRequest { keys: Vec<Pubkey>, commitment: Commitment, minimum_context_slot: u64 }
struct Account { key: Pubkey, owner: Pubkey, executable: bool, bytes: Vec<u8> }
struct FinalizedBatch { context_slot: u64, accounts: Vec<Account> }
trait Transport {
    fn genesis(&self) -> Result<[u8; 32], Error>;
    fn finalized_accounts(&self, request: &FinalizedRequest) -> Result<FinalizedBatch, Error>;
}

#[cfg(test)]
mod tests;
