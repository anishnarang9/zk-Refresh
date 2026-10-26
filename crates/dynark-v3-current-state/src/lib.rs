//! Bounded loopback finalized v3 deployment/current-state verification.
//! JSON account records and user-implemented traits cannot mint capabilities.
#![allow(deprecated)]
use sha2::{Digest, Sha256};
use solana_program::{
    bpf_loader_upgradeable::{self, UpgradeableLoaderState},
    clock::Clock, pubkey::Pubkey, sysvar,
};
use zk_fresh_program::{application_runtime_v3::config_address, application_v3::{
    Config, Issuer, PublisherHead, Request, RequestState, Queue, QUEUE_CAPACITY,
}};

const MAX_ELF_LENGTH: usize = 4 * 1024 * 1024;
const MAX_CLOCK_AGE_SECONDS: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error { Unavailable, Transport, Deployment, Finality, Account, Clock }

/// Publicly constructible pins are NOT an independent trust anchor. Verification
/// establishes only consistency relative to these pins; application deployment
/// policy must authenticate their provenance separately. HTTP is loopback-only;
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
/// proof, request or operation; detached source/publisher checks remain separate.
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

/// Chain-current-state capability relative to separately trusted pins, as of
/// one finalized batch. It is not a promise about a later execution context. This
/// does NOT establish detached source/publisher signatures, holder proof, Merkle
/// membership, relevant-extra-account authentication, or execution authorization.
/// No public constructor, serde, Clone, Debug, From<JSON> or authority trait.
pub struct AuthenticatedV3Current {
    deployment: VerifiedDeployment,
    current_accounts: [Pubkey;4],
    config: Config,
    issuer: Issuer,
    publisher_head: PublisherHead,
    request: Request,
    queue: Queue,
    clock: Clock,
    validated_at: i64,
}
impl AuthenticatedV3Current {
    pub fn finalized_slot(&self) -> u64 { self.deployment.finalized_slot }
    pub fn deployment(&self) -> &VerifiedDeployment { &self.deployment }
    pub fn issuer_account(&self) -> &Pubkey { &self.current_accounts[0] }
    pub fn publisher_head_account(&self) -> &Pubkey { &self.current_accounts[1] }
    pub fn request_account(&self) -> &Pubkey { &self.current_accounts[2] }
    pub fn queue_account(&self) -> &Pubkey { &self.current_accounts[3] }
    pub fn config(&self) -> &Config { &self.config }
    pub fn issuer(&self) -> &Issuer { &self.issuer }
    pub fn publisher_head(&self) -> &PublisherHead { &self.publisher_head }
    pub fn request(&self) -> &Request { &self.request }
    pub fn queue(&self) -> &Queue { &self.queue }
    pub fn clock(&self) -> &Clock { &self.clock }
    pub fn validated_at(&self) -> i64 { self.validated_at }
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
    /// Construct only the fixed bounded loopback transport, without RPC reads.
    /// Pins remain caller data: application policy must authenticate provenance.
    /// This admits no deployment, current state, detached envelope or operation;
    /// fresh verify_deployment/verify_current calls perform the account checks.
    /// No caller-supplied transport implementation or endpoint fallback is used.
    pub fn new(pins: DeploymentPins) -> Result<Self, Error> {
        let transport = loopback_http::configured_transport(&pins.endpoint)?;
        Ok(Self { pins, transport })
    }

    /// Authenticate deployment and current records from ONE fresh finalized
    /// batch. There is no batch cache or caller-provided account/JSON input.
    /// Construction admits no state; each call performs fresh transport reads.
    pub fn verify_current(&self, selection: &CurrentSelection, local_unix: i64)
        -> Result<AuthenticatedV3Current, Error>
    {
        use zk_fresh_program::application_runtime_v3 as runtime;
        let p=&self.pins;
        let issuer=runtime::issuer_address(&p.program,&p.config,&selection.issuer_hash).0;
        let keys=vec![p.program,p.programdata,p.config,sysvar::clock::id(),issuer,
                runtime::publisher_head_address(&p.program,&p.config,&issuer,&selection.publisher).0,
                runtime::request_address(&p.program,&p.config,&selection.creator,&selection.nonce).0,
                runtime::queue_address(&p.program,&p.config).0];
        let genesis=self.transport.genesis()?;
        let batch=self.transport.finalized_accounts(&FinalizedRequest {
            keys:keys.clone(),
            commitment:Commitment::Finalized, minimum_context_slot:p.minimum_finalized_slot,
        })?;
        let (config,clock)=self.check_deployment_batch(genesis,&batch,&keys,local_unix)?;
        for account in &batch.accounts[4..] {
            if account.owner!=p.program || account.executable { return Err(Error::Account); }
        }
        let issuer=Issuer::decode(&batch.accounts[4].bytes).map_err(|_|Error::Account)?;
        let head=PublisherHead::decode(&batch.accounts[5].bytes).map_err(|_|Error::Account)?;
        let request=Request::decode(&batch.accounts[6].bytes).map_err(|_|Error::Account)?;
        let queue=Queue::decode(&batch.accounts[7].bytes).map_err(|_|Error::Account)?;
        if config.publisher!=selection.publisher || issuer.config!=p.config
            || issuer.issuer_hash!=selection.issuer_hash
            || head.config!=p.config || head.issuer!=keys[4] || head.publisher!=config.publisher
            || request.config!=p.config || request.creator!=selection.creator
            || request.nonce!=selection.nonce || request.issuer_hash!=issuer.issuer_hash
            || queue.config!=p.config
        { return Err(Error::Account); }
        issuer.binding_current(&config).map_err(|_|Error::Account)?;
        // The program's legacy fresh() has an inclusive endpoint. Authorization
        // use here is deliberately strict, agreeing with BindWithHead/preflight.
        if !issuer.status_valid || issuer.sequence==0 || issuer.digest==[0;32]
            || issuer.observed_at>clock.unix_timestamp || local_unix>=issuer.expires_at
            || local_unix.checked_sub(issuer.observed_at).ok_or(Error::Clock)? > 300
        { return Err(Error::Clock); }
        if head.root!=config.root || head.root_version!=config.root_version
            || head.source_sequence!=issuer.sequence || head.source_digest!=issuer.digest
            || head.config_epoch!=config.eligibility_epoch || head.issuer_epoch!=issuer.eligibility_epoch
            || head.committed_at<issuer.observed_at || head.committed_at>clock.unix_timestamp
        { return Err(Error::Account); }
        if request.state!=RequestState::Finalized || local_unix>request.deadline
            || queue.entries.contains(&keys[6]) || queue.entries.len()>=QUEUE_CAPACITY
        { return Err(Error::Account); }
        // Owning codec already checks upload completeness and distinct metas.
        // Check stored writable roles and owners for the two included accounts.
        // Actual transaction privileges, extra-account authentication and action
        // execution remain outside this capability.
        if request.metas[0].key!=keys[6] || request.metas[1].key!=keys[7]
            || request.metas[..2].iter().any(|m|m.flags!=2 || m.owner!=p.program)
            || request.metas.iter().any(|m|m.key==p.config || m.key==keys[4] || m.key==keys[5])
        { return Err(Error::Account); }
        Ok(AuthenticatedV3Current {
            deployment:VerifiedDeployment {program:p.program,config:p.config,finalized_slot:batch.context_slot},
            current_accounts:[keys[4],keys[5],keys[6],keys[7]], config,issuer,publisher_head:head,
            request,queue,clock,validated_at:local_unix,
        })
    }

    /// Deployment-only checks against separately trusted pins and a private
    /// finalized transport. Does not authenticate source/publisher/action state.
    pub fn verify_deployment(&self, local_unix: i64) -> Result<VerifiedDeployment, Error> {
        let p=&self.pins;
        let keys=vec![p.program,p.programdata,p.config,sysvar::clock::id()];
        let genesis=self.transport.genesis()?;
        let batch=self.transport.finalized_accounts(&FinalizedRequest {
            keys:keys.clone(),commitment:Commitment::Finalized,
            minimum_context_slot:p.minimum_finalized_slot,
        })?;
        self.check_deployment_batch(genesis,&batch,&keys,local_unix)?;
        Ok(VerifiedDeployment {program:p.program,config:p.config,finalized_slot:batch.context_slot})
    }

    /// Shared in-memory validator: never makes another RPC read or uses an
    /// earlier VerifiedDeployment token to stand in for this batch's deployment.
    fn check_deployment_batch(&self, genesis:[u8;32], batch:&FinalizedBatch,
        keys:&[Pubkey], local_unix:i64) -> Result<(Config,Clock),Error>
    {
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
        if genesis != p.genesis { return Err(Error::Deployment); }
        // Avoid ambiguous role/account aliasing even under caller-chosen pins.
        for (i, key) in keys.iter().enumerate() {
            if keys[..i].contains(key) { return Err(Error::Account); }
        }
        if batch.context_slot == 0 || batch.context_slot < p.minimum_finalized_slot {
            return Err(Error::Finality);
        }
        if batch.accounts.len() != keys.len()
            || batch.accounts.iter().zip(keys).any(|(a,k)| a.key != *k)
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
        let image_end=metadata_len.checked_add(p.elf_length).ok_or(Error::Deployment)?;
        let allocation_end=metadata_len.checked_add(MAX_ELF_LENGTH).ok_or(Error::Deployment)?;
        if programdata.bytes.len()<image_end || programdata.bytes.len()>allocation_end {
            return Err(Error::Deployment);
        }
        match canonical_loader(&programdata.bytes[..metadata_len], true)? {
            UpgradeableLoaderState::ProgramData { slot, upgrade_authority_address }
                if slot <= batch.context_slot && upgrade_authority_address == p.upgrade_authority => (),
            _ => return Err(Error::Deployment),
        }
        // Loader allocation capacity may exceed the reviewed artifact length.
        // Preserve that exact pinned prefix (including genuine ELF end zeros);
        // reserve bytes are accepted only when zero and within the capacity cap.
        let image = &programdata.bytes[metadata_len..image_end];
        let digest: [u8;32] = Sha256::digest(image).into();
        if !image.starts_with(b"\x7fELF") || digest != p.elf_sha256
            || programdata.bytes[image_end..].iter().any(|byte|*byte!=0)
        { return Err(Error::Deployment); }
        if config.owner != p.program || config.executable { return Err(Error::Account); }
        // Owning program codec validates exact length/magic/canonical fields and
        // the compiled profile/circuit/schema/package/ordinary-VK identities.
        let decoded_config = Config::decode(&config.bytes).map_err(|_| Error::Account)?;
        if decoded_config.admin != p.admin || decoded_config.seed != p.seed || decoded_config.genesis != p.genesis {
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
        Ok((decoded_config,decoded))
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

mod loopback_rpc;
mod loopback_http;

mod current_envelopes;
pub use current_envelopes::AuthenticatedV3Envelopes;
