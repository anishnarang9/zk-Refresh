//! Tests-first six-public-field queue contract. RED stubs fail closed until reviewed GREEN.
//! Account layout v3, BE integers; epoch extensions implement fresh-after-reenable.
use solana_program::{program_error::ProgramError, pubkey::Pubkey};
pub const PREFIX: u8 = 0x51;
pub const CONFIG_LEN: usize = 381;
pub const ISSUER_LEN: usize = 374;
pub const REQUEST_LEN: usize = 2249;
pub const QUEUE_LEN: usize = 2090;
pub const QUEUE_CAPACITY: usize = 64;
pub const MAX_PAYLOAD: usize = 1024;
pub const MAX_METAS: usize = 16;
pub const MAX_CHUNK: usize = 512;
pub const MAX_META_CHUNK: usize = 4;
pub const STATUS_MAX_AGE: i64 = 300;
// Layout: config profile268, VK300, root332, root_version364, eligibility_epoch372, enabled380.
// Issuer preserves v2 revised offsets through309; enrollment_version309, evidence317,
// observed_config_epoch349, status_valid357; appended eligibility_epoch358..366,
// observed_issuer_epoch366..374. Existing 358-byte prefix is preserved.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppError {
    Instruction = 700,
    State,
    Bounds,
    Authority,
    Version,
    Status,
    Expired,
    Consumed,
    Capacity,
    Accounts,
    Owner,
    Privileges,
    Action,
    Policy,
    Proof,
    Binding,
    Unavailable = 799,
}
impl From<AppError> for ProgramError {
    fn from(e: AppError) -> Self {
        Self::Custom(e as u32)
    }
}
pub type Result<T> = core::result::Result<T, AppError>;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Authority {
    pub key: Pubkey,
    pub is_signer: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub admin: Pubkey,
    pub seed: [u8; 32],
    pub publisher: Pubkey,
    pub genesis: [u8; 32],
    pub policy_id: [u8; 32],
    pub policy_version: u32,
    pub circuit_id: [u8; 32],
    pub package_id: [u8; 32],
    pub schema_id: [u8; 32],
    pub profile_id: [u8; 32],
    pub ordinary_vk_digest: [u8; 32],
    pub root: [u8; 32],
    pub root_version: u64,
    pub eligibility_epoch: u64,
    pub enabled: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issuer {
    pub config: Pubkey,
    pub issuer_hash: [u8; 32],
    pub profile_id: [u8; 32],
    pub profile_version: u32,
    pub aki: [u8; 32],
    pub source: Pubkey,
    pub enabled: bool,
    pub sequence: u64,
    pub digest: [u8; 32],
    pub observed_at: i64,
    pub expires_at: i64,
    pub bound_root: [u8; 32],
    pub bound_root_version: u64,
    pub bound_source_sequence: u64,
    pub bound_source_digest: [u8; 32],
    pub enrollment_version: u64,
    pub evidence_digest: [u8; 32],
    pub observed_config_epoch: u64,
    pub status_valid: bool,
    pub eligibility_epoch: u64,
    pub observed_issuer_epoch: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelevantMeta {
    pub key: Pubkey,
    pub flags: u8,
    pub owner: Pubkey,
}
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestState {
    Staging = 0,
    Finalized = 1,
    Consumed = 2,
    Cancelled = 3,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub config: Pubkey,
    pub creator: Pubkey,
    pub nonce: [u8; 32],
    pub issuer_hash: [u8; 32],
    pub recipient: Pubkey,
    pub request_type: u16,
    pub deadline: i64,
    pub payload_len: u16,
    pub uploaded: u16,
    pub metas_uploaded: u8,
    pub state: RequestState,
    pub metas: Vec<RelevantMeta>,
    pub payload: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Queue {
    pub config: Pubkey,
    pub entries: Vec<Pubkey>,
}
impl Config {
    pub fn encode(&self) -> Vec<u8> {
        Vec::new()
    }
    pub fn decode(_bytes: &[u8]) -> Result<Self> {
        Err(AppError::Unavailable)
    }
    pub fn publish(&mut self, _actor: Authority, _expected: u64, _root: [u8; 32]) -> Result<()> {
        Err(AppError::Unavailable)
    }
    pub fn set_enabled(&mut self, _actor: Authority, _enabled: bool) -> Result<()> {
        Err(AppError::Unavailable)
    }
    pub fn require_policy(&self, _policy: &[u8; 32]) -> Result<()> {
        Err(AppError::Unavailable)
    }
}
impl Issuer {
    #[allow(clippy::too_many_arguments)]
    pub fn enroll(
        _config_key: Pubkey,
        _config: &Config,
        _actor: Authority,
        _issuer_hash: [u8; 32],
        _aki: [u8; 32],
        _source: Pubkey,
        _enrollment_version: u64,
        _evidence: [u8; 32],
    ) -> Result<Self> {
        Err(AppError::Unavailable)
    }
    pub fn encode(&self) -> Vec<u8> {
        Vec::new()
    }
    pub fn decode(_bytes: &[u8]) -> Result<Self> {
        Err(AppError::Unavailable)
    }
    pub fn admitted(&self, _config: &Config) -> Result<()> {
        Err(AppError::Unavailable)
    }
    pub fn set_enabled(
        &mut self,
        _config: &Config,
        _actor: Authority,
        _enabled: bool,
    ) -> Result<()> {
        Err(AppError::Unavailable)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn observe(
        &mut self,
        _config: &Config,
        _actor: Authority,
        _expected_config_epoch: u64,
        _expected_issuer_epoch: u64,
        _expected: u64,
        _sequence: u64,
        _digest: [u8; 32],
        _observed: i64,
        _expires: i64,
        _now: i64,
    ) -> Result<()> {
        Err(AppError::Unavailable)
    }
    pub fn fresh(&self, _config: &Config, _now: i64) -> Result<()> {
        Err(AppError::Unavailable)
    }
    pub fn binding_current(&self, _config: &Config) -> Result<()> {
        Err(AppError::Unavailable)
    }
    pub fn bind_current(
        &mut self,
        _config: &Config,
        _actor: Authority,
        _expected_config_epoch: u64,
        _expected_issuer_epoch: u64,
        _root_version: u64,
        _source_sequence: u64,
        _now: i64,
    ) -> Result<()> {
        Err(AppError::Unavailable)
    }
}
impl Request {
    pub fn encode(&self) -> Vec<u8> {
        Vec::new()
    }
    pub fn decode(_bytes: &[u8]) -> Result<Self> {
        Err(AppError::Unavailable)
    }
}
impl Queue {
    pub fn new(config: Pubkey) -> Self {
        Self {
            config,
            entries: Vec::new(),
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        Vec::new()
    }
    pub fn decode(_bytes: &[u8]) -> Result<Self> {
        Err(AppError::Unavailable)
    }
}
pub fn action_preimage(_program: &Pubkey, _config: &Config, _request: &Request) -> Result<Vec<u8>> {
    Err(AppError::Unavailable)
}
pub fn action_hash(_program: &Pubkey, _config: &Config, _request: &Request) -> Result<[u8; 32]> {
    Err(AppError::Unavailable)
}
/// Prefix0x51; each wire variant is exact length with no trailing bytes.
/// Observe body: config_epoch, issuer_epoch, expected_seq, next_seq (each u64 BE),
/// digest32, observed_i64, expires_i64: 82 bytes including prefix/opcode.
/// BindCurrent body: config_epoch, issuer_epoch, root_version, source_sequence:
/// four u64 BE, 34 bytes including prefix/opcode. Epochs are signed predecessors.
#[derive(Debug, PartialEq, Eq)]
pub enum AppInstruction {
    Initialize {
        seed: [u8; 32],
        publisher: Pubkey,
        genesis: [u8; 32],
        policy_id: [u8; 32],
        policy_version: u32,
        circuit_id: [u8; 32],
        package_id: [u8; 32],
        schema_id: [u8; 32],
        profile_id: [u8; 32],
        ordinary_vk_digest: [u8; 32],
        root: [u8; 32],
    },
    Enroll {
        issuer_hash: [u8; 32],
        aki: [u8; 32],
        source: Pubkey,
        enrollment_version: u64,
        evidence_digest: [u8; 32],
    },
    Publish {
        expected: u64,
        root: [u8; 32],
    },
    Observe {
        expected_config_epoch: u64,
        expected_issuer_epoch: u64,
        expected: u64,
        sequence: u64,
        digest: [u8; 32],
        observed: i64,
        expires: i64,
    },
    Create {
        nonce: [u8; 32],
        issuer_hash: [u8; 32],
        recipient: Pubkey,
        request_type: u16,
        deadline: i64,
        payload_len: u16,
        meta_count: u8,
    },
    Finalize,
    Upload {
        offset: u16,
        bytes: Vec<u8>,
    },
    Execute {
        inputs: [[u8; 32]; 6],
        proof: [u8; 256],
    },
    UploadMetas {
        offset: u8,
        metas: Vec<RelevantMeta>,
    },
    Cancel,
    SetConfigEnabled {
        enabled: bool,
    },
    BindCurrent {
        expected_config_epoch: u64,
        expected_issuer_epoch: u64,
        root_version: u64,
        source_sequence: u64,
    },
    SetIssuerEnabled {
        enabled: bool,
    },
}
impl AppInstruction {
    pub fn parse(_bytes: &[u8]) -> Result<Self> {
        Err(AppError::Unavailable)
    }
}
