//! Versioned development credential queue. Wire and account integers use big endian.
use solana_program::{program_error::ProgramError, pubkey::Pubkey};
pub const PREFIX: u8 = 0x50;
pub const QUEUE_CAPACITY: usize = 64;
pub const MAX_PAYLOAD: usize = 1024;
pub const MAX_METAS: usize = 16;
pub const MAX_CHUNK: usize = 512;
pub const MAX_META_CHUNK: usize = 4;
pub const STATUS_MAX_AGE: i64 = 300;
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppError {
    Instruction = 500,
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
}
impl From<AppError> for ProgramError {
    fn from(e: AppError) -> Self {
        Self::Custom(e as u32)
    }
}
type Result<T> = core::result::Result<T, AppError>;
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
    pub root: [u8; 32],
    pub root_version: u64,
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

pub const CONFIG_LEN: usize = 309;
pub const ISSUER_LEN: usize = 229;
pub const REQUEST_LEN: usize = 185 + MAX_METAS * 65 + MAX_PAYLOAD;
pub const QUEUE_LEN: usize = 42 + QUEUE_CAPACITY * 32;
const CONFIG_MAGIC: &[u8; 8] = b"DYNCONF2";
const ISSUER_MAGIC: &[u8; 8] = b"DYNISS02";
const REQUEST_MAGIC: &[u8; 8] = b"DYNREQ02";
const QUEUE_MAGIC: &[u8; 8] = b"DYNQUE02";

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self.pos.checked_add(N).ok_or(AppError::Bounds)?;
        let b = self.bytes.get(self.pos..end).ok_or(AppError::Instruction)?;
        self.pos = end;
        Ok(b.try_into().map_err(|_| AppError::Instruction)?)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take()?))
    }
    fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_be_bytes(self.take()?))
    }
    fn key(&mut self) -> Result<Pubkey> {
        Ok(Pubkey::new_from_array(self.take()?))
    }
    fn boolean(&mut self) -> Result<bool> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(AppError::State),
        }
    }
    fn finish(&self) -> Result<()> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(AppError::Instruction)
        }
    }
    fn account(bytes: &'a [u8], len: usize, magic: &[u8; 8]) -> Result<Self> {
        if bytes.len() != len || bytes.get(..8) != Some(magic.as_slice()) {
            return Err(AppError::State);
        }
        Ok(Self { bytes, pos: 8 })
    }
}
fn push_key(b: &mut Vec<u8>, k: &Pubkey) {
    b.extend(k.as_ref());
}
fn canonical(x: &[u8; 32]) -> Result<()> {
    crate::canonical(x).map_err(|_| AppError::State)
}
impl Config {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = CONFIG_MAGIC.to_vec();
        push_key(&mut b, &self.admin);
        b.extend(self.seed);
        push_key(&mut b, &self.publisher);
        b.extend(self.genesis);
        b.extend(self.policy_id);
        b.extend(self.policy_version.to_be_bytes());
        b.extend(self.circuit_id);
        b.extend(self.package_id);
        b.extend(self.schema_id);
        b.extend(self.root);
        b.extend(self.root_version.to_be_bytes());
        b.push(self.enabled as u8);
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::account(b, CONFIG_LEN, CONFIG_MAGIC)?;
        let c = Self {
            admin: r.key()?,
            seed: r.take()?,
            publisher: r.key()?,
            genesis: r.take()?,
            policy_id: r.take()?,
            policy_version: r.u32()?,
            circuit_id: r.take()?,
            package_id: r.take()?,
            schema_id: r.take()?,
            root: r.take()?,
            root_version: r.u64()?,
            enabled: r.boolean()?,
        };
        r.finish()?;
        canonical(&c.root)?;
        if c.policy_version == 0 {
            return Err(AppError::Policy);
        }
        Ok(c)
    }
    pub fn publish(&mut self, expected: u64, root: [u8; 32]) -> Result<()> {
        if expected != self.root_version {
            return Err(AppError::Version);
        }
        canonical(&root)?;
        let next = expected.checked_add(1).ok_or(AppError::Version)?;
        self.root = root;
        self.root_version = next;
        Ok(())
    }
}
impl Issuer {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = ISSUER_MAGIC.to_vec();
        push_key(&mut b, &self.config);
        b.extend(self.issuer_hash);
        b.extend(self.profile_id);
        b.extend(self.profile_version.to_be_bytes());
        b.extend(self.aki);
        push_key(&mut b, &self.source);
        b.push(self.enabled as u8);
        b.extend(self.sequence.to_be_bytes());
        b.extend(self.digest);
        b.extend(self.observed_at.to_be_bytes());
        b.extend(self.expires_at.to_be_bytes());
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::account(b, ISSUER_LEN, ISSUER_MAGIC)?;
        let i = Self {
            config: r.key()?,
            issuer_hash: r.take()?,
            profile_id: r.take()?,
            profile_version: r.u32()?,
            aki: r.take()?,
            source: r.key()?,
            enabled: r.boolean()?,
            sequence: r.u64()?,
            digest: r.take()?,
            observed_at: r.i64()?,
            expires_at: r.i64()?,
        };
        r.finish()?;
        canonical(&i.issuer_hash)?;
        if i.profile_version == 0 {
            return Err(AppError::Policy);
        }
        Ok(i)
    }
    /// Source transaction authenticates this observation for this issuer PDA and config.
    pub fn observe(
        &mut self,
        expected: u64,
        sequence: u64,
        digest: [u8; 32],
        observed: i64,
        expires: i64,
        now: i64,
    ) -> Result<()> {
        if expected != self.sequence
            || sequence != expected.checked_add(1).ok_or(AppError::Version)?
        {
            return Err(AppError::Version);
        }
        if digest == [0; 32]
            || digest == self.digest
            || observed <= self.observed_at
            || observed > now
            || expires < observed
            || expires <= now
            || expires.checked_sub(observed).ok_or(AppError::Status)? > STATUS_MAX_AGE
        {
            return Err(AppError::Status);
        }
        self.sequence = sequence;
        self.digest = digest;
        self.observed_at = observed;
        self.expires_at = expires;
        Ok(())
    }
    pub fn fresh(&self, now: i64) -> Result<()> {
        if !self.enabled
            || self.sequence == 0
            || now < self.observed_at
            || now > self.expires_at
            || now.checked_sub(self.observed_at).ok_or(AppError::Status)? > STATUS_MAX_AGE
        {
            return Err(AppError::Status);
        }
        Ok(())
    }
}
impl RelevantMeta {
    fn read(r: &mut Reader) -> Result<Self> {
        let m = Self {
            key: r.key()?,
            flags: r.byte()?,
            owner: r.key()?,
        };
        if m.flags > 3 {
            return Err(AppError::Privileges);
        }
        Ok(m)
    }
    fn encode(&self, b: &mut Vec<u8>) {
        push_key(b, &self.key);
        b.push(self.flags);
        push_key(b, &self.owner);
    }
}
impl Request {
    fn valid_shape(&self) -> Result<()> {
        if self.payload_len as usize > MAX_PAYLOAD
            || self.payload.len() != self.payload_len as usize
            || self.uploaded > self.payload_len
            || self.metas.len() < 2
            || self.metas.len() > MAX_METAS
            || self.metas_uploaded as usize > self.metas.len()
            || self.deadline <= 0
            || self.request_type != 1
        {
            return Err(AppError::Bounds);
        }
        canonical(&self.issuer_hash)?;
        if self.metas.iter().any(|m| m.flags > 3) {
            return Err(AppError::Privileges);
        }
        Ok(())
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = REQUEST_MAGIC.to_vec();
        push_key(&mut b, &self.config);
        push_key(&mut b, &self.creator);
        b.extend(self.nonce);
        b.extend(self.issuer_hash);
        push_key(&mut b, &self.recipient);
        b.extend(self.request_type.to_be_bytes());
        b.extend(self.deadline.to_be_bytes());
        b.extend(self.payload_len.to_be_bytes());
        b.extend(self.uploaded.to_be_bytes());
        b.push(self.metas_uploaded);
        b.push(self.state as u8);
        b.push(self.metas.len() as u8);
        for m in &self.metas {
            m.encode(&mut b)
        }
        b.resize(185 + MAX_METAS * 65, 0);
        b.extend(&self.payload);
        b.resize(REQUEST_LEN, 0);
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::account(b, REQUEST_LEN, REQUEST_MAGIC)?;
        let config = r.key()?;
        let creator = r.key()?;
        let nonce = r.take()?;
        let issuer_hash = r.take()?;
        let recipient = r.key()?;
        let request_type = r.u16()?;
        let deadline = r.i64()?;
        let payload_len = r.u16()?;
        let uploaded = r.u16()?;
        let metas_uploaded = r.byte()?;
        let state = match r.byte()? {
            0 => RequestState::Staging,
            1 => RequestState::Finalized,
            2 => RequestState::Consumed,
            3 => RequestState::Cancelled,
            _ => return Err(AppError::State),
        };
        let n = r.byte()? as usize;
        if n < 2 || n > MAX_METAS || payload_len as usize > MAX_PAYLOAD {
            return Err(AppError::Bounds);
        }
        let mut metas = Vec::with_capacity(n);
        for _ in 0..n {
            metas.push(RelevantMeta::read(&mut r)?)
        }
        let p = 185 + MAX_METAS * 65;
        if b[r.pos..p].iter().any(|byte| *byte != 0)
            || b[p + payload_len as usize..].iter().any(|byte| *byte != 0)
        {
            return Err(AppError::State);
        }
        let payload = b[p..p + payload_len as usize].to_vec();
        let x = Self {
            config,
            creator,
            nonce,
            issuer_hash,
            recipient,
            request_type,
            deadline,
            payload_len,
            uploaded,
            metas_uploaded,
            state,
            metas,
            payload,
        };
        x.valid_shape()?;
        if matches!(state, RequestState::Finalized | RequestState::Consumed)
            && (uploaded != payload_len || metas_uploaded as usize != n)
        {
            return Err(AppError::State);
        }
        Ok(x)
    }
    pub fn upload(&mut self, offset: u16, chunk: &[u8]) -> Result<()> {
        self.valid_shape()?;
        let end = offset as usize + chunk.len();
        if self.state != RequestState::Staging
            || offset != self.uploaded
            || chunk.is_empty()
            || chunk.len() > MAX_CHUNK
            || end > self.payload.len()
        {
            return Err(AppError::State);
        }
        self.payload[offset as usize..end].copy_from_slice(chunk);
        self.uploaded = end as u16;
        Ok(())
    }
    pub fn upload_metas(&mut self, offset: u8, metas: &[RelevantMeta]) -> Result<()> {
        let end = offset as usize + metas.len();
        if self.state != RequestState::Staging
            || offset != self.metas_uploaded
            || metas.is_empty()
            || metas.len() > MAX_META_CHUNK
            || end > self.metas.len()
            || metas.iter().any(|m| m.flags > 3)
        {
            return Err(AppError::State);
        }
        self.metas[offset as usize..end].clone_from_slice(metas);
        self.metas_uploaded = end as u8;
        Ok(())
    }
    pub fn finalize(&mut self, now: i64) -> Result<()> {
        self.valid_shape()?;
        if self.state != RequestState::Staging
            || self.uploaded != self.payload_len
            || self.metas_uploaded as usize != self.metas.len()
        {
            return Err(AppError::State);
        }
        if now < 0 || now > self.deadline {
            return Err(AppError::Expired);
        }
        for (index, m) in self.metas.iter().enumerate() {
            if self.metas[..index].iter().any(|prior| prior.key == m.key) {
                return Err(AppError::Accounts);
            }
        }
        self.state = RequestState::Finalized;
        Ok(())
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
        let mut b = QUEUE_MAGIC.to_vec();
        push_key(&mut b, &self.config);
        b.extend((self.entries.len() as u16).to_be_bytes());
        for k in &self.entries {
            push_key(&mut b, k)
        }
        b.resize(QUEUE_LEN, 0);
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::account(b, QUEUE_LEN, QUEUE_MAGIC)?;
        let config = r.key()?;
        let n = r.u16()? as usize;
        if n > QUEUE_CAPACITY {
            return Err(AppError::Bounds);
        }
        let mut entries = Vec::with_capacity(n);
        for _ in 0..n {
            entries.push(r.key()?)
        }
        if b[r.pos..].iter().any(|byte| *byte != 0) {
            return Err(AppError::State);
        }
        Ok(Self { config, entries })
    }
}
pub fn append(queue: &mut Queue, request: &mut Request, key: Pubkey, now: i64) -> Result<()> {
    if request.state != RequestState::Finalized {
        return Err(AppError::Consumed);
    }
    if now < 0 || now > request.deadline {
        return Err(AppError::Expired);
    }
    if queue.config != request.config || queue.entries.contains(&key) {
        return Err(AppError::Accounts);
    }
    if queue.entries.len() >= QUEUE_CAPACITY {
        return Err(AppError::Capacity);
    }
    queue.entries.push(key);
    request.state = RequestState::Consumed;
    Ok(())
}
/// Exactly component-contracts action-v2; owners are validated but absent from its preimage.
pub fn action_preimage(program: &Pubkey, c: &Config, r: &Request) -> Result<Vec<u8>> {
    r.valid_shape()?;
    let mut b = b"DYNARK-WORK-REQUEST".to_vec();
    b.push(2);
    b.extend(c.genesis);
    push_key(&mut b, program);
    push_key(&mut b, &r.config);
    b.extend(c.policy_id);
    b.extend(c.policy_version.to_be_bytes());
    b.extend(c.circuit_id);
    b.extend(r.nonce);
    push_key(&mut b, &r.recipient);
    b.extend(r.request_type.to_be_bytes());
    b.extend((r.payload.len() as u32).to_be_bytes());
    b.extend(solana_program::hash::hash(&r.payload).to_bytes());
    b.push(r.metas.len() as u8);
    for m in &r.metas {
        push_key(&mut b, &m.key);
        b.push(m.flags)
    }
    b.extend(r.deadline.to_be_bytes());
    Ok(b)
}
pub fn action_hash(program: &Pubkey, c: &Config, r: &Request) -> Result<[u8; 32]> {
    let mut h = solana_program::hash::hash(&action_preimage(program, c, r)?).to_bytes();
    while h >= crate::FIELD_MODULUS {
        let mut borrow = 0u16;
        for i in (0..32).rev() {
            let sub = crate::FIELD_MODULUS[i] as u16 + borrow;
            let v = h[i] as u16;
            h[i] = v.wrapping_sub(sub) as u8;
            borrow = u16::from(v < sub)
        }
    }
    Ok(h)
}

/// Prefix 0x50, opcode, exact fixed fields, no trailing bytes. All integers BE.
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
        root: [u8; 32],
    },
    Enroll {
        issuer_hash: [u8; 32],
        profile_id: [u8; 32],
        profile_version: u32,
        aki: [u8; 32],
        source: Pubkey,
    },
    Publish {
        expected: u64,
        root: [u8; 32],
    },
    Observe {
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
    UploadMetas {
        offset: u8,
        metas: Vec<RelevantMeta>,
    },
    Cancel,
    SetEnabled {
        policy: bool,
        issuer: bool,
    },
    Execute {
        inputs: [[u8; 32]; 5],
        proof: [u8; 256],
    },
}
impl AppInstruction {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_CHUNK + 16 {
            return Err(AppError::Bounds);
        }
        let mut r = Reader::new(bytes);
        if r.byte()? != PREFIX {
            return Err(AppError::Instruction);
        }
        let x = match r.byte()? {
            0 => Self::Initialize {
                seed: r.take()?,
                publisher: r.key()?,
                genesis: r.take()?,
                policy_id: r.take()?,
                policy_version: r.u32()?,
                circuit_id: r.take()?,
                package_id: r.take()?,
                schema_id: r.take()?,
                root: r.take()?,
            },
            1 => Self::Enroll {
                issuer_hash: r.take()?,
                profile_id: r.take()?,
                profile_version: r.u32()?,
                aki: r.take()?,
                source: r.key()?,
            },
            2 => Self::Publish {
                expected: r.u64()?,
                root: r.take()?,
            },
            3 => Self::Observe {
                expected: r.u64()?,
                sequence: r.u64()?,
                digest: r.take()?,
                observed: r.i64()?,
                expires: r.i64()?,
            },
            4 => {
                let nonce = r.take()?;
                let issuer_hash = r.take()?;
                let recipient = r.key()?;
                let request_type = r.u16()?;
                let deadline = r.i64()?;
                let payload_len = r.u16()?;
                let meta_count = r.byte()?;
                if payload_len as usize > MAX_PAYLOAD
                    || !(2..=MAX_METAS as u8).contains(&meta_count)
                    || request_type != 1
                    || deadline <= 0
                {
                    return Err(AppError::Bounds);
                }
                Self::Create {
                    nonce,
                    issuer_hash,
                    recipient,
                    request_type,
                    deadline,
                    payload_len,
                    meta_count,
                }
            }
            5 => Self::Finalize,
            6 => {
                let offset = r.u16()?;
                let n = r.u16()? as usize;
                if n == 0 || n > MAX_CHUNK || r.pos + n != bytes.len() {
                    return Err(AppError::Bounds);
                }
                let bytes = bytes[r.pos..].to_vec();
                r.pos += n;
                Self::Upload { offset, bytes }
            }
            7 => Self::Execute {
                inputs: [r.take()?, r.take()?, r.take()?, r.take()?, r.take()?],
                proof: r.take()?,
            },
            8 => {
                let offset = r.byte()?;
                let n = r.byte()? as usize;
                if n == 0 || n > MAX_META_CHUNK {
                    return Err(AppError::Bounds);
                }
                let mut metas = Vec::with_capacity(n);
                for _ in 0..n {
                    metas.push(RelevantMeta::read(&mut r)?)
                }
                Self::UploadMetas { offset, metas }
            }
            9 => Self::Cancel,
            10 => Self::SetEnabled {
                policy: r.boolean()?,
                issuer: r.boolean()?,
            },
            _ => return Err(AppError::Instruction),
        };
        r.finish()?;
        Ok(x)
    }
}
