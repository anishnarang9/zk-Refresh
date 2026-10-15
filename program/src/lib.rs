#![allow(deprecated)]
use groth16_solana::groth16::Groth16Verifier;
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint::ProgramResult,
    hash::hashv,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction, system_program,
    sysvar::Sysvar,
};
pub mod application_runtime_v2;
pub mod application_runtime_v3;
pub mod application_v2;
pub mod application_v3;
pub mod generated_vk;
#[rustfmt::skip]
pub mod generated_vk_v2;
pub mod generated_vk_v3;

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

pub const FIELD_MODULUS: [u8; 32] = [
    48, 100, 78, 114, 225, 49, 160, 41, 184, 80, 69, 182, 129, 129, 88, 93, 40, 51, 232, 72, 121,
    185, 112, 145, 67, 225, 245, 147, 240, 0, 0, 1,
];
pub const HISTORY_CAPACITY: usize = 128;
pub const REGISTRY_LEN: usize = 128 + HISTORY_CAPACITY * 48;
pub const RECEIPT_LEN: usize = 152;
pub const POLICY_VERSION: u64 = 1;
const REGISTRY_MAGIC: &[u8; 8] = b"ZKFREG01";
const RECEIPT_MAGIC: &[u8; 8] = b"ZKFREC01";

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum FreshError {
    InvalidInstruction = 1,
    NonCanonicalField = 2,
    InvalidTime = 3,
    NotYetValid = 4,
    CredentialExpired = 5,
    RootExpired = 6,
    RootNotAccepted = 7,
    InvalidPolicy = 8,
    InvalidVersion = 9,
    AlreadyUsed = 10,
    VerificationKeyDisabled = 11,
    InvalidAccount = 12,
    InvalidOwner = 13,
    MissingSignature = 14,
    NotWritable = 15,
    Unauthorized = 16,
    IssuerMismatch = 17,
    ActionMismatch = 18,
    InvalidProof = 19,
    InvalidState = 20,
    VersionOverflow = 21,
    InvalidSystemProgram = 22,
}
impl From<FreshError> for ProgramError {
    fn from(e: FreshError) -> Self {
        Self::Custom(e as u32)
    }
}

#[derive(Debug, PartialEq)]
pub enum Instruction {
    Initialize {
        seed: [u8; 32],
        issuer: [u8; 32],
        root: [u8; 32],
        policy: u8,
        max_age: u64,
    },
    Update {
        root: [u8; 32],
        expected_version: u64,
    },
    Authorize {
        inputs: [[u8; 32]; 5],
        proof: [u8; 256],
        action_id: [u8; 32],
        recipient: [u8; 32],
    },
}
impl Instruction {
    pub fn parse(data: &[u8]) -> Result<Self, FreshError> {
        match data.first() {
            Some(0) if data.len() == 106 => Ok(Self::Initialize {
                seed: array(&data[1..33]),
                issuer: array(&data[33..65]),
                root: array(&data[65..97]),
                policy: data[97],
                max_age: u64::from_le_bytes(array(&data[98..106])),
            }),
            Some(1) if data.len() == 41 => Ok(Self::Update {
                root: array(&data[1..33]),
                expected_version: u64::from_le_bytes(array(&data[33..41])),
            }),
            Some(2) if data.len() == 481 => {
                let mut inputs = [[0; 32]; 5];
                for (i, input) in inputs.iter_mut().enumerate() {
                    *input = array(&data[1 + i * 32..33 + i * 32]);
                }
                Ok(Self::Authorize {
                    inputs,
                    proof: array(&data[161..417]),
                    action_id: array(&data[417..449]),
                    recipient: array(&data[449..481]),
                })
            }
            _ => Err(FreshError::InvalidInstruction),
        }
    }
}
fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut value = [0; N];
    value.copy_from_slice(bytes);
    value
}
pub fn canonical(value: &[u8; 32]) -> Result<(), FreshError> {
    if value < &FIELD_MODULUS {
        Ok(())
    } else {
        Err(FreshError::NonCanonicalField)
    }
}
fn epoch(value: &[u8; 32]) -> Result<u64, FreshError> {
    if value[..24].iter().any(|b| *b != 0) {
        return Err(FreshError::InvalidTime);
    }
    Ok(u64::from_be_bytes(array(&value[24..])))
}
pub fn validate_times(before: &[u8; 32], after: &[u8; 32], now: i64) -> Result<(), FreshError> {
    let before = epoch(before)?;
    let after = epoch(after)?;
    let now = u64::try_from(now).map_err(|_| FreshError::InvalidTime)?;
    if before > after {
        return Err(FreshError::InvalidTime);
    }
    if now < before {
        return Err(FreshError::NotYetValid);
    }
    if now > after {
        return Err(FreshError::CredentialExpired);
    }
    Ok(())
}
pub fn action_digest(
    program: &Pubkey,
    registry: &Pubkey,
    recipient: &[u8; 32],
    action: &[u8; 32],
) -> [u8; 32] {
    let mut digest = hashv(&[
        b"zk-fresh-action-v1",
        program.as_ref(),
        registry.as_ref(),
        &POLICY_VERSION.to_le_bytes(),
        recipient,
        action,
    ])
    .to_bytes();
    while digest >= FIELD_MODULUS {
        let mut borrow = 0u16;
        for i in (0..32).rev() {
            let sub = FIELD_MODULUS[i] as u16 + borrow;
            let v = digest[i] as u16;
            digest[i] = v.wrapping_sub(sub) as u8;
            borrow = u16::from(v < sub);
        }
    }
    digest
}
#[derive(Debug, Clone)]
pub struct RootEntry {
    pub root: [u8; 32],
    pub version: u64,
    pub activated_at: i64,
}
#[derive(Debug)]
pub struct Registry {
    pub authority: Pubkey,
    pub seed: [u8; 32],
    pub issuer: [u8; 32],
    pub policy: u8,
    pub bump: u8,
    pub max_age: u64,
    pub current_version: u64,
    pub entries: Vec<RootEntry>,
    pub next_slot: usize,
}
impl Registry {
    pub fn new(
        authority: Pubkey,
        seed: [u8; 32],
        issuer: [u8; 32],
        root: [u8; 32],
        policy: u8,
        max_age: u64,
        now: i64,
        bump: u8,
    ) -> Result<Self, FreshError> {
        if policy > 1 || max_age == 0 || max_age > 300 {
            return Err(FreshError::InvalidPolicy);
        }
        if now < 0 {
            return Err(FreshError::InvalidTime);
        }
        canonical(&issuer)?;
        canonical(&root)?;
        Ok(Self {
            authority,
            seed,
            issuer,
            policy,
            bump,
            max_age,
            current_version: 0,
            entries: vec![RootEntry {
                root,
                version: 0,
                activated_at: now,
            }],
            next_slot: 1,
        })
    }
    pub fn update(
        &mut self,
        root: [u8; 32],
        expected_version: u64,
        now: i64,
    ) -> Result<(), FreshError> {
        if expected_version != self.current_version {
            return Err(FreshError::InvalidVersion);
        }
        canonical(&root)?;
        let latest = (self.next_slot + self.entries.len() - 1) % self.entries.len();
        if now < self.entries[latest].activated_at {
            return Err(FreshError::InvalidTime);
        }
        let version = self
            .current_version
            .checked_add(1)
            .ok_or(FreshError::VersionOverflow)?;
        let entry = RootEntry {
            root,
            version,
            activated_at: now,
        };
        if self.entries.len() < HISTORY_CAPACITY {
            self.entries.push(entry)
        } else {
            self.entries[self.next_slot] = entry
        }
        self.next_slot = (self.next_slot + 1) % HISTORY_CAPACITY;
        self.current_version = version;
        Ok(())
    }
    pub fn accepted_root(&self, root: &[u8; 32], now: i64) -> Result<u64, FreshError> {
        let len = self.entries.len();
        for offset in 0..len {
            let index = (self.next_slot + len - 1 - offset) % len;
            let entry = &self.entries[index];
            if self.policy == 0 && offset > 0 {
                break;
            }
            if &entry.root == root {
                let age = now
                    .checked_sub(entry.activated_at)
                    .filter(|v| *v >= 0)
                    .ok_or(FreshError::InvalidTime)?;
                if self.policy == 1 && age as u64 > self.max_age {
                    return Err(FreshError::RootExpired);
                }
                return Ok(entry.version);
            }
        }
        Err(FreshError::RootNotAccepted)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![0; REGISTRY_LEN];
        bytes[..8].copy_from_slice(REGISTRY_MAGIC);
        bytes[8..40].copy_from_slice(self.authority.as_ref());
        bytes[40..72].copy_from_slice(&self.seed);
        bytes[72..104].copy_from_slice(&self.issuer);
        bytes[104] = self.policy;
        bytes[105] = self.bump;
        bytes[106..114].copy_from_slice(&self.max_age.to_le_bytes());
        bytes[114..122].copy_from_slice(&self.current_version.to_le_bytes());
        bytes[122..124].copy_from_slice(&(self.entries.len() as u16).to_le_bytes());
        bytes[124..126].copy_from_slice(&(self.next_slot as u16).to_le_bytes());
        for (i, e) in self.entries.iter().enumerate() {
            let start = 128 + i * 48;
            bytes[start..start + 32].copy_from_slice(&e.root);
            bytes[start + 32..start + 40].copy_from_slice(&e.version.to_le_bytes());
            bytes[start + 40..start + 48].copy_from_slice(&e.activated_at.to_le_bytes())
        }
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, FreshError> {
        if bytes.len() != REGISTRY_LEN || &bytes[..8] != REGISTRY_MAGIC {
            return Err(FreshError::InvalidState);
        }
        let len = u16::from_le_bytes(array(&bytes[122..124])) as usize;
        let next_slot = u16::from_le_bytes(array(&bytes[124..126])) as usize;
        let max_age = u64::from_le_bytes(array(&bytes[106..114]));
        if len == 0
            || len > HISTORY_CAPACITY
            || next_slot >= HISTORY_CAPACITY
            || (len < HISTORY_CAPACITY && next_slot != len)
            || bytes[104] > 1
            || max_age == 0
            || max_age > 300
        {
            return Err(FreshError::InvalidState);
        }
        let mut entries = Vec::with_capacity(len);
        for i in 0..len {
            let start = 128 + i * 48;
            entries.push(RootEntry {
                root: array(&bytes[start..start + 32]),
                version: u64::from_le_bytes(array(&bytes[start + 32..start + 40])),
                activated_at: i64::from_le_bytes(array(&bytes[start + 40..start + 48])),
            })
        }
        Ok(Self {
            authority: Pubkey::new_from_array(array(&bytes[8..40])),
            seed: array(&bytes[40..72]),
            issuer: array(&bytes[72..104]),
            policy: bytes[104],
            bump: bytes[105],
            max_age,
            current_version: u64::from_le_bytes(array(&bytes[114..122])),
            entries,
            next_slot,
        })
    }
}
pub fn check_receipt_unused(
    program: &Pubkey,
    owner: &Pubkey,
    len: usize,
) -> Result<(), FreshError> {
    if owner == program {
        return Err(FreshError::AlreadyUsed);
    }
    if owner != &system_program::id() || len != 0 {
        return Err(FreshError::InvalidAccount);
    }
    Ok(())
}
pub fn verify_proof(inputs: &[[u8; 32]; 5], proof: &[u8; 256]) -> Result<(), FreshError> {
    if !generated_vk::VK_ENABLED {
        return Err(FreshError::VerificationKeyDisabled);
    }
    for input in inputs {
        canonical(input)?
    }
    let a = array(&proof[..64]);
    let b = array(&proof[64..192]);
    let c = array(&proof[192..]);
    let mut verifier = Groth16Verifier::new(&a, &b, &c, inputs, &generated_vk::VERIFYING_KEY)
        .map_err(|_| FreshError::InvalidProof)?;
    verifier.verify().map_err(|_| FreshError::InvalidProof)
}
fn signer(account: &AccountInfo) -> ProgramResult {
    if !account.is_signer {
        return Err(FreshError::MissingSignature.into());
    }
    Ok(())
}
fn writable(account: &AccountInfo) -> ProgramResult {
    if !account.is_writable {
        return Err(FreshError::NotWritable.into());
    }
    Ok(())
}
fn load_registry(program: &Pubkey, account: &AccountInfo) -> Result<Registry, ProgramError> {
    if account.owner != program {
        return Err(FreshError::InvalidOwner.into());
    }
    let registry = Registry::decode(&account.try_borrow_data()?)?;
    let expected = Pubkey::create_program_address(
        &[
            b"registry",
            registry.authority.as_ref(),
            &registry.seed,
            &[registry.bump],
        ],
        program,
    )
    .map_err(|_| FreshError::InvalidAccount)?;
    if account.key != &expected {
        return Err(FreshError::InvalidAccount.into());
    }
    Ok(registry)
}
fn create_pda<'a>(
    program: &Pubkey,
    payer: &AccountInfo<'a>,
    account: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    len: usize,
    seeds: &[&[u8]],
) -> ProgramResult {
    if system.key != &system_program::id() || !system.executable {
        return Err(FreshError::InvalidSystemProgram.into());
    }
    if payer.key == account.key {
        return Err(FreshError::InvalidAccount.into());
    }
    let rent = Rent::get()?.minimum_balance(len);
    if account.lamports() == 0 {
        invoke_signed(
            &system_instruction::create_account(payer.key, account.key, rent, len as u64, program),
            &[payer.clone(), account.clone(), system.clone()],
            &[seeds],
        )?;
    } else {
        if rent > account.lamports() {
            invoke_signed(
                &system_instruction::transfer(payer.key, account.key, rent - account.lamports()),
                &[payer.clone(), account.clone(), system.clone()],
                &[],
            )?;
        }
        invoke_signed(
            &system_instruction::allocate(account.key, len as u64),
            &[account.clone(), system.clone()],
            &[seeds],
        )?;
        invoke_signed(
            &system_instruction::assign(account.key, program),
            &[account.clone(), system.clone()],
            &[seeds],
        )?;
    }
    Ok(())
}
pub fn process_instruction(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.first() == Some(&application_v2::PREFIX) {
        return application_runtime_v2::process(program, accounts, data);
    }
    if data.first() == Some(&application_v3::PREFIX) {
        return application_runtime_v3::process(program, accounts, data);
    }
    let instruction = Instruction::parse(data)?;
    let mut accounts = accounts.iter();
    match instruction {
        Instruction::Initialize {
            seed,
            issuer,
            root,
            policy,
            max_age,
        } => {
            let payer = next_account_info(&mut accounts)?;
            let account = next_account_info(&mut accounts)?;
            let system = next_account_info(&mut accounts)?;
            signer(payer)?;
            writable(payer)?;
            writable(account)?;
            check_receipt_unused(program, account.owner, account.data_len())?;
            let (expected, bump) =
                Pubkey::find_program_address(&[b"registry", payer.key.as_ref(), &seed], program);
            if account.key != &expected {
                return Err(FreshError::InvalidAccount.into());
            }
            let registry = Registry::new(
                *payer.key,
                seed,
                issuer,
                root,
                policy,
                max_age,
                Clock::get()?.unix_timestamp,
                bump,
            )?;
            create_pda(
                program,
                payer,
                account,
                system,
                REGISTRY_LEN,
                &[b"registry", payer.key.as_ref(), &seed, &[bump]],
            )?;
            account
                .try_borrow_mut_data()?
                .copy_from_slice(&registry.encode());
        }
        Instruction::Update {
            root,
            expected_version,
        } => {
            let authority = next_account_info(&mut accounts)?;
            let account = next_account_info(&mut accounts)?;
            signer(authority)?;
            writable(account)?;
            let mut registry = load_registry(program, account)?;
            if authority.key != &registry.authority {
                return Err(FreshError::Unauthorized.into());
            }
            registry.update(root, expected_version, Clock::get()?.unix_timestamp)?;
            account
                .try_borrow_mut_data()?
                .copy_from_slice(&registry.encode());
        }
        Instruction::Authorize {
            inputs,
            proof,
            action_id,
            recipient,
        } => {
            let payer = next_account_info(&mut accounts)?;
            let account = next_account_info(&mut accounts)?;
            let receipt = next_account_info(&mut accounts)?;
            let system = next_account_info(&mut accounts)?;
            signer(payer)?;
            writable(payer)?;
            writable(receipt)?;
            let registry = load_registry(program, account)?;
            let (expected, bump) = Pubkey::find_program_address(
                &[b"receipt", account.key.as_ref(), &action_id],
                program,
            );
            if receipt.key != &expected {
                return Err(FreshError::InvalidAccount.into());
            }
            check_receipt_unused(program, receipt.owner, receipt.data_len())?;
            for input in &inputs {
                canonical(input)?
            }
            if inputs[1] != registry.issuer {
                return Err(FreshError::IssuerMismatch.into());
            }
            if inputs[4] != action_digest(program, account.key, &recipient, &action_id) {
                return Err(FreshError::ActionMismatch.into());
            }
            let now = Clock::get()?.unix_timestamp;
            validate_times(&inputs[2], &inputs[3], now)?;
            let version = registry.accepted_root(&inputs[0], now)?;
            verify_proof(&inputs, &proof)?;
            create_pda(
                program,
                payer,
                receipt,
                system,
                RECEIPT_LEN,
                &[b"receipt", account.key.as_ref(), &action_id, &[bump]],
            )?;
            let mut bytes = receipt.try_borrow_mut_data()?;
            bytes[..8].copy_from_slice(RECEIPT_MAGIC);
            bytes[8..40].copy_from_slice(account.key.as_ref());
            bytes[40..72].copy_from_slice(&recipient);
            bytes[72..104].copy_from_slice(&action_id);
            bytes[104..136].copy_from_slice(&inputs[0]);
            bytes[136..144].copy_from_slice(&version.to_le_bytes());
            bytes[144..152].copy_from_slice(&now.to_le_bytes());
        }
    }
    Ok(())
}
