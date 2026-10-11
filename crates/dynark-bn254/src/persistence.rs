//! Authenticated process-lifetime checkpoints. Trusted setup/context and current
//! application root/issuer policy remain external. No raw-state codec is public.
use crate::{
    CircuitDescriptor, DynamicConfig, DynamicState, Error, PackageIdentity, PublicPackage,
    ReconstructionMaterial, Reduction, Shape,
};
use ark_bn254::Fr;
use ark_serialize::CanonicalSerialize;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::io::Write;
use zeroize::Zeroizing;
mod provider;
pub(crate) mod storage;
pub(crate) mod wire;
use crate::dynamic::persistence_codec as codec;
pub use provider::{InvalidationReason, SyntheticCasFault, SyntheticProvider, SyntheticResolution};
pub use storage::{ProtectedStore, StoreLimits};

#[derive(Debug)]
pub enum PersistenceError {
    Engine(Error),
    Malformed(&'static str),
    Unsupported(&'static str),
    Bound(&'static str),
    Trust(&'static str),
    RebuildRequired(&'static str),
    Fenced,
    ReservationExhausted,
    Entropy { draw: usize, source: rand::Error },
    Io(std::io::Error),
}
impl std::fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for PersistenceError {}
impl From<Error> for PersistenceError {
    fn from(e: Error) -> Self {
        Self::Engine(e)
    }
}
impl From<std::io::Error> for PersistenceError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<rustix::io::Errno> for PersistenceError {
    fn from(e: rustix::io::Errno) -> Self {
        Self::Io(e.into())
    }
}
pub(crate) type Result<T> = std::result::Result<T, PersistenceError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncTier {
    FileAndDirectory,
    Media,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderCapability {
    ProcessLifetime,
    Durable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionStatus {
    Active,
    Invalidated,
}
/// Complete independently supplied manifest/policy scope, checked against the package.
#[derive(Clone)]
pub struct ExpectedContext {
    pub(crate) identity: PackageIdentity,
    pub(crate) shape: Shape,
    pub(crate) reduction: Reduction,
    pub(crate) descriptor: [[u8; 32]; 4],
    pub(crate) material: [[u8; 32]; 3],
    pub(crate) session: [u8; 32],
    pub(crate) credential: [u8; 32],
    pub(crate) action: [u8; 32],
    trusted_tables: ReconstructionMaterial,
    pub(crate) issuer: [u8; 32],
    pub(crate) application: [u8; 32],
    pub(crate) digest: [u8; 32],
}
impl ExpectedContext {
    pub fn new(
        p: &PublicPackage,
        t: &ReconstructionMaterial,
        d: &CircuitDescriptor,
        session: [u8; 32],
        credential: [u8; 32],
        action: [u8; 32],
        issuer: [u8; 32],
        application: [u8; 32],
    ) -> Result<Self> {
        if session == [0; 32]
            || d.public_schema.len() != p.shape().instance_len - 1
            || d.public_schema_digest != crate::public_schema_digest(&d.public_schema)
        {
            return Err(PersistenceError::Trust("descriptor/schema"));
        }
        let descriptor = [
            d.r1cs_artifact_digest,
            d.witness_executable_digest,
            d.profile_digest,
            d.public_schema_digest,
        ];
        let mut h = HashWriter(Sha256::new());
        h.0.update(b"dynark-bn254/circuit/v1;curve=BN254;domain=radix2;roots=omega^i;quotient=seven-transform;encoding=ark-compressed-v0.5");
        h.0.update(p.identity().matrix_digest);
        for x in descriptor {
            h.0.update(x);
        }
        h.0.update([match d.reduction {
            Reduction::Original => 0,
            Reduction::InstanceAugmentedA => 1,
        }]);
        for x in shape_values(p.shape()) {
            h.0.update(x.to_le_bytes());
        }
        p.0.domain
            .serialize_compressed(&mut h)
            .map_err(Error::from)?;
        if <[u8; 32]>::from(h.0.finalize()) != p.identity().circuit_digest {
            return Err(PersistenceError::Trust("descriptor/package binding"));
        }
        let material = t.persistence_commitments(p)?;
        let mut out = Self {
            identity: p.identity(),
            shape: p.shape(),
            reduction: d.reduction,
            descriptor,
            material,
            session,
            credential,
            action,
            issuer,
            application,
            trusted_tables: t.clone(),
            digest: [0; 32],
        };
        let mut h = Sha256::new();
        h.update(b"dynark-bn254/persistence-context/v1");
        for x in identity_values(out.identity)
            .into_iter()
            .chain(descriptor)
            .chain(material)
            .chain([session, credential, action, issuer, application])
        {
            h.update(x);
        }
        for x in shape_values(out.shape) {
            h.update(x.to_le_bytes());
        }
        h.update([match out.reduction {
            Reduction::Original => 0,
            Reduction::InstanceAugmentedA => 1,
        }]);
        out.digest = h.finalize().into();
        Ok(out)
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn session_id(&self) -> [u8; 32] {
        self.session
    }
    pub(crate) fn check(&self, p: &PublicPackage, t: &ReconstructionMaterial) -> Result<()> {
        t.check(p)?;
        if self.identity != p.identity()
            || self.shape != p.shape()
            || !self.trusted_tables.shares_storage_with(t)
        {
            return Err(PersistenceError::Trust("package/context"));
        }
        Ok(())
    }
}
pub(crate) fn shape_values(s: Shape) -> [u64; 5] {
    [
        s.constraint_rows as u64,
        s.reduction_rows as u64,
        s.assignment_len as u64,
        s.instance_len as u64,
        s.domain_size as u64,
    ]
}
pub(crate) fn identity_values(i: PackageIdentity) -> [[u8; 32]; 5] {
    [
        i.matrix_digest,
        i.circuit_digest,
        i.proving_key_digest,
        i.verifying_key_digest,
        i.package_digest,
    ]
}
pub(crate) struct HashWriter(pub(crate) Sha256);
impl Write for HashWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.update(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Fixed-size authoritative receipt. The final-file hash is external, never self-embedded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub context: [u8; 32],
    pub session: [u8; 32],
    pub session_epoch: u64,
    pub revision: u64,
    pub commit_id: [u8; 32],
    pub base_present: bool,
    pub base_id: [u8; 32],
    pub base_revision: u64,
    pub base_generation: u64,
    pub envelope_digest: [u8; 32],
    pub key_id: [u8; 32],
    pub key_epoch: u64,
    pub generation: u64,
    pub state_token: [u8; 32],
    pub config_digest: [u8; 32],
    pub statement_digest: [u8; 32],
    pub schema: u16,
    pub units: u16,
    pub tier: SyncTier,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderSnapshot {
    pub context: [u8; 32],
    pub session: [u8; 32],
    pub session_epoch: u64,
    pub key_id: [u8; 32],
    pub key_epoch: u64,
    pub status: SessionStatus,
    pub capability: ProviderCapability,
    pub enrollment_authorized: bool,
    pub receipt: Option<Receipt>,
    pub unresolved: Option<[u8; 32]>,
}
impl ProviderSnapshot {
    pub(crate) fn check(&self, c: &ExpectedContext) -> Result<()> {
        if self.context != c.digest || self.session != c.session {
            return Err(PersistenceError::Trust("provider context"));
        }
        if self.status != SessionStatus::Active {
            return Err(PersistenceError::RebuildRequired("invalidated session"));
        }
        if self.unresolved.is_some() {
            return Err(PersistenceError::Fenced);
        }
        if self.capability != ProviderCapability::ProcessLifetime {
            return Err(PersistenceError::Unsupported("provider capability"));
        }
        if self.receipt.is_none() && !self.enrollment_authorized {
            return Err(PersistenceError::RebuildRequired("missing trust"));
        }
        Ok(())
    }
}
// A definitive conflict must describe a coherent competing state or an
// invalidation. An unchanged old receipt does not cancel a dispatched operation.
fn definitive_conflict(old: &ProviderSnapshot, proposed: &Receipt, s: &ProviderSnapshot) -> bool {
    if s.context != old.context
        || s.session != old.session
        || s.session_epoch < old.session_epoch
        || s.session_epoch == 0
        || s.key_id == [0; 32]
        || s.key_epoch < old.key_epoch
        || s.key_epoch == 0
        || (s.key_epoch == old.key_epoch && s.key_id != old.key_id)
        || s.capability != old.capability
        || s.unresolved.is_some()
        || s == old
        || s.receipt == Some(*proposed)
        || (s.status == SessionStatus::Invalidated
            && (s.session_epoch <= old.session_epoch || s.enrollment_authorized))
    {
        return false;
    }
    let Some(r) = s.receipt else {
        return match s.status {
            SessionStatus::Active => s.enrollment_authorized && s.session_epoch > old.session_epoch,
            SessionStatus::Invalidated => !s.enrollment_authorized && old.receipt.is_none(),
        };
    };
    if s.enrollment_authorized
        || r.context != s.context
        || r.session != s.session
        || r.session_epoch == 0
        || r.session_epoch > s.session_epoch
        || (s.status == SessionStatus::Active && r.session_epoch != s.session_epoch)
        || r.key_id != s.key_id
        || r.key_epoch != s.key_epoch
        || r.commit_id == [0; 32]
        || r.envelope_digest == [0; 32]
        || r.revision == 0
        || r.schema != 1
        || r.units != 1
        || r.tier != SyncTier::FileAndDirectory
        || if r.base_present {
            r.base_id == [0; 32]
                || r.base_id == r.commit_id
                || r.base_revision.checked_add(1) != Some(r.revision)
                || r.base_generation > r.generation
        } else {
            r.base_id != [0; 32]
                || r.base_revision != 0
                || r.base_generation != 0
                || r.revision != 1
        }
    {
        return false;
    }
    if let Some(previous) = old.receipt {
        if r.session_epoch < previous.session_epoch
            || (r.session_epoch == previous.session_epoch
                && (r.revision < previous.revision
                    || r.generation < previous.generation
                    || (r.revision == previous.revision && r != previous)))
        {
            return false;
        }
    }
    true
}
pub struct KeyLease(pub(crate) Zeroizing<[u8; 32]>);
impl KeyLease {
    pub fn protected(key: [u8; 32]) -> Self {
        Self(Zeroizing::new(key))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reservation {
    pub nonce: [u8; 12],
    pub commit_id: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReserveOutcome {
    Reserved,
    Duplicate,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CasOutcome {
    Committed(Receipt),
    Conflict(ProviderSnapshot),
    KnownNotAttempted,
    Unknown,
}
/// Implementations must linearize exact CAS/invalidation/reservations and retain
/// unknown operations until definitive resolution. A use lease fences invalidation
/// for its entire lifetime. A rollbackable backend cannot claim durable protection.
pub trait TrustedProvider {
    type UseLease<'a>
    where
        Self: 'a;
    fn read(&self, session: [u8; 32]) -> Result<ProviderSnapshot>;
    fn key(&self, expected: &ProviderSnapshot) -> Result<KeyLease>;
    fn reserve(&self, expected: &ProviderSnapshot, r: Reservation) -> Result<ReserveOutcome>;
    fn compare_and_set(
        &self,
        expected: &ProviderSnapshot,
        r: Reservation,
        proposed: Receipt,
    ) -> CasOutcome;
    fn resolve(&self, session: [u8; 32], operation: [u8; 32]) -> CasOutcome;
    fn use_lease<'a>(&'a self, expected: &ProviderSnapshot) -> Result<Self::UseLease<'a>>;
    fn invalidate(&self, session: [u8; 32], epoch: u64, reason: InvalidationReason) -> Result<()>;
}
#[derive(Clone, Copy, Debug)]
pub struct LoadPolicy {
    pub config: DynamicConfig,
    pub max_record_bytes: usize,
    pub max_private_peak: usize,
    pub max_global_peak: usize,
    pub old_live_bytes: usize,
    pub max_group_checks: usize,
    pub max_field_checks: usize,
    pub max_map_scan: usize,
    pub max_group_scalar_calls: usize,
    pub max_matrix_entries: usize,
}
impl LoadPolicy {
    pub fn small(config: DynamicConfig) -> Self {
        Self {
            config,
            max_record_bytes: 16 * 1024 * 1024,
            max_private_peak: 64 * 1024 * 1024,
            max_global_peak: 128 * 1024 * 1024,
            old_live_bytes: 0,
            max_group_checks: 8192,
            max_field_checks: 16384,
            max_map_scan: 16384,
            max_group_scalar_calls: 8192,
            max_matrix_entries: 65536,
        }
    }
    pub(crate) fn peak(&self, private: usize, public: usize) -> Result<()> {
        if private > self.max_private_peak
            || private > self.config.max_private_bytes
            || add(private, public)? > self.max_global_peak
            || add(private, public)? > self.config.max_global_bytes
        {
            return Err(PersistenceError::Bound("admission peak"));
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub struct AdmissionMetrics {
    pub received_bytes: usize,
    pub buffer_capacity: usize,
    pub decoded_allocations: usize,
    pub group_checks: usize,
    pub field_checks: usize,
    pub row_entries: usize,
    pub group_scalar_calls: usize,
    pub map_scan_entries: usize,
    pub private_peak: usize,
    pub canonical_bytes: usize,
}
pub(crate) fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b)
        .ok_or(PersistenceError::Bound("size overflow"))
}
pub(crate) fn mul(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b)
        .ok_or(PersistenceError::Bound("size overflow"))
}
pub(crate) fn reserve<T>(n: usize) -> Result<Vec<T>> {
    let mut v = Vec::new();
    v.try_reserve_exact(n)
        .map_err(|_| PersistenceError::Bound("allocation"))?;
    Ok(v)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupStatus {
    Retained,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveOutcome {
    Committed {
        receipt: Receipt,
        cleanup: CleanupStatus,
    },
    Conflict(ProviderSnapshot),
    KnownNotAttempted,
    Unknown {
        proposed: Receipt,
    },
}

pub struct CheckpointSession<'a, P: TrustedProvider> {
    provider: &'a P,
    store: ProtectedStore,
    context: ExpectedContext,
    expected: ProviderSnapshot,
    unknown: Option<Receipt>,
}
impl<'a, P: TrustedProvider> CheckpointSession<'a, P> {
    pub fn open(provider: &'a P, store: ProtectedStore, context: ExpectedContext) -> Result<Self> {
        let expected = provider.read(context.session)?;
        expected.check(&context)?;
        Ok(Self {
            provider,
            store,
            context,
            expected,
            unknown: None,
        })
    }
    pub fn receipt(&self) -> Option<Receipt> {
        self.expected.receipt
    }
    pub fn save<R: RngCore + CryptoRng + ?Sized>(
        &mut self,
        state: &mut DynamicState,
        policy: LoadPolicy,
        tier: SyncTier,
        rng: &mut R,
        metrics: &mut AdmissionMetrics,
    ) -> Result<SaveOutcome> {
        if tier != SyncTier::FileAndDirectory {
            return Err(PersistenceError::Unsupported("media sync"));
        }
        if self.unknown.is_some() {
            return Err(PersistenceError::Fenced);
        }
        let now = self.provider.read(self.context.session)?;
        now.check(&self.context)?;
        if now != self.expected {
            return Ok(SaveOutcome::Conflict(now));
        }
        self.context
            .check(codec::package(state), codec::tables(state))?;
        let mut payload = codec::encode(state, &self.context, &policy, metrics)?;
        let key = self.provider.key(&self.expected)?;
        let mut reservation = None;
        for _ in 0..16 {
            let mut nonce = [0; 12];
            let mut id = [0; 32];
            rng.try_fill_bytes(&mut nonce)
                .map_err(|source| PersistenceError::Entropy { draw: 0, source })?;
            rng.try_fill_bytes(&mut id)
                .map_err(|source| PersistenceError::Entropy { draw: 1, source })?;
            if id == [0; 32] {
                continue;
            }
            let r = Reservation {
                nonce,
                commit_id: id,
            };
            if self.provider.reserve(&self.expected, r)? == ReserveOutcome::Reserved {
                reservation = Some(r);
                break;
            }
        }
        let r = reservation.ok_or(PersistenceError::ReservationExhausted)?;
        let (header, mut proposed) =
            wire::header(state, &self.context, &self.expected, r, payload.len(), tier)?;
        let tag = wire::seal(&key, &header, &mut payload)?;
        let mut h = Sha256::new();
        h.update(header);
        h.update(&payload);
        h.update(tag);
        proposed.envelope_digest = h.finalize().into();
        self.store.publish(
            r.commit_id,
            &header,
            &payload,
            &tag,
            proposed.envelope_digest,
            policy.max_record_bytes,
        )?;
        storage::fault(storage::FaultPoint::BeforeCas)?;
        let outcome = self.provider.compare_and_set(&self.expected, r, proposed);
        Ok(match outcome {
            CasOutcome::Committed(got) if got == proposed => {
                self.expected.receipt = Some(proposed);
                self.expected.enrollment_authorized = false;
                SaveOutcome::Committed {
                    receipt: proposed,
                    cleanup: CleanupStatus::Retained,
                }
            }
            CasOutcome::Conflict(s) if definitive_conflict(&self.expected, &proposed, &s) => {
                SaveOutcome::Conflict(s)
            }
            CasOutcome::KnownNotAttempted => SaveOutcome::KnownNotAttempted,
            _ => {
                self.unknown = Some(proposed);
                SaveOutcome::Unknown { proposed }
            }
        })
    }
    pub fn resolve(&mut self) -> Result<SaveOutcome> {
        let p = self
            .unknown
            .ok_or(PersistenceError::Trust("no unknown operation"))?;
        match self.provider.resolve(self.context.session, p.commit_id) {
            CasOutcome::Committed(r) if r == p => {
                self.unknown = None;
                self.expected.receipt = Some(r);
                self.expected.enrollment_authorized = false;
                self.expected.unresolved = None;
                Ok(SaveOutcome::Committed {
                    receipt: r,
                    cleanup: CleanupStatus::Retained,
                })
            }
            CasOutcome::Conflict(s) if definitive_conflict(&self.expected, &p, &s) => {
                self.unknown = None;
                Ok(SaveOutcome::Conflict(s))
            }
            CasOutcome::KnownNotAttempted => {
                self.unknown = None;
                Ok(SaveOutcome::KnownNotAttempted)
            }
            _ => Ok(SaveOutcome::Unknown { proposed: p }),
        }
    }
    pub fn recover(
        &self,
        p: &PublicPackage,
        t: &ReconstructionMaterial,
        expected_public: &[Fr],
        policy: LoadPolicy,
        metrics: &mut AdmissionMetrics,
    ) -> Result<FencedState> {
        if self.unknown.is_some() {
            return Err(PersistenceError::Fenced);
        }
        let s = self.provider.read(self.context.session)?;
        s.check(&self.context)?;
        self.context.check(p, t)?;
        let receipt = s
            .receipt
            .ok_or(PersistenceError::RebuildRequired("no committed receipt"))?;
        if codec::expected_statement(p, receipt.generation, expected_public)?
            != receipt.statement_digest
        {
            return Err(PersistenceError::Trust("expected public digest"));
        }
        let key = self.provider.key(&s)?;
        let (header, mut payload, tag) =
            self.store
                .receive(receipt.commit_id, &self.context, &s, &policy, metrics)?;
        let mut h = Sha256::new();
        h.update(header);
        h.update(&payload);
        h.update(tag);
        if <[u8; 32]>::from(h.finalize()) != receipt.envelope_digest {
            return Err(PersistenceError::RebuildRequired("envelope digest"));
        }
        wire::open(&key, &header, &mut payload, &tag)?;
        let state = codec::decode(
            &payload,
            &header,
            p,
            t,
            &self.context,
            &policy,
            expected_public,
            metrics,
        )?;
        let after = self.provider.read(self.context.session)?;
        if after != s {
            codec::wipe(state);
            return Err(PersistenceError::Fenced);
        }
        Ok(FencedState { state, expected: s })
    }
}
/// Borrow engine state only while the provider holds a lease that linearizes use
/// against invalidation. The callback must not re-enter provider operations,
/// and the caller must keep the borrowed state within this lease (Rust permits
/// replacing a borrowed state). This is an explicit caller contract. Returned proofs still require external execution-current
/// root/issuer/action authorization; this lease does not execute an application.
pub struct FencedState {
    state: DynamicState,
    expected: ProviderSnapshot,
}
impl FencedState {
    pub fn with_state<P: TrustedProvider, T>(
        &mut self,
        p: &P,
        f: impl FnOnce(&mut DynamicState) -> T,
    ) -> Result<T> {
        let _lease = p.use_lease(&self.expected)?;
        Ok(f(&mut self.state))
    }
    pub fn checkpoint<P: TrustedProvider, R: RngCore + CryptoRng + ?Sized>(
        &mut self,
        session: &mut CheckpointSession<'_, P>,
        policy: LoadPolicy,
        tier: SyncTier,
        rng: &mut R,
        metrics: &mut AdmissionMetrics,
    ) -> Result<SaveOutcome> {
        if self.expected != session.expected {
            return Err(PersistenceError::Fenced);
        }
        let out = session.save(&mut self.state, policy, tier, rng, metrics)?;
        if matches!(out, SaveOutcome::Committed { .. }) {
            self.expected = session.expected;
        }
        Ok(out)
    }
    pub fn receipt(&self) -> Receipt {
        self.expected.receipt.expect("validated receipt")
    }
}
impl Drop for FencedState {
    fn drop(&mut self) {
        codec::wipe_borrowed(&mut self.state);
    }
}
