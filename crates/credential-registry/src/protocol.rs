//! Domain-tagged canonical JSON wire for separately pinned development authorities.
use crate::{Error, Field, Identity, Tree};
use openssl::{
    pkey::{Id, PKey, Private},
    sign::{Signer, Verifier},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::VecDeque, path::Path};

pub const DEPTH: usize = 10;
pub const MAX_CHANGES: usize = 64;
pub const RETAINED_DELTAS: usize = 256;
pub const MAX_SNAPSHOT_BYTES: usize = 2 * 1024 * 1024;
const MAX_SOURCE_BYTES: usize = 128 * 1024;
const MAX_TOMBSTONES: usize = 4096;
// ark-bn254 0.5 Fr modulus, canonical big-endian. Comparison never reduces input.
const FR_MODULUS: Field = [
    48, 100, 78, 114, 225, 49, 160, 41, 184, 80, 69, 182, 129, 129, 88, 93, 40, 51, 232, 72, 121,
    185, 112, 145, 67, 225, 245, 147, 240, 0, 0, 1,
];
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub network: [u8; 32],
    pub registry: [u8; 32],
    pub policy_version: u32,
    pub source_version: u64,
    pub publisher_version: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub scope: Scope,
    pub source_key: [u8; 32],
    pub publisher_key: [u8; 32],
    pub freshness_seconds: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerStatus {
    pub issuer: [u8; 32],
    pub version: u64,
    pub issuer_hash: Field,
    pub enabled: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Change {
    Issue {
        identity: Identity,
        slot: u16,
        allocation_epoch: u64,
    },
    Revoke {
        identity: Identity,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub scope: Scope,
    pub sequence: u64,
    pub observed_at: i64,
    pub valid_until: i64,
    pub issuers: Vec<IssuerStatus>,
    pub changes: Vec<Change>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSource {
    pub observation: Observation,
    pub signature: Vec<u8>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub root: Field,
    pub root_version: u64,
    pub source_sequence: u64,
    pub envelope_digest: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delta {
    pub scope: Scope,
    pub previous: Head,
    pub head: Head,
    pub source: SignedSource,
    pub published_at: i64,
    pub expires_at: i64,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotRecord {
    pub identity: Identity,
    pub slot: u16,
    pub allocation_epoch: u64,
    pub active: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub scope: Scope,
    pub head: Head,
    pub source: SignedSource,
    pub records: Vec<SlotRecord>,
    pub tombstones: Vec<Identity>,
    pub published_at: i64,
    pub expires_at: i64,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum CatchUp {
    Deltas(Vec<Delta>),
    Snapshot(Snapshot),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedPath {
    pub head: Head,
    pub slot: u16,
    pub allocation_epoch: u64,
    pub siblings: Vec<Field>,
    pub issuer: IssuerStatus,
    pub source_observed_at: i64,
    pub publisher_accepted_at: i64,
    pub onchain_effective_at: Option<i64>,
}
fn bytes<T: Serialize>(tag: &[u8], value: &T) -> Result<Vec<u8>, Error> {
    let mut out = tag.to_vec();
    out.extend(serde_json::to_vec(value).map_err(|_| Error::Invalid)?);
    Ok(out)
}
fn digest(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}
fn sign(key: &PKey<Private>, value: &[u8]) -> Result<Vec<u8>, Error> {
    if key.id() != Id::ED25519 {
        return Err(Error::Authentication);
    }
    Signer::new_without_digest(key)
        .and_then(|mut s| s.sign_oneshot_to_vec(value))
        .map_err(|_| Error::Authentication)
}
fn verify(key: [u8; 32], value: &[u8], signature: &[u8]) -> Result<(), Error> {
    if signature.len() != 64 {
        return Err(Error::Authentication);
    }
    let key =
        PKey::public_key_from_raw_bytes(&key, Id::ED25519).map_err(|_| Error::Authentication)?;
    if !Verifier::new_without_digest(&key)
        .and_then(|mut v| v.verify_oneshot(signature, value))
        .map_err(|_| Error::Authentication)?
    {
        return Err(Error::Authentication);
    }
    Ok(())
}
fn key_matches(key: &PKey<Private>, expected: [u8; 32]) -> Result<(), Error> {
    if key.id() != Id::ED25519
        || key.raw_public_key().map_err(|_| Error::Authentication)? != expected
    {
        return Err(Error::Authentication);
    }
    Ok(())
}
impl Config {
    fn check(&self) -> Result<(), Error> {
        if self.source_key == self.publisher_key
            || self.source_key == [0; 32]
            || self.publisher_key == [0; 32]
            || self.freshness_seconds == 0
            || self.freshness_seconds > 300
            || self.scope.policy_version == 0
            || self.scope.source_version == 0
            || self.scope.publisher_version == 0
            || self.scope.network == [0; 32]
            || self.scope.registry == [0; 32]
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
fn fresh(source: &Observation, c: &Config, now: i64) -> Result<(), Error> {
    let timeout = i64::try_from(c.freshness_seconds).map_err(|_| Error::Invalid)?;
    if source.observed_at < 0
        || source.valid_until < source.observed_at
        || now < source.observed_at
        || now > source.valid_until
        || now.checked_sub(source.observed_at).ok_or(Error::Invalid)? > timeout
    {
        return Err(Error::Stale);
    }
    Ok(())
}
fn valid_identity(id: &Identity) -> bool {
    id.issuer != [0; 32] && id.issuer_version > 0 && id.tbs_digest != [0; 32]
}
impl Observation {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        bytes(b"DYNARK-SOURCE-STATUS-v1\0", self)
    }
    fn bounds(&self) -> Result<(), Error> {
        if self.sequence == 0
            || self.issuers.is_empty()
            || self.issuers.len() > 8
            || self.changes.len() > MAX_CHANGES
        {
            return Err(Error::Bound);
        }
        let mut seen = Vec::new();
        for issuer in &self.issuers {
            let key = (issuer.issuer, issuer.version);
            if issuer.issuer == [0; 32]
                || issuer.version == 0
                || issuer.issuer_hash == [0; 32]
                || issuer.issuer_hash >= FR_MODULUS
                || seen.contains(&key)
            {
                return Err(Error::Invalid);
            }
            seen.push(key);
        }
        if !self
            .issuers
            .windows(2)
            .all(|w| (w[0].issuer, w[0].version) < (w[1].issuer, w[1].version))
        {
            return Err(Error::Invalid);
        }
        let change_key = |change: &Change| match change {
            Change::Revoke { identity } => (0u8, identity.clone()),
            Change::Issue { identity, .. } => (1u8, identity.clone()),
        };
        if !self
            .changes
            .windows(2)
            .all(|w| change_key(&w[0]) < change_key(&w[1]))
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
impl SignedSource {
    pub fn sign(observation: Observation, key: &PKey<Private>) -> Result<Self, Error> {
        let signature = sign(key, &observation.signing_bytes()?)?;
        Ok(Self {
            observation,
            signature,
        })
    }
    pub fn verify(&self, config: &Config, now: i64) -> Result<(), Error> {
        config.check()?;
        if self.observation.scope != config.scope {
            return Err(Error::Authentication);
        }
        self.observation.bounds()?;
        fresh(&self.observation, config, now)?;
        if self.encode()?.len() > MAX_SOURCE_BYTES {
            return Err(Error::Bound);
        }
        verify(
            config.source_key,
            &self.observation.signing_bytes()?,
            &self.signature,
        )
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let out = bytes(b"DYNARK-SOURCE-WIRE-v1\0", self)?;
        if out.len() > MAX_SOURCE_BYTES {
            return Err(Error::Bound);
        }
        Ok(out)
    }
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        let tag = b"DYNARK-SOURCE-WIRE-v1\0";
        if input.len() > MAX_SOURCE_BYTES {
            return Err(Error::Bound);
        }
        let body = input.strip_prefix(tag).ok_or(Error::Invalid)?;
        let out: Self = serde_json::from_slice(body).map_err(|_| Error::Invalid)?;
        out.observation.bounds()?;
        if out.signature.len() != 64 || out.encode()? != input {
            return Err(Error::Invalid);
        }
        Ok(out)
    }
}
impl Delta {
    fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        // Exclude only the next envelope digest, avoiding a self-referential commitment.
        bytes(
            b"DYNARK-REGISTRY-DELTA-v1\0",
            &(
                &self.scope,
                &self.previous,
                self.head.root,
                self.head.root_version,
                self.head.source_sequence,
                digest(&self.source.encode()?),
                &self.source,
                self.published_at,
                self.expires_at,
            ),
        )
    }
    fn computed_digest(&self) -> Result<[u8; 32], Error> {
        Ok(digest(&bytes(
            b"DYNARK-REGISTRY-HEAD-v1\0",
            &(self.signing_bytes()?, &self.signature),
        )?))
    }
    fn verify(&self, c: &Config, now: i64) -> Result<(), Error> {
        if self.scope != c.scope || self.head.envelope_digest != self.computed_digest()? {
            return Err(Error::Authentication);
        }
        self.source.verify(c, now)?;
        publication(&self.source, self.published_at, self.expires_at, now)?;
        verify(c.publisher_key, &self.signing_bytes()?, &self.signature)
    }
}
fn publication(s: &SignedSource, published: i64, expires: i64, now: i64) -> Result<(), Error> {
    if published < s.observation.observed_at
        || published > now
        || expires != s.observation.valid_until
        || expires < now
    {
        return Err(Error::Stale);
    }
    Ok(())
}
impl Snapshot {
    fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        bytes(
            b"DYNARK-REGISTRY-SNAPSHOT-v1\0",
            &(
                &self.scope,
                self.head,
                &self.source,
                &self.records,
                &self.tombstones,
                self.published_at,
                self.expires_at,
            ),
        )
    }
    pub(crate) fn encode(&self) -> Result<Vec<u8>, Error> {
        let out = bytes(b"DYNARK-REGISTRY-STORE-v1\0", self)?;
        if out.len() > MAX_SNAPSHOT_BYTES {
            return Err(Error::Bound);
        }
        Ok(out)
    }
    pub(crate) fn decode(input: &[u8]) -> Result<Self, Error> {
        if input.len() > MAX_SNAPSHOT_BYTES {
            return Err(Error::Bound);
        }
        let body = input
            .strip_prefix(b"DYNARK-REGISTRY-STORE-v1\0")
            .ok_or(Error::Invalid)?;
        let out: Self = serde_json::from_slice(body).map_err(|_| Error::Invalid)?;
        if out.encode()? != input {
            return Err(Error::Invalid);
        }
        Ok(out)
    }
}
fn preserve_source_history(previous: &Observation, next: &Observation) -> Result<(), Error> {
    if next.observed_at < previous.observed_at {
        return Err(Error::Replay);
    }
    for old in &previous.issuers {
        let new = next
            .issuers
            .iter()
            .find(|x| x.issuer == old.issuer && x.version == old.version)
            .ok_or(Error::Invalid)?;
        if new.issuer_hash != old.issuer_hash || (!old.enabled && new.enabled) {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}

#[derive(Clone)]
struct State {
    tree: Tree,
    head: Head,
    records: Vec<SlotRecord>,
    tombstones: Vec<Identity>,
    source: Option<SignedSource>,
    published_at: i64,
}
impl State {
    fn new() -> Result<Self, Error> {
        let tree = Tree::new()?;
        let head = Head {
            root: tree.root(),
            root_version: 0,
            source_sequence: 0,
            envelope_digest: [0; 32],
        };
        Ok(Self {
            tree,
            head,
            records: vec![],
            tombstones: vec![],
            source: None,
            published_at: 0,
        })
    }
    fn changed(&self, s: &SignedSource) -> Result<Self, Error> {
        if s.observation.sequence
            != self
                .head
                .source_sequence
                .checked_add(1)
                .ok_or(Error::Bound)?
        {
            return Err(Error::Replay);
        }
        if let Some(previous) = &self.source {
            preserve_source_history(&previous.observation, &s.observation)?;
        }
        let mut out = self.clone();
        let mut seen = Vec::new();
        let mut slots = Vec::new();
        for change in &s.observation.changes {
            let id = match change {
                Change::Issue { identity, .. } | Change::Revoke { identity } => identity,
            };
            if !valid_identity(id) || seen.contains(id) {
                return Err(Error::Invalid);
            }
            seen.push(id.clone());
            match change {
                Change::Revoke { identity } => {
                    let record = out
                        .records
                        .iter_mut()
                        .find(|r| r.identity == *identity && r.active)
                        .ok_or(Error::Revoked)?;
                    if slots.contains(&record.slot) {
                        return Err(Error::Invalid);
                    }
                    slots.push(record.slot);
                    record.active = false;
                    out.tree
                        .set(record.slot as usize, record.identity.tbs_digest, false)?;
                    out.tombstones.push(identity.clone());
                }
                Change::Issue {
                    identity,
                    slot,
                    allocation_epoch,
                } => {
                    if *slot >= 1024
                        || *allocation_epoch == 0
                        || out.tombstones.contains(identity)
                        || out.records.iter().any(|r| r.identity == *identity)
                        || slots.contains(slot)
                    {
                        return Err(Error::Invalid);
                    }
                    let issuer = s
                        .observation
                        .issuers
                        .iter()
                        .find(|i| {
                            i.issuer == identity.issuer
                                && i.version == identity.issuer_version
                                && i.enabled
                        })
                        .ok_or(Error::Disabled)?;
                    let _ = issuer;
                    if let Some(old) = out.records.iter_mut().find(|r| r.slot == *slot) {
                        if old.active || *allocation_epoch <= old.allocation_epoch {
                            return Err(Error::Invalid);
                        }
                        *old = SlotRecord {
                            identity: identity.clone(),
                            slot: *slot,
                            allocation_epoch: *allocation_epoch,
                            active: true,
                        };
                    } else {
                        out.records.push(SlotRecord {
                            identity: identity.clone(),
                            slot: *slot,
                            allocation_epoch: *allocation_epoch,
                            active: true,
                        });
                    }
                    slots.push(*slot);
                    out.tree.set(*slot as usize, identity.tbs_digest, true)?;
                }
            }
        }
        if out.tombstones.len() > MAX_TOMBSTONES {
            return Err(Error::Bound);
        }
        out.records.sort_by_key(|r| r.slot);
        out.tombstones.sort();
        out.head.root = out.tree.root();
        if out.head.root != self.head.root {
            out.head.root_version = self.head.root_version.checked_add(1).ok_or(Error::Bound)?;
        }
        out.head.source_sequence = s.observation.sequence;
        out.source = Some(s.clone());
        Ok(out)
    }
}
pub struct Registry {
    config: Config,
    state: State,
    history: VecDeque<Delta>,
}
impl Registry {
    pub fn new(config: Config) -> Result<Self, Error> {
        config.check()?;
        Ok(Self {
            config,
            state: State::new()?,
            history: VecDeque::new(),
        })
    }
    pub fn head(&self) -> Head {
        self.state.head
    }
    pub fn publish(
        &mut self,
        source: SignedSource,
        key: &PKey<Private>,
        now: i64,
    ) -> Result<Delta, Error> {
        key_matches(key, self.config.publisher_key)?;
        source.verify(&self.config, now)?;
        if now < self.state.published_at {
            return Err(Error::Replay);
        }
        let mut candidate = self.state.changed(&source)?;
        let mut delta = Delta {
            scope: self.config.scope.clone(),
            previous: self.head(),
            head: candidate.head,
            expires_at: source.observation.valid_until,
            source,
            published_at: now,
            signature: vec![],
        };
        delta.signature = sign(key, &delta.signing_bytes()?)?;
        delta.head.envelope_digest = delta.computed_digest()?;
        candidate.head = delta.head;
        candidate.published_at = now;
        self.state = candidate;
        self.history.push_back(delta.clone());
        if self.history.len() > RETAINED_DELTAS {
            self.history.pop_front();
        }
        Ok(delta)
    }
    pub fn snapshot(&self, key: &PKey<Private>, now: i64) -> Result<Snapshot, Error> {
        key_matches(key, self.config.publisher_key)?;
        let source = self.state.source.clone().ok_or(Error::Stale)?;
        source.verify(&self.config, now)?;
        if now < self.state.published_at {
            return Err(Error::Replay);
        }
        let mut snapshot = Snapshot {
            scope: self.config.scope.clone(),
            head: self.head(),
            expires_at: source.observation.valid_until,
            source,
            records: self.state.records.clone(),
            tombstones: self.state.tombstones.clone(),
            published_at: self.state.published_at,
            signature: vec![],
        };
        snapshot.signature = sign(key, &snapshot.signing_bytes()?)?;
        snapshot.encode()?;
        Ok(snapshot)
    }
    pub fn catch_up(&self, from: Head, key: &PKey<Private>, now: i64) -> Result<CatchUp, Error> {
        key_matches(key, self.config.publisher_key)?;
        self.state
            .source
            .as_ref()
            .ok_or(Error::Stale)?
            .verify(&self.config, now)?;
        if from == self.head() {
            return Ok(CatchUp::Deltas(vec![]));
        }
        if let Some(index) = self.history.iter().position(|d| d.previous == from) {
            return Ok(CatchUp::Deltas(
                self.history.iter().skip(index).cloned().collect(),
            ));
        }
        Ok(CatchUp::Snapshot(self.snapshot(key, now)?))
    }
    pub fn save(&self, path: &Path, key: &PKey<Private>, now: i64) -> Result<(), Error> {
        crate::storage::save(path, &self.snapshot(key, now)?.encode()?)
    }
    pub fn reopen(
        path: &Path,
        config: Config,
        authoritative: Head,
        now: i64,
    ) -> Result<Self, Error> {
        let snapshot = Snapshot::decode(&crate::storage::load(path)?)?;
        let mut registry = Self::new(config.clone())?;
        let mut client = Client {
            config,
            state: State::new()?,
        };
        client.recover(&snapshot, authoritative, now)?;
        registry.state = client.state;
        Ok(registry)
    }
}
pub struct Client {
    config: Config,
    state: State,
}
impl Client {
    /// Initial head must be trusted genesis; use recover for non-genesis state.
    pub fn new(config: Config, trusted_initial: Head) -> Result<Self, Error> {
        config.check()?;
        let state = State::new()?;
        if state.head != trusted_initial {
            return Err(Error::Authentication);
        }
        Ok(Self { config, state })
    }
    pub fn head(&self) -> Head {
        self.state.head
    }
    pub fn apply(&mut self, delta: &Delta, now: i64) -> Result<(), Error> {
        delta.verify(&self.config, now)?;
        if delta.head.source_sequence <= self.head().source_sequence {
            return Err(Error::Replay);
        }
        if delta.previous != self.head() {
            return Err(Error::GapRequiresSnapshot);
        }
        if delta.published_at < self.state.published_at {
            return Err(Error::Replay);
        }
        let mut candidate = self.state.changed(&delta.source)?;
        if candidate.head.root != delta.head.root
            || candidate.head.root_version != delta.head.root_version
            || candidate.head.source_sequence != delta.head.source_sequence
        {
            return Err(Error::Authentication);
        }
        candidate.head = delta.head;
        candidate.published_at = delta.published_at;
        self.state = candidate;
        Ok(())
    }
    pub fn recover(
        &mut self,
        snapshot: &Snapshot,
        authoritative: Head,
        now: i64,
    ) -> Result<(), Error> {
        if snapshot.scope != self.config.scope || snapshot.head != authoritative {
            return Err(Error::Authentication);
        }
        if snapshot.head.source_sequence < self.head().source_sequence
            || snapshot.head.root_version < self.head().root_version
            || (snapshot.head.source_sequence == self.head().source_sequence
                && snapshot.head != self.head())
            || snapshot.published_at < self.state.published_at
        {
            return Err(Error::Replay);
        }
        if snapshot.records.len() > 1024 || snapshot.tombstones.len() > MAX_TOMBSTONES {
            return Err(Error::Bound);
        }
        snapshot.encode()?;
        snapshot.source.verify(&self.config, now)?;
        publication(
            &snapshot.source,
            snapshot.published_at,
            snapshot.expires_at,
            now,
        )?;
        verify(
            self.config.publisher_key,
            &snapshot.signing_bytes()?,
            &snapshot.signature,
        )?;
        if snapshot.source.observation.sequence != snapshot.head.source_sequence
            || snapshot.head.envelope_digest == [0; 32]
        {
            return Err(Error::Authentication);
        }
        if !snapshot.records.windows(2).all(|w| w[0].slot < w[1].slot)
            || !snapshot.tombstones.windows(2).all(|w| w[0] < w[1])
        {
            return Err(Error::Invalid);
        }
        // Snapshot catch-up must preserve facts already authenticated by this client.
        // A new process still needs an independently fresh authoritative checkpoint.
        if let Some(previous) = &self.state.source {
            preserve_source_history(&previous.observation, &snapshot.source.observation)?;
        }
        for old in &self.state.tombstones {
            if !snapshot.tombstones.contains(old) {
                return Err(Error::Replay);
            }
        }
        for old in &self.state.records {
            let new = snapshot
                .records
                .iter()
                .find(|r| r.slot == old.slot)
                .ok_or(Error::Replay)?;
            if new.allocation_epoch < old.allocation_epoch
                || (new.identity != old.identity && new.allocation_epoch <= old.allocation_epoch)
                || (new.identity == old.identity && new.allocation_epoch != old.allocation_epoch)
                || (new.identity != old.identity && !snapshot.tombstones.contains(&old.identity))
            {
                return Err(Error::Replay);
            }
        }
        let mut candidate = State::new()?;
        let mut identities = Vec::new();
        for id in &snapshot.tombstones {
            if !valid_identity(id) {
                return Err(Error::Invalid);
            }
        }
        for r in &snapshot.records {
            if !valid_identity(&r.identity)
                || r.slot >= 1024
                || r.allocation_epoch == 0
                || identities.contains(&r.identity)
                || (r.active && snapshot.tombstones.contains(&r.identity))
                || (!r.active && !snapshot.tombstones.contains(&r.identity))
                || !snapshot.source.observation.issuers.iter().any(|i| {
                    i.issuer == r.identity.issuer && i.version == r.identity.issuer_version
                })
            {
                return Err(Error::Invalid);
            }
            identities.push(r.identity.clone());
            candidate
                .tree
                .set(r.slot as usize, r.identity.tbs_digest, r.active)?;
        }
        if candidate.tree.root() != snapshot.head.root {
            return Err(Error::Authentication);
        }
        candidate.head = snapshot.head;
        candidate.records = snapshot.records.clone();
        candidate.tombstones = snapshot.tombstones.clone();
        candidate.source = Some(snapshot.source.clone());
        candidate.published_at = snapshot.published_at;
        self.state = candidate;
        Ok(())
    }
    pub fn authorize(&self, identity: &Identity, now: i64) -> Result<AuthenticatedPath, Error> {
        let source = self.state.source.as_ref().ok_or(Error::Stale)?;
        fresh(&source.observation, &self.config, now)?;
        if self.state.tombstones.contains(identity) {
            return Err(Error::Revoked);
        }
        let issuer = source
            .observation
            .issuers
            .iter()
            .find(|i| i.issuer == identity.issuer && i.version == identity.issuer_version)
            .ok_or(Error::Disabled)?;
        if !issuer.enabled {
            return Err(Error::Disabled);
        }
        let record = self
            .state
            .records
            .iter()
            .find(|r| r.identity == *identity && r.active)
            .ok_or(Error::Revoked)?;
        Ok(AuthenticatedPath {
            head: self.head(),
            slot: record.slot,
            allocation_epoch: record.allocation_epoch,
            siblings: self.state.tree.path(record.slot as usize)?,
            issuer: issuer.clone(),
            source_observed_at: source.observation.observed_at,
            publisher_accepted_at: self.state.published_at,
            onchain_effective_at: None,
        })
    }
}
