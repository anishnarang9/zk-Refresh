//! Enrolled v3 source authentication. Publisher/current-head gates still reject.
//! Constructing EnrolledSource/CurrentHead authenticates no chain/enrollment or
//! clock data; those inputs must come from an independently authenticated adapter.
use super::{Error, Field, CAPACITY, DEPTH, LEAF_DOMAIN};
use openssl::{
    pkey::{Id, PKey},
    sign::Verifier,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::{self, Write},
};

pub const SOURCE_SIGN_TAG: &[u8] = b"DYNARK-V3-SOURCE-STATUS-v1\0";
pub const SOURCE_WIRE_TAG: &[u8] = b"DYNARK-V3-SOURCE-WIRE-v1\0";
const MAX_SOURCE_CHANGES: usize = 64;
const MAX_SOURCE_BYTES: usize = 128 * 1024;
const MAX_SOURCE_AGE_SECONDS: u64 = 300;
const FR_MODULUS: Field = [
    48, 100, 78, 114, 225, 49, 160, 41, 184, 80, 69, 182, 129, 129, 88, 93, 40, 51, 232, 72, 121,
    185, 112, 145, 67, 225, 245, 147, 240, 0, 0, 1,
];

/// Count canonical JSON before allocating encoded output. The second bounded
/// writer keeps the same ceiling even if the representation changes later.
struct JsonCount(usize);
impl Write for JsonCount {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|size| *size <= MAX_SOURCE_BYTES)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "v3 source size bound"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct JsonBytes(Vec<u8>);
impl Write for JsonBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .len()
            .checked_add(bytes.len())
            .filter(|size| *size <= MAX_SOURCE_BYTES)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "v3 source size bound"))?;
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn canonical_json<T: Serialize>(tag: &[u8], value: &T) -> Result<Vec<u8>, Error> {
    let mut count = JsonCount(0);
    count.write_all(tag).map_err(|_| Error::Bound)?;
    serde_json::to_writer(&mut count, value).map_err(|_| Error::Bound)?;
    let mut bytes = JsonBytes(Vec::with_capacity(count.0));
    bytes.write_all(tag).map_err(|_| Error::Bound)?;
    serde_json::to_writer(&mut bytes, value).map_err(|_| Error::Bound)?;
    if bytes.0.len() != count.0 {
        return Err(Error::Invalid);
    }
    Ok(bytes.0)
}

/// Exact signed realm. Field words are canonical BE32 at the registry boundary.
/// Both leaf domain and depth must match the fixed v3 tree, not caller choices.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub network: [u8; 32],
    pub program: [u8; 32],
    pub config: [u8; 32],
    pub registry: [u8; 32],
    pub profile: [u8; 32],
    pub circuit: [u8; 32],
    pub schema: [u8; 32],
    pub package: [u8; 32],
    pub ordinary_vk: [u8; 32],
    pub policy_hash: Field,
    pub policy_version: u32,
    pub config_eligibility_epoch: u64,
    pub leaf_domain: u64,
    pub depth: u8,
}

/// Source key belongs to this exact enrolled modulus+AKI issuerHash. Evidence
/// version is separate from the issuer lifecycle/eligibility epoch. Epoch zero
/// can be a genuine initialized lifecycle; it is not an unobserved-source flag.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerScope {
    pub issuer_account: [u8; 32],
    pub issuer_hash: Field,
    pub source_key: [u8; 32],
    pub issuer_eligibility_epoch: u64,
    pub enrollment_evidence_version: u64,
    pub evidence_digest: [u8; 32],
}

/// Input from an independently authenticated administrator/chain adapter.
/// A source signature cannot enroll its own key or change these permissions.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolledSource {
    pub scope: Scope,
    pub issuer: IssuerScope,
    pub config_enabled: bool,
    pub issuer_enabled: bool,
    pub max_age_seconds: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceHead {
    pub sequence: u64,
    pub digest: [u8; 32],
}

/// Changes apply only to the issuer in the containing signed observation.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Change {
    Issue {
        tbs_digest: [u8; 32],
        slot: u16,
        allocation_epoch: u64,
    },
    Revoke {
        tbs_digest: [u8; 32],
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub scope: Scope,
    pub issuer: IssuerScope,
    pub sequence: u64,
    pub previous_digest: [u8; 32],
    pub observed_at: i64,
    pub valid_until: i64,
    pub issuer_status_active: bool,
    pub changes: Vec<Change>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSource {
    pub observation: Observation,
    pub signature: Vec<u8>,
}

/// Opaque authenticated result bound to the exact immutable checked observation
/// and canonical source-head digest. No constructor/serde/Debug/Clone is exposed.
/// Authenticated inactive status is a negative fact, never authorization.
pub struct VerifiedSource {
    observation: Observation,
    head: SourceHead,
}
impl VerifiedSource {
    pub fn observation(&self) -> &Observation {
        &self.observation
    }
    pub fn head(&self) -> &SourceHead {
        &self.head
    }
}

fn scope_valid(scope: &Scope, issuer: &IssuerScope) -> Result<(), Error> {
    // All Fr words in a source observation are checked without reduction.
    if scope.policy_hash >= FR_MODULUS
        || issuer.issuer_hash >= FR_MODULUS
        || scope.leaf_domain != LEAF_DOMAIN
        || usize::from(scope.depth) != DEPTH
        || scope.policy_version == 0
        || issuer.enrollment_evidence_version == 0
        || issuer.evidence_digest == [0; 32]
        || issuer.source_key == [0; 32]
        || issuer.issuer_account == [0; 32]
        || [
            &scope.network,
            &scope.program,
            &scope.config,
            &scope.registry,
            &scope.profile,
            &scope.circuit,
            &scope.schema,
            &scope.package,
            &scope.ordinary_vk,
        ]
        .iter()
        .any(|id| **id == [0; 32])
    {
        return Err(Error::Invalid);
    }
    // Lifecycle epochs may be zero at initialization; they must match exactly.
    Ok(())
}

fn source_bounds(source: &SignedSource) -> Result<(), Error> {
    if source.signature.len() != 64 {
        return Err(Error::Authentication);
    }
    let changes = &source.observation.changes;
    if changes.len() > MAX_SOURCE_CHANGES || changes.len() > CAPACITY {
        return Err(Error::Bound);
    }
    let mut identities = BTreeSet::new();
    let mut issue_slots = BTreeSet::new();
    for change in changes {
        let digest = match change {
            Change::Issue {
                tbs_digest,
                slot,
                allocation_epoch,
            } => {
                if usize::from(*slot) >= CAPACITY
                    || *allocation_epoch == 0
                    || !issue_slots.insert(*slot)
                {
                    return Err(Error::Invalid);
                }
                if !source.observation.issuer_status_active {
                    return Err(Error::Disabled);
                }
                tbs_digest
            }
            Change::Revoke { tbs_digest } => tbs_digest,
        };
        if *digest == [0; 32] || !identities.insert(*digest) {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}

impl SignedSource {
    /// Authenticate a typed observation against the independently trusted current
    /// enrollment and that issuer's previous checkpoint. No state is mutated.
    /// Signatures cover the one bounded canonical encoding, not presentation JSON.
    /// Raw untrusted wire decoding/current-head/application checks are separate.
    pub fn verify(
        &self,
        enrolled: &EnrolledSource,
        previous: &SourceHead,
        now: i64,
    ) -> Result<VerifiedSource, Error> {
        // Structural bounds precede all JSON materialization and crypto work.
        source_bounds(self)?;
        scope_valid(&enrolled.scope, &enrolled.issuer)?;
        let observation = &self.observation;
        // Compare the whole scope before verifying a re-signed foreign claim.
        // This includes both eligibility epochs, evidence version/digest, issuer
        // hash, enrolled source key and every realm/policy/package identity.
        if observation.scope != enrolled.scope || observation.issuer != enrolled.issuer {
            return Err(Error::Authentication);
        }
        if !enrolled.config_enabled || !enrolled.issuer_enabled {
            return Err(Error::Disabled);
        }
        if enrolled.max_age_seconds == 0 || enrolled.max_age_seconds > MAX_SOURCE_AGE_SECONDS {
            return Err(Error::Invalid);
        }
        let expected = previous.sequence.checked_add(1).ok_or(Error::Bound)?;
        if observation.sequence == 0
            || observation.sequence != expected
            || observation.previous_digest != previous.digest
            || (previous.sequence == 0) != (previous.digest == [0; 32])
        {
            return Err(Error::Replay);
        }
        let age = i64::try_from(enrolled.max_age_seconds).map_err(|_| Error::Bound)?;
        if now < 0
            || observation.observed_at < 0
            || now < observation.observed_at
            || observation.valid_until < observation.observed_at
            || now > observation.valid_until
            || observation
                .valid_until
                .checked_sub(observation.observed_at)
                .ok_or(Error::Stale)?
                > age
            || now
                .checked_sub(observation.observed_at)
                .ok_or(Error::Stale)?
                > age
        {
            return Err(Error::Stale);
        }
        let wire = canonical_json(SOURCE_WIRE_TAG, self)?;
        let message = canonical_json(SOURCE_SIGN_TAG, observation)?;
        let key = PKey::public_key_from_raw_bytes(&enrolled.issuer.source_key, Id::ED25519)
            .map_err(|_| Error::Authentication)?;
        let accepted = Verifier::new_without_digest(&key)
            .and_then(|mut verifier| verifier.verify_oneshot(&self.signature, &message))
            .map_err(|_| Error::Authentication)?;
        if !accepted {
            return Err(Error::Authentication);
        }
        let head = SourceHead {
            sequence: observation.sequence,
            digest: Sha256::digest(&wire).into(),
        };
        Ok(VerifiedSource {
            observation: observation.clone(),
            head,
        })
    }
}

/// Unverified publisher assertion, with source and both lifecycle epochs bound
/// by its scope/issuer. Root version is distinct from source/publication counters.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublisherBinding {
    pub scope: Scope,
    pub issuer: IssuerScope,
    pub source_head: SourceHead,
    pub root: Field,
    pub root_version: u64,
    pub publisher_key: [u8; 32],
    pub publication_sequence: u64,
    pub previous_publication_digest: [u8; 32],
    pub signature: Vec<u8>,
}

/// Independently authenticated execution-current account/clock input supplied
/// by the M2 adapter. The registry cannot establish chain finality by decoding it.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentHead {
    pub scope: Scope,
    pub issuer: IssuerScope,
    pub source_head: SourceHead,
    pub root: Field,
    pub root_version: u64,
    pub publisher_key: [u8; 32],
    pub config_enabled: bool,
    pub issuer_enabled: bool,
    pub status_valid: bool,
    pub observed_config_epoch: u64,
    pub observed_issuer_epoch: u64,
    pub clock_unix: i64,
    pub valid_until: i64,
}

impl PublisherBinding {
    /// Deliberate fail-closed boundary, not publisher/current-head qualification.
    /// Root version zero alone is valid; source sequence zero is unobserved.
    pub fn require_current(&self, _current: &CurrentHead, _now: i64) -> Result<(), Error> {
        Err(Error::Authentication)
    }
}
