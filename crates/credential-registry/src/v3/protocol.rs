//! First authenticated-protocol RED scaffold. Records are untrusted claims;
//! no source, publisher or current-head gate succeeds in this slice. Constructing
//! EnrolledSource/CurrentHead does not authenticate chain/enrollment/clock data.
use super::{Error, Field};
use serde::{Deserialize, Serialize};

pub const SOURCE_SIGN_TAG: &[u8] = b"DYNARK-V3-SOURCE-STATUS-v1\0";
pub const SOURCE_WIRE_TAG: &[u8] = b"DYNARK-V3-SOURCE-WIRE-v1\0";

/// Exact signed realm. Field words are canonical BE32 at the registry boundary.
/// Both leaf domain and depth must match the fixed v3 tree, not caller choices.
#[derive(Clone, Serialize, Deserialize)]
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
#[derive(Clone, Serialize, Deserialize)]
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

/// Opaque future authenticated result; no constructor/serde/Debug is exposed.
pub struct VerifiedSource {
    _authenticated: (),
}

impl SignedSource {
    /// Deliberate RED gate. GREEN must check bounded canonical encoding, exact
    /// scope/enrollment/epochs, enrolled Ed25519 signature, per-issuer sequence
    /// and predecessor, enablement, status and freshness before any state change.
    pub fn verify(
        &self,
        _enrolled: &EnrolledSource,
        _previous: &SourceHead,
        _now: i64,
    ) -> Result<VerifiedSource, Error> {
        Err(Error::Authentication)
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
