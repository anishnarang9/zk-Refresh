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

const PUBLISHER_SIGN_TAG: &[u8] = b"DYNARK-V3-PUBLISHER-BINDING-v1\0";
const PUBLISHER_WIRE_TAG: &[u8] = b"DYNARK-V3-PUBLISHER-WIRE-v1\0";

/// Explicit predecessor CLAIM, not authenticated persistence or latest state.
/// Current v3 Config/Issuer accounts contain root/version and bound source head,
/// but contain no publisher envelope sequence/digest. A protected/HMAC file can
/// still be rolled back. Restart requires separate fresh checkpoint provenance
/// or a reviewed onchain extension; neither exists in this slice.
#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublisherPredecessorClaim {
    sequence: u64,
    digest: [u8; 32],
}

#[allow(dead_code)]
#[derive(Serialize)]
struct PublisherSigningBody<'a> {
    scope: &'a Scope,
    issuer: &'a IssuerScope,
    source_head: &'a SourceHead,
    root: Field,
    root_version: u64,
    publisher_key: [u8; 32],
    publication_sequence: u64,
    previous_publication_digest: [u8; 32],
}

/// Private mathematical evidence only. It is deliberately not a capability:
/// no constructor, public export, serde/Debug/Clone or authorization API exists.
/// No concrete finalized RPC verifier or durable checkpoint validator can mint
/// current-state/predecessor capabilities yet; a public trait implementation or
/// caller JSON must not be substituted for those missing provenance checks.
#[allow(dead_code)]
struct CheckedPublisherClaim {
    binding: PublisherBinding,
    source_head: SourceHead,
    envelope_digest: [u8; 32],
}

#[allow(dead_code)]
fn publisher_signing_bytes(binding: &PublisherBinding) -> Result<Vec<u8>, Error> {
    canonical_json(
        PUBLISHER_SIGN_TAG,
        &PublisherSigningBody {
            scope: &binding.scope,
            issuer: &binding.issuer,
            source_head: &binding.source_head,
            root: binding.root,
            root_version: binding.root_version,
            publisher_key: binding.publisher_key,
            publication_sequence: binding.publication_sequence,
            previous_publication_digest: binding.previous_publication_digest,
        },
    )
}

/// Verify bounded signatures and coherence against EXPLICIT CLAIMS. This is
/// intentionally private and disconnected from every public authorization path.
/// In particular, `current` is not authenticated chain state and `previous` is
/// not a trusted persisted checkpoint. Even success establishes neither fact.
#[allow(dead_code)]
fn check_publisher_envelope_claim(
    binding: &PublisherBinding,
    source: &VerifiedSource,
    current: &CurrentHead,
    previous: &PublisherPredecessorClaim,
    now: i64,
) -> Result<CheckedPublisherClaim, Error> {
    if binding.signature.len() != 64 {
        return Err(Error::Authentication);
    }
    scope_valid(&current.scope, &current.issuer)?;
    if binding.root >= FR_MODULUS || current.root >= FR_MODULUS || current.publisher_key == [0; 32]
    {
        return Err(Error::Invalid);
    }
    let observation = source.observation();
    if binding.scope != observation.scope
        || binding.issuer != observation.issuer
        || binding.scope != current.scope
        || binding.issuer != current.issuer
        || binding.publisher_key != current.publisher_key
        || binding.publisher_key == binding.issuer.source_key
        || binding.root != current.root
        || binding.root_version != current.root_version
        || binding.source_head.sequence != source.head().sequence
        || binding.source_head.digest != source.head().digest
        || current.source_head.sequence != source.head().sequence
        || current.source_head.digest != source.head().digest
        || current.source_head.sequence == 0
        || current.source_head.digest == [0; 32]
        || current.observed_config_epoch != binding.scope.config_eligibility_epoch
        || current.observed_issuer_epoch != binding.issuer.issuer_eligibility_epoch
    {
        return Err(Error::Authentication);
    }
    if !observation.issuer_status_active
        || !current.config_enabled
        || !current.issuer_enabled
        || !current.status_valid
    {
        return Err(Error::Disabled);
    }
    // Recheck the retained source at use time, not merely when its immutable
    // VerifiedSource was created. This still does not authenticate `now`/clock.
    if now < 0
        || current.clock_unix < 0
        || current.clock_unix > now
        || current.valid_until < current.clock_unix
        || now > current.valid_until
        || current
            .valid_until
            .checked_sub(current.clock_unix)
            .ok_or(Error::Stale)?
            > 300
        || observation.observed_at > current.clock_unix
        || observation.observed_at > now
        || now >= observation.valid_until
    {
        return Err(Error::Stale);
    }
    if (previous.sequence == 0) != (previous.digest == [0; 32])
        || binding.publication_sequence == 0
        || binding.publication_sequence != previous.sequence.checked_add(1).ok_or(Error::Bound)?
        || binding.previous_publication_digest != previous.digest
    {
        return Err(Error::Replay);
    }
    let wire = canonical_json(PUBLISHER_WIRE_TAG, binding)?;
    let message = publisher_signing_bytes(binding)?;
    let key = PKey::public_key_from_raw_bytes(&current.publisher_key, Id::ED25519)
        .map_err(|_| Error::Authentication)?;
    let accepted = Verifier::new_without_digest(&key)
        .and_then(|mut verifier| verifier.verify_oneshot(&binding.signature, &message))
        .map_err(|_| Error::Authentication)?;
    if !accepted {
        return Err(Error::Authentication);
    }
    Ok(CheckedPublisherClaim {
        binding: binding.clone(),
        source_head: source.head().clone(),
        envelope_digest: Sha256::digest(&wire).into(),
    })
}

impl PublisherBinding {
    /// Permanently rejecting legacy JSON-only route. Neither a valid publisher
    /// signature nor a caller-constructed CurrentHead proves finalized current
    /// accounts or the latest persisted publisher predecessor. No public trait
    /// adapter can mint authority through this entrypoint.
    pub fn require_current(&self, _current: &CurrentHead, _now: i64) -> Result<(), Error> {
        Err(Error::Authentication)
    }
}

#[cfg(test)]
mod publisher_claim_tests {
    use super::*;
    use serde_json::Value;
    use std::{fs, path::Path};

    fn vectors() -> Value {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/v3-publisher-auth-v1.json");
        let raw = fs::read(path).unwrap();
        assert!(raw.len() <= 2 * 1024 * 1024);
        let digest: String = Sha256::digest(&raw)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            digest,
            "c2e4d6c73cdfe20ff2b7d8cd06a5e47b4a622ad9716de3671bd910632f461b48"
        );
        serde_json::from_slice(&raw).unwrap()
    }
    fn source(row: &Value) -> VerifiedSource {
        let signed: SignedSource = serde_json::from_value(row["signed_source"].clone()).unwrap();
        let enrolled: EnrolledSource =
            serde_json::from_value(row["enrolled_source"].clone()).unwrap();
        let previous: SourceHead =
            serde_json::from_value(row["previous_source_head"].clone()).unwrap();
        signed
            .verify(
                &enrolled,
                &previous,
                row["source_verified_at"].as_i64().unwrap(),
            )
            .unwrap()
    }
    fn claims(row: &Value) -> (PublisherBinding, CurrentHead, PublisherPredecessorClaim) {
        (
            serde_json::from_value(row["binding"].clone()).unwrap(),
            serde_json::from_value(row["current_head"].clone()).unwrap(),
            serde_json::from_value(row["previous_publication_head"].clone()).unwrap(),
        )
    }
    #[test]
    fn all28_independent_publisher_signatures_have_exact_typed_preimages() {
        let v = vectors();
        assert_eq!(v["cases"].as_array().unwrap().len(), 28);
        for row in v["cases"].as_array().unwrap() {
            let (binding, _, _) = claims(row);
            let message = publisher_signing_bytes(&binding).unwrap();
            let hex: String = message.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(hex, row["signing_bytes_hex"].as_str().unwrap());
            let key = PKey::public_key_from_raw_bytes(&binding.publisher_key, Id::ED25519).unwrap();
            assert!(Verifier::new_without_digest(&key)
                .unwrap()
                .verify_oneshot(&binding.signature, &message)
                .unwrap());
        }
    }
    #[test]
    fn independent_crypto_and_explicit_claim_coherence_match_all28_cases() {
        let v = vectors();
        let mut positives = 0;
        let mut negatives = 0;
        for row in v["cases"].as_array().unwrap() {
            let (binding, current, previous) = claims(row);
            let source = source(row);
            let result = check_publisher_envelope_claim(
                &binding,
                &source,
                &current,
                &previous,
                row["now"].as_i64().unwrap(),
            );
            if row["expect"] == "accept" {
                let checked = result.unwrap();
                assert_eq!(checked.binding.root, binding.root);
                assert_eq!(checked.source_head.digest, source.head().digest);
                assert_ne!(checked.envelope_digest, [0; 32]);
                positives += 1;
            } else {
                assert!(result.is_err(), "claim mismatch admitted: {}", row["name"]);
                negatives += 1;
            }
        }
        assert_eq!((positives, negatives), (2, 26));
    }
    #[test]
    fn corrupted_publisher_signature_rejects_internal_envelope_claim() {
        let v = vectors();
        let row = &v["cases"][0];
        let (mut binding, current, previous) = claims(row);
        let source = source(row);
        assert!(
            check_publisher_envelope_claim(&binding, &source, &current, &previous, 150).is_ok()
        );
        binding.signature[0] ^= 1;
        assert!(
            check_publisher_envelope_claim(&binding, &source, &current, &previous, 150).is_err()
        );
    }
    #[test]
    fn checked_envelope_claim_cannot_authorize_current_application_work() {
        let v = vectors();
        let row = &v["cases"][0];
        let (binding, current, previous) = claims(row);
        let source = source(row);
        let _checked =
            check_publisher_envelope_claim(&binding, &source, &current, &previous, 150).unwrap();
        assert_eq!(
            binding.require_current(&current, 150),
            Err(Error::Authentication)
        );
    }
    #[test]
    fn independent_frozen_body_and_signature_define_full_envelope_digest() {
        let v = vectors();
        let row = &v["cases"][0];
        let (binding, current, previous) = claims(row);
        let source = source(row);
        let checked =
            check_publisher_envelope_claim(&binding, &source, &current, &previous, 150).unwrap();
        let encoded = row["signing_bytes_hex"].as_str().unwrap();
        let message: Vec<u8> = (0..encoded.len() / 2)
            .map(|i| u8::from_str_radix(&encoded[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        // Reconstruct the signed wire independently from frozen generator bytes,
        // not from the production PublisherBinding serializer/helper.
        let body = message
            .strip_prefix(b"DYNARK-V3-PUBLISHER-BINDING-v1\0")
            .unwrap();
        assert_eq!(body.last(), Some(&b'}'));
        let mut expected = b"DYNARK-V3-PUBLISHER-WIRE-v1\0".to_vec();
        expected.extend_from_slice(&body[..body.len() - 1]);
        expected.extend_from_slice(b",\"signature\":[");
        let signature = binding
            .signature
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        expected.extend_from_slice(signature.as_bytes());
        expected.extend_from_slice(b"]}");
        let digest: [u8; 32] = Sha256::digest(&expected).into();
        assert_eq!(checked.envelope_digest, digest);
        assert_ne!(
            digest,
            <[u8; 32]>::from(Sha256::digest(body)),
            "digest includes domain and exact signature"
        );
    }
    #[test]
    fn authenticated_inactive_source_is_only_a_negative_fact() {
        let v = vectors();
        let row = v["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == "inactive_source")
            .unwrap();
        let (binding, current, previous) = claims(row);
        let source = source(row);
        assert!(!source.observation().issuer_status_active);
        assert_eq!(
            check_publisher_envelope_claim(&binding, &source, &current, &previous, 150).map(|_| ()),
            Err(Error::Disabled)
        );
    }
    #[test]
    fn coherent_json_cannot_collapse_publisher_and_issuer_source_roles() {
        let v = vectors();
        let row = v["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == "source_key_used_as_publisher")
            .unwrap();
        let (binding, mut current, previous) = claims(row);
        let source = source(row);
        // This fixture is genuinely signed by the issuer source key. Normalize
        // the raw current claim too, so key-mismatch cannot mask the role guard.
        current.publisher_key = binding.publisher_key;
        assert_eq!(binding.publisher_key, binding.issuer.source_key);
        assert_eq!(
            check_publisher_envelope_claim(&binding, &source, &current, &previous, 150).map(|_| ()),
            Err(Error::Authentication)
        );
    }
}
