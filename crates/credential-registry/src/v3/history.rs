//! Historical signature/tree replay only. Caller-supplied enrollment, publisher
//! keys and times establish no chain, deployment, current-clock or pin authority.

use super::{
    protocol::{
        self, Change, CurrentHead, EnrolledSource, PublisherBinding, SignedSource, SourceHead,
    },
    Error, Field, Tree, CAPACITY, DEPTH,
};
use std::collections::BTreeMap;

/// Finite replay envelope, independent of source/publication/root counters.
pub const MAX_HISTORY_CHECKPOINTS: usize = 64;

#[derive(Clone)]
struct Allocation {
    tbs_digest: [u8; 32],
    allocation_epoch: u64,
    active: bool,
}

/// Historical evidence relative to explicitly supplied enrollment/key/time
/// claims. No serde, Debug, Clone, current-state token or authority conversion.
/// Slots and TBS digests are allocated once, including after revocation. Epochs
/// are nonzero per-slot identifiers; different slots may share an epoch.
pub struct HistoricalReplay {
    enrolled: EnrolledSource,
    publisher_key: [u8; 32],
    tree: Tree,
    allocations: Vec<Option<Allocation>>,
    by_digest: BTreeMap<[u8; 32], usize>,
    source: SourceHead,
    publication_sequence: u64,
    publication_digest: [u8; 32],
    root_version: Option<u64>,
    observed_at: Option<i64>,
    checked_at: Option<i64>,
    checkpoints: usize,
}

/// Owned historical membership evidence for one replayed root. Later replay
/// updates can supersede it; this value grants no current-chain eligibility.
pub struct HistoricalMembership {
    tbs_digest: [u8; 32],
    slot: u16,
    allocation_epoch: u64,
    root: Field,
    root_version: u64,
    siblings: [Field; DEPTH],
}
impl HistoricalMembership {
    pub fn tbs_digest(&self) -> [u8; 32] {
        self.tbs_digest
    }
    pub fn slot(&self) -> u16 {
        self.slot
    }
    pub fn allocation_epoch(&self) -> u64 {
        self.allocation_epoch
    }
    pub fn root(&self) -> Field {
        self.root
    }
    pub fn root_version(&self) -> u64 {
        self.root_version
    }
    pub fn siblings(&self) -> &[Field; DEPTH] {
        &self.siblings
    }
}
impl HistoricalReplay {
    /// Caller inputs are trust CLAIMS, never enrollment, clock or chain proof.
    /// The first accepted checkpoint starts both signed chains at one/zero
    /// predecessor and publishes root version zero after replaying its Issues.
    pub fn new(enrolled: EnrolledSource, publisher_key: [u8; 32]) -> Result<Self, Error> {
        if publisher_key == [0; 32] || publisher_key == enrolled.issuer.source_key {
            return Err(Error::Authentication);
        }
        Ok(Self {
            enrolled,
            publisher_key,
            tree: Tree::new()?,
            allocations: vec![None; CAPACITY],
            by_digest: BTreeMap::new(),
            source: SourceHead {
                sequence: 0,
                digest: [0; 32],
            },
            publication_sequence: 0,
            publication_digest: [0; 32],
            root_version: None,
            observed_at: None,
            checked_at: None,
            checkpoints: 0,
        })
    }

    /// Atomically apply a complete signed observation/publication checkpoint.
    /// checked_at is an explicit HISTORICAL time claim, not an authenticated
    /// clock. Source observation and check times cannot
    /// decrease and must lie within the signed source freshness interval.
    /// Active-source publications only; own-certificate revocation is supported.
    pub fn apply(
        &mut self,
        source: &SignedSource,
        publisher: &PublisherBinding,
        checked_at: i64,
    ) -> Result<(), Error> {
        if self.checkpoints >= MAX_HISTORY_CHECKPOINTS {
            return Err(Error::Bound);
        }
        if self.checked_at.is_some_and(|prior| checked_at < prior)
            || self
                .observed_at
                .is_some_and(|prior| source.observation.observed_at < prior)
        {
            return Err(Error::Stale);
        }
        let verified = source.verify(&self.enrolled, &self.source, checked_at)?;
        let observation = verified.observation();
        let mut tree = self.tree.clone();
        let mut allocations = self.allocations.clone();
        let mut by_digest = self.by_digest.clone();
        for change in &observation.changes {
            match change {
                Change::Issue {
                    tbs_digest,
                    slot,
                    allocation_epoch,
                } => {
                    let slot = usize::from(*slot);
                    if slot >= CAPACITY
                        || *allocation_epoch == 0
                        || allocations[slot].is_some()
                        || by_digest.contains_key(tbs_digest)
                    {
                        return Err(Error::Invalid);
                    }
                    tree.set(slot, *tbs_digest, true)?;
                    allocations[slot] = Some(Allocation {
                        tbs_digest: *tbs_digest,
                        allocation_epoch: *allocation_epoch,
                        active: true,
                    });
                    by_digest.insert(*tbs_digest, slot);
                }
                Change::Revoke { tbs_digest } => {
                    let slot = *by_digest.get(tbs_digest).ok_or(Error::Invalid)?;
                    let allocation = allocations[slot].as_mut().ok_or(Error::Invalid)?;
                    if allocation.tbs_digest != *tbs_digest || !allocation.active {
                        return Err(Error::Revoked);
                    }
                    tree.set(slot, *tbs_digest, false)?;
                    allocation.active = false;
                }
            }
        }
        let root = tree.root();
        let root_version = match self.root_version {
            None => 0,
            Some(version) if root == self.tree.root() => version,
            Some(version) => version.checked_add(1).ok_or(Error::Bound)?,
        };
        let current = CurrentHead {
            scope: self.enrolled.scope.clone(),
            issuer: self.enrolled.issuer.clone(),
            source_head: verified.head().clone(),
            root,
            root_version,
            publisher_key: self.publisher_key,
            config_enabled: self.enrolled.config_enabled,
            issuer_enabled: self.enrolled.issuer_enabled,
            status_valid: observation.issuer_status_active,
            observed_config_epoch: self.enrolled.scope.config_eligibility_epoch,
            observed_issuer_epoch: self.enrolled.issuer.issuer_eligibility_epoch,
            clock_unix: checked_at,
            valid_until: observation.valid_until,
        };
        let publication_digest = protocol::check_history_publisher_claim(
            publisher,
            &verified,
            &current,
            self.publication_sequence,
            self.publication_digest,
            checked_at,
        )?;
        // All fallible math, signatures, counter and chronological checks finish
        // before any replay state is committed.
        self.tree = tree;
        self.allocations = allocations;
        self.by_digest = by_digest;
        self.source = verified.head().clone();
        self.publication_sequence = publisher.publication_sequence;
        self.publication_digest = publication_digest;
        self.root_version = Some(root_version);
        self.observed_at = Some(observation.observed_at);
        self.checked_at = Some(checked_at);
        self.checkpoints += 1;
        Ok(())
    }

    pub fn root(&self) -> Field {
        self.tree.root()
    }
    pub fn root_version(&self) -> Option<u64> {
        self.root_version
    }
    pub fn source_head(&self) -> &SourceHead {
        &self.source
    }
    pub fn publication_sequence(&self) -> u64 {
        self.publication_sequence
    }
    pub fn publication_digest(&self) -> [u8; 32] {
        self.publication_digest
    }
    pub fn checkpoints(&self) -> usize {
        self.checkpoints
    }

    /// Match exact imported TBS/slot/epoch and verify active v3 membership at
    /// this historical head. No source/publisher freshness at a later time, or
    /// equality with any current chain root, follows from this operation.
    pub fn active_holder(
        &self,
        tbs_digest: [u8; 32],
        slot: u16,
        allocation_epoch: u64,
    ) -> Result<HistoricalMembership, Error> {
        let root_version = self.root_version.ok_or(Error::RebuildRequired)?;
        let index = usize::from(slot);
        let allocation = self
            .allocations
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(Error::Invalid)?;
        if allocation.tbs_digest != tbs_digest || allocation.allocation_epoch != allocation_epoch {
            return Err(Error::Authentication);
        }
        if !allocation.active {
            return Err(Error::Revoked);
        }
        let siblings: [Field; DEPTH] = self
            .tree
            .path(index)?
            .try_into()
            .map_err(|_| Error::Invalid)?;
        Tree::verify(tbs_digest, index, true, &siblings, self.tree.root())?;
        Ok(HistoricalMembership {
            tbs_digest,
            slot,
            allocation_epoch,
            root: self.tree.root(),
            root_version,
            siblings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v3::protocol::{IssuerScope, Observation, Scope, SOURCE_SIGN_TAG, SOURCE_WIRE_TAG};
    use openssl::{
        pkey::{PKey, Private},
        sign::Signer,
    };
    use serde::Serialize;
    use sha2::{Digest, Sha256};

    struct Fixture {
        source: PKey<Private>,
        publisher: PKey<Private>,
        enrolled: EnrolledSource,
    }
    impl Fixture {
        fn new() -> Self {
            let source = PKey::generate_ed25519().unwrap();
            let publisher = PKey::generate_ed25519().unwrap();
            let enrolled = EnrolledSource {
                scope: Scope {
                    network: [1; 32],
                    program: [2; 32],
                    config: [3; 32],
                    registry: [4; 32],
                    profile: [5; 32],
                    circuit: [6; 32],
                    schema: [7; 32],
                    package: [8; 32],
                    ordinary_vk: [9; 32],
                    policy_hash: [10; 32],
                    policy_version: 1,
                    config_eligibility_epoch: 0,
                    leaf_domain: super::super::LEAF_DOMAIN,
                    depth: DEPTH as u8,
                },
                issuer: IssuerScope {
                    issuer_account: [11; 32],
                    issuer_hash: [12; 32],
                    source_key: source.raw_public_key().unwrap().try_into().unwrap(),
                    issuer_eligibility_epoch: 0,
                    enrollment_evidence_version: 1,
                    evidence_digest: [13; 32],
                },
                config_enabled: true,
                issuer_enabled: true,
                max_age_seconds: 180,
            };
            Self {
                source,
                publisher,
                enrolled,
            }
        }
        fn replay(&self) -> HistoricalReplay {
            HistoricalReplay::new(
                self.enrolled.clone(),
                self.publisher.raw_public_key().unwrap().try_into().unwrap(),
            )
            .unwrap()
        }
        fn checkpoint(
            &self,
            sequence: u64,
            previous_source: [u8; 32],
            previous_publication: [u8; 32],
            root_version: u64,
            root: Field,
            changes: Vec<Change>,
        ) -> (SignedSource, PublisherBinding) {
            let observed = 100 + sequence as i64;
            let observation = Observation {
                scope: self.enrolled.scope.clone(),
                issuer: self.enrolled.issuer.clone(),
                sequence,
                previous_digest: previous_source,
                observed_at: observed,
                valid_until: observed + 180,
                issuer_status_active: true,
                changes,
            };
            let mut message = SOURCE_SIGN_TAG.to_vec();
            message.extend(serde_json::to_vec(&observation).unwrap());
            let source = SignedSource {
                observation,
                signature: sign(&self.source, &message),
            };
            let mut wire = SOURCE_WIRE_TAG.to_vec();
            wire.extend(serde_json::to_vec(&source).unwrap());
            let mut publisher = PublisherBinding {
                scope: self.enrolled.scope.clone(),
                issuer: self.enrolled.issuer.clone(),
                source_head: SourceHead {
                    sequence,
                    digest: Sha256::digest(wire).into(),
                },
                root,
                root_version,
                publisher_key: self.publisher.raw_public_key().unwrap().try_into().unwrap(),
                publication_sequence: sequence,
                previous_publication_digest: previous_publication,
                signature: Vec::new(),
            };
            publisher.signature = publisher_signature(&publisher, &self.publisher);
            (source, publisher)
        }
    }
    fn sign(key: &PKey<Private>, bytes: &[u8]) -> Vec<u8> {
        Signer::new_without_digest(key)
            .unwrap()
            .sign_oneshot_to_vec(bytes)
            .unwrap()
    }
    // Independent typed publisher signing body, matching the documented wire.
    fn publisher_signature(binding: &PublisherBinding, key: &PKey<Private>) -> Vec<u8> {
        #[derive(Serialize)]
        struct Body<'a> {
            scope: &'a Scope,
            issuer: &'a IssuerScope,
            source_head: &'a SourceHead,
            root: Field,
            root_version: u64,
            publisher_key: [u8; 32],
            publication_sequence: u64,
            previous_publication_digest: [u8; 32],
        }
        let mut message = b"DYNARK-V3-PUBLISHER-BINDING-v1\0".to_vec();
        message.extend(
            serde_json::to_vec(&Body {
                scope: &binding.scope,
                issuer: &binding.issuer,
                source_head: &binding.source_head,
                root: binding.root,
                root_version: binding.root_version,
                publisher_key: binding.publisher_key,
                publication_sequence: binding.publication_sequence,
                previous_publication_digest: binding.previous_publication_digest,
            })
            .unwrap(),
        );
        sign(key, &message)
    }
    fn digest(index: usize) -> [u8; 32] {
        [index as u8 + 20; 32]
    }
    fn issue(index: usize) -> Change {
        Change::Issue {
            tbs_digest: digest(index),
            slot: if index == 0 { 0 } else { 15 + index as u16 },
            allocation_epoch: 1,
        }
    }
    fn initial_tree() -> Tree {
        let mut tree = Tree::new().unwrap();
        for index in 0..11 {
            tree.set(if index == 0 { 0 } else { 15 + index }, digest(index), true)
                .unwrap();
        }
        tree
    }
    fn state(replay: &HistoricalReplay) -> (Field, Option<u64>, u64, [u8; 32], u64, [u8; 32]) {
        (
            replay.root(),
            replay.root_version(),
            replay.source_head().sequence,
            replay.source_head().digest,
            replay.publication_sequence(),
            replay.publication_digest(),
        )
    }

    #[test]
    fn eleven_issues_then_ten_unrelated_revokes_keep_exact_active_holder_path() {
        let f = Fixture::new();
        let mut replay = f.replay();
        let mut tree = initial_tree();
        let (source, publisher) = f.checkpoint(
            1,
            [0; 32],
            [0; 32],
            0,
            tree.root(),
            (0..11).map(issue).collect(),
        );
        replay.apply(&source, &publisher, 101).unwrap();
        for index in 0..=10 {
            if index > 0 {
                tree.set(15 + index, digest(index), false).unwrap();
                let (source, publisher) = f.checkpoint(
                    index as u64 + 1,
                    replay.source_head().digest,
                    replay.publication_digest(),
                    index as u64,
                    tree.root(),
                    vec![Change::Revoke {
                        tbs_digest: digest(index),
                    }],
                );
                replay
                    .apply(&source, &publisher, 101 + index as i64)
                    .unwrap();
                assert!(replay
                    .active_holder(digest(index), (15 + index) as u16, 1)
                    .is_err());
            }
            let member = replay.active_holder(digest(0), 0, 1).unwrap();
            assert_eq!(member.root(), tree.root());
            assert_eq!(member.root_version(), index as u64);
            assert_eq!(
                member.siblings().as_slice(),
                tree.path(0).unwrap().as_slice()
            );
            Tree::verify(digest(0), 0, true, member.siblings(), member.root()).unwrap();
        }
        assert_eq!(replay.checkpoints(), 11);
        assert!(replay.active_holder(digest(0), 1, 1).is_err());
        assert!(replay.active_holder(digest(0), 0, 2).is_err());
        tree.set(0, digest(0), false).unwrap();
        let (source, publisher) = f.checkpoint(
            12,
            replay.source_head().digest,
            replay.publication_digest(),
            11,
            tree.root(),
            vec![Change::Revoke {
                tbs_digest: digest(0),
            }],
        );
        replay.apply(&source, &publisher, 112).unwrap();
        assert!(matches!(
            replay.active_holder(digest(0), 0, 1),
            Err(Error::Revoked)
        ));
    }

    #[test]
    fn duplicate_allocations_and_invalid_revokes_leave_replay_atomic() {
        let f = Fixture::new();
        let tree = initial_tree();
        for change in [
            issue(0),
            Change::Issue {
                tbs_digest: [99; 32],
                slot: 0,
                allocation_epoch: 2,
            },
            Change::Issue {
                tbs_digest: digest(0),
                slot: 500,
                allocation_epoch: 1,
            },
            Change::Issue {
                tbs_digest: [99; 32],
                slot: 500,
                allocation_epoch: 0,
            },
            Change::Revoke {
                tbs_digest: [99; 32],
            },
        ] {
            let mut replay = f.replay();
            let (source, publisher) = f.checkpoint(
                1,
                [0; 32],
                [0; 32],
                0,
                tree.root(),
                (0..11).map(issue).collect(),
            );
            replay.apply(&source, &publisher, 101).unwrap();
            let before = state(&replay);
            let (source, publisher) = f.checkpoint(
                2,
                replay.source_head().digest,
                replay.publication_digest(),
                0,
                tree.root(),
                vec![
                    Change::Revoke {
                        tbs_digest: digest(1),
                    },
                    change,
                ],
            );
            assert!(replay.apply(&source, &publisher, 102).is_err());
            assert_eq!(state(&replay), before);
            replay.active_holder(digest(1), 16, 1).unwrap();
        }
    }

    #[test]
    fn publisher_failure_rolls_back_revocation_and_repeated_revoke_is_rejected() {
        let f = Fixture::new();
        let mut replay = f.replay();
        let mut tree = initial_tree();
        let (source, publisher) = f.checkpoint(
            1,
            [0; 32],
            [0; 32],
            0,
            tree.root(),
            (0..11).map(issue).collect(),
        );
        replay.apply(&source, &publisher, 101).unwrap();
        let before = state(&replay);
        tree.set(16, digest(1), false).unwrap();
        let (source, mut publisher) = f.checkpoint(
            2,
            replay.source_head().digest,
            replay.publication_digest(),
            1,
            tree.root(),
            vec![Change::Revoke {
                tbs_digest: digest(1),
            }],
        );
        publisher.signature[0] ^= 1;
        assert!(replay.apply(&source, &publisher, 102).is_err());
        assert_eq!(state(&replay), before);
        replay.active_holder(digest(1), 16, 1).unwrap();
        publisher.signature[0] ^= 1;
        replay.apply(&source, &publisher, 102).unwrap();
        let before = state(&replay);
        let (source, publisher) = f.checkpoint(
            3,
            replay.source_head().digest,
            replay.publication_digest(),
            1,
            tree.root(),
            vec![Change::Revoke {
                tbs_digest: digest(1),
            }],
        );
        assert!(matches!(
            replay.apply(&source, &publisher, 103),
            Err(Error::Revoked)
        ));
        assert_eq!(state(&replay), before);
        let (source, publisher) = f.checkpoint(
            3,
            replay.source_head().digest,
            replay.publication_digest(),
            1,
            tree.root(),
            vec![Change::Issue {
                tbs_digest: [99; 32],
                slot: 16,
                allocation_epoch: 2,
            }],
        );
        assert!(replay.apply(&source, &publisher, 103).is_err());
        assert_eq!(state(&replay), before);
    }

    #[test]
    fn distinct_signed_checkpoints_can_share_one_observation_second() {
        let f = Fixture::new();
        let mut replay = f.replay();
        let tree = initial_tree();
        let (source, publisher) = f.checkpoint(
            1,
            [0; 32],
            [0; 32],
            0,
            tree.root(),
            (0..11).map(issue).collect(),
        );
        replay.apply(&source, &publisher, 101).unwrap();
        let first_digest = replay.source_head().digest;
        let (mut source, mut publisher) = f.checkpoint(
            2,
            first_digest,
            replay.publication_digest(),
            0,
            tree.root(),
            Vec::new(),
        );
        source.observation.observed_at = 101;
        source.observation.valid_until = 281;
        let mut message = SOURCE_SIGN_TAG.to_vec();
        message.extend(serde_json::to_vec(&source.observation).unwrap());
        source.signature = sign(&f.source, &message);
        let mut wire = SOURCE_WIRE_TAG.to_vec();
        wire.extend(serde_json::to_vec(&source).unwrap());
        publisher.source_head.digest = Sha256::digest(wire).into();
        publisher.signature = publisher_signature(&publisher, &f.publisher);
        replay.apply(&source, &publisher, 101).unwrap();
        assert_eq!(replay.source_head().sequence, 2);
        assert_ne!(replay.source_head().digest, first_digest);
        assert_eq!(replay.publication_sequence(), 2);
        assert_eq!(replay.root_version(), Some(0));
        replay.active_holder(digest(0), 0, 1).unwrap();
    }

    #[test]
    fn status_only_checkpoints_keep_root_version_and_enforce_history_bound_and_expiry() {
        let f = Fixture::new();
        let mut replay = f.replay();
        assert!(matches!(
            replay.active_holder(digest(0), 0, 1),
            Err(Error::RebuildRequired)
        ));
        let tree = initial_tree();
        for index in 1..=MAX_HISTORY_CHECKPOINTS {
            let (source, publisher) = f.checkpoint(
                index as u64,
                replay.source_head().digest,
                replay.publication_digest(),
                0,
                tree.root(),
                if index == 1 {
                    (0..11).map(issue).collect()
                } else {
                    Vec::new()
                },
            );
            if index == 1 {
                assert!(replay
                    .apply(&source, &publisher, source.observation.valid_until)
                    .is_err());
                assert_eq!(replay.checkpoints(), 0);
                assert!(replay
                    .apply(&source, &publisher, source.observation.observed_at - 1)
                    .is_err());
                assert_eq!(replay.checkpoints(), 0);
            }
            replay
                .apply(&source, &publisher, 100 + index as i64)
                .unwrap();
            assert_eq!(replay.root_version(), Some(0));
        }
        let before = state(&replay);
        let (source, publisher) = f.checkpoint(
            MAX_HISTORY_CHECKPOINTS as u64 + 1,
            replay.source_head().digest,
            replay.publication_digest(),
            0,
            tree.root(),
            Vec::new(),
        );
        assert!(matches!(
            replay.apply(
                &source,
                &publisher,
                100 + MAX_HISTORY_CHECKPOINTS as i64 + 1
            ),
            Err(Error::Bound)
        ));
        assert_eq!(state(&replay), before);
    }

    #[test]
    fn replay_gap_wrong_signer_root_and_time_are_rejected_atomically() {
        let f = Fixture::new();
        for field in 0..9 {
            let mut replay = f.replay();
            let tree = initial_tree();
            let (source, publisher) = f.checkpoint(
                1,
                [0; 32],
                [0; 32],
                0,
                tree.root(),
                (0..11).map(issue).collect(),
            );
            replay.apply(&source, &publisher, 101).unwrap();
            let before = state(&replay);
            assert!(replay.apply(&source, &publisher, 101).is_err());
            let (mut source, mut publisher) = f.checkpoint(
                2,
                replay.source_head().digest,
                replay.publication_digest(),
                0,
                tree.root(),
                Vec::new(),
            );
            let mut at = 102;
            match field {
                0 => source.observation.sequence = 3,
                1 => source.observation.previous_digest[0] ^= 1,
                2 => publisher.publication_sequence = 3,
                3 => publisher.previous_publication_digest[0] ^= 1,
                4 => source.signature = sign(&PKey::generate_ed25519().unwrap(), b"wrong source"),
                5 => {
                    publisher.signature =
                        publisher_signature(&publisher, &PKey::generate_ed25519().unwrap())
                }
                6 => {
                    publisher.root[31] ^= 1;
                    publisher.signature = publisher_signature(&publisher, &f.publisher);
                }
                7 => {
                    publisher.root_version = 1;
                    publisher.signature = publisher_signature(&publisher, &f.publisher);
                }
                _ => at = 100,
            }
            assert!(
                replay.apply(&source, &publisher, at).is_err(),
                "invalid checkpoint {field}"
            );
            assert_eq!(state(&replay), before);
        }
    }
}
