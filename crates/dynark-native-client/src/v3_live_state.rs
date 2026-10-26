//! Concrete local finalized-state and signed-history binding. Deployment pins
//! must come from separately trusted application configuration. Constructing this
//! source admits nothing; each use fetches fresh current accounts and signatures.
use crate::{
    v3_action_hash, ClientError, Digest, FieldBytes, ImportedV3Credential, OperationControl,
    V3ActionConfig, V3ActionMeta, V3ActionRequest, V3AuthenticatedClock, V3Enrollment,
    V3FinalizedAction, V3InputWorkerRequest, V3LocalAccount, V3LocalAccountSet,
    V3RootPublication, V3SharedSetup, V3SourceObservation, V3StateSnapshot,
    V3UntrustedLocalPath,
};
use credential_registry::v3::{
    history::{HistoricalMembership, HistoricalReplay, MAX_HISTORY_CHECKPOINTS},
    protocol::{EnrolledSource, IssuerScope, PublisherBinding, Scope, SignedSource},
};
use dynark_v3_current_state::{ConfiguredVerifier, CurrentSelection};
use sha2::{Digest as _, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Untrusted signed history and historical check-time claims. Native replay
/// derives enrollment from the finalized batch, then anchors the final heads.
pub struct V3SignedHistoryCheckpoint<'a> {
    pub source: &'a SignedSource,
    pub publisher: &'a PublisherBinding,
    pub checked_at: i64,
}

/// Fixed concrete verifier and immutable candidate history. No caller-supplied
/// state trait, snapshot, current-head JSON or standalone membership is accepted.
/// The verifier's deployment-pin provenance remains application configuration.
pub struct V3RequestStateSource<'a> {
    verifier: &'a ConfiguredVerifier,
    selection: &'a CurrentSelection,
    history: &'a [V3SignedHistoryCheckpoint<'a>],
    slot: u16,
    allocation_epoch: u64,
    generation: u64,
}
impl<'a> V3RequestStateSource<'a> {
    pub fn new(
        verifier: &'a ConfiguredVerifier,
        selection: &'a CurrentSelection,
        history: &'a [V3SignedHistoryCheckpoint<'a>],
        slot: u16,
        allocation_epoch: u64,
        generation: u64,
    ) -> Result<Self, ClientError> {
        if history.is_empty() || history.len() > MAX_HISTORY_CHECKPOINTS || slot >= 1024 {
            return Err(ClientError::Bound);
        }
        if allocation_epoch == 0 || generation == 0 { return Err(ClientError::Generation); }
        Ok(Self { verifier, selection, history, slot, allocation_epoch, generation })
    }

    pub(crate) fn authenticate(
        &self,
        credential: &ImportedV3Credential,
        setup: &V3SharedSetup,
        expected_action_be: Digest,
        holder_signature: &[u8; 256],
        control: &OperationControl,
    ) -> Result<AuthenticatedFrame, ClientError> {
        control.check()?;
        let now = wall_clock()?;
        let local_unix = i64::try_from(now).map_err(|_| ClientError::Deadline)?;
        let observed = self.verifier.verify_current(self.selection, local_unix)
            .map_err(|_| ClientError::State);
        control.check()?;
        let observed = observed?;
        let last = self.history.last().ok_or(ClientError::RebuildRequired)?;
        let joined = observed.authenticate_detached_envelopes(last.source, last.publisher)
            .map_err(|_| ClientError::Identity)?;
        let current = joined.current();
        reject_future_history(self.history, current.validated_at())?;
        let config = current.config();
        let issuer = current.issuer();
        let head = current.publisher_head();
        let request = current.request();
        // The concrete verifier authenticates request and queue. Extra relevant
        // accounts need their own same-batch ownership/privilege qualification.
        if request.metas.len() != 2 { return Err(ClientError::Unsupported); }
        let enrolled = EnrolledSource {
            scope: Scope {
                network: config.genesis,
                program: current.deployment().program().to_bytes(),
                config: current.deployment().config().to_bytes(),
                registry: current.queue_account().to_bytes(),
                profile: config.profile_id, circuit: config.circuit_id,
                schema: config.schema_id, package: config.package_id,
                ordinary_vk: config.ordinary_vk_digest, policy_hash: config.policy_id,
                policy_version: config.policy_version,
                config_eligibility_epoch: config.eligibility_epoch,
                leaf_domain: credential_registry::v3::LEAF_DOMAIN,
                depth: credential_registry::v3::DEPTH as u8,
            },
            issuer: IssuerScope {
                issuer_account: current.issuer_account().to_bytes(),
                issuer_hash: issuer.issuer_hash,
                source_key: issuer.source.to_bytes(),
                issuer_eligibility_epoch: issuer.eligibility_epoch,
                enrollment_evidence_version: issuer.enrollment_version,
                evidence_digest: issuer.evidence_digest,
            },
            config_enabled: config.enabled, issuer_enabled: issuer.enabled, max_age_seconds: 300,
        };
        let expected = ReplayHead {
            root: config.root, root_version: config.root_version,
            source_sequence: issuer.sequence, source_digest: issuer.digest,
            publication_sequence: head.publication_sequence, publication_digest: head.envelope_digest,
        };
        let membership = replay_current_membership(enrolled, config.publisher.to_bytes(), self.history,
            &expected, credential.summary().tbs_digest, self.slot, self.allocation_epoch, control)?;
        let siblings: [FieldBytes; 10] = std::array::from_fn(|n| little_endian(membership.siblings()[n]));
        let metas: Vec<_> = request.metas.iter().map(|meta| V3ActionMeta {
            key: meta.key.to_bytes(), flags: meta.flags, owner: meta.owner.to_bytes(),
        }).collect();
        let action_config = V3ActionConfig {
            genesis: config.genesis, program: current.deployment().program().to_bytes(),
            config: current.deployment().config().to_bytes(), policy_id_be: config.policy_id,
            policy_version: config.policy_version, circuit_id: config.circuit_id,
            request_key: current.request_account().to_bytes(), queue_key: current.queue_account().to_bytes(),
            issuer_account: current.issuer_account().to_bytes(),
        };
        let action_request = V3ActionRequest {
            config: request.config.to_bytes(), creator: request.creator.to_bytes(), nonce: request.nonce,
            issuer_hash_be: request.issuer_hash, recipient: request.recipient.to_bytes(),
            request_type: request.request_type, deadline: request.deadline,
            payload: request.payload.clone(), metas: metas.clone(),
        };
        if v3_action_hash(&action_config, &action_request)? != expected_action_be
            || config.ordinary_vk_digest != setup.adapter_identity().tagged_digest
        { return Err(ClientError::Identity); }
        let c = config.encode();
        let i = issuer.encode();
        let h = head.encode();
        let r = request.encode();
        let q = current.queue().encode();
        let program = action_config.program;
        let accounts = V3LocalAccountSet {
            program, genesis: config.genesis,
            config: V3LocalAccount { key: action_config.config, owner: program, executable: false, data: &c },
            issuer: V3LocalAccount { key: action_config.issuer_account, owner: program, executable: false, data: &i },
            request: V3LocalAccount { key: action_config.request_key, owner: program, executable: false, data: &r },
            queue: V3LocalAccount { key: action_config.queue_key, owner: program, executable: false, data: &q },
            publisher_head: V3LocalAccount { key: current.publisher_head_account().to_bytes(), owner: program, executable: false, data: &h },
            actual_metas: &metas,
        };
        // Owner/PDA/finality provenance above comes from the opaque concrete
        // batch; the local checker independently rechecks codecs and action.
        let checked = accounts.check(credential.summary(), setup.manifest(), expected_action_be, now, control)?;
        let input = V3InputWorkerRequest::from_imported_local(credential, setup, &accounts,
            expected_action_be, holder_signature, &V3UntrustedLocalPath { slot: membership.slot(), siblings: &siblings }, now, control)?;
        let mut context = Sha256::new();
        context.update(b"dynark-v3/full-live-context/v1");
        context.update(program);
        for account in [&accounts.config, &accounts.issuer, &accounts.request, &accounts.queue, &accounts.publisher_head] {
            context.update(account.key);
            context.update((account.data.len() as u64).to_le_bytes());
            context.update(account.data);
        }
        let expires = u64::try_from(issuer.expires_at).map_err(|_| ClientError::Deadline)?;
        let deadline = u64::try_from(request.deadline).map_err(|_| ClientError::Expired)?;
        let snapshot = V3StateSnapshot {
            source: V3SourceObservation { issuer_account: action_config.issuer_account, sequence: issuer.sequence,
                digest: issuer.digest, observed_at: u64::try_from(issuer.observed_at).map_err(|_| ClientError::Deadline)?, valid_until: expires },
            publication: V3RootPublication { publisher_account: config.publisher.to_bytes(), issuer_account: action_config.issuer_account,
                source_sequence: head.source_sequence, source_digest: head.source_digest, root: little_endian(config.root),
                root_version: config.root_version, allocation_epoch: membership.allocation_epoch() },
            enrollment: V3Enrollment { issuer_account: action_config.issuer_account, config_account: action_config.config,
                issuer_hash: little_endian(issuer.issuer_hash), policy_hash: little_endian(config.policy_id),
                profile: config.profile_id, circuit: config.circuit_id, issuer_version: issuer.enrollment_version,
                policy_version: u64::from(config.policy_version), issuer_enabled: issuer.enabled, policy_enabled: config.enabled },
            clock: V3AuthenticatedClock { finalized_slot: current.finalized_slot(),
                unix_timestamp: u64::try_from(current.clock().unix_timestamp).map_err(|_| ClientError::Deadline)?,
                valid_until: expires.min(deadline).min(credential.summary().not_after) },
            action: V3FinalizedAction { request_account: action_config.request_key, queue_account: action_config.queue_key,
                config_account: action_config.config, action_be: expected_action_be, nonce: request.nonce, deadline, consumed: false },
            adapter_key: setup.adapter_identity(), slot: membership.slot(), siblings, generation: self.generation,
        };
        let finish_now = wall_clock()?;
        final_timestamp_guard(now, finish_now, expires, deadline, credential.summary().not_after)?;
        snapshot.validate_record_coherence(credential.summary(), setup.manifest(), finish_now)?;
        control.check()?;
        Ok(AuthenticatedFrame { snapshot, request: input, context: context.finalize().into(), publics: *checked.public_values(), checked_at: finish_now })
    }
}

pub(crate) struct AuthenticatedFrame {
    pub(crate) snapshot: V3StateSnapshot,
    pub(crate) request: V3InputWorkerRequest,
    pub(crate) context: Digest,
    pub(crate) publics: [FieldBytes; 6],
    pub(crate) checked_at: u64,
}
#[derive(Clone)]
struct ReplayHead {
    root: Digest, root_version: u64, source_sequence: u64, source_digest: Digest,
    publication_sequence: u64, publication_digest: Digest,
}
// Pure helper: expected records are authoritative only when derived by the
// concrete caller above. A standalone HistoricalMembership is insufficient.
fn replay_current_membership(
    enrolled: EnrolledSource, publisher: Digest, history: &[V3SignedHistoryCheckpoint<'_>],
    expected: &ReplayHead, tbs_digest: Digest, slot: u16, allocation_epoch: u64,
    control: &OperationControl,
) -> Result<HistoricalMembership, ClientError> {
    control.check()?;
    if history.is_empty() || history.len() > MAX_HISTORY_CHECKPOINTS { return Err(ClientError::Bound); }
    let mut replay = HistoricalReplay::new(enrolled, publisher).map_err(registry_error)?;
    for checkpoint in history {
        control.check()?;
        replay.apply(checkpoint.source, checkpoint.publisher, checkpoint.checked_at).map_err(registry_error)?;
        control.check()?;
    }
    if replay.root() != expected.root || replay.root_version() != Some(expected.root_version)
        || replay.source_head().sequence != expected.source_sequence
        || replay.source_head().digest != expected.source_digest
        || replay.publication_sequence() != expected.publication_sequence
        || replay.publication_digest() != expected.publication_digest
    { return Err(ClientError::Superseded); }
    let membership = replay.active_holder(tbs_digest, slot, allocation_epoch).map_err(registry_error)?;
    control.check()?;
    Ok(membership)
}
fn registry_error(error: credential_registry::Error) -> ClientError {
    match error {
        credential_registry::Error::Revoked => ClientError::Revoked,
        credential_registry::Error::Stale => ClientError::StaleIssuer,
        credential_registry::Error::Bound => ClientError::Bound,
        credential_registry::Error::RebuildRequired => ClientError::RebuildRequired,
        _ => ClientError::Identity,
    }
}
fn little_endian(mut word: Digest) -> FieldBytes { word.reverse(); word }
fn reject_future_history(history: &[V3SignedHistoryCheckpoint<'_>], verified_at: i64) -> Result<(), ClientError> {
    if history.iter().any(|checkpoint| checkpoint.checked_at > verified_at) {
        return Err(ClientError::Deadline);
    }
    Ok(())
}
fn final_timestamp_guard(start: u64, finish: u64, source_expires: u64,
    request_deadline: u64, credential_not_after: u64) -> Result<(), ClientError> {
    if finish < start { return Err(ClientError::Deadline); }
    if finish >= source_expires { return Err(ClientError::StaleIssuer); }
    if finish >= request_deadline || finish >= credential_not_after {
        return Err(ClientError::Expired);
    }
    Ok(())
}
pub(crate) fn wall_clock() -> Result<u64, ClientError> {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).map_err(|_| ClientError::Deadline)
}
#[cfg(test)]
#[path = "../tests/support/v3_live_state.rs"]
mod tests;
