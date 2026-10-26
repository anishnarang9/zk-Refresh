//! Detached-envelope verification against one immutable finalized account batch.
//! The batch remains relative to separately trusted deployment pins. This join
//! authenticates neither allocation/history nor membership, proof or execution.
use super::{AuthenticatedV3Current, Error};
use credential_registry::v3::protocol::{
    CurrentHead, EnrolledSource, IssuerScope, PublisherBinding,
    PublisherEnvelopeCommitment, Scope, SignedSource, SourceEnvelopeCommitment, SourceHead,
};

/// Both detached signatures matched this exact batch at its validated_at time.
/// Pin provenance remains an independent application-policy requirement. This
/// object is not evidence of a later current head or clock and grants no
/// allocation, membership, holder-signing, proof or execution authority.
/// No constructor, Clone, Debug, serialization or caller-record conversion.
pub struct AuthenticatedV3Envelopes<'a> {
    current: &'a AuthenticatedV3Current,
}
impl AuthenticatedV3Envelopes<'_> {
    pub fn current(&self) -> &AuthenticatedV3Current {
        self.current
    }
}
impl AuthenticatedV3Current {
    /// Derive every expected source/publisher claim from this same verified
    /// batch; never accept caller-created enrollment, current-head or clock data.
    /// Verification uses the batch's retained validated_at time. Later proof or
    /// execution use requires a fresh batch and another complete join.
    pub fn authenticate_detached_envelopes(
        &self,
        source: &SignedSource,
        publisher: &PublisherBinding,
    ) -> Result<AuthenticatedV3Envelopes<'_>, Error> {
        let config = self.config();
        let issuer = self.issuer();
        let head = self.publisher_head();
        let scope = Scope {
            network: config.genesis,
            program: self.deployment().program().to_bytes(),
            config: self.deployment().config().to_bytes(),
            // Existing bounded local queue application registry identity.
            registry: self.queue_account().to_bytes(),
            profile: config.profile_id,
            circuit: config.circuit_id,
            schema: config.schema_id,
            package: config.package_id,
            ordinary_vk: config.ordinary_vk_digest,
            policy_hash: config.policy_id,
            policy_version: config.policy_version,
            config_eligibility_epoch: config.eligibility_epoch,
            leaf_domain: credential_registry::v3::LEAF_DOMAIN,
            depth: credential_registry::v3::DEPTH as u8,
        };
        let issuer_scope = IssuerScope {
            issuer_account: self.issuer_account().to_bytes(),
            issuer_hash: issuer.issuer_hash,
            source_key: issuer.source.to_bytes(),
            issuer_eligibility_epoch: issuer.eligibility_epoch,
            enrollment_evidence_version: issuer.enrollment_version,
            evidence_digest: issuer.evidence_digest,
        };
        let enrolled = EnrolledSource {
            scope: scope.clone(),
            issuer: issuer_scope.clone(),
            config_enabled: config.enabled,
            issuer_enabled: issuer.enabled,
            max_age_seconds: zk_fresh_program::application_v3::STATUS_MAX_AGE as u64,
        };
        let source_head = SourceHead { sequence: issuer.sequence, digest: issuer.digest };
        let source_commitment = SourceEnvelopeCommitment {
            source_head: source_head.clone(),
            observed_at: issuer.observed_at,
            valid_until: issuer.expires_at,
            issuer_status_active: issuer.status_valid,
        };
        let publisher_commitment = PublisherEnvelopeCommitment {
            current: CurrentHead {
                scope,
                issuer: issuer_scope,
                source_head,
                root: config.root,
                root_version: config.root_version,
                publisher_key: config.publisher.to_bytes(),
                config_enabled: config.enabled,
                issuer_enabled: issuer.enabled,
                status_valid: issuer.status_valid,
                observed_config_epoch: issuer.observed_config_epoch,
                observed_issuer_epoch: issuer.observed_issuer_epoch,
                clock_unix: self.clock().unix_timestamp,
                valid_until: issuer.expires_at,
            },
            publication_sequence: head.publication_sequence,
            envelope_digest: head.envelope_digest,
            previous_publication_digest: head.previous_publication_digest,
            committed_at: head.committed_at,
        };
        publisher.check_current_envelopes(
            source, &enrolled, &source_commitment, &publisher_commitment, self.validated_at(),
        ).map_err(|_| Error::Account)?;
        Ok(AuthenticatedV3Envelopes { current: self })
    }
}
