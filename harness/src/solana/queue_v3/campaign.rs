//! Frozen eleven-leaf allocation schedule for the cumulative training run.
//! This is pure tree arithmetic; signed source/publisher and finalized account
//! replay must still establish that the operator adopted each checkpoint.
use super::*;
use credential_registry::v3::Tree;
use num_bigint::BigUint;
use std::collections::BTreeSet;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CampaignAllocations {
    pub(super) holder_slot: usize,
    pub(super) unrelated_slots: Vec<usize>,
    pub(super) tbs_digests: Vec<String>,
    pub(super) allocation_epoch: u64,
    pub(super) cohort_receipt_sha256: String,
    pub(super) membership_sha256: String,
    pub(super) root_sequence_sha256: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CampaignContext {
    pub(super) schema: String,
    pub(super) training_only: bool,
    pub(super) root: String,
    pub(super) issuer_hash: String,
    pub(super) policy_id: String,
    pub(super) aki: String,
    pub(super) evidence_digest: String,
    pub(super) not_before: i64,
    pub(super) not_after: i64,
    pub(super) initial_allocations: CampaignAllocations,
    pub(super) root_sequence: Vec<String>,
}

pub(super) struct CheckedSchedule {
    pub(super) digests: [[u8; 32]; 11],
    pub(super) roots: [[u8; 32]; 11],
    pub(super) paths: [[[u8; 32]; 10]; 11],
}

impl CampaignContext {
    pub(super) fn check(&self) -> Result<CheckedSchedule> {
        ensure!(
            self.schema == "part5-v3-campaign-context-v1"
                && self.training_only
                && self.not_before >= 0
                && self.not_before < self.not_after
                && self.root_sequence.len() == 11,
            "registered bounded campaign context"
        );
        let roots: Vec<[u8; 32]> = self
            .root_sequence
            .iter()
            .map(|word| transport::unhex(word))
            .collect::<Result<_>>()?;
        ensure!(
            self.root == self.root_sequence[0],
            "campaign R0 context root"
        );
        transport::unhex(&self.issuer_hash)?;
        transport::unhex(&self.policy_id)?;
        transport::unhex(&self.aki)?;
        transport::unhex(&self.evidence_digest)?;
        let checked = self.initial_allocations.check()?;
        ensure!(
            roots.as_slice() == checked.roots.as_slice(),
            "campaign context roots differ from independent tree"
        );
        Ok(checked)
    }
}

impl CampaignAllocations {
    pub(super) fn changes(&self) -> Result<Vec<Change>> {
        let checked = self.check()?;
        Ok(checked
            .digests
            .iter()
            .enumerate()
            .map(|(index, digest)| Change::Issue {
                tbs_digest: *digest,
                slot: if index == 0 { 0 } else { (15 + index) as u16 },
                allocation_epoch: 1,
            })
            .collect())
    }

    pub(super) fn revocation(&self, update: usize) -> Result<Change> {
        ensure!((1..=10).contains(&update), "registered revocation index");
        let checked = self.check()?;
        Ok(Change::Revoke {
            tbs_digest: checked.digests[update],
        })
    }

    pub(super) fn check(&self) -> Result<CheckedSchedule> {
        ensure!(
            self.holder_slot == 0
                && self.unrelated_slots == (16..=25).collect::<Vec<_>>()
                && self.tbs_digests.len() == 11
                && self.allocation_epoch == 1,
            "fixed eleven-leaf allocation positions"
        );
        for pin in [
            &self.cohort_receipt_sha256,
            &self.membership_sha256,
            &self.root_sequence_sha256,
        ] {
            ensure!(
                transport::unhex(pin)? != [0; 32],
                "nonzero campaign receipt pin"
            );
        }
        let digests: Vec<[u8; 32]> = self
            .tbs_digests
            .iter()
            .map(|word| transport::unhex(word))
            .collect::<Result<_>>()?;
        let distinct = digests.iter().copied().collect::<BTreeSet<_>>();
        ensure!(
            distinct.len() == 11 && !distinct.contains(&[0; 32]),
            "eleven distinct allocated signed TBS digests"
        );
        let mut tree = Tree::new().map_err(|e| anyhow::anyhow!("empty tree {e:?}"))?;
        for (index, digest) in digests.iter().enumerate() {
            let slot = if index == 0 { 0 } else { 15 + index };
            tree.set(slot, *digest, true)
                .map_err(|e| anyhow::anyhow!("issue tree {e:?}"))?;
        }
        let mut roots: Vec<[u8; 32]> = Vec::with_capacity(11);
        let mut paths: Vec<[[u8; 32]; 10]> = Vec::with_capacity(11);
        for update in 0..=10 {
            if update > 0 {
                tree.set(15 + update, digests[update], false)
                    .map_err(|e| anyhow::anyhow!("revoke tree {e:?}"))?;
            }
            let root = tree.root();
            let path = tree
                .path(0)
                .map_err(|e| anyhow::anyhow!("holder path {e:?}"))?;
            Tree::verify(digests[0], 0, true, &path, root)
                .map_err(|e| anyhow::anyhow!("active holder {e:?}"))?;
            roots.push(root);
            paths.push(
                path.try_into()
                    .map_err(|_| anyhow::anyhow!("depth10 path"))?,
            );
        }
        ensure!(
            roots.iter().copied().collect::<BTreeSet<_>>().len() == 11,
            "distinct sequential campaign roots"
        );
        for path in paths.iter().skip(1) {
            ensure!(
                path.iter()
                    .enumerate()
                    .filter(|(level, sibling)| **sibling != paths[0][*level])
                    .map(|(level, _)| level)
                    .collect::<Vec<_>>()
                    == [4],
                "exact level-four sibling change"
            );
        }
        let decimals: Vec<String> = roots
            .iter()
            .map(|root| BigUint::from_bytes_be(root).to_string())
            .collect();
        let serialized = format!("[{}]\n", decimals.join(","));
        ensure!(
            hex::encode(Sha256::digest(serialized)) == self.root_sequence_sha256,
            "registered root sequence digest"
        );
        Ok(CheckedSchedule {
            digests: digests
                .try_into()
                .map_err(|_| anyhow::anyhow!("eleven digests"))?,
            roots: roots
                .try_into()
                .map_err(|_| anyhow::anyhow!("eleven roots"))?,
            paths: paths
                .try_into()
                .map_err(|_| anyhow::anyhow!("eleven paths"))?,
        })
    }
}

pub(super) fn replay_history(
    history: &TrainingHistory,
    p: &V3QueuePlan,
    context: &CampaignContext,
    c: &Config,
    i: &Issuer,
    h: &PublisherHead,
) -> Result<credential_registry::v3::history::HistoricalReplay> {
    use credential_registry::v3::history::HistoricalReplay;
    let checked = context.check()?;
    ensure!(
        history.schema == "part5-v3-eleven-leaf-signed-history-v1"
            && !history.checkpoints.is_empty()
            && history.checkpoints.len() <= checked.roots.len(),
        "bounded complete campaign history"
    );
    let a = p.addresses();
    ensure!(
        i.config == a.config
            && c.admin.to_bytes() == p.admin
            && c.seed == p.seed
            && c.genesis == p.genesis
            && c.publisher.to_bytes() == p.publisher
            && i.source.to_bytes() == p.source
            && i.issuer_hash == p.issuer_hash
            && p.root == checked.roots[0],
        "campaign enrollment differs from finalized deployment tuple"
    );
    let enrolled = EnrolledSource {
        scope: Scope {
            network: p.genesis,
            program: p.program,
            config: a.config.to_bytes(),
            registry: a.queue.to_bytes(),
            profile: c.profile_id,
            circuit: c.circuit_id,
            schema: c.schema_id,
            package: c.package_id,
            ordinary_vk: c.ordinary_vk_digest,
            policy_hash: c.policy_id,
            policy_version: c.policy_version,
            config_eligibility_epoch: c.eligibility_epoch,
            leaf_domain: credential_registry::v3::LEAF_DOMAIN,
            depth: credential_registry::v3::DEPTH as u8,
        },
        issuer: IssuerScope {
            issuer_account: a.issuer.to_bytes(),
            issuer_hash: i.issuer_hash,
            source_key: i.source.to_bytes(),
            issuer_eligibility_epoch: i.eligibility_epoch,
            enrollment_evidence_version: i.enrollment_version,
            evidence_digest: i.evidence_digest,
        },
        config_enabled: c.enabled,
        issuer_enabled: i.enabled,
        max_age_seconds: 240,
    };
    let mut replay = HistoricalReplay::new(enrolled.clone(), c.publisher.to_bytes())
        .map_err(|e| anyhow::anyhow!("campaign replay initialization {e:?}"))?;
    for (index, checkpoint) in history.checkpoints.iter().enumerate() {
        let expected = if index == 0 {
            context.initial_allocations.changes()?
        } else {
            vec![context.initial_allocations.revocation(index)?]
        };
        ensure!(
            serde_json::to_vec(&checkpoint.source.observation.changes)?
                == serde_json::to_vec(&expected)?,
            "exact signed campaign allocation change"
        );
        replay
            .apply(
                &checkpoint.source,
                &checkpoint.publisher,
                checkpoint.checked_at,
            )
            .map_err(|e| anyhow::anyhow!("campaign signed history {e:?}"))?;
        ensure!(
            replay.root() == checked.roots[index] && replay.root_version() == Some(index as u64),
            "campaign replay root/version differs from independent tree"
        );
        let member = replay
            .active_holder(checked.digests[0], 0, 1)
            .map_err(|e| anyhow::anyhow!("campaign active holder {e:?}"))?;
        ensure!(
            member.siblings() == &checked.paths[index],
            "campaign replay holder path differs from independent tree"
        );
    }
    let last = history
        .checkpoints
        .last()
        .context("last campaign checkpoint")?;
    check_finalized_envelopes(
        &enrolled,
        &last.source,
        &last.publisher,
        c,
        i,
        h,
        last.checked_at,
    )?;
    let index = history.checkpoints.len() - 1;
    ensure!(
        c.root == checked.roots[index]
            && c.root_version == index as u64
            && replay.source_head().sequence == i.sequence
            && replay.source_head().digest == i.digest
            && replay.publication_sequence() == h.publication_sequence
            && replay.publication_digest() == h.envelope_digest,
        "campaign replay differs from exact finalized accounts"
    );
    Ok(replay)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eleven_leaves() -> CampaignAllocations {
        let digests = (1..=11).map(|n| [n; 32]).collect::<Vec<_>>();
        let mut tree = Tree::new().unwrap();
        for (index, digest) in digests.iter().enumerate() {
            tree.set(if index == 0 { 0 } else { 15 + index }, *digest, true)
                .unwrap();
        }
        let mut roots = vec![BigUint::from_bytes_be(&tree.root()).to_string()];
        for update in 1..=10 {
            tree.set(15 + update, digests[update], false).unwrap();
            roots.push(BigUint::from_bytes_be(&tree.root()).to_string());
        }
        let root_sequence_sha256 = hex::encode(Sha256::digest(
            format!("[{}]\n", roots.join(",")).as_bytes(),
        ));
        CampaignAllocations {
            holder_slot: 0,
            unrelated_slots: (16..=25).collect(),
            tbs_digests: digests.iter().map(hex::encode).collect(),
            allocation_epoch: 1,
            cohort_receipt_sha256: "01".repeat(32),
            membership_sha256: "02".repeat(32),
            root_sequence_sha256,
        }
    }

    #[test]
    fn campaign_schedule_has_one_fixed_sibling_change_at_each_cumulative_root() {
        let checked = eleven_leaves().check().unwrap();
        for (index, path) in checked.paths.iter().enumerate().skip(1) {
            let changed = path
                .iter()
                .enumerate()
                .filter(|(level, sibling)| **sibling != checked.paths[0][*level])
                .map(|(level, _)| level)
                .collect::<Vec<_>>();
            assert_eq!(changed, [4], "R{index}");
        }
        let mut wrong_slot = eleven_leaves();
        wrong_slot.unrelated_slots[0] = 1;
        assert!(wrong_slot.check().is_err());
        let mut duplicate_digest = eleven_leaves();
        duplicate_digest.tbs_digests[1] = duplicate_digest.tbs_digests[0].clone();
        assert!(duplicate_digest.check().is_err());
        let mut wrong_sequence = eleven_leaves();
        wrong_sequence.root_sequence_sha256 = "03".repeat(32);
        assert!(wrong_sequence.check().is_err());
    }
}
