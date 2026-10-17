//! Frozen eleven-leaf allocation schedule for the cumulative training run.
//! This is pure tree arithmetic; signed source/publisher and finalized account
//! replay must still establish that the operator adopted each checkpoint.
use super::*;
use credential_registry::v3::Tree;
use num_bigint::BigUint;
use std::collections::BTreeSet;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

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
    let enrolled = enrolled_source(p, c, i);
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

fn enrolled_source(p: &V3QueuePlan, c: &Config, i: &Issuer) -> EnrolledSource {
    let a = p.addresses();
    EnrolledSource {
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
    }
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

fn private_dir(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && fs::canonicalize(path)? == path
            && meta.is_dir()
            && meta.permissions().mode() & 0o7777 == 0o700
            && meta.uid() == unsafe { libc::geteuid() },
        "canonical private campaign stage required"
    );
    Ok(())
}

/// Publish exactly k signed cumulative unrelated revocations from a separately
/// cloned R0 ledger. The external supervisor must attest the clone, loaded ELF,
/// source certificates and finalized accounts before and after this child.
pub(super) fn transition_from_env() -> Result<()> {
    ensure!(
        transport::env("P5_V3_CAMPAIGN_TRANSITION_SCOPE")? == "part5-v3-campaign-transition",
        "explicit bounded campaign transition scope"
    );
    let count: usize = transport::env("P5_V3_CAMPAIGN_COUNT")?.parse()?;
    ensure!(matches!(count, 1 | 2 | 5 | 10), "registered campaign count");
    let output = transport::output()?;
    ensure!(
        fs::read_dir(&output)?.next().is_none(),
        "fresh campaign output"
    );
    let stage_root = PathBuf::from(transport::env("P5_V3_STAGE_ROOT")?);
    private_dir(&stage_root)?;
    let stage_sha = transport::env("P5_V3_STAGE_REPORT_SHA256")?;
    let plan_sha = transport::env("P5_V3_STAGE_PLAN_SHA256")?;
    let report: Value = serde_json::from_slice(&transport::pinned(
        &stage_root.join("stage-report.json"),
        &stage_sha,
        65536,
    )?)?;
    let p: V3QueuePlan = serde_json::from_slice(&transport::pinned(
        &stage_root.join("plan.json"),
        &plan_sha,
        8192,
    )?)?;
    let context_sha = transport::env("P5_V3_CONTEXT_SHA256")?;
    let context: CampaignContext = serde_json::from_slice(&transport::pinned(
        Path::new(&transport::env("P5_V3_CONTEXT")?),
        &context_sha,
        8192,
    )?)?;
    let schedule = context.check()?;
    let allocation_bytes = serde_json::to_vec_pretty(&context.initial_allocations)?;
    ensure!(
        report["initial_allocations_sha256"] == hex::encode(Sha256::digest(&allocation_bytes))
            && transport::pinned(
                &stage_root.join("initial-allocations.json"),
                report["initial_allocations_sha256"]
                    .as_str()
                    .context("allocation pin")?,
                8192
            )? == allocation_bytes,
        "stage allocated the exact admitted campaign certificates"
    );
    let rpc = transport::local_rpc()?;
    let (program, genesis, loaded) = transport::domain(&rpc)?;
    let a = p.addresses();
    ensure!(
        p.program == program
            && p.genesis == genesis
            && p.root == schedule.roots[0]
            && p.issuer_hash == transport::unhex(&context.issuer_hash)?
            && p.policy_id == transport::unhex(&context.policy_id)?
            && p.aki == transport::unhex(&context.aki)?
            && report["schema"] == "part5-v3-campaign-stage-v1"
            && report["passed"] == true
            && report["registry_history_authenticated"] == true
            && report["allocation_history_authenticated"] == true
            && report["proof_created"] == false
            && report["application_effect"] == false
            && report["plan_sha256"] == plan_sha
            && report["program"] == Pubkey::new_from_array(program).to_string()
            && report["genesis"] == Hash::new_from_array(genesis).to_string()
            && report["loaded_program"]["elf_sha256"] == transport::env("P5_QUEUE_ELF_SHA256")?
            && report["loaded_program"]["elf_match"] == true
            && report["config"] == a.config.to_string()
            && report["issuer"] == a.issuer.to_string()
            && report["head"] == a.head.to_string()
            && report["request"] == a.request.to_string()
            && report["queue"] == a.queue.to_string(),
        "exact signed campaign stage and application identity"
    );
    let minimum_slot = report["finalized_slot"].as_u64().context("R0 slot")?;
    ensure!(minimum_slot > 0, "nonzero R0 finality");
    let hashes = report["account_sha256"]
        .as_array()
        .context("R0 account hashes")?;
    ensure!(hashes.len() == 5, "five R0 account hashes");
    let mut saved = Vec::with_capacity(5);
    for (index, name) in ["config", "issuer", "head", "request", "queue"]
        .iter()
        .enumerate()
    {
        saved.push(transport::pinned(
            &stage_root.join(format!("{name}.bin")),
            hashes[index].as_str().context("R0 account digest")?,
            4096,
        )?);
    }
    let saved: [Vec<u8>; 5] = saved
        .try_into()
        .map_err(|_| anyhow::anyhow!("R0 account width"))?;
    let (_, mut before) = finalized_accounts(&rpc, &p, minimum_slot)?;
    ensure!(
        before == saved,
        "cloned R0 accounts differ from staged bytes"
    );
    let mut c = Config::decode(&before[0]).map_err(|e| anyhow::anyhow!("R0 config {e:?}"))?;
    let mut i = Issuer::decode(&before[1]).map_err(|e| anyhow::anyhow!("R0 issuer {e:?}"))?;
    let mut h = PublisherHead::decode(&before[2]).map_err(|e| anyhow::anyhow!("R0 head {e:?}"))?;
    let request = Request::decode(&before[3]).map_err(|e| anyhow::anyhow!("R0 request {e:?}"))?;
    let queue = Queue::decode(&before[4]).map_err(|e| anyhow::anyhow!("R0 queue {e:?}"))?;
    ensure!(
        c.root == schedule.roots[0]
            && c.root_version == 0
            && c.enabled
            && i.config == a.config
            && i.issuer_hash == p.issuer_hash
            && i.source.to_bytes() == p.source
            && i.enabled
            && i.status_valid
            && i.sequence == 1
            && h.config == a.config
            && h.issuer == a.issuer
            && h.publisher.to_bytes() == p.publisher
            && h.root == c.root
            && h.root_version == 0
            && request.state == RequestState::Finalized
            && queue.entries.is_empty(),
        "active R0 request and signed source required"
    );
    let mut history = load_training_history(&stage_root, &report)?;
    ensure!(history.checkpoints.len() == 1, "exact R0 signed checkpoint");
    replay_history(&history, &p, &context, &c, &i, &h)?;
    let admin = transport::load_key(&stage_root, "admin.json", p.admin)?;
    let publisher = transport::load_key(&stage_root, "publisher.json", p.publisher)?;
    let source = transport::load_key(&stage_root, "source.json", p.source)?;
    let mut events = Vec::new();
    let mut checkpoints = Vec::with_capacity(count);
    for update in 1..=count {
        let observation_deadline = Instant::now() + Duration::from_secs(20);
        let observed = loop {
            let candidate = transport::clock(&rpc)?;
            if candidate > i.observed_at {
                break candidate;
            }
            ensure!(
                Instant::now() < observation_deadline,
                "new campaign observation deadline"
            );
            thread::sleep(Duration::from_millis(250));
        };
        let expires = observed
            .checked_add(180)
            .context("source expiry overflow")?;
        let sequence = i
            .sequence
            .checked_add(1)
            .context("source sequence overflow")?;
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
                source_key: p.source,
                issuer_eligibility_epoch: i.eligibility_epoch,
                enrollment_evidence_version: i.enrollment_version,
                evidence_digest: i.evidence_digest,
            },
            config_enabled: c.enabled,
            issuer_enabled: i.enabled,
            max_age_seconds: 180,
        };
        let observation = Observation {
            scope: enrolled.scope.clone(),
            issuer: enrolled.issuer.clone(),
            sequence,
            previous_digest: i.digest,
            observed_at: observed,
            valid_until: expires,
            issuer_status_active: true,
            changes: vec![context.initial_allocations.revocation(update)?],
        };
        let mut message = SOURCE_SIGN_TAG.to_vec();
        message.extend(serde_json::to_vec(&observation)?);
        let signed = SignedSource {
            observation,
            signature: source.sign_message(&message).as_ref().to_vec(),
        };
        let source_digest = signed
            .verify(
                &enrolled,
                &SourceHead {
                    sequence: i.sequence,
                    digest: i.digest,
                },
                observed,
            )
            .map_err(|e| anyhow::anyhow!("signed campaign revocation {e:?}"))?
            .head()
            .digest;
        ensure!(source_digest != i.digest, "new campaign source digest");
        let target_root = schedule.roots[update];
        let mut expected_config = c.clone();
        expected_config
            .publish(
                Authority {
                    key: publisher.pubkey(),
                    is_signer: true,
                },
                c.root_version,
                target_root,
            )
            .map_err(|e| anyhow::anyhow!("pure campaign root publish {e:?}"))?;
        transport::send(
            &rpc,
            &admin,
            Some(&publisher),
            p.publish(c.root_version, target_root),
            "v3-campaign-publish-unrelated-root",
            None,
            &mut events,
        )?;
        transport::send(
            &rpc,
            &admin,
            Some(&source),
            p.observe(
                c.eligibility_epoch,
                i.eligibility_epoch,
                i.sequence,
                sequence,
                source_digest,
                true,
                observed,
                expires,
            ),
            "v3-campaign-observe-signed-revocation",
            None,
            &mut events,
        )?;
        let next_publication = h
            .publication_sequence
            .checked_add(1)
            .context("publication sequence overflow")?;
        let (signed_publisher, envelope_digest) = branch::signed_publisher_envelope(
            &enrolled,
            SourceHead {
                sequence,
                digest: source_digest,
            },
            target_root,
            expected_config.root_version,
            &publisher,
            next_publication,
            h.envelope_digest,
        )?;
        let binding = V3HeadBinding {
            expected_config_epoch: c.eligibility_epoch,
            expected_issuer_epoch: i.eligibility_epoch,
            expected_root: target_root,
            expected_root_version: expected_config.root_version,
            expected_source_sequence: sequence,
            expected_source_digest: source_digest,
            expected_publication_sequence: h.publication_sequence,
            expected_publication_digest: h.envelope_digest,
            next_publication_sequence: next_publication,
            envelope_digest,
        };
        transport::send(
            &rpc,
            &admin,
            Some(&publisher),
            p.bind_with_head(&binding),
            "v3-campaign-bind-signed-head",
            None,
            &mut events,
        )?;
        let rooted = transport::wait_finalized(&rpc, &events)?;
        let (finalized_slot, after) = finalized_accounts(&rpc, &p, rooted)?;
        let next_issuer =
            Issuer::decode(&after[1]).map_err(|e| anyhow::anyhow!("campaign issuer {e:?}"))?;
        let next_head =
            PublisherHead::decode(&after[2]).map_err(|e| anyhow::anyhow!("campaign head {e:?}"))?;
        let checked_at = transport::clock(&rpc)?;
        next_issuer
            .fresh(&expected_config, checked_at)
            .map_err(|e| anyhow::anyhow!("campaign issuer fresh {e:?}"))?;
        next_issuer
            .binding_current(&expected_config)
            .map_err(|e| anyhow::anyhow!("campaign issuer current {e:?}"))?;
        ensure!(
            after[0] == expected_config.encode()
                && after[3] == before[3]
                && after[4] == before[4]
                && next_issuer.sequence == sequence
                && next_issuer.digest == source_digest
                && next_issuer.observed_at == observed
                && next_issuer.expires_at == expires
                && next_issuer.bound_root == target_root
                && next_issuer.bound_root_version == update as u64
                && next_head.root == target_root
                && next_head.root_version == update as u64
                && next_head.publication_sequence == next_publication
                && next_head.previous_publication_digest == h.envelope_digest
                && next_head.envelope_digest == envelope_digest
                && next_head.source_sequence == sequence
                && next_head.source_digest == source_digest,
            "campaign successor differs from exact finalized accounts"
        );
        check_finalized_envelopes(
            &enrolled,
            &signed,
            &signed_publisher,
            &expected_config,
            &next_issuer,
            &next_head,
            checked_at,
        )?;
        history.push(signed, signed_publisher, checked_at);
        replay_history(
            &history,
            &p,
            &context,
            &expected_config,
            &next_issuer,
            &next_head,
        )?;
        checkpoints.push(json!({
            "root_version":update,"root":hex::encode(target_root),
            "finalized_slot":finalized_slot,"source_sequence":sequence,
            "source_head_digest":hex::encode(source_digest),
            "publication_sequence":next_publication,
            "publisher_envelope_digest":hex::encode(envelope_digest),
            "account_sha256":after.iter().map(|data|
                hex::encode(Sha256::digest(data))).collect::<Vec<_>>(),
        }));
        before = after;
        c = expected_config;
        i = next_issuer;
        h = next_head;
    }
    let history_sha256 = write_training_history(&output, &history)?;
    for (index, name) in ["config", "issuer", "head", "request", "queue"]
        .iter()
        .enumerate()
    {
        transport::new_file(&output.join(format!("{name}.bin")), &before[index])?;
    }
    let final_slot = checkpoints
        .last()
        .and_then(|v| v["finalized_slot"].as_u64())
        .context("last finalized campaign checkpoint")?;
    transport::new_json(
        &output.join("transition-report.json"),
        &json!({
            "schema":"part5-v3-campaign-transition-v1", "passed":true,
            "training_only":true,"registry_history_authenticated":true,
            "allocation_history_authenticated":true,
            "upstream_source_authentication":true,
            "upstream_publisher_authentication":true,
            "request_unconsumed":true,"application_effect":false,"devnet":false,
            "target_count":count,"root_sequence_sha256":context.initial_allocations.root_sequence_sha256,
            "initial_allocations_sha256":report["initial_allocations_sha256"],
            "signed_history_sha256":history_sha256,
            "context_sha256":context_sha,"stage_report_sha256":stage_sha,
            "stage_plan_sha256":plan_sha,
            "program":Pubkey::new_from_array(program).to_string(),
            "genesis":Hash::new_from_array(genesis).to_string(),
            "loaded_program":loaded,"base_root":hex::encode(schedule.roots[0]),
            "current_root":hex::encode(schedule.roots[count]),
            "base_finalized_slot":minimum_slot,"finalized_slot":final_slot,
            "account_sha256":before.iter().map(|data|
                hex::encode(Sha256::digest(data))).collect::<Vec<_>>(),
            "checkpoints":checkpoints,"transactions":events,
        }),
    )?;
    Ok(())
}

fn pinned_accounts(root: &Path, report: &Value) -> Result<[Vec<u8>; 5]> {
    let hashes = report["account_sha256"]
        .as_array()
        .context("five pinned campaign account hashes")?;
    ensure!(hashes.len() == 5, "five campaign accounts required");
    let mut accounts = Vec::with_capacity(5);
    for (index, name) in ["config", "issuer", "head", "request", "queue"]
        .iter()
        .enumerate()
    {
        accounts.push(transport::pinned(
            &root.join(format!("{name}.bin")),
            hashes[index].as_str().context("campaign account digest")?,
            4096,
        )?);
    }
    accounts
        .try_into()
        .map_err(|_| anyhow::anyhow!("campaign account width"))
}

/// Complete one protected queue effect from a pinned R0 or Rk campaign clone.
/// The external supervisor reattests the ledger, proofs, and finalized bytes.
pub(super) fn effect_from_env() -> Result<()> {
    ensure!(
        transport::env("P5_V3_CAMPAIGN_EFFECT_SCOPE")? == "part5-v3-campaign-effect",
        "explicit bounded campaign effect scope"
    );
    let mode = transport::env("P5_V3_CAMPAIGN_EFFECT_MODE")?;
    ensure!(
        matches!(mode.as_str(), "full" | "anchor" | "coalesced-full"),
        "registered campaign proof mode"
    );
    let count: usize = transport::env("P5_V3_CAMPAIGN_COUNT")?.parse()?;
    ensure!(
        matches!(count, 0 | 1 | 2 | 5 | 10),
        "registered campaign count"
    );
    let output = transport::output()?;
    ensure!(
        fs::read_dir(&output)?.next().is_none(),
        "fresh campaign effect output"
    );
    let stage_root = PathBuf::from(transport::env("P5_V3_STAGE_ROOT")?);
    private_dir(&stage_root)?;
    let stage_sha = transport::env("P5_V3_STAGE_REPORT_SHA256")?;
    let plan_sha = transport::env("P5_V3_STAGE_PLAN_SHA256")?;
    let stage: Value = serde_json::from_slice(&transport::pinned(
        &stage_root.join("stage-report.json"),
        &stage_sha,
        65536,
    )?)?;
    let p: V3QueuePlan = serde_json::from_slice(&transport::pinned(
        &stage_root.join("plan.json"),
        &plan_sha,
        8192,
    )?)?;
    let context_sha = transport::env("P5_V3_CONTEXT_SHA256")?;
    let context: CampaignContext = serde_json::from_slice(&transport::pinned(
        Path::new(&transport::env("P5_V3_CONTEXT")?),
        &context_sha,
        8192,
    )?)?;
    let schedule = context.check()?;
    let rpc = transport::local_rpc()?;
    let (program, genesis, loaded) = transport::domain(&rpc)?;
    let a = p.addresses();
    ensure!(
        p.program == program
            && p.genesis == genesis
            && p.root == schedule.roots[0]
            && p.issuer_hash == transport::unhex(&context.issuer_hash)?
            && p.policy_id == transport::unhex(&context.policy_id)?
            && p.aki == transport::unhex(&context.aki)?
            && stage["schema"] == "part5-v3-campaign-stage-v1"
            && stage["passed"] == true
            && stage["training_only"] == true
            && stage["registry_history_authenticated"] == true
            && stage["allocation_history_authenticated"] == true
            && stage["upstream_source_authentication"] == true
            && stage["upstream_publisher_authentication"] == true
            && stage["proof_created"] == false
            && stage["application_effect"] == false
            && stage["plan_sha256"] == plan_sha
            && stage["program"] == Pubkey::new_from_array(program).to_string()
            && stage["genesis"] == Hash::new_from_array(genesis).to_string()
            && stage["loaded_program"] == loaded
            && stage["config"] == a.config.to_string()
            && stage["issuer"] == a.issuer.to_string()
            && stage["head"] == a.head.to_string()
            && stage["request"] == a.request.to_string()
            && stage["queue"] == a.queue.to_string(),
        "exact signed campaign stage and loaded application identity"
    );
    let stage_accounts = pinned_accounts(&stage_root, &stage)?;
    let allocation_bytes = serde_json::to_vec_pretty(&context.initial_allocations)?;
    ensure!(
        stage["initial_allocations_sha256"] == hex::encode(Sha256::digest(&allocation_bytes))
            && transport::pinned(
                &stage_root.join("initial-allocations.json"),
                stage["initial_allocations_sha256"]
                    .as_str()
                    .context("R0 allocation pin")?,
                8192,
            )? == allocation_bytes,
        "exact frozen campaign allocation provenance required"
    );
    let stage_config =
        Config::decode(&stage_accounts[0]).map_err(|e| anyhow::anyhow!("R0 config {e:?}"))?;
    let stage_issuer =
        Issuer::decode(&stage_accounts[1]).map_err(|e| anyhow::anyhow!("R0 issuer {e:?}"))?;
    let stage_head =
        PublisherHead::decode(&stage_accounts[2]).map_err(|e| anyhow::anyhow!("R0 head {e:?}"))?;
    let stage_history = load_training_history(&stage_root, &stage)?;
    ensure!(
        stage_history.checkpoints.len() == 1,
        "exact signed R0 stage checkpoint"
    );
    replay_history(
        &stage_history,
        &p,
        &context,
        &stage_config,
        &stage_issuer,
        &stage_head,
    )?;
    let stage_slot = stage["finalized_slot"]
        .as_u64()
        .context("R0 finalized slot")?;
    ensure!(stage_slot > 0, "nonzero R0 finality");
    let (final_root, final_report, transition_sha) = if count == 0 {
        (stage_root.clone(), stage.clone(), None)
    } else {
        let root = PathBuf::from(transport::env("P5_V3_TRANSITION_ROOT")?);
        private_dir(&root)?;
        let digest = transport::env("P5_V3_TRANSITION_REPORT_SHA256")?;
        let report: Value = serde_json::from_slice(&transport::pinned(
            &root.join("transition-report.json"),
            &digest,
            1024 * 1024,
        )?)?;
        ensure!(
            report["schema"] == "part5-v3-campaign-transition-v1"
                && report["passed"] == true
                && report["training_only"] == true
                && report["registry_history_authenticated"] == true
                && report["allocation_history_authenticated"] == true
                && report["upstream_source_authentication"] == true
                && report["upstream_publisher_authentication"] == true
                && report["request_unconsumed"] == true
                && report["application_effect"] == false
                && report["target_count"] == count
                && report["context_sha256"] == context_sha
                && report["stage_report_sha256"] == stage_sha
                && report["stage_plan_sha256"] == plan_sha
                && report["initial_allocations_sha256"] == stage["initial_allocations_sha256"]
                && report["root_sequence_sha256"]
                    == context.initial_allocations.root_sequence_sha256
                && report["program"] == stage["program"]
                && report["genesis"] == stage["genesis"]
                && report["loaded_program"] == loaded
                && report["base_root"] == hex::encode(schedule.roots[0])
                && report["current_root"] == hex::encode(schedule.roots[count])
                && report["base_finalized_slot"] == stage_slot,
            "exact signed R0-to-Rk campaign transition required"
        );
        (root, report, Some(digest))
    };
    let final_slot = final_report["finalized_slot"]
        .as_u64()
        .context("final campaign checkpoint slot")?;
    ensure!(
        final_slot >= stage_slot && (count == 0 || final_slot > stage_slot),
        "monotone finalized campaign slots"
    );
    let saved = pinned_accounts(&final_root, &final_report)?;
    ensure!(
        saved[3] == stage_accounts[3] && saved[4] == stage_accounts[4],
        "unconsumed campaign request and queue preserved"
    );
    let (_, initial) = finalized_accounts(&rpc, &p, final_slot)?;
    ensure!(
        initial == saved,
        "restarted campaign accounts differ from pinned finalized bytes"
    );
    let c = Config::decode(&initial[0]).map_err(|e| anyhow::anyhow!("config {e:?}"))?;
    let i = Issuer::decode(&initial[1]).map_err(|e| anyhow::anyhow!("issuer {e:?}"))?;
    let h = PublisherHead::decode(&initial[2]).map_err(|e| anyhow::anyhow!("head {e:?}"))?;
    let r = Request::decode(&initial[3]).map_err(|e| anyhow::anyhow!("request {e:?}"))?;
    let q = Queue::decode(&initial[4]).map_err(|e| anyhow::anyhow!("queue {e:?}"))?;
    ensure!(
        c.root == schedule.roots[count]
            && c.root_version == count as u64
            && c.enabled
            && c.policy_id == p.policy_id
            && i.config == a.config
            && i.issuer_hash == p.issuer_hash
            && i.aki == p.aki
            && i.evidence_digest == transport::unhex(&context.evidence_digest)?
            && i.enabled
            && i.status_valid
            && i.bound_root == c.root
            && i.bound_root_version == c.root_version
            && h.config == a.config
            && h.issuer == a.issuer
            && h.publisher.to_bytes() == p.publisher
            && h.root == c.root
            && h.root_version == c.root_version
            && h.source_sequence == i.sequence
            && h.source_digest == i.digest
            && r.state == RequestState::Finalized
            && q.entries.is_empty(),
        "exact active campaign root and unconsumed request required"
    );
    let history = load_training_history(&final_root, &final_report)?;
    ensure!(
        history.checkpoints.len() == count + 1,
        "complete exact R0-to-Rk signed campaign history"
    );
    ensure!(
        serde_json::to_vec(&history.checkpoints[0])?
            == serde_json::to_vec(&stage_history.checkpoints[0])?,
        "current signed campaign history must begin at staged R0"
    );
    let mut replay = replay_history(&history, &p, &context, &c, &i, &h)?;
    let base_wire = if mode == "coalesced-full" {
        None
    } else {
        let digest = transport::env("P5_V3_BASE_WIRE_SHA256")?;
        let wire = transport::pinned(Path::new(&transport::env("P5_V3_BASE_WIRE")?), &digest, 448)?;
        Some((digest, wire))
    };
    let current_sha = transport::env("P5_V3_CURRENT_WIRE_SHA256")?;
    let current_wire = transport::pinned(
        Path::new(&transport::env("P5_V3_CURRENT_WIRE")?),
        &current_sha,
        448,
    )?;
    if let Some((_, wire)) = &base_wire {
        validate_full_wire(
            &p,
            &stage_config,
            &r,
            context.not_before,
            context.not_after,
            wire,
        )?;
    }
    let mut current_plan = p.clone();
    current_plan.root = schedule.roots[count];
    validate_full_wire(
        &current_plan,
        &c,
        &r,
        context.not_before,
        context.not_after,
        &current_wire,
    )?;
    if let Some((_, wire)) = &base_wire {
        ensure!(
            wire[32..192] == current_wire[32..192],
            "same signed credential, policy and protected action across campaign"
        );
    }
    let admin = transport::load_key(&stage_root, "admin.json", p.admin)?;
    let publisher = transport::load_key(&stage_root, "publisher.json", p.publisher)?;
    let source = transport::load_key(&stage_root, "source.json", p.source)?;
    let observation_deadline = Instant::now() + Duration::from_secs(20);
    let observed = loop {
        let candidate = transport::clock(&rpc)?;
        if candidate > i.observed_at {
            break candidate;
        }
        ensure!(
            Instant::now() < observation_deadline,
            "new campaign effect observation deadline"
        );
        thread::sleep(Duration::from_millis(250));
    };
    let expires = observed
        .checked_add(180)
        .context("campaign effect expiry overflow")?;
    let sequence = i
        .sequence
        .checked_add(1)
        .context("campaign effect source sequence overflow")?;
    let enrolled = enrolled_source(&p, &c, &i);
    let observation = Observation {
        scope: enrolled.scope.clone(),
        issuer: enrolled.issuer.clone(),
        sequence,
        previous_digest: i.digest,
        observed_at: observed,
        valid_until: expires,
        issuer_status_active: true,
        changes: vec![],
    };
    let mut message = SOURCE_SIGN_TAG.to_vec();
    message.extend(serde_json::to_vec(&observation)?);
    let signed = SignedSource {
        observation,
        signature: source.sign_message(&message).as_ref().to_vec(),
    };
    let source_digest = signed
        .verify(
            &enrolled,
            &SourceHead {
                sequence: i.sequence,
                digest: i.digest,
            },
            observed,
        )
        .map_err(|e| anyhow::anyhow!("campaign effect signed status {e:?}"))?
        .head()
        .digest;
    let next_publication = h
        .publication_sequence
        .checked_add(1)
        .context("campaign effect publication sequence overflow")?;
    let (signed_publisher, envelope_digest) = branch::signed_publisher_envelope(
        &enrolled,
        SourceHead {
            sequence,
            digest: source_digest,
        },
        c.root,
        c.root_version,
        &publisher,
        next_publication,
        h.envelope_digest,
    )?;
    let source_json = serde_json::to_vec_pretty(&signed)?;
    let publisher_json = serde_json::to_vec_pretty(&signed_publisher)?;
    let enrolled_json = serde_json::to_vec_pretty(&enrolled)?;
    transport::new_file(&output.join("effect-signed-source.json"), &source_json)?;
    transport::new_file(
        &output.join("effect-signed-publisher.json"),
        &publisher_json,
    )?;
    transport::new_file(&output.join("effect-enrolled-source.json"), &enrolled_json)?;
    let mut events = Vec::new();
    transport::send(
        &rpc,
        &admin,
        Some(&source),
        p.observe(
            c.eligibility_epoch,
            i.eligibility_epoch,
            i.sequence,
            sequence,
            source_digest,
            true,
            observed,
            expires,
        ),
        "v3-campaign-refresh-active-source",
        None,
        &mut events,
    )?;
    let binding = V3HeadBinding {
        expected_config_epoch: c.eligibility_epoch,
        expected_issuer_epoch: i.eligibility_epoch,
        expected_root: c.root,
        expected_root_version: c.root_version,
        expected_source_sequence: sequence,
        expected_source_digest: source_digest,
        expected_publication_sequence: h.publication_sequence,
        expected_publication_digest: h.envelope_digest,
        next_publication_sequence: next_publication,
        envelope_digest,
    };
    transport::send(
        &rpc,
        &admin,
        Some(&publisher),
        p.bind_with_head(&binding),
        "v3-campaign-bind-current-head",
        None,
        &mut events,
    )?;
    let rooted = transport::wait_finalized(&rpc, &events)?;
    let (bound_slot, bound) = finalized_accounts(&rpc, &p, rooted)?;
    let next_issuer =
        Issuer::decode(&bound[1]).map_err(|e| anyhow::anyhow!("bound issuer {e:?}"))?;
    let next_head =
        PublisherHead::decode(&bound[2]).map_err(|e| anyhow::anyhow!("bound head {e:?}"))?;
    let checked_at = transport::clock(&rpc)?;
    next_issuer
        .fresh(&c, checked_at)
        .map_err(|e| anyhow::anyhow!("campaign effect issuer fresh {e:?}"))?;
    next_issuer
        .binding_current(&c)
        .map_err(|e| anyhow::anyhow!("campaign effect issuer current {e:?}"))?;
    ensure!(
        bound[0] == initial[0]
            && bound[3] == initial[3]
            && bound[4] == initial[4]
            && next_issuer.sequence == sequence
            && next_issuer.digest == source_digest
            && next_issuer.observed_at == observed
            && next_issuer.expires_at == expires
            && next_issuer.bound_root == c.root
            && next_issuer.bound_root_version == c.root_version
            && next_head.root == c.root
            && next_head.root_version == c.root_version
            && next_head.publication_sequence == next_publication
            && next_head.previous_publication_digest == h.envelope_digest
            && next_head.envelope_digest == envelope_digest
            && next_head.source_sequence == sequence
            && next_head.source_digest == source_digest,
        "signed no-change campaign successor differs from finalized accounts"
    );
    check_finalized_envelopes(
        &enrolled,
        &signed,
        &signed_publisher,
        &c,
        &next_issuer,
        &next_head,
        checked_at,
    )?;
    replay
        .apply(&signed, &signed_publisher, checked_at)
        .map_err(|e| anyhow::anyhow!("campaign effect successor replay {e:?}"))?;
    ensure!(
        replay.root() == c.root
            && replay.root_version() == Some(c.root_version)
            && replay.source_head().sequence == next_issuer.sequence
            && replay.source_head().digest == next_issuer.digest
            && replay.publication_sequence() == next_head.publication_sequence
            && replay.publication_digest() == next_head.envelope_digest,
        "campaign effect replay differs from current finalized accounts"
    );
    if count > 0 && mode != "coalesced-full" {
        transport::send(
            &rpc,
            &admin,
            None,
            p.execute(&base_wire.as_ref().context("R0 wire")?.1)?,
            "v3-campaign-stale-R0",
            Some(zk_fresh_program::application_v3::AppError::Policy as u64),
            &mut events,
        )?;
    }
    let mut wrong_action = current_wire.clone();
    wrong_action[128..160].fill(0);
    if wrong_action[128..160] == current_wire[128..160] {
        wrong_action[159] = 1;
    }
    transport::send(
        &rpc,
        &admin,
        None,
        p.execute(&wrong_action)?,
        "v3-campaign-wrong-action",
        Some(zk_fresh_program::application_v3::AppError::Action as u64),
        &mut events,
    )?;
    let mut wrong_proof = current_wire.clone();
    wrong_proof[192..].fill(0);
    transport::send(
        &rpc,
        &admin,
        None,
        p.execute(&wrong_proof)?,
        "v3-campaign-invalid-proof",
        Some(zk_fresh_program::application_v3::AppError::Proof as u64),
        &mut events,
    )?;
    let rooted = transport::wait_finalized(&rpc, &events)?;
    let (_, rejected) = finalized_accounts(&rpc, &p, rooted)?;
    ensure!(
        rejected == bound,
        "rejected campaign Execute changed finalized accounts"
    );
    let good = p.execute(&current_wire)?;
    transport::send(
        &rpc,
        &admin,
        None,
        good.clone(),
        &format!("v3-campaign-valid-{mode}"),
        None,
        &mut events,
    )?;
    transport::send(
        &rpc,
        &admin,
        None,
        good,
        &format!("v3-campaign-replay-{mode}"),
        Some(zk_fresh_program::application_v3::AppError::Consumed as u64),
        &mut events,
    )?;
    let rooted = transport::wait_finalized(&rpc, &events)?;
    let (finalized_slot, after) = finalized_accounts(&rpc, &p, rooted)?;
    let mut expected_request = r.clone();
    expected_request.state = RequestState::Consumed;
    let mut expected_queue = q.clone();
    expected_queue.entries.push(a.request);
    ensure!(
        after[0] == bound[0]
            && after[1] == bound[1]
            && after[2] == bound[2]
            && after[3] == expected_request.encode()
            && after[4] == expected_queue.encode(),
        "campaign proof must append and consume exactly once"
    );
    let (program_after, genesis_after, loaded_after) = transport::domain(&rpc)?;
    ensure!(
        program_after == program && genesis_after == genesis && loaded_after == loaded,
        "loaded program identity changed across campaign effect"
    );
    for (index, name) in ["config", "issuer", "head", "request", "queue"]
        .iter()
        .enumerate()
    {
        transport::new_file(&output.join(format!("{name}.bin")), &after[index])?;
    }
    transport::new_json(
        &output.join("effect-report.json"),
        &json!({
            "schema":"part5-v3-campaign-effect-v1", "passed":true,
            "training_only":true,"devnet":false,"mode":mode,"target_count":count,
            "registry_history_authenticated":true,"allocation_history_authenticated":true,
            "upstream_source_authentication":true,"upstream_publisher_authentication":true,
            "application_effect":true,"effect_count":1,"request_consumed":true,
            "stale_r0_rejected":count > 0 && mode != "coalesced-full",
            "stage_report_sha256":stage_sha,"stage_plan_sha256":plan_sha,
            "transition_report_sha256":transition_sha,"context_sha256":context_sha,
            "signed_history_sha256":final_report["signed_history_sha256"],
            "base_wire_sha256":base_wire.as_ref().map(|(digest, _)| digest),
            "current_wire_sha256":current_sha,
            "effect_signed_source_sha256":hex::encode(Sha256::digest(&source_json)),
            "effect_signed_publisher_sha256":hex::encode(Sha256::digest(&publisher_json)),
            "effect_enrolled_source_sha256":hex::encode(Sha256::digest(&enrolled_json)),
            "program":Pubkey::new_from_array(program).to_string(),
            "genesis":Hash::new_from_array(genesis).to_string(),
            "loaded_program":loaded_after,"base_root":hex::encode(schedule.roots[0]),
            "current_root":hex::encode(schedule.roots[count]),
            "source_sequence":sequence,"source_head_digest":hex::encode(source_digest),
            "publication_sequence":next_publication,
            "publisher_envelope_digest":hex::encode(envelope_digest),
            "previous_finalized_slot":final_slot,"bound_finalized_slot":bound_slot,
            "finalized_slot":finalized_slot,
            "account_sha256":after.iter().map(|data|
                hex::encode(Sha256::digest(data))).collect::<Vec<_>>(),
            "transactions":events,
        }),
    )?;
    Ok(())
}
