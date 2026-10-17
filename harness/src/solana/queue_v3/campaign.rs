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
