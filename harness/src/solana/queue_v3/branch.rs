//! Restart a byte-pinned R1 request in one of two isolated local ledger branches.
use super::*;
use credential_registry::v3::protocol::{
    Change, EnrolledSource, IssuerScope, Observation, Scope, SignedSource, SourceHead,
    SOURCE_SIGN_TAG,
};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

fn private_dir(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && fs::canonicalize(path)? == path
            && meta.is_dir()
            && meta.permissions().mode() & 0o7777 == 0o700
            && meta.uid() == unsafe { libc::geteuid() },
        "canonical owner-only v3 branch directory required"
    );
    Ok(())
}

fn report_accounts(root: &Path, report: &Value) -> Result<[Vec<u8>; 5]> {
    let hashes = report["account_sha256"]
        .as_array()
        .context("five pinned branch account hashes")?;
    ensure!(hashes.len() == 5, "five branch accounts required");
    let mut result = Vec::with_capacity(5);
    for (index, name) in ["config", "issuer", "head", "request", "queue"]
        .iter()
        .enumerate()
    {
        result.push(transport::pinned(
            &root.join(format!("{name}.bin")),
            hashes[index].as_str().context("branch account hash")?,
            4096,
        )?);
    }
    result
        .try_into()
        .map_err(|_| anyhow::anyhow!("account width"))
}

fn sign_and_bind(
    rpc: &Rpc,
    p: &V3QueuePlan,
    initial: &[Vec<u8>; 5],
    c: &Config,
    i: &Issuer,
    h: &PublisherHead,
    target_root: [u8; 32],
    revocation: Option<[u8; 32]>,
    stage_root: &Path,
    output: &Path,
) -> Result<(u64, [Vec<u8>; 5], Vec<Value>, [u8; 32])> {
    let a = p.addresses();
    let admin = transport::load_key(stage_root, "admin.json", p.admin)?;
    let publisher = transport::load_key(stage_root, "publisher.json", p.publisher)?;
    let source = transport::load_key(stage_root, "source.json", p.source)?;
    let deadline = Instant::now() + Duration::from_secs(20);
    let observed = loop {
        let candidate = transport::clock(rpc)?;
        if candidate > i.observed_at {
            break candidate;
        }
        ensure!(Instant::now() < deadline, "new signed observation deadline");
        thread::sleep(Duration::from_millis(250));
    };
    let expires = observed
        .checked_add(180)
        .context("source expiry overflow")?;
    let sequence = i
        .sequence
        .checked_add(1)
        .context("source sequence overflow")?;
    let scope = Scope {
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
    };
    let issuer = IssuerScope {
        issuer_account: a.issuer.to_bytes(),
        issuer_hash: i.issuer_hash,
        source_key: p.source,
        issuer_eligibility_epoch: i.eligibility_epoch,
        enrollment_evidence_version: i.enrollment_version,
        evidence_digest: i.evidence_digest,
    };
    let enrolled = EnrolledSource {
        scope: scope.clone(),
        issuer: issuer.clone(),
        config_enabled: c.enabled,
        issuer_enabled: i.enabled,
        max_age_seconds: 180,
    };
    let observation = Observation {
        scope,
        issuer,
        sequence,
        previous_digest: i.digest,
        observed_at: observed,
        valid_until: expires,
        issuer_status_active: true,
        changes: revocation
            .map(|tbs_digest| Change::Revoke { tbs_digest })
            .into_iter()
            .collect(),
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
        .map_err(|e| anyhow::anyhow!("signed source successor {e:?}"))?
        .head()
        .digest;
    transport::new_json(&output.join("signed-source.json"), &signed)?;
    transport::new_json(&output.join("enrolled-source.json"), &enrolled)?;
    let publishing = target_root != c.root;
    ensure!(
        publishing == revocation.is_some(),
        "revocation/root step mismatch"
    );
    let mut expected_config = c.clone();
    let mut events = Vec::new();
    if publishing {
        expected_config
            .publish(
                Authority {
                    key: publisher.pubkey(),
                    is_signer: true,
                },
                c.root_version,
                target_root,
            )
            .map_err(|e| anyhow::anyhow!("pure own-root publish {e:?}"))?;
        transport::send(
            rpc,
            &admin,
            Some(&publisher),
            p.publish(c.root_version, target_root),
            "v3-publish-own-revocation",
            None,
            &mut events,
        )?;
    }
    transport::send(
        rpc,
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
        if publishing {
            "v3-observe-signed-own-revocation"
        } else {
            "v3-observe-signed-current-status"
        },
        None,
        &mut events,
    )?;
    let next_publication = h
        .publication_sequence
        .checked_add(1)
        .context("head sequence overflow")?;
    let envelope_digest: [u8; 32] = Sha256::digest(
        [
            b"part5-v3-r1-branch-head-v1".as_slice(),
            &target_root,
            &source_digest,
            &h.envelope_digest,
            &observed.to_be_bytes(),
        ]
        .concat(),
    )
    .into();
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
        rpc,
        &admin,
        Some(&publisher),
        p.bind_with_head(&binding),
        "v3-bind-current-branch-head",
        None,
        &mut events,
    )?;
    let rooted = transport::wait_finalized(rpc, &events)?;
    let (slot, after) = finalized_accounts(rpc, p, rooted)?;
    let next_issuer = Issuer::decode(&after[1]).map_err(|e| anyhow::anyhow!("issuer {e:?}"))?;
    let next_head = PublisherHead::decode(&after[2]).map_err(|e| anyhow::anyhow!("head {e:?}"))?;
    next_issuer
        .fresh(&expected_config, transport::clock(rpc)?)
        .map_err(|e| anyhow::anyhow!("fresh issuer {e:?}"))?;
    next_issuer
        .binding_current(&expected_config)
        .map_err(|e| anyhow::anyhow!("bound issuer {e:?}"))?;
    ensure!(
        after[0] == expected_config.encode()
            && after[3] == initial[3]
            && after[4] == initial[4]
            && next_issuer.sequence == sequence
            && next_issuer.digest == source_digest
            && next_issuer.observed_at == observed
            && next_issuer.expires_at == expires
            && next_issuer.bound_root == target_root
            && next_issuer.bound_root_version == expected_config.root_version
            && next_head.publication_sequence == next_publication
            && next_head.previous_publication_digest == h.envelope_digest
            && next_head.envelope_digest == envelope_digest
            && next_head.root == target_root
            && next_head.root_version == expected_config.root_version
            && next_head.source_sequence == sequence
            && next_head.source_digest == source_digest,
        "signed successor differs from finalized config/status/head"
    );
    Ok((slot, after, events, source_digest))
}

/// The external bounded supervisor owns the restarted validator and verifies
/// loaded identity and saved account bytes independently after this test exits.
pub fn branch_from_env() -> Result<()> {
    let mode = transport::env("P5_V3_BRANCH_MODE")?;
    ensure!(mode == "anchor" || mode == "own-revocation", "branch mode");
    let output = transport::output()?;
    ensure!(
        fs::read_dir(&output)?.next().is_none(),
        "fresh branch output"
    );
    let stage_root = PathBuf::from(transport::env("P5_V3_STAGE_ROOT")?);
    let transition_root = PathBuf::from(transport::env("P5_V3_TRANSITION_ROOT")?);
    private_dir(&stage_root)?;
    private_dir(&transition_root)?;
    let stage_sha = transport::env("P5_V3_STAGE_REPORT_SHA256")?;
    let plan_sha = transport::env("P5_V3_STAGE_PLAN_SHA256")?;
    let transition_sha = transport::env("P5_V3_TRANSITION_REPORT_SHA256")?;
    let stage_report: Value = serde_json::from_slice(&transport::pinned(
        &stage_root.join("stage-report.json"),
        &stage_sha,
        65536,
    )?)?;
    let p: V3QueuePlan = serde_json::from_slice(&transport::pinned(
        &stage_root.join("plan.json"),
        &plan_sha,
        8192,
    )?)?;
    let transition: Value = serde_json::from_slice(&transport::pinned(
        &transition_root.join("transition-report.json"),
        &transition_sha,
        65536,
    )?)?;
    let (context, near_root) = transition_context()?;
    let (certificate, base_root, issuer_hash, policy_id, aki, evidence_digest) =
        training_context()?;
    let rpc = transport::local_rpc()?;
    let (program, genesis, loaded) = transport::domain(&rpc)?;
    let a = p.addresses();
    ensure!(
        p.program == program
            && p.genesis == genesis
            && stage_report["schema"] == "part5-v3-local-stage-v1"
            && stage_report["passed"] == true
            && stage_report["plan_sha256"] == plan_sha
            && transition["schema"] == "part5-v3-unrelated-local-transition-v1"
            && transition["passed"] == true
            && transition["request_unconsumed"] == true
            && transition["upstream_source_authentication"] == true
            && transition["stage_report_sha256"] == stage_sha
            && transition["stage_plan_sha256"] == plan_sha
            && transition["base_root"] == context.base_root
            && transition["near_root"] == context.near_root
            && transition["loaded_program"]["elf_sha256"] == transport::env("P5_QUEUE_ELF_SHA256")?
            && transition["loaded_program"]["elf_match"] == true
            && transition["program"] == Pubkey::new_from_array(program).to_string()
            && transition["genesis"] == Hash::new_from_array(genesis).to_string()
            && context.stage_report_sha256 == stage_sha
            && p.root == base_root
            && p.issuer_hash == issuer_hash
            && p.policy_id == policy_id,
        "reviewed exact R1 source, package and application identity"
    );
    let minimum_slot = transition["finalized_slot"].as_u64().context("R1 slot")?;
    ensure!(minimum_slot > 0, "nonzero R1 finality");
    let saved = report_accounts(&transition_root, &transition)?;
    let (_, initial) = finalized_accounts(&rpc, &p, minimum_slot)?;
    ensure!(
        initial == saved,
        "restarted R1 accounts differ from saved bytes"
    );
    let c = Config::decode(&initial[0]).map_err(|e| anyhow::anyhow!("config {e:?}"))?;
    let i = Issuer::decode(&initial[1]).map_err(|e| anyhow::anyhow!("issuer {e:?}"))?;
    let h = PublisherHead::decode(&initial[2]).map_err(|e| anyhow::anyhow!("head {e:?}"))?;
    let r = Request::decode(&initial[3]).map_err(|e| anyhow::anyhow!("request {e:?}"))?;
    let q = Queue::decode(&initial[4]).map_err(|e| anyhow::anyhow!("queue {e:?}"))?;
    ensure!(
        c.root == near_root
            && c.root_version == 1
            && c.enabled
            && c.policy_id == policy_id
            && i.config == a.config
            && i.issuer_hash == issuer_hash
            && i.aki == aki
            && i.evidence_digest == evidence_digest
            && i.enabled
            && i.status_valid
            && i.sequence == 2
            && h.config == a.config
            && h.issuer == a.issuer
            && h.root == near_root
            && h.root_version == 1
            && h.source_sequence == i.sequence
            && h.source_digest == i.digest
            && r.state == RequestState::Finalized
            && q.entries.is_empty(),
        "exact R1 policy, signed status, head and unconsumed request required"
    );
    let base_wire = transport::pinned(
        Path::new(&transport::env("P5_V3_FULL_WIRE")?),
        &transport::env("P5_V3_FULL_WIRE_SHA256")?,
        448,
    )?;
    let anchor_wire = transport::pinned(
        Path::new(&transport::env("P5_V3_ANCHOR_WIRE")?),
        &transport::env("P5_V3_ANCHOR_WIRE_SHA256")?,
        448,
    )?;
    let base_config = Config::decode(&transport::pinned(
        &stage_root.join("config.bin"),
        stage_report["account_sha256"][0]
            .as_str()
            .context("R0 config hash")?,
        4096,
    )?)
    .map_err(|e| anyhow::anyhow!("R0 config {e:?}"))?;
    validate_full_wire(
        &p,
        &base_config,
        &r,
        certificate.not_before,
        certificate.not_after,
        &base_wire,
    )?;
    let mut near_plan = p.clone();
    near_plan.root = near_root;
    validate_full_wire(
        &near_plan,
        &c,
        &r,
        certificate.not_before,
        certificate.not_after,
        &anchor_wire,
    )?;
    ensure!(
        base_wire[32..192] == anchor_wire[32..192],
        "same issuer, validity, action, policy"
    );
    let own = transport::unhex(&context.own_tbs_digest)?;
    let unrelated = transport::unhex(&context.unrelated_tbs_digest)?;
    let target_root = if mode == "own-revocation" {
        own_revocation_root(own, unrelated, context.slot)?
    } else {
        near_root
    };
    ensure!(
        target_root != base_root && (mode == "anchor" || target_root != near_root),
        "distinct root for branch"
    );
    let (bound_slot, bound, mut events, source_digest) = sign_and_bind(
        &rpc,
        &p,
        &initial,
        &c,
        &i,
        &h,
        target_root,
        if mode == "own-revocation" {
            Some(own)
        } else {
            None
        },
        &stage_root,
        &output,
    )?;
    let admin = transport::load_key(&stage_root, "admin.json", p.admin)?;
    transport::send(
        &rpc,
        &admin,
        None,
        p.execute(&base_wire)?,
        "v3-stale-R0-full",
        Some(zk_fresh_program::application_v3::AppError::Policy as u64),
        &mut events,
    )?;
    let mut effect = false;
    if mode == "anchor" {
        let mut wrong_action = anchor_wire.clone();
        wrong_action[128..160].fill(0);
        if wrong_action[128..160] == anchor_wire[128..160] {
            wrong_action[159] = 1;
        }
        transport::send(
            &rpc,
            &admin,
            None,
            p.execute(&wrong_action)?,
            "v3-anchor-wrong-action",
            Some(zk_fresh_program::application_v3::AppError::Action as u64),
            &mut events,
        )?;
        let mut wrong_proof = anchor_wire.clone();
        wrong_proof[192..].fill(0);
        transport::send(
            &rpc,
            &admin,
            None,
            p.execute(&wrong_proof)?,
            "v3-anchor-invalid-proof",
            Some(zk_fresh_program::application_v3::AppError::Proof as u64),
            &mut events,
        )?;
        let rooted = transport::wait_finalized(&rpc, &events)?;
        let (_, rejected) = finalized_accounts(&rpc, &p, rooted)?;
        ensure!(rejected == bound, "negative proof changed R1 branch");
        let good = p.execute(&anchor_wire)?;
        transport::send(
            &rpc,
            &admin,
            None,
            good.clone(),
            "v3-valid-anchor-R1",
            None,
            &mut events,
        )?;
        transport::send(
            &rpc,
            &admin,
            None,
            good,
            "v3-anchor-replay",
            Some(zk_fresh_program::application_v3::AppError::Consumed as u64),
            &mut events,
        )?;
        effect = true;
    } else {
        transport::send(
            &rpc,
            &admin,
            None,
            p.execute(&anchor_wire)?,
            "v3-own-revoked-R1-anchor",
            Some(zk_fresh_program::application_v3::AppError::Policy as u64),
            &mut events,
        )?;
    }
    let rooted = transport::wait_finalized(&rpc, &events)?;
    let (finalized_slot, after) = finalized_accounts(&rpc, &p, rooted)?;
    if effect {
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
            "refreshed Anchor must append and consume exactly once"
        );
    } else {
        ensure!(
            after == bound,
            "own-revoked Execute changed finalized request or queue"
        );
    }
    let (program_after, genesis_after, loaded_after) = transport::domain(&rpc)?;
    ensure!(
        program_after == program
            && genesis_after == genesis
            && [
                "program",
                "programdata",
                "elf_sha256",
                "program_account_sha256",
                "programdata_account_sha256"
            ]
            .iter()
            .all(|key| loaded_after[*key] == loaded[*key]),
        "loaded identity changed across branch"
    );
    for (index, name) in ["config", "issuer", "head", "request", "queue"]
        .iter()
        .enumerate()
    {
        transport::new_file(&output.join(format!("{name}.bin")), &after[index])?;
    }
    transport::new_json(
        &output.join("branch-report.json"),
        &json!({
            "schema":"part5-v3-r1-branch-v1", "passed":true, "mode":mode,
            "training_only":true, "devnet":false,
            "upstream_source_authentication":true,
            "registry_history_authenticated":false,
            "application_effect":effect, "effect_count":u8::from(effect),
            "request_consumed":effect, "request_unconsumed":!effect,
            "stage_report_sha256":stage_sha, "stage_plan_sha256":plan_sha,
            "transition_report_sha256":transition_sha,
            "program":Pubkey::new_from_array(program).to_string(),
            "genesis":Hash::new_from_array(genesis).to_string(),
            "loaded_program":loaded_after,
            "base_root":hex::encode(base_root), "near_root":hex::encode(near_root),
            "current_root":hex::encode(target_root),
            "source_head_digest":hex::encode(source_digest),
            "previous_finalized_slot":minimum_slot, "bound_finalized_slot":bound_slot,
            "finalized_slot":finalized_slot,
            "account_sha256":after.iter().map(|data| hex::encode(Sha256::digest(data))).collect::<Vec<_>>(),
            "transactions":events,
        }),
    )?;
    Ok(())
}
