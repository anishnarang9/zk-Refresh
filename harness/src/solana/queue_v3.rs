//! Independent v3 local transaction encodings for the bounded queue demo.
//! Constructing an instruction or PDA does not authenticate current chain state.
use super::queue_v2 as transport;
use super::*;
use zk_fresh_program::application_v3::{
    Authority, Config, Issuer, PublisherHead, Queue, Request, RequestState, CONFIG_LEN, HEAD_LEN,
    ISSUER_LEN, QUEUE_LEN, REQUEST_LEN,
};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TrainingContext {
    schema: String,
    training_only: bool,
    root: String,
    issuer_hash: String,
    policy_id: String,
    aki: String,
    evidence_digest: String,
    not_before: i64,
    not_after: i64,
}

fn training_context() -> Result<(
    TrainingContext,
    [u8; 32],
    [u8; 32],
    [u8; 32],
    [u8; 32],
    [u8; 32],
)> {
    let raw = transport::pinned(
        Path::new(&transport::env("P5_V3_CONTEXT")?),
        &transport::env("P5_V3_CONTEXT_SHA256")?,
        8192,
    )?;
    parse_training_context(&raw)
}

fn parse_training_context(
    raw: &[u8],
) -> Result<(
    TrainingContext,
    [u8; 32],
    [u8; 32],
    [u8; 32],
    [u8; 32],
    [u8; 32],
)> {
    let context: TrainingContext = serde_json::from_slice(&raw)?;
    ensure!(
        context.schema == "part5-v3-local-training-context-v1"
            && context.training_only
            && context.not_before >= 0
            && context.not_before < context.not_after,
        "bounded v3 training context required"
    );
    let root = transport::unhex(&context.root)?;
    let issuer_hash = transport::unhex(&context.issuer_hash)?;
    let policy_id = transport::unhex(&context.policy_id)?;
    let aki = transport::unhex(&context.aki)?;
    let evidence_digest = transport::unhex(&context.evidence_digest)?;
    ensure!(
        aki[20..] == [0; 12] && evidence_digest != [0; 32],
        "signed AKI/evidence shape"
    );
    Ok((context, root, issuer_hash, policy_id, aki, evidence_digest))
}

fn finalized_accounts(
    rpc: &Rpc,
    p: &V3QueuePlan,
    minimum_slot: u64,
) -> Result<(u64, [Vec<u8>; 5])> {
    let a = p.addresses();
    let keys = [a.config, a.issuer, a.head, a.request, a.queue];
    let sizes = [CONFIG_LEN, ISSUER_LEN, HEAD_LEN, REQUEST_LEN, QUEUE_LEN];
    let genesis_before = rpc.call("getGenesisHash", json!([]))?;
    ensure!(
        genesis_before.as_str() == Some(transport::env("P5_QUEUE_GENESIS")?.as_str()),
        "local genesis changed before account read"
    );
    let result = rpc.call(
        "getMultipleAccounts",
        json!([keys.iter().map(ToString::to_string).collect::<Vec<_>>(),
            {"encoding":"base64","commitment":"finalized","minContextSlot":minimum_slot}]),
    )?;
    let slot = result["context"]["slot"]
        .as_u64()
        .context("finalized batch slot")?;
    ensure!(
        slot >= minimum_slot,
        "finalized account batch predates staging"
    );
    let values = result["value"]
        .as_array()
        .context("finalized account batch")?;
    ensure!(
        values.len() == keys.len(),
        "complete finalized account batch required"
    );
    let mut bytes = Vec::with_capacity(keys.len());
    for (index, value) in values.iter().enumerate() {
        ensure!(
            value["owner"] == Pubkey::new_from_array(p.program).to_string()
                && value["executable"] == false
                && value["data"][1] == "base64",
            "finalized account owner/encoding mismatch"
        );
        let encoded = value["data"][0]
            .as_str()
            .context("finalized account bytes missing")?;
        ensure!(encoded.len() <= 4096, "finalized account byte cap");
        let data = STANDARD.decode(encoded)?;
        ensure!(
            data.len() == sizes[index],
            "finalized account length mismatch"
        );
        bytes.push(data);
    }
    ensure!(
        rpc.call("getGenesisHash", json!([]))? == genesis_before,
        "local genesis changed during account read"
    );
    Ok((
        slot,
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("batch width"))?,
    ))
}

fn validate_full_wire(
    plan: &V3QueuePlan,
    config: &Config,
    request: &Request,
    not_before: i64,
    not_after: i64,
    wire: &[u8],
) -> Result<()> {
    ensure!(
        not_before >= 0 && not_before < not_after,
        "signed validity interval"
    );
    ensure!(
        config.root == plan.root
            && config.policy_id == plan.policy_id
            && config.genesis == plan.genesis
            && config.seed == plan.seed
            && request.config == plan.addresses().config
            && request.creator == Pubkey::new_from_array(plan.creator)
            && request.nonce == plan.nonce
            && request.issuer_hash == plan.issuer_hash
            && request.recipient == Pubkey::new_from_array(plan.recipient)
            && request.deadline == plan.deadline
            && request.payload == plan.payload
            && request.state == RequestState::Finalized,
        "exact staged request context required"
    );
    let epoch_word = |seconds: i64| -> Result<[u8; 32]> {
        let mut result = [0; 32];
        result[24..].copy_from_slice(&u64::try_from(seconds)?.to_be_bytes());
        Ok(result)
    };
    let expected = [
        plan.root,
        plan.issuer_hash,
        epoch_word(not_before)?,
        epoch_word(not_after)?,
        zk_fresh_program::application_v3::action_hash(
            &Pubkey::new_from_array(plan.program),
            config,
            request,
        )
        .map_err(|e| anyhow::anyhow!("action derivation {e:?}"))?,
        plan.policy_id,
    ];
    let instruction = plan.execute(wire)?;
    ensure!(
        instruction.data[2..194]
            == expected
                .iter()
                .flat_map(|word| word.iter().copied())
                .collect::<Vec<_>>(),
        "Full proof statement differs from staged request"
    );
    Ok(())
}

/// Prepare one training request through the loaded SBF program. The external
/// supervisor authenticates the live validator, bounds this child and owns it.
/// This function does not create or verify a proof or authorize an Execute.
pub fn stage_from_env() -> Result<()> {
    ensure!(
        transport::env("P5_V3_STAGE_SCOPE")? == "part5-v3-local-stage",
        "explicit v3 local stage scope required"
    );
    let output = transport::output()?;
    ensure!(
        fs::read_dir(&output)?.next().is_none(),
        "fresh private output required"
    );
    let rpc = transport::local_rpc()?;
    let (program, genesis, loaded) = transport::domain(&rpc)?;
    let (context, root, issuer_hash, policy_id, aki, evidence_digest) = training_context()?;
    let now = transport::clock(&rpc)?;
    ensure!(
        now >= context.not_before && now < context.not_after,
        "training certificate currently valid"
    );
    let admin = transport::keys(&output, "admin.json")?;
    let publisher = transport::keys(&output, "publisher.json")?;
    let source = transport::keys(&output, "source.json")?;
    let creator = transport::keys(&output, "creator.json")?;
    let p = V3QueuePlan {
        program,
        genesis,
        admin: admin.pubkey().to_bytes(),
        publisher: publisher.pubkey().to_bytes(),
        source: source.pubkey().to_bytes(),
        creator: creator.pubkey().to_bytes(),
        seed: random_bytes(),
        nonce: random_bytes(),
        recipient: source.pubkey().to_bytes(),
        issuer_hash,
        aki,
        root,
        policy_id,
        deadline: (now + 86_400).min(context.not_after),
        payload: vec![0, 1, 2, 3],
    };
    ensure!(p.deadline > now, "positive request lifetime required");
    let a = p.addresses();
    let mut funding = Vec::new();
    for key in [&admin, &publisher, &creator] {
        let signature = rpc.call(
            "requestAirdrop",
            json!([key.pubkey().to_string(), 2_000_000_000u64]),
        )?;
        let signature = signature.as_str().context("airdrop signature missing")?;
        let record = rpc.confirmed_transaction(signature)?;
        ensure!(record["meta"]["err"].is_null(), "training funding failed");
        funding.push(signature.to_owned());
    }
    let mut events = Vec::new();
    transport::send(
        &rpc,
        &admin,
        None,
        p.initialize(),
        "v3-initialize",
        None,
        &mut events,
    )?;
    transport::send(
        &rpc,
        &admin,
        None,
        p.enroll(1, evidence_digest),
        "v3-enroll",
        None,
        &mut events,
    )?;
    transport::send(
        &rpc,
        &admin,
        Some(&creator),
        p.create()?,
        "v3-create",
        None,
        &mut events,
    )?;
    for (index, chunk) in p.payload.chunks(512).enumerate() {
        transport::send(
            &rpc,
            &admin,
            Some(&creator),
            p.upload_payload(index * 512, chunk)?,
            "v3-upload-payload",
            None,
            &mut events,
        )?;
    }
    transport::send(
        &rpc,
        &admin,
        Some(&creator),
        p.upload_metas(),
        "v3-upload-metas",
        None,
        &mut events,
    )?;
    transport::send(
        &rpc,
        &admin,
        Some(&creator),
        p.finalize(),
        "v3-finalize",
        None,
        &mut events,
    )?;
    let observed = transport::clock(&rpc)?;
    let source_digest: [u8; 32] = Sha256::digest(
        [
            b"part5-v3-local-source-training-v1".as_slice(),
            &root,
            &issuer_hash,
            &evidence_digest,
            &observed.to_be_bytes(),
        ]
        .concat(),
    )
    .into();
    transport::send(
        &rpc,
        &admin,
        Some(&source),
        p.observe(0, 0, 0, 1, source_digest, true, observed, observed + 240),
        "v3-observe-active",
        None,
        &mut events,
    )?;
    let envelope_digest: [u8; 32] = Sha256::digest(
        [
            b"part5-v3-local-head-training-v1".as_slice(),
            &root,
            &source_digest,
        ]
        .concat(),
    )
    .into();
    let binding = V3HeadBinding {
        expected_config_epoch: 0,
        expected_issuer_epoch: 0,
        expected_root: root,
        expected_root_version: 0,
        expected_source_sequence: 1,
        expected_source_digest: source_digest,
        expected_publication_sequence: 0,
        expected_publication_digest: [0; 32],
        next_publication_sequence: 1,
        envelope_digest,
    };
    transport::send(
        &rpc,
        &admin,
        Some(&publisher),
        p.bind_with_head(&binding),
        "v3-bind-head",
        None,
        &mut events,
    )?;
    let rooted = transport::wait_finalized(&rpc, &events)?;
    let (finalized_slot, bytes) = finalized_accounts(&rpc, &p, rooted)?;
    let c = Config::decode(&bytes[0]).map_err(|e| anyhow::anyhow!("config codec {e:?}"))?;
    let i = Issuer::decode(&bytes[1]).map_err(|e| anyhow::anyhow!("issuer codec {e:?}"))?;
    let h = PublisherHead::decode(&bytes[2]).map_err(|e| anyhow::anyhow!("head codec {e:?}"))?;
    let r = Request::decode(&bytes[3]).map_err(|e| anyhow::anyhow!("request codec {e:?}"))?;
    let q = Queue::decode(&bytes[4]).map_err(|e| anyhow::anyhow!("queue codec {e:?}"))?;
    let checked_at = transport::clock(&rpc)?;
    i.fresh(&c, checked_at)
        .map_err(|e| anyhow::anyhow!("issuer currentness {e:?}"))?;
    i.binding_current(&c)
        .map_err(|e| anyhow::anyhow!("issuer binding {e:?}"))?;
    ensure!(
        c.admin == admin.pubkey()
            && c.publisher == publisher.pubkey()
            && c.seed == p.seed
            && c.genesis == genesis
            && c.root == root
            && c.policy_id == policy_id
            && c.root_version == 0
            && c.enabled
            && i.config == a.config
            && i.issuer_hash == issuer_hash
            && i.aki == aki
            && i.source == source.pubkey()
            && i.sequence == 1
            && i.digest == source_digest
            && i.observed_at == observed
            && i.expires_at == observed + 240
            && i.status_valid
            && i.enrollment_version == 1
            && i.evidence_digest == evidence_digest
            && i.observed_config_epoch == 0
            && i.observed_issuer_epoch == 0
            && i.eligibility_epoch == 0
            && i.bound_root == root
            && i.bound_root_version == 0
            && i.bound_source_sequence == 1
            && i.bound_source_digest == source_digest
            && h.config == a.config
            && h.issuer == a.issuer
            && h.publisher == publisher.pubkey()
            && h.publication_sequence == 1
            && h.envelope_digest == envelope_digest
            && h.previous_publication_digest == [0; 32]
            && h.root == root
            && h.root_version == 0
            && h.source_sequence == 1
            && h.source_digest == source_digest
            && h.config_epoch == 0
            && h.issuer_epoch == 0
            && h.committed_at >= observed
            && h.committed_at <= checked_at
            && r.config == a.config
            && r.creator == creator.pubkey()
            && r.nonce == p.nonce
            && r.issuer_hash == issuer_hash
            && r.recipient == source.pubkey()
            && r.deadline == p.deadline
            && r.request_type == 1
            && r.state == RequestState::Finalized
            && r.payload == p.payload
            && r.payload_len as usize == p.payload.len()
            && r.uploaded == r.payload_len
            && r.metas_uploaded == 2
            && r.metas.len() == 2
            && r.metas[0].key == a.request
            && r.metas[1].key == a.queue
            && r.metas
                .iter()
                .all(|m| m.flags == 2 && m.owner == Pubkey::new_from_array(program))
            && q.config == a.config
            && q.entries.is_empty(),
        "finalized v3 account state differs from exact prepared request"
    );
    transport::new_json(&output.join("plan.json"), &p)?;
    for (name, data) in [
        ("config.bin", &bytes[0]),
        ("issuer.bin", &bytes[1]),
        ("head.bin", &bytes[2]),
        ("request.bin", &bytes[3]),
        ("queue.bin", &bytes[4]),
    ] {
        transport::new_file(&output.join(name), data)?;
    }
    transport::new_json(
        &output.join("stage-report.json"),
        &json!({
            "schema":"part5-v3-local-stage-v1", "passed":true,
            "training_only":true,"upstream_source_authentication":false,
            "proof_created":false,"application_effect":false,"devnet":false,
            "program":Pubkey::new_from_array(program).to_string(),
            "genesis":Hash::new_from_array(genesis).to_string(),"loaded_program":loaded,
            "finalized_slot":finalized_slot,"config":a.config.to_string(),
            "issuer":a.issuer.to_string(),"head":a.head.to_string(),
            "request":a.request.to_string(),"queue":a.queue.to_string(),
            "plan_sha256":hex::encode(Sha256::digest(fs::read(output.join("plan.json"))?)),
            "account_sha256":bytes.iter().map(|data| hex::encode(Sha256::digest(data))).collect::<Vec<_>>(),
            "funding_signatures":funding,"transactions":events,
        }),
    )?;
    Ok(())
}

/// Consume one exact staged request with a genuine request-bound Full proof.
/// The supervisor must independently reattest the persistent local ledger and
/// finalized account bytes before starting this child and after it returns.
pub fn execute_from_env() -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    ensure!(
        transport::env("P5_V3_EXEC_SCOPE")? == "part5-v3-local-execute",
        "explicit local Full Execute scope required"
    );
    let output = transport::output()?;
    ensure!(
        fs::read_dir(&output)?.next().is_none(),
        "fresh Execute output required"
    );
    let stage_root = PathBuf::from(transport::env("P5_V3_STAGE_ROOT")?);
    let stage_meta = fs::symlink_metadata(&stage_root)?;
    ensure!(
        stage_root.is_absolute()
            && fs::canonicalize(&stage_root)? == stage_root
            && stage_meta.is_dir()
            && stage_meta.permissions().mode() & 0o7777 == 0o700
            && stage_meta.uid() == unsafe { libc::geteuid() },
        "canonical private staged request required"
    );
    let report_sha = transport::env("P5_V3_STAGE_REPORT_SHA256")?;
    let plan_sha = transport::env("P5_V3_STAGE_PLAN_SHA256")?;
    let report_raw = transport::pinned(&stage_root.join("stage-report.json"), &report_sha, 65536)?;
    let report: Value = serde_json::from_slice(&report_raw)?;
    let plan_raw = transport::pinned(&stage_root.join("plan.json"), &plan_sha, 8192)?;
    let p: V3QueuePlan = serde_json::from_slice(&plan_raw)?;
    let rpc = transport::local_rpc()?;
    let (program, genesis, loaded) = transport::domain(&rpc)?;
    let a = p.addresses();
    ensure!(
        p.program == program
            && p.genesis == genesis
            && report["schema"] == "part5-v3-local-stage-v1"
            && report["passed"] == true
            && report["training_only"] == true
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
        "exact staged application identity required"
    );
    let minimum_slot = report["finalized_slot"]
        .as_u64()
        .context("staged finalized slot")?;
    ensure!(minimum_slot > 0, "nonzero staged finality required");
    let hashes = report["account_sha256"]
        .as_array()
        .context("five staged account hashes")?;
    ensure!(hashes.len() == 5, "five staged account hashes required");
    let mut saved = Vec::with_capacity(5);
    for (index, name) in ["config", "issuer", "head", "request", "queue"]
        .iter()
        .enumerate()
    {
        let digest = hashes[index].as_str().context("staged account hash")?;
        saved.push(transport::pinned(
            &stage_root.join(format!("{name}.bin")),
            digest,
            4096,
        )?);
    }
    let saved: [Vec<u8>; 5] = saved
        .try_into()
        .map_err(|_| anyhow::anyhow!("staged width"))?;
    let (_, initial) = finalized_accounts(&rpc, &p, minimum_slot)?;
    ensure!(
        initial == saved,
        "restarted finalized state differs from staged bytes"
    );
    let c = Config::decode(&initial[0]).map_err(|e| anyhow::anyhow!("config codec {e:?}"))?;
    let i = Issuer::decode(&initial[1]).map_err(|e| anyhow::anyhow!("issuer codec {e:?}"))?;
    let h = PublisherHead::decode(&initial[2]).map_err(|e| anyhow::anyhow!("head codec {e:?}"))?;
    let r = Request::decode(&initial[3]).map_err(|e| anyhow::anyhow!("request codec {e:?}"))?;
    let q = Queue::decode(&initial[4]).map_err(|e| anyhow::anyhow!("queue codec {e:?}"))?;
    let (context, root, issuer_hash, policy_id, aki, evidence_digest) = training_context()?;
    ensure!(
        c.root == root
            && c.policy_id == policy_id
            && c.enabled
            && i.config == a.config
            && i.issuer_hash == issuer_hash
            && i.aki == aki
            && i.evidence_digest == evidence_digest
            && i.status_valid
            && i.enabled
            && h.config == a.config
            && h.issuer == a.issuer
            && r.state == RequestState::Finalized
            && q.entries.is_empty(),
        "staged credential and request context required"
    );
    let wire_sha = transport::env("P5_V3_FULL_WIRE_SHA256")?;
    let wire = transport::pinned(
        Path::new(&transport::env("P5_V3_FULL_WIRE")?),
        &wire_sha,
        448,
    )?;
    validate_full_wire(&p, &c, &r, context.not_before, context.not_after, &wire)?;
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
            "newer source observation deadline"
        );
        thread::sleep(Duration::from_millis(250));
    };
    let expires = observed
        .checked_add(240)
        .context("status expiry overflow")?;
    let next_sequence = i
        .sequence
        .checked_add(1)
        .context("status sequence overflow")?;
    let source_digest: [u8; 32] = Sha256::digest(
        [
            b"part5-v3-local-execute-source-training-v1".as_slice(),
            &root,
            &issuer_hash,
            &evidence_digest,
            &i.digest,
            &next_sequence.to_be_bytes(),
            &observed.to_be_bytes(),
        ]
        .concat(),
    )
    .into();
    ensure!(
        source_digest != i.digest,
        "new signed source digest required"
    );
    let mut events = Vec::new();
    transport::send(
        &rpc,
        &admin,
        Some(&source),
        p.observe(
            c.eligibility_epoch,
            i.eligibility_epoch,
            i.sequence,
            next_sequence,
            source_digest,
            true,
            observed,
            expires,
        ),
        "v3-refresh-active-source",
        None,
        &mut events,
    )?;
    let next_publication = h
        .publication_sequence
        .checked_add(1)
        .context("head sequence overflow")?;
    let envelope_digest: [u8; 32] = Sha256::digest(
        [
            b"part5-v3-local-execute-head-training-v1".as_slice(),
            &root,
            &h.envelope_digest,
            &source_digest,
            &observed.to_be_bytes(),
        ]
        .concat(),
    )
    .into();
    let binding = V3HeadBinding {
        expected_config_epoch: c.eligibility_epoch,
        expected_issuer_epoch: i.eligibility_epoch,
        expected_root: c.root,
        expected_root_version: c.root_version,
        expected_source_sequence: next_sequence,
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
        "v3-bind-refreshed-head",
        None,
        &mut events,
    )?;
    let rooted = transport::wait_finalized(&rpc, &events)?;
    let (_, bound) = finalized_accounts(&rpc, &p, rooted)?;
    let current_issuer =
        Issuer::decode(&bound[1]).map_err(|e| anyhow::anyhow!("issuer codec {e:?}"))?;
    let current_head =
        PublisherHead::decode(&bound[2]).map_err(|e| anyhow::anyhow!("head codec {e:?}"))?;
    let current_time = transport::clock(&rpc)?;
    current_issuer
        .fresh(&c, current_time)
        .map_err(|e| anyhow::anyhow!("issuer freshness {e:?}"))?;
    current_issuer
        .binding_current(&c)
        .map_err(|e| anyhow::anyhow!("issuer binding {e:?}"))?;
    ensure!(
        bound[0] == initial[0]
            && bound[3] == initial[3]
            && bound[4] == initial[4]
            && current_issuer.sequence == next_sequence
            && current_issuer.digest == source_digest
            && current_issuer.expires_at == expires
            && current_head.publication_sequence == next_publication
            && current_head.previous_publication_digest == h.envelope_digest
            && current_head.envelope_digest == envelope_digest
            && current_head.root == c.root
            && current_head.root_version == c.root_version
            && current_head.source_sequence == next_sequence
            && current_head.source_digest == source_digest,
        "finalized refreshed source/head differs from exact signed update"
    );
    let mut wrong_action = wire.clone();
    let mut changed_action = [0; 32];
    changed_action[31] = u8::from(wire[128..160] == [0; 32]);
    wrong_action[128..160].copy_from_slice(&changed_action);
    transport::send(
        &rpc,
        &admin,
        None,
        p.execute(&wrong_action)?,
        "v3-wrong-action",
        Some(zk_fresh_program::application_v3::AppError::Action as u64),
        &mut events,
    )?;
    let mut wrong_proof = wire.clone();
    wrong_proof[192..].fill(0);
    transport::send(
        &rpc,
        &admin,
        None,
        p.execute(&wrong_proof)?,
        "v3-invalid-proof",
        Some(zk_fresh_program::application_v3::AppError::Proof as u64),
        &mut events,
    )?;
    let rooted = transport::wait_finalized(&rpc, &events)?;
    let (_, rejected) = finalized_accounts(&rpc, &p, rooted)?;
    ensure!(
        rejected == bound,
        "rejected Execute changed any finalized account"
    );
    let good = p.execute(&wire)?;
    transport::send(
        &rpc,
        &admin,
        None,
        good.clone(),
        "v3-valid-full-execute",
        None,
        &mut events,
    )?;
    transport::send(
        &rpc,
        &admin,
        None,
        good,
        "v3-replay-new-transaction",
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
        "finalized protected queue effect differs from one append/consumption"
    );
    for (index, name) in ["config", "issuer", "head", "request", "queue"]
        .iter()
        .enumerate()
    {
        transport::new_file(&output.join(format!("{name}.bin")), &after[index])?;
    }
    transport::new_json(
        &output.join("execute-report.json"),
        &json!({
            "schema":"part5-v3-local-execute-v1", "passed":true,
            "training_only":true, "upstream_source_authentication":false,
            "application_effect":true, "effect_count":1, "request_consumed":true,
            "proof_mode":"Full", "devnet":false,
            "program":Pubkey::new_from_array(program).to_string(),
            "genesis":Hash::new_from_array(genesis).to_string(),
            "loaded_program":loaded, "finalized_slot":finalized_slot,
            "stage_report_sha256":report_sha, "stage_plan_sha256":plan_sha,
            "wire_sha256":wire_sha, "source_sequence":next_sequence,
            "publication_sequence":next_publication,
            "account_sha256":after.iter().map(|data| hex::encode(Sha256::digest(data))).collect::<Vec<_>>(),
            "transactions":events,
        }),
    )?;
    Ok(())
}

/// Publish one issuer-signed, same-action unrelated revocation on a separately
/// staged, still unconsumed training request. The external supervisor must
/// independently reattest the loaded ledger and certificate-backed allocation.
pub fn transition_from_env() -> Result<()> {
    use credential_registry::v3::protocol::{
        Change, EnrolledSource, IssuerScope, Observation, Scope, SignedSource, SourceHead,
        SOURCE_SIGN_TAG,
    };
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    ensure!(
        transport::env("P5_V3_TRANSITION_SCOPE")? == "part5-v3-unrelated-transition",
        "explicit unrelated transition scope required"
    );
    let output = transport::output()?;
    ensure!(
        fs::read_dir(&output)?.next().is_none(),
        "fresh transition output required"
    );
    let stage_root = PathBuf::from(transport::env("P5_V3_STAGE_ROOT")?);
    let stage_meta = fs::symlink_metadata(&stage_root)?;
    ensure!(
        stage_root.is_absolute()
            && fs::canonicalize(&stage_root)? == stage_root
            && stage_meta.is_dir()
            && stage_meta.permissions().mode() & 0o7777 == 0o700
            && stage_meta.uid() == unsafe { libc::geteuid() },
        "canonical private staged request required"
    );
    let report_sha = transport::env("P5_V3_STAGE_REPORT_SHA256")?;
    let plan_sha = transport::env("P5_V3_STAGE_PLAN_SHA256")?;
    let report_raw = transport::pinned(&stage_root.join("stage-report.json"), &report_sha, 65536)?;
    let report: Value = serde_json::from_slice(&report_raw)?;
    let plan_raw = transport::pinned(&stage_root.join("plan.json"), &plan_sha, 8192)?;
    let p: V3QueuePlan = serde_json::from_slice(&plan_raw)?;
    let (transition, near_root) = transition_context()?;
    ensure!(
        transition.stage_report_sha256 == report_sha,
        "exact staged transition request"
    );
    let rpc = transport::local_rpc()?;
    let (program, genesis, loaded) = transport::domain(&rpc)?;
    let a = p.addresses();
    ensure!(
        p.program == program
            && p.genesis == genesis
            && report["schema"] == "part5-v3-local-stage-v1"
            && report["passed"] == true
            && report["training_only"] == true
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
        "exact staged application identity required"
    );
    let minimum_slot = report["finalized_slot"]
        .as_u64()
        .context("staged finality")?;
    ensure!(minimum_slot > 0, "nonzero staged finality required");
    let hashes = report["account_sha256"]
        .as_array()
        .context("five staged hashes")?;
    ensure!(hashes.len() == 5, "five staged account hashes required");
    let mut saved = Vec::with_capacity(5);
    for (index, name) in ["config", "issuer", "head", "request", "queue"]
        .iter()
        .enumerate()
    {
        saved.push(transport::pinned(
            &stage_root.join(format!("{name}.bin")),
            hashes[index].as_str().context("staged account hash")?,
            4096,
        )?);
    }
    let saved: [Vec<u8>; 5] = saved
        .try_into()
        .map_err(|_| anyhow::anyhow!("staged width"))?;
    let (_, initial) = finalized_accounts(&rpc, &p, minimum_slot)?;
    ensure!(
        initial == saved,
        "restarted finalized state differs from staged bytes"
    );
    let c = Config::decode(&initial[0]).map_err(|e| anyhow::anyhow!("config {e:?}"))?;
    let i = Issuer::decode(&initial[1]).map_err(|e| anyhow::anyhow!("issuer {e:?}"))?;
    let h = PublisherHead::decode(&initial[2]).map_err(|e| anyhow::anyhow!("head {e:?}"))?;
    let r = Request::decode(&initial[3]).map_err(|e| anyhow::anyhow!("request {e:?}"))?;
    let q = Queue::decode(&initial[4]).map_err(|e| anyhow::anyhow!("queue {e:?}"))?;
    ensure!(
        c.root == p.root
            && c.root == transport::unhex(&transition.base_root)?
            && c.root_version == 0
            && c.enabled
            && i.config == a.config
            && i.issuer_hash == p.issuer_hash
            && i.source == Pubkey::new_from_array(p.source)
            && i.enabled
            && i.status_valid
            && i.sequence == 1
            && h.config == a.config
            && h.issuer == a.issuer
            && h.publisher == Pubkey::new_from_array(p.publisher)
            && h.root == c.root
            && h.root_version == 0
            && r.state == RequestState::Finalized
            && q.entries.is_empty(),
        "staged unconsumed request and source required"
    );
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
            "new observation deadline"
        );
        thread::sleep(Duration::from_millis(250));
    };
    let expires = observed
        .checked_add(180)
        .context("status expiry overflow")?;
    let sequence = i
        .sequence
        .checked_add(1)
        .context("source sequence overflow")?;
    let scope = Scope {
        network: genesis,
        program,
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
        changes: vec![Change::Revoke {
            tbs_digest: transport::unhex(&transition.unrelated_tbs_digest)?,
        }],
    };
    let mut message = SOURCE_SIGN_TAG.to_vec();
    message.extend(serde_json::to_vec(&observation)?);
    let signed = SignedSource {
        observation,
        signature: source.sign_message(&message).as_ref().to_vec(),
    };
    let previous = SourceHead {
        sequence: i.sequence,
        digest: i.digest,
    };
    let verified = signed
        .verify(&enrolled, &previous, observed)
        .map_err(|e| anyhow::anyhow!("signed source revocation {e:?}"))?;
    let source_digest = verified.head().digest;
    ensure!(
        source_digest != i.digest,
        "fresh signed source digest required"
    );
    transport::new_json(&output.join("signed-source.json"), &signed)?;
    transport::new_json(&output.join("enrolled-source.json"), &enrolled)?;
    let mut expected_config = c.clone();
    expected_config
        .publish(
            Authority {
                key: publisher.pubkey(),
                is_signer: true,
            },
            c.root_version,
            near_root,
        )
        .map_err(|e| anyhow::anyhow!("pure root transition {e:?}"))?;
    let mut events = Vec::new();
    transport::send(
        &rpc,
        &admin,
        Some(&publisher),
        p.publish(0, near_root),
        "v3-publish-unrelated-root",
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
        "v3-observe-signed-unrelated-revocation",
        None,
        &mut events,
    )?;
    let next_publication = h
        .publication_sequence
        .checked_add(1)
        .context("publication sequence overflow")?;
    let envelope_digest: [u8; 32] = Sha256::digest(
        [
            b"part5-v3-unrelated-head-training-v1".as_slice(),
            &near_root,
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
        expected_root: near_root,
        expected_root_version: 1,
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
        "v3-bind-unrelated-current-head",
        None,
        &mut events,
    )?;
    let rooted = transport::wait_finalized(&rpc, &events)?;
    let (finalized_slot, after) = finalized_accounts(&rpc, &p, rooted)?;
    let next_issuer = Issuer::decode(&after[1]).map_err(|e| anyhow::anyhow!("issuer {e:?}"))?;
    let next_head = PublisherHead::decode(&after[2]).map_err(|e| anyhow::anyhow!("head {e:?}"))?;
    let checked_at = transport::clock(&rpc)?;
    next_issuer
        .fresh(&expected_config, checked_at)
        .map_err(|e| anyhow::anyhow!("issuer freshness {e:?}"))?;
    next_issuer
        .binding_current(&expected_config)
        .map_err(|e| anyhow::anyhow!("issuer binding {e:?}"))?;
    ensure!(
        after[0] == expected_config.encode()
            && after[3] == initial[3]
            && after[4] == initial[4]
            && next_issuer.sequence == sequence
            && next_issuer.digest == source_digest
            && next_issuer.observed_at == observed
            && next_issuer.expires_at == expires
            && next_issuer.bound_root == near_root
            && next_issuer.bound_root_version == 1
            && next_head.publication_sequence == next_publication
            && next_head.previous_publication_digest == h.envelope_digest
            && next_head.envelope_digest == envelope_digest
            && next_head.root == near_root
            && next_head.root_version == 1
            && next_head.source_sequence == sequence
            && next_head.source_digest == source_digest,
        "finalized signed unrelated transition differs from exact expected state"
    );
    for (index, name) in ["config", "issuer", "head", "request", "queue"]
        .iter()
        .enumerate()
    {
        transport::new_file(&output.join(format!("{name}.bin")), &after[index])?;
    }
    transport::new_json(
        &output.join("transition-report.json"),
        &json!({
            "schema":"part5-v3-unrelated-local-transition-v1", "passed":true,
            "training_only":true, "upstream_source_authentication":true,
            "registry_history_authenticated":false, "application_effect":false,
            "request_unconsumed":true, "devnet":false,
            "program":Pubkey::new_from_array(program).to_string(),
            "genesis":Hash::new_from_array(genesis).to_string(),
            "loaded_program":loaded, "stage_report_sha256":report_sha,
            "stage_plan_sha256":plan_sha, "transition_context_sha256":transport::env("P5_V3_TRANSITION_CONTEXT_SHA256")?,
            "cohort_receipt_sha256":transition.cohort_receipt_sha256,
            "membership_sha256":transition.membership_sha256,
            "source_head_digest":hex::encode(source_digest),
            "base_root":hex::encode(c.root), "near_root":hex::encode(near_root),
            "base_finalized_slot":minimum_slot, "finalized_slot":finalized_slot,
            "account_sha256":after.iter().map(|data| hex::encode(Sha256::digest(data))).collect::<Vec<_>>(),
            "transactions":events,
        }),
    )?;
    Ok(())
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V3QueuePlan {
    pub program: [u8; 32],
    pub genesis: [u8; 32],
    pub admin: [u8; 32],
    pub publisher: [u8; 32],
    pub source: [u8; 32],
    pub creator: [u8; 32],
    pub seed: [u8; 32],
    pub nonce: [u8; 32],
    pub recipient: [u8; 32],
    pub issuer_hash: [u8; 32],
    pub aki: [u8; 32],
    pub root: [u8; 32],
    pub policy_id: [u8; 32],
    pub deadline: i64,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V3Addresses {
    pub config: Pubkey,
    pub issuer: Pubkey,
    pub head: Pubkey,
    pub request: Pubkey,
    pub queue: Pubkey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V3HeadBinding {
    pub expected_config_epoch: u64,
    pub expected_issuer_epoch: u64,
    pub expected_root: [u8; 32],
    pub expected_root_version: u64,
    pub expected_source_sequence: u64,
    pub expected_source_digest: [u8; 32],
    pub expected_publication_sequence: u64,
    pub expected_publication_digest: [u8; 32],
    pub next_publication_sequence: u64,
    pub envelope_digest: [u8; 32],
}

fn unrelated_revocation_roots(
    own_digest: [u8; 32],
    unrelated_digest: [u8; 32],
    slot: usize,
) -> Result<([u8; 32], [u8; 32], Vec<[u8; 32]>, Vec<[u8; 32]>)> {
    ensure!(
        own_digest != [0; 32]
            && unrelated_digest != [0; 32]
            && own_digest != unrelated_digest
            && slot < 1024,
        "two distinct allocated credential digests required"
    );
    let registry = |error| anyhow::anyhow!("v3 tree {error:?}");
    let mut tree = credential_registry::v3::Tree::new().map_err(registry)?;
    tree.set(slot, own_digest, true).map_err(registry)?;
    tree.set(slot ^ 1, unrelated_digest, true)
        .map_err(registry)?;
    let base_root = tree.root();
    let base_path = tree.path(slot).map_err(registry)?;
    tree.set(slot ^ 1, unrelated_digest, false)
        .map_err(registry)?;
    let near_root = tree.root();
    let near_path = tree.path(slot).map_err(registry)?;
    ensure!(
        base_root != near_root
            && base_path
                .iter()
                .zip(&near_path)
                .filter(|(a, b)| a != b)
                .count()
                == 1,
        "one unrelated sibling revocation required"
    );
    credential_registry::v3::Tree::verify(own_digest, slot, true, &base_path, base_root)
        .map_err(registry)?;
    credential_registry::v3::Tree::verify(own_digest, slot, true, &near_path, near_root)
        .map_err(registry)?;
    Ok((base_root, near_root, base_path, near_path))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TransitionContext {
    schema: String,
    training_only: bool,
    stage_report_sha256: String,
    cohort_receipt_sha256: String,
    membership_sha256: String,
    own_tbs_digest: String,
    unrelated_tbs_digest: String,
    slot: usize,
    unrelated_slot: usize,
    base_root: String,
    near_root: String,
}

fn transition_context() -> Result<(TransitionContext, [u8; 32])> {
    let raw = transport::pinned(
        Path::new(&transport::env("P5_V3_TRANSITION_CONTEXT")?),
        &transport::env("P5_V3_TRANSITION_CONTEXT_SHA256")?,
        8192,
    )?;
    let context: TransitionContext = serde_json::from_slice(&raw)?;
    ensure!(
        context.schema == "part5-v3-unrelated-training-transition-v1"
            && context.training_only
            && context.unrelated_slot == context.slot ^ 1
            && context.slot < 1024,
        "exact unrelated training transition context"
    );
    for digest in [
        &context.stage_report_sha256,
        &context.cohort_receipt_sha256,
        &context.membership_sha256,
    ] {
        transport::unhex(digest)?;
    }
    let own = transport::unhex(&context.own_tbs_digest)?;
    let other = transport::unhex(&context.unrelated_tbs_digest)?;
    let (base, near, _, _) = unrelated_revocation_roots(own, other, context.slot)?;
    ensure!(
        base == transport::unhex(&context.base_root)?
            && near == transport::unhex(&context.near_root)?,
        "transition roots differ from recomputed signed-leaf allocation"
    );
    Ok((context, near))
}

#[cfg(test)]
mod revocation_transition_tests {
    use super::*;

    #[test]
    fn unrelated_revocation_changes_one_sibling_and_own_revocation_blocks_path() {
        let (base, near, base_path, near_path) =
            unrelated_revocation_roots([7; 32], [9; 32], 44).unwrap();
        assert_ne!(base, near);
        assert_eq!(
            base_path
                .iter()
                .zip(&near_path)
                .filter(|(a, b)| a != b)
                .count(),
            1
        );
        credential_registry::v3::Tree::verify([7; 32], 44, true, &near_path, near).unwrap();
        assert!(
            credential_registry::v3::Tree::verify([7; 32], 44, false, &near_path, near).is_err()
        );
    }
}

impl V3QueuePlan {
    pub fn addresses(&self) -> V3Addresses {
        let program = Pubkey::new_from_array(self.program);
        let config =
            Pubkey::find_program_address(&[b"dyn-config-v3", &self.admin, &self.seed], &program).0;
        let issuer = Pubkey::find_program_address(
            &[b"dyn-issuer-v3", config.as_ref(), &self.issuer_hash],
            &program,
        )
        .0;
        let head = Pubkey::find_program_address(
            &[
                b"dyn-pubhead-v3",
                config.as_ref(),
                issuer.as_ref(),
                &self.publisher,
            ],
            &program,
        )
        .0;
        let request = Pubkey::find_program_address(
            &[
                b"dyn-request-v3",
                config.as_ref(),
                &self.creator,
                &self.nonce,
            ],
            &program,
        )
        .0;
        let queue = Pubkey::find_program_address(&[b"dyn-queue-v3", config.as_ref()], &program).0;
        V3Addresses {
            config,
            issuer,
            head,
            request,
            queue,
        }
    }

    fn instruction(&self, opcode: u8, body: Vec<u8>, accounts: Vec<AccountMeta>) -> Instruction {
        let mut data = vec![0x51, opcode];
        data.extend(body);
        Instruction {
            program_id: Pubkey::new_from_array(self.program),
            accounts,
            data,
        }
    }

    pub fn initialize(&self) -> Instruction {
        let a = self.addresses();
        let mut body = Vec::with_capacity(324);
        for value in [self.seed, self.publisher, self.genesis, self.policy_id] {
            body.extend(value);
        }
        body.extend(1u32.to_be_bytes());
        for value in [
            "eae99530daf7331037f2d1c6dc93ccc582603bd448f38d06e6469c734e8252fe",
            "61d941890d823433468048dd1bd91da80c1bf7e1b3d2b6f5d509077a47ed06c8",
            "eabfaa2d95e4abc9126b87a04e94397091c103891e92dbaefaafba79cf3b26d4",
            "2e5d26564fb055e70cff924c4cb6e296509030b8c0062130f86ad5af783f7918",
            "2f9b770ff51ac399619a3127ddb32efad67697402f10c4549441a3578e4f9a4e",
        ] {
            body.extend(hex::decode(value).expect("frozen reviewed v3 identity"));
        }
        body.extend(self.root);
        self.instruction(
            0,
            body,
            vec![
                AccountMeta::new(Pubkey::new_from_array(self.admin), true),
                AccountMeta::new(a.config, false),
                AccountMeta::new(a.queue, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
        )
    }

    pub fn enroll(&self, enrollment_version: u64, evidence_digest: [u8; 32]) -> Instruction {
        let a = self.addresses();
        let mut body = Vec::with_capacity(136);
        body.extend(self.issuer_hash);
        body.extend(self.aki);
        body.extend(self.source);
        body.extend(enrollment_version.to_be_bytes());
        body.extend(evidence_digest);
        self.instruction(
            1,
            body,
            vec![
                AccountMeta::new(Pubkey::new_from_array(self.admin), true),
                AccountMeta::new_readonly(a.config, false),
                AccountMeta::new(a.issuer, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
        )
    }

    pub fn publish(&self, expected: u64, root: [u8; 32]) -> Instruction {
        let a = self.addresses();
        let mut body = Vec::with_capacity(40);
        body.extend(expected.to_be_bytes());
        body.extend(root);
        self.instruction(
            2,
            body,
            vec![
                AccountMeta::new_readonly(Pubkey::new_from_array(self.publisher), true),
                AccountMeta::new(a.config, false),
            ],
        )
    }

    pub fn observe(
        &self,
        config_epoch: u64,
        issuer_epoch: u64,
        expected_sequence: u64,
        next_sequence: u64,
        digest: [u8; 32],
        active: bool,
        observed: i64,
        expires: i64,
    ) -> Instruction {
        let a = self.addresses();
        let mut body = Vec::with_capacity(81);
        for value in [config_epoch, issuer_epoch, expected_sequence, next_sequence] {
            body.extend(value.to_be_bytes());
        }
        body.extend(digest);
        body.push(u8::from(active));
        body.extend(observed.to_be_bytes());
        body.extend(expires.to_be_bytes());
        self.instruction(
            3,
            body,
            vec![
                AccountMeta::new_readonly(Pubkey::new_from_array(self.source), true),
                AccountMeta::new_readonly(a.config, false),
                AccountMeta::new(a.issuer, false),
            ],
        )
    }

    pub fn bind_with_head(&self, binding: &V3HeadBinding) -> Instruction {
        let a = self.addresses();
        let mut body = vec![1];
        body.extend(binding.expected_config_epoch.to_be_bytes());
        body.extend(binding.expected_issuer_epoch.to_be_bytes());
        body.extend(binding.expected_root);
        body.extend(binding.expected_root_version.to_be_bytes());
        body.extend(binding.expected_source_sequence.to_be_bytes());
        body.extend(binding.expected_source_digest);
        body.extend(binding.expected_publication_sequence.to_be_bytes());
        body.extend(binding.expected_publication_digest);
        body.extend(binding.next_publication_sequence.to_be_bytes());
        body.extend(binding.envelope_digest);
        self.instruction(
            13,
            body,
            vec![
                AccountMeta::new(Pubkey::new_from_array(self.publisher), true),
                AccountMeta::new_readonly(a.config, false),
                AccountMeta::new(a.issuer, false),
                AccountMeta::new(a.head, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
        )
    }

    pub fn create(&self) -> Result<Instruction> {
        ensure!(
            self.payload.len() <= 1024 && self.deadline > 0,
            "bounded request required"
        );
        let a = self.addresses();
        let mut body = Vec::with_capacity(109);
        body.extend(self.nonce);
        body.extend(self.issuer_hash);
        body.extend(self.recipient);
        body.extend(1u16.to_be_bytes());
        body.extend(self.deadline.to_be_bytes());
        body.extend((self.payload.len() as u16).to_be_bytes());
        body.push(2);
        Ok(self.instruction(
            4,
            body,
            vec![
                AccountMeta::new(Pubkey::new_from_array(self.creator), true),
                AccountMeta::new_readonly(a.config, false),
                AccountMeta::new_readonly(a.issuer, false),
                AccountMeta::new(a.request, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
        ))
    }

    fn edit_accounts(&self) -> Vec<AccountMeta> {
        let a = self.addresses();
        vec![
            AccountMeta::new_readonly(Pubkey::new_from_array(self.creator), true),
            AccountMeta::new_readonly(a.config, false),
            AccountMeta::new(a.request, false),
        ]
    }

    pub fn upload_payload(&self, offset: usize, chunk: &[u8]) -> Result<Instruction> {
        ensure!(
            offset <= 1024
                && !chunk.is_empty()
                && chunk.len() <= 512
                && offset + chunk.len() <= self.payload.len()
                && chunk == &self.payload[offset..offset + chunk.len()],
            "bounded upload chunk required"
        );
        let mut body = Vec::with_capacity(4 + chunk.len());
        body.extend((offset as u16).to_be_bytes());
        body.extend((chunk.len() as u16).to_be_bytes());
        body.extend(chunk);
        Ok(self.instruction(6, body, self.edit_accounts()))
    }

    pub fn upload_metas(&self) -> Instruction {
        let a = self.addresses();
        let mut body = vec![0, 2];
        for key in [a.request, a.queue] {
            body.extend(key.to_bytes());
            body.push(2);
            body.extend(self.program);
        }
        self.instruction(8, body, self.edit_accounts())
    }

    pub fn finalize(&self) -> Instruction {
        self.instruction(5, Vec::new(), self.edit_accounts())
    }

    pub fn execute(&self, wire: &[u8]) -> Result<Instruction> {
        ensure!(wire.len() == 448, "six publics and v3 proof required");
        for public in wire[..192].chunks_exact(32) {
            let word: [u8; 32] = public.try_into()?;
            ensure!(
                zk_fresh_program::canonical(&word).is_ok(),
                "canonical public field required"
            );
        }
        let a = self.addresses();
        Ok(self.instruction(
            7,
            wire.to_vec(),
            vec![
                AccountMeta::new_readonly(a.config, false),
                AccountMeta::new_readonly(a.issuer, false),
                AccountMeta::new_readonly(a.head, false),
                AccountMeta::new(a.request, false),
                AccountMeta::new(a.queue, false),
            ],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zk_fresh_program::{application_runtime_v3 as runtime, application_v3::AppInstruction};

    fn plan() -> V3QueuePlan {
        V3QueuePlan {
            program: [12; 32],
            genesis: [1; 32],
            admin: [18; 32],
            publisher: [19; 32],
            source: [20; 32],
            creator: [21; 32],
            seed: [7; 32],
            nonce: [16; 32],
            recipient: [17; 32],
            issuer_hash: {
                let mut b = [0; 32];
                b[31] = 8;
                b
            },
            aki: {
                let mut b = [0; 32];
                b[..20].fill(8);
                b
            },
            root: {
                let mut b = [0; 32];
                b[31] = 6;
                b
            },
            policy_id: {
                let mut b = [0; 32];
                b[31] = 5;
                b
            },
            deadline: 500,
            payload: vec![0, 1, 2, 3],
        }
    }
    #[test]
    fn independent_pd_as_and_admin_instructions_match_v3_parser() {
        let p = plan();
        let a = p.addresses();
        let program = Pubkey::new_from_array(p.program);
        assert_eq!(
            a.config,
            runtime::config_address(&program, &Pubkey::new_from_array(p.admin), &p.seed).0
        );
        assert_eq!(
            a.issuer,
            runtime::issuer_address(&program, &a.config, &p.issuer_hash).0
        );
        assert_eq!(
            a.head,
            runtime::publisher_head_address(
                &program,
                &a.config,
                &a.issuer,
                &Pubkey::new_from_array(p.publisher)
            )
            .0
        );
        assert_eq!(
            a.request,
            runtime::request_address(
                &program,
                &a.config,
                &Pubkey::new_from_array(p.creator),
                &p.nonce
            )
            .0
        );
        assert_eq!(a.queue, runtime::queue_address(&program, &a.config).0);
        assert!(matches!(
            AppInstruction::parse(&p.initialize().data),
            Ok(AppInstruction::Initialize { .. })
        ));
        assert!(matches!(
            AppInstruction::parse(&p.enroll(1, [9; 32]).data),
            Ok(AppInstruction::Enroll { .. })
        ));
        assert!(matches!(
            AppInstruction::parse(&p.create().unwrap().data),
            Ok(AppInstruction::Create { .. })
        ));
    }
    #[test]
    fn request_chunks_and_exact_relevant_metas_match_v3_parser() {
        let p = plan();
        let a = p.addresses();
        let upload = p.upload_payload(0, &p.payload).unwrap();
        assert!(
            matches!(AppInstruction::parse(&upload.data), Ok(AppInstruction::Upload { offset:0, bytes }) if bytes == p.payload)
        );
        let metas = p.upload_metas();
        assert!(
            matches!(AppInstruction::parse(&metas.data), Ok(AppInstruction::UploadMetas { offset:0, metas }) if metas.len()==2 && metas[0].key==a.request && metas[1].key==a.queue && metas.iter().all(|m| m.flags==2 && m.owner==Pubkey::new_from_array(p.program)))
        );
        assert_eq!(
            AppInstruction::parse(&p.finalize().data),
            Ok(AppInstruction::Finalize)
        );
        assert!(p.upload_payload(0, &[]).is_err());
        assert!(p.upload_payload(0, &[0; 513]).is_err());
        assert!(p.upload_payload(3, &p.payload).is_err());
        assert!(p.upload_payload(0, &[9, 1, 2, 3]).is_err());
    }
    #[test]
    fn signed_source_observation_and_head_binding_match_v3_parser() {
        use zk_fresh_program::application_v3::PublisherHeadBinding;
        let p = plan();
        let observed = p.observe(0, 0, 0, 1, [41; 32], true, 100, 340);
        assert_eq!(observed.accounts.len(), 3);
        assert!(
            matches!(AppInstruction::parse(&observed.data), Ok(AppInstruction::Observe { expected_config_epoch:0, expected_issuer_epoch:0, expected:0, sequence:1, digest, active:true, observed:100, expires:340 }) if digest == [41;32])
        );
        let binding = V3HeadBinding {
            expected_config_epoch: 0,
            expected_issuer_epoch: 0,
            expected_root: p.root,
            expected_root_version: 0,
            expected_source_sequence: 1,
            expected_source_digest: [41; 32],
            expected_publication_sequence: 0,
            expected_publication_digest: [0; 32],
            next_publication_sequence: 1,
            envelope_digest: [91; 32],
        };
        let ix = p.bind_with_head(&binding);
        assert_eq!(ix.accounts.len(), 5);
        assert_eq!(
            AppInstruction::parse(&ix.data),
            Ok(AppInstruction::BindWithHead(PublisherHeadBinding {
                expected_config_epoch: binding.expected_config_epoch,
                expected_issuer_epoch: binding.expected_issuer_epoch,
                expected_root: binding.expected_root,
                expected_root_version: binding.expected_root_version,
                expected_source_sequence: binding.expected_source_sequence,
                expected_source_digest: binding.expected_source_digest,
                expected_publication_sequence: binding.expected_publication_sequence,
                expected_publication_digest: binding.expected_publication_digest,
                next_publication_sequence: binding.next_publication_sequence,
                envelope_digest: binding.envelope_digest,
            }))
        );
    }
    #[test]
    fn training_context_requires_exact_profile_fields_and_canonical_hex() {
        let p = plan();
        let mut context = json!({
            "schema":"part5-v3-local-training-context-v1", "training_only":true,
            "root":hex::encode(p.root), "issuer_hash":hex::encode(p.issuer_hash),
            "policy_id":hex::encode(p.policy_id), "aki":hex::encode(p.aki),
            "evidence_digest":hex::encode([9;32]),
            "not_before":100, "not_after":1000,
        });
        let encoded = serde_json::to_vec(&context).unwrap();
        assert!(parse_training_context(&encoded).is_ok());
        context["root"] = hex::encode([0xab; 32]).to_uppercase().into();
        assert!(parse_training_context(&serde_json::to_vec(&context).unwrap()).is_err());
        context["root"] = hex::encode(p.root).into();
        context["aki"] = hex::encode([8; 32]).into();
        assert!(parse_training_context(&serde_json::to_vec(&context).unwrap()).is_err());
        context["aki"] = hex::encode(p.aki).into();
        context["unexpected"] = true.into();
        assert!(parse_training_context(&serde_json::to_vec(&context).unwrap()).is_err());
    }

    #[test]
    fn execute_wire_binds_exact_ordered_v3_accounts_and_packet() {
        use solana_sdk::transaction::Transaction;
        let mut p = plan();
        let payer = Keypair::new();
        p.admin = payer.pubkey().to_bytes();
        let mut wire = vec![0; 448];
        wire[192] = 1;
        let ix = p.execute(&wire).unwrap();
        let a = p.addresses();
        assert_eq!(ix.data.len(), 450);
        assert_eq!(&ix.data[..2], &[0x51, 7]);
        assert_eq!(&ix.data[2..], wire);
        assert_eq!(
            ix.accounts.iter().map(|m| m.pubkey).collect::<Vec<_>>(),
            vec![a.config, a.issuer, a.head, a.request, a.queue]
        );
        assert!(ix
            .accounts
            .iter()
            .enumerate()
            .all(|(index, m)| !m.is_signer && m.is_writable == (index >= 3)));
        assert!(matches!(
            AppInstruction::parse(&ix.data),
            Ok(AppInstruction::Execute { .. })
        ));
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            Hash::new_unique(),
        );
        assert!(bincode::serialize(&tx).unwrap().len() <= 1232);
        assert!(p.execute(&wire[..447]).is_err());
        wire[..32].fill(0xff);
        assert!(p.execute(&wire).is_err());
    }

    #[test]
    fn full_wire_requires_staged_action_and_signed_validity_fields() {
        use zk_fresh_program::{
            application_v3::{action_hash, RelevantMeta},
            generated_vk_v3 as identity,
        };
        let p = plan();
        let a = p.addresses();
        let c = Config {
            admin: Pubkey::new_from_array(p.admin),
            seed: p.seed,
            publisher: Pubkey::new_from_array(p.publisher),
            genesis: p.genesis,
            policy_id: p.policy_id,
            policy_version: 1,
            circuit_id: identity::CIRCUIT_ID,
            package_id: identity::PACKAGE_ID,
            schema_id: identity::SEMANTIC_SCHEMA_ID,
            profile_id: identity::PROFILE_ID,
            ordinary_vk_digest: identity::ORDINARY_VK_DIGEST,
            root: p.root,
            root_version: 0,
            eligibility_epoch: 0,
            enabled: true,
        };
        let r = Request {
            config: a.config,
            creator: Pubkey::new_from_array(p.creator),
            nonce: p.nonce,
            issuer_hash: p.issuer_hash,
            recipient: Pubkey::new_from_array(p.recipient),
            request_type: 1,
            deadline: p.deadline,
            payload_len: p.payload.len() as u16,
            uploaded: p.payload.len() as u16,
            metas_uploaded: 2,
            state: RequestState::Finalized,
            metas: [a.request, a.queue]
                .into_iter()
                .map(|key| RelevantMeta {
                    key,
                    flags: 2,
                    owner: Pubkey::new_from_array(p.program),
                })
                .collect(),
            payload: p.payload.clone(),
        };
        let mut wire = vec![0; 448];
        for (index, word) in [
            p.root,
            p.issuer_hash,
            {
                let mut x = [0; 32];
                x[24..].copy_from_slice(&100u64.to_be_bytes());
                x
            },
            {
                let mut x = [0; 32];
                x[24..].copy_from_slice(&1000u64.to_be_bytes());
                x
            },
            action_hash(&Pubkey::new_from_array(p.program), &c, &r).unwrap(),
            p.policy_id,
        ]
        .iter()
        .enumerate()
        {
            wire[index * 32..(index + 1) * 32].copy_from_slice(word);
        }
        wire[192] = 1;
        assert!(validate_full_wire(&p, &c, &r, 100, 1000, &wire).is_ok());
        wire[159] ^= 1;
        assert!(validate_full_wire(&p, &c, &r, 100, 1000, &wire).is_err());
        wire[159] ^= 1;
        assert!(validate_full_wire(&p, &c, &r, 101, 1000, &wire).is_err());
    }
}
