//! Loaded-ELF negative for a valid Full request after config disable.
use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

const ACCOUNT_NAMES: [&str; 5] = ["config", "issuer", "head", "request", "queue"];
const POLICY_ERROR: u64 = zk_fresh_program::application_v3::AppError::Policy as u64;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NegativeConfig {
    schema: String,
    variant: u8,
    request_slot: String,
    stage_root: PathBuf,
    stage_report: PathBuf,
    stage_report_sha256: String,
    stage_plan: PathBuf,
    stage_plan_sha256: String,
    ledger: PathBuf,
    heldout_r0_clone_report: PathBuf,
    heldout_r0_clone_report_sha256: String,
    full_wire: PathBuf,
    full_wire_sha256: String,
    expected_program: String,
    expected_genesis: String,
    expected_elf_sha256: String,
    output_dir: PathBuf,
    control_output: PathBuf,
    runner: PathBuf,
    runner_sha256: String,
}

fn private_dir(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && fs::canonicalize(path)? == path
            && meta.is_dir()
            && meta.permissions().mode() & 0o7777 == 0o700
            && meta.uid() == unsafe { libc::geteuid() },
        "canonical owner-only directory required"
    );
    Ok(())
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn account_hashes(accounts: &[Vec<u8>; 5]) -> Vec<String> {
    accounts.iter().map(|bytes| sha(bytes)).collect()
}

fn save_snapshot(output: &Path, name: &str, accounts: &[Vec<u8>; 5]) -> Result<Vec<Value>> {
    let root = output.join(name);
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let mut refs = Vec::with_capacity(5);
    for (role, bytes) in ACCOUNT_NAMES.iter().zip(accounts) {
        let path = root.join(format!("{role}.bin"));
        transport::new_file(&path, bytes)?;
        refs.push(json!({"name":role,"path":path,"sha256":sha(bytes)}));
    }
    Ok(refs)
}

fn event<'a>(events: &'a [Value], index: usize, label: &str) -> Result<&'a Value> {
    events
        .get(index)
        .with_context(|| format!("{label} transaction evidence"))
}

fn instruction_event(value: &Value, expected: Option<u64>, label: &str) -> Result<(String, u64)> {
    let signature = value["signature"]
        .as_str()
        .with_context(|| format!("{label} signature"))?
        .to_owned();
    let slot = value["slot"]
        .as_u64()
        .with_context(|| format!("{label} slot"))?;
    if let Some(code) = expected {
        ensure!(
            value["customError"].as_u64() == Some(code),
            "{label} expected custom error {code}, received {}",
            value["err"]
        );
    } else {
        ensure!(value["err"].is_null(), "{label} failed: {}", value["err"]);
    }
    Ok((signature, slot))
}

fn source_digest(root: [u8; 32], issuer: &Issuer, observed: i64, sequence: u64) -> [u8; 32] {
    Sha256::digest(
        [
            b"part5-v3-local-execute-source-training-v1".as_slice(),
            &root,
            &issuer.issuer_hash,
            &issuer.evidence_digest,
            &issuer.digest,
            &sequence.to_be_bytes(),
            &observed.to_be_bytes(),
        ]
        .concat(),
    )
    .into()
}

fn head_digest(root: [u8; 32], previous: [u8; 32], source: [u8; 32], observed: i64) -> [u8; 32] {
    Sha256::digest(
        [
            b"part5-v3-local-execute-head-training-v1".as_slice(),
            &root,
            &previous,
            &source,
            &observed.to_be_bytes(),
        ]
        .concat(),
    )
    .into()
}

pub fn disabled_config_negative_from_env() -> Result<()> {
    ensure!(
        transport::env("P5_V3_DISABLED_CONFIG_NEGATIVE_SCOPE")?
            == "part5-v3-disabled-config-negative",
        "explicit disabled-config negative scope required"
    );
    let config_path = PathBuf::from(transport::env("P5_V3_DISABLED_CONFIG_NEGATIVE_CONFIG")?);
    let config_sha = transport::env("P5_V3_DISABLED_CONFIG_NEGATIVE_CONFIG_SHA256")?;
    let config_raw = transport::pinned(&config_path, &config_sha, 32768)?;
    let config: NegativeConfig = serde_json::from_slice(&config_raw)?;
    ensure!(
        config.schema == "part5-v3-disabled-config-negative-config-v1"
            && config.variant <= 7
            && config.request_slot == "A"
            && config.output_dir == transport::output()?
            && config.stage_root.is_absolute()
            && config.ledger.is_absolute()
            && config.control_output.is_absolute()
            && config.runner.is_absolute(),
        "exact heldout disabled-config config required"
    );
    private_dir(&config.stage_root)?;
    private_dir(&config.ledger)?;
    private_dir(&config.control_output)?;
    private_dir(&config.output_dir)?;
    ensure!(
        fs::read_dir(&config.output_dir)?.next().is_none(),
        "fresh negative output required"
    );
    ensure!(
        transport::env("P5_V3_STAGE_ROOT")? == config.stage_root.to_string_lossy().as_ref()
            && transport::env("P5_QUEUE_PROGRAM")? == config.expected_program
            && transport::env("P5_QUEUE_GENESIS")? == config.expected_genesis
            && transport::env("P5_QUEUE_ELF_SHA256")? == config.expected_elf_sha256,
        "negative config differs from supervised runtime pins"
    );
    let stage_report_raw =
        transport::pinned(&config.stage_report, &config.stage_report_sha256, 65536)?;
    let stage_report: Value = serde_json::from_slice(&stage_report_raw)?;
    let plan_raw = transport::pinned(&config.stage_plan, &config.stage_plan_sha256, 8192)?;
    let plan: V3QueuePlan = serde_json::from_slice(&plan_raw)?;
    let clone_raw = transport::pinned(
        &config.heldout_r0_clone_report,
        &config.heldout_r0_clone_report_sha256,
        8192,
    )?;
    let clone: Value = serde_json::from_slice(&clone_raw)?;
    ensure!(
        stage_report["schema"] == "part5-v3-local-stage-v1"
            && stage_report["passed"] == true
            && stage_report["training_only"] == true
            && stage_report["application_effect"] == false
            && stage_report["proof_created"] == false
            && stage_report["plan_sha256"] == config.stage_plan_sha256
            && clone["schema"] == "part5-v3-heldout-r0-ledger-clone-v1"
            && clone["heldout_acceptance"] == false
            && clone["stage_report_sha256"] == config.stage_report_sha256
            && clone["stage_status_sha256"].as_str().is_some()
            && clone["stage_monitor_sha256"].as_str().is_some()
            && clone["source_stable"] == true
            && clone["copy_identical"] == true
            && clone["loaded_identity_rechecked_after_restart"] == false
            && clone["application_effect"] == false
            && clone["destination"] == config.ledger.to_string_lossy().as_ref()
            && clone["source"]
                .as_str()
                .is_some_and(|source| source != config.ledger.to_string_lossy().as_ref()),
        "pinned stage and separate heldout R0 clone receipts required"
    );
    ensure!(
        stage_report["loaded_program"]["elf_sha256"] == config.expected_elf_sha256
            && stage_report["loaded_program"]["elf_match"] == true
            && stage_report["program"] == config.expected_program
            && stage_report["genesis"] == config.expected_genesis
            && stage_report["config"] == plan.addresses().config.to_string()
            && stage_report["issuer"] == plan.addresses().issuer.to_string()
            && stage_report["head"] == plan.addresses().head.to_string()
            && stage_report["request"] == plan.addresses().request.to_string()
            && stage_report["queue"] == plan.addresses().queue.to_string(),
        "stage identity differs from exact heldout request"
    );
    ensure!(
        plan.program == Pubkey::from_str(&config.expected_program)?.to_bytes()
            && plan.genesis == Hash::from_str(&config.expected_genesis)?.to_bytes(),
        "request plan domain mismatch"
    );
    transport::pinned(&config.runner, &config.runner_sha256, 128 * 1024 * 1024)?;
    let wire = transport::pinned(&config.full_wire, &config.full_wire_sha256, 448)?;
    ensure!(wire.len() == 448, "exact valid Full Execute wire required");
    let stage_hashes = stage_report["account_sha256"]
        .as_array()
        .context("five staged account hashes")?;
    ensure!(
        stage_hashes.len() == ACCOUNT_NAMES.len(),
        "five stage account hashes required"
    );
    let mut staged = Vec::with_capacity(5);
    for (index, name) in ACCOUNT_NAMES.iter().enumerate() {
        staged.push(transport::pinned(
            &config.stage_root.join(format!("{name}.bin")),
            stage_hashes[index]
                .as_str()
                .context("stage account digest")?,
            4096,
        )?);
    }
    let staged: [Vec<u8>; 5] = staged
        .try_into()
        .map_err(|_| anyhow::anyhow!("five staged accounts"))?;

    let rpc = transport::local_rpc()?;
    let (program, genesis, loaded) = transport::domain(&rpc)?;
    ensure!(
        program == plan.program
            && genesis == plan.genesis
            && loaded["elf_sha256"] == config.expected_elf_sha256
            && loaded["elf_match"] == true,
        "loaded local validator identity mismatch"
    );
    let initial_slot = stage_report["finalized_slot"]
        .as_u64()
        .context("stage finalized slot")?;
    let (source_slot, initial) = finalized_accounts(&rpc, &plan, initial_slot)?;
    ensure!(
        initial == staged,
        "fresh R0 clone accounts differ from staged R0 bytes"
    );
    let c = Config::decode(&initial[0]).map_err(|e| anyhow::anyhow!("config codec {e:?}"))?;
    let i = Issuer::decode(&initial[1]).map_err(|e| anyhow::anyhow!("issuer codec {e:?}"))?;
    let h = PublisherHead::decode(&initial[2]).map_err(|e| anyhow::anyhow!("head codec {e:?}"))?;
    let r = Request::decode(&initial[3]).map_err(|e| anyhow::anyhow!("request codec {e:?}"))?;
    let q = Queue::decode(&initial[4]).map_err(|e| anyhow::anyhow!("queue codec {e:?}"))?;
    ensure!(
        c.enabled && i.enabled && r.state == RequestState::Finalized && q.entries.is_empty(),
        "enabled, finalized, unconsumed R0 request required"
    );
    let (context, context_root, context_issuer, context_policy, _, _) = training_context()?;
    ensure!(
        plan.root == context_root
            && plan.issuer_hash == context_issuer
            && plan.policy_id == context_policy,
        "Full request must match the registered R0 holder context"
    );
    validate_full_wire(&plan, &c, &r, context.not_before, context.not_after, &wire)?;

    let admin = transport::load_key(&config.stage_root, "admin.json", plan.admin)?;
    let publisher = transport::load_key(&config.stage_root, "publisher.json", plan.publisher)?;
    let source = transport::load_key(&config.stage_root, "source.json", plan.source)?;
    let mut events = Vec::new();

    // Match Full Execute's two successful issuer/head refresh transactions so
    // that the disabled-config rejection is tested against otherwise current state.
    let observed_deadline = Instant::now() + Duration::from_secs(20);
    let observed = loop {
        let candidate = transport::clock(&rpc)?;
        if candidate > i.observed_at {
            break candidate;
        }
        ensure!(
            Instant::now() < observed_deadline,
            "newer source observation deadline"
        );
        thread::sleep(Duration::from_millis(250));
    };
    let expires = observed
        .checked_add(240)
        .context("source expiry overflow")?;
    let next_sequence = i
        .sequence
        .checked_add(1)
        .context("source sequence overflow")?;
    let source_digest = source_digest(c.root, &i, observed, next_sequence);
    ensure!(
        source_digest != i.digest,
        "fresh signed source digest required"
    );
    transport::send(
        &rpc,
        &admin,
        Some(&source),
        plan.observe(
            c.eligibility_epoch,
            i.eligibility_epoch,
            i.sequence,
            next_sequence,
            source_digest,
            true,
            observed,
            expires,
        ),
        "v3-disabled-negative-refresh-source",
        None,
        &mut events,
    )?;
    let observed_finalized_slot = transport::wait_finalized(&rpc, &events)?;
    let (_, after_observe) = finalized_accounts(&rpc, &plan, observed_finalized_slot)?;
    let observed_issuer = Issuer::decode(&after_observe[1])
        .map_err(|e| anyhow::anyhow!("issuer codec after observe {e:?}"))?;
    ensure!(
        after_observe[0] == initial[0]
            && after_observe[2] == initial[2]
            && after_observe[3] == initial[3]
            && after_observe[4] == initial[4]
            && observed_issuer.sequence == next_sequence
            && observed_issuer.digest == source_digest
            && observed_issuer.expires_at == expires,
        "source refresh changed unexpected accounts or bytes"
    );
    let envelope_digest = head_digest(c.root, h.envelope_digest, source_digest, observed);
    let binding = V3HeadBinding {
        expected_config_epoch: c.eligibility_epoch,
        expected_issuer_epoch: observed_issuer.eligibility_epoch,
        expected_root: c.root,
        expected_root_version: c.root_version,
        expected_source_sequence: next_sequence,
        expected_source_digest: source_digest,
        expected_publication_sequence: h.publication_sequence,
        expected_publication_digest: h.envelope_digest,
        next_publication_sequence: h
            .publication_sequence
            .checked_add(1)
            .context("head publication sequence overflow")?,
        envelope_digest,
    };
    transport::send(
        &rpc,
        &admin,
        Some(&publisher),
        plan.bind_with_head(&binding),
        "v3-disabled-negative-refresh-head",
        None,
        &mut events,
    )?;
    let eligible_barrier_slot = transport::wait_finalized(&rpc, &events)?;
    let (eligible_slot, eligible) = finalized_accounts(&rpc, &plan, eligible_barrier_slot)?;
    let eligible_issuer = Issuer::decode(&eligible[1])
        .map_err(|e| anyhow::anyhow!("issuer codec after bind {e:?}"))?;
    let eligible_head = PublisherHead::decode(&eligible[2])
        .map_err(|e| anyhow::anyhow!("head codec after bind {e:?}"))?;
    eligible_issuer
        .fresh(&c, transport::clock(&rpc)?)
        .map_err(|e| anyhow::anyhow!("refreshed issuer freshness {e:?}"))?;
    eligible_issuer
        .binding_current(&c)
        .map_err(|e| anyhow::anyhow!("refreshed issuer binding {e:?}"))?;
    ensure!(
        eligible[0] == initial[0]
            && eligible[3] == initial[3]
            && eligible[4] == initial[4]
            && eligible_head.root == c.root
            && eligible_head.root_version == c.root_version
            && eligible_head.source_sequence == next_sequence
            && eligible_head.source_digest == source_digest
            && eligible_issuer.sequence == next_sequence
            && eligible_issuer.digest == source_digest,
        "eligible refreshed state does not match exact R0 request"
    );
    let eligible_refs = save_snapshot(&config.output_dir, "eligible", &eligible)?;

    let disable_ix = plan.instruction(
        10,
        vec![0],
        vec![
            AccountMeta::new(Pubkey::new_from_array(plan.admin), true),
            AccountMeta::new(plan.addresses().config, false),
        ],
    );
    ensure!(
        disable_ix.data == [0x51, 10, 0],
        "disabled-config instruction must be exact opcode 10 false"
    );
    transport::send(
        &rpc,
        &admin,
        None,
        disable_ix,
        "v3-disabled-negative-disable-config",
        None,
        &mut events,
    )?;
    let disabled_barrier_slot = transport::wait_finalized(&rpc, &events)?;
    let (disabled_finalized_slot, before) = finalized_accounts(&rpc, &plan, disabled_barrier_slot)?;
    let disabled_config = Config::decode(&before[0])
        .map_err(|e| anyhow::anyhow!("config codec after disable {e:?}"))?;
    let mut expected_disabled_config = c.clone();
    expected_disabled_config
        .set_enabled(
            Authority {
                key: admin.pubkey(),
                is_signer: true,
            },
            false,
        )
        .map_err(|e| anyhow::anyhow!("expected config disable {e:?}"))?;
    ensure!(
        !disabled_config.enabled
            && disabled_config.eligibility_epoch
                == c.eligibility_epoch
                    .checked_add(1)
                    .context("config eligibility epoch overflow")?
            && before[0] == expected_disabled_config.encode()
            && before[1..] == eligible[1..],
        "disable must only flip config enabled and advance its epoch"
    );
    let before_refs = save_snapshot(&config.output_dir, "before", &before)?;

    transport::send(
        &rpc,
        &admin,
        None,
        plan.execute(&wire)?,
        "v3-disabled-negative-valid-full-execute",
        Some(POLICY_ERROR),
        &mut events,
    )?;
    let rejected_barrier_slot = transport::wait_finalized(&rpc, &events)?;
    let (rejected_finalized_slot, after) = finalized_accounts(&rpc, &plan, rejected_barrier_slot)?;
    ensure!(
        after == before,
        "rejected Execute changed one or more finalized accounts"
    );
    let after_refs = save_snapshot(&config.output_dir, "after", &after)?;

    // Restore config eligibility, then refresh and bind the issuer against the
    // new config epoch before exercising issuer disablement independently.
    let enable_ix = plan.instruction(
        10,
        vec![1],
        vec![
            AccountMeta::new(Pubkey::new_from_array(plan.admin), true),
            AccountMeta::new(plan.addresses().config, false),
        ],
    );
    ensure!(
        enable_ix.data == [0x51, 10, 1],
        "reenable-config instruction must be exact opcode 10 true"
    );
    transport::send(
        &rpc,
        &admin,
        None,
        enable_ix,
        "v3-disabled-negative-reenable-config",
        None,
        &mut events,
    )?;
    let reenabled_barrier_slot = transport::wait_finalized(&rpc, &events)?;
    let (reenabled_slot, reenabled) = finalized_accounts(&rpc, &plan, reenabled_barrier_slot)?;
    let reenabled_config = Config::decode(&reenabled[0])
        .map_err(|e| anyhow::anyhow!("config codec after reenable {e:?}"))?;
    let mut expected_reenabled_config = disabled_config.clone();
    expected_reenabled_config
        .set_enabled(
            Authority {
                key: admin.pubkey(),
                is_signer: true,
            },
            true,
        )
        .map_err(|e| anyhow::anyhow!("expected config reenable {e:?}"))?;
    ensure!(
        reenabled_config.enabled
            && reenabled_config.eligibility_epoch
                == disabled_config
                    .eligibility_epoch
                    .checked_add(1)
                    .context("config eligibility epoch overflow after reenable")?
            && reenabled[0] == expected_reenabled_config.encode()
            && reenabled[1..] == before[1..],
        "reenable must only flip config enabled and advance its epoch"
    );
    let reenabled_issuer = Issuer::decode(&reenabled[1])
        .map_err(|e| anyhow::anyhow!("issuer codec after reenable {e:?}"))?;

    let observed_deadline = Instant::now() + Duration::from_secs(20);
    let issuer_observed = loop {
        let candidate = transport::clock(&rpc)?;
        if candidate > reenabled_issuer.observed_at {
            break candidate;
        }
        ensure!(
            Instant::now() < observed_deadline,
            "newer issuer observation deadline"
        );
        thread::sleep(Duration::from_millis(250));
    };
    let issuer_expires = issuer_observed
        .checked_add(240)
        .context("issuer source expiry overflow")?;
    let issuer_next_sequence = reenabled_issuer
        .sequence
        .checked_add(1)
        .context("issuer source sequence overflow")?;
    let issuer_source_digest = source_digest(
        reenabled_config.root,
        &reenabled_issuer,
        issuer_observed,
        issuer_next_sequence,
    );
    ensure!(
        issuer_source_digest != reenabled_issuer.digest,
        "fresh issuer source digest required"
    );
    transport::send(
        &rpc,
        &admin,
        Some(&source),
        plan.observe(
            reenabled_config.eligibility_epoch,
            reenabled_issuer.eligibility_epoch,
            reenabled_issuer.sequence,
            issuer_next_sequence,
            issuer_source_digest,
            true,
            issuer_observed,
            issuer_expires,
        ),
        "v3-disabled-negative-refresh-issuer-source",
        None,
        &mut events,
    )?;
    let issuer_refresh_barrier_slot = transport::wait_finalized(&rpc, &events)?;
    let (_, issuer_observed_accounts) =
        finalized_accounts(&rpc, &plan, issuer_refresh_barrier_slot)?;
    let issuer_observed_state = Issuer::decode(&issuer_observed_accounts[1])
        .map_err(|e| anyhow::anyhow!("issuer codec after issuer observe {e:?}"))?;
    ensure!(
        issuer_observed_accounts[0] == reenabled[0]
            && issuer_observed_accounts[2..] == reenabled[2..]
            && issuer_observed_state.sequence == issuer_next_sequence
            && issuer_observed_state.digest == issuer_source_digest
            && issuer_observed_state.observed_at == issuer_observed
            && issuer_observed_state.expires_at == issuer_expires
            && issuer_observed_state.observed_config_epoch == reenabled_config.eligibility_epoch
            && issuer_observed_state.observed_issuer_epoch == reenabled_issuer.eligibility_epoch
            && issuer_observed_state.status_valid,
        "issuer source refresh changed unexpected accounts or bytes"
    );

    let disabled_head = PublisherHead::decode(&before[2])
        .map_err(|e| anyhow::anyhow!("head codec before issuer rebind {e:?}"))?;
    let issuer_envelope_digest = head_digest(
        reenabled_config.root,
        disabled_head.envelope_digest,
        issuer_source_digest,
        issuer_observed,
    );
    let issuer_binding = V3HeadBinding {
        expected_config_epoch: reenabled_config.eligibility_epoch,
        expected_issuer_epoch: issuer_observed_state.eligibility_epoch,
        expected_root: reenabled_config.root,
        expected_root_version: reenabled_config.root_version,
        expected_source_sequence: issuer_next_sequence,
        expected_source_digest: issuer_source_digest,
        expected_publication_sequence: disabled_head.publication_sequence,
        expected_publication_digest: disabled_head.envelope_digest,
        next_publication_sequence: disabled_head
            .publication_sequence
            .checked_add(1)
            .context("issuer head publication sequence overflow")?,
        envelope_digest: issuer_envelope_digest,
    };
    transport::send(
        &rpc,
        &admin,
        Some(&publisher),
        plan.bind_with_head(&issuer_binding),
        "v3-disabled-negative-rebind-issuer-head",
        None,
        &mut events,
    )?;
    let issuer_eligible_barrier_slot = transport::wait_finalized(&rpc, &events)?;
    let (issuer_eligible_finalized_slot, issuer_eligible) =
        finalized_accounts(&rpc, &plan, issuer_eligible_barrier_slot)?;
    let issuer_eligible_config = Config::decode(&issuer_eligible[0])
        .map_err(|e| anyhow::anyhow!("config codec after issuer bind {e:?}"))?;
    let issuer_eligible_state = Issuer::decode(&issuer_eligible[1])
        .map_err(|e| anyhow::anyhow!("issuer codec after issuer bind {e:?}"))?;
    let issuer_eligible_head = PublisherHead::decode(&issuer_eligible[2])
        .map_err(|e| anyhow::anyhow!("head codec after issuer bind {e:?}"))?;
    ensure!(
        issuer_eligible_config.enabled && issuer_eligible_state.enabled,
        "issuer eligibility requires enabled config and issuer"
    );
    let issuer_eligible_clock = transport::clock(&rpc)?;
    issuer_eligible_state
        .fresh(&issuer_eligible_config, issuer_eligible_clock)
        .map_err(|e| anyhow::anyhow!("issuer freshness after rebind {e:?}"))?;
    issuer_eligible_state
        .binding_current(&issuer_eligible_config)
        .map_err(|e| anyhow::anyhow!("issuer binding after rebind {e:?}"))?;
    ensure!(
        issuer_eligible[0] == reenabled[0]
            && issuer_eligible[3] == reenabled[3]
            && issuer_eligible[4] == reenabled[4]
            && issuer_eligible_head.root == issuer_eligible_config.root
            && issuer_eligible_head.root_version == issuer_eligible_config.root_version
            && issuer_eligible_head.source_sequence == issuer_next_sequence
            && issuer_eligible_head.source_digest == issuer_source_digest
            && issuer_eligible_state.sequence == issuer_next_sequence
            && issuer_eligible_state.digest == issuer_source_digest,
        "issuer-eligible state does not match refreshed source and exact R0 request"
    );
    let issuer_eligible_refs =
        save_snapshot(&config.output_dir, "issuer_eligible", &issuer_eligible)?;

    let disable_issuer_ix = plan.instruction(
        12,
        vec![0],
        vec![
            AccountMeta::new(Pubkey::new_from_array(plan.admin), true),
            AccountMeta::new_readonly(plan.addresses().config, false),
            AccountMeta::new(plan.addresses().issuer, false),
        ],
    );
    ensure!(
        disable_issuer_ix.data == [0x51, 12, 0],
        "disable-issuer instruction must be exact opcode 12 false"
    );
    transport::send(
        &rpc,
        &admin,
        None,
        disable_issuer_ix,
        "v3-disabled-negative-disable-issuer",
        None,
        &mut events,
    )?;
    let issuer_disabled_barrier_slot = transport::wait_finalized(&rpc, &events)?;
    let (issuer_disabled_finalized_slot, issuer_before) =
        finalized_accounts(&rpc, &plan, issuer_disabled_barrier_slot)?;
    let issuer_disabled_state = Issuer::decode(&issuer_before[1])
        .map_err(|e| anyhow::anyhow!("issuer codec after disable {e:?}"))?;
    let mut expected_issuer_disabled = issuer_eligible_state.clone();
    expected_issuer_disabled
        .set_enabled(
            &issuer_eligible_config,
            Authority {
                key: admin.pubkey(),
                is_signer: true,
            },
            false,
        )
        .map_err(|e| anyhow::anyhow!("expected issuer disable {e:?}"))?;
    ensure!(
        !issuer_disabled_state.enabled
            && issuer_disabled_state.eligibility_epoch
                == issuer_eligible_state
                    .eligibility_epoch
                    .checked_add(1)
                    .context("issuer eligibility epoch overflow")?
            && !issuer_disabled_state.status_valid
            && issuer_before[1] == expected_issuer_disabled.encode()
            && issuer_before[0] == issuer_eligible[0]
            && issuer_before[2..] == issuer_eligible[2..],
        "disable issuer must only change issuer bytes as expected"
    );
    let issuer_before_refs = save_snapshot(&config.output_dir, "issuer_before", &issuer_before)?;

    transport::send(
        &rpc,
        &admin,
        None,
        plan.execute(&wire)?,
        "v3-disabled-negative-valid-full-execute-issuer",
        Some(POLICY_ERROR),
        &mut events,
    )?;
    let issuer_rejected_barrier_slot = transport::wait_finalized(&rpc, &events)?;
    let (issuer_rejected_finalized_slot, issuer_after) =
        finalized_accounts(&rpc, &plan, issuer_rejected_barrier_slot)?;
    ensure!(
        issuer_after == issuer_before,
        "issuer-disabled Execute changed one or more finalized accounts"
    );
    let issuer_after_refs = save_snapshot(&config.output_dir, "issuer_after", &issuer_after)?;

    ensure!(
        events.len() == 9,
        "exactly nine negative-run events required"
    );
    let (refresh_signature, refresh_slot) =
        instruction_event(event(&events, 0, "refresh")?, None, "refresh")?;
    let (bind_signature, bind_slot) = instruction_event(event(&events, 1, "bind")?, None, "bind")?;
    let (disable_signature, disable_slot) =
        instruction_event(event(&events, 2, "disable")?, None, "disable")?;
    let (execute_signature, execute_slot) =
        instruction_event(event(&events, 3, "Execute")?, Some(POLICY_ERROR), "Execute")?;
    let (reenable_signature, reenable_slot) = instruction_event(
        event(&events, 4, "reenable config")?,
        None,
        "reenable config",
    )?;
    let (issuer_refresh_signature, issuer_refresh_slot) =
        instruction_event(event(&events, 5, "issuer refresh")?, None, "issuer refresh")?;
    let (issuer_bind_signature, issuer_bind_slot) =
        instruction_event(event(&events, 6, "issuer bind")?, None, "issuer bind")?;
    let (issuer_disable_signature, issuer_disable_slot) =
        instruction_event(event(&events, 7, "issuer disable")?, None, "issuer disable")?;
    let (issuer_execute_signature, issuer_execute_slot) = instruction_event(
        event(&events, 8, "issuer Execute")?,
        Some(POLICY_ERROR),
        "issuer Execute",
    )?;
    let report = json!({
        "schema":"part5-v3-disabled-config-negative-report-v2",
        "variant":config.variant,
        "request_slot":"A",
        "passed":true,
        "program":config.expected_program,
        "genesis":config.expected_genesis,
        "loaded_elf_sha256":config.expected_elf_sha256,
        "stage_report_sha256":config.stage_report_sha256,
        "stage_plan_sha256":config.stage_plan_sha256,
        "full_wire_sha256":config.full_wire_sha256,
        "clone_receipt_sha256":config.heldout_r0_clone_report_sha256,
        "config_disabled":true,
        "execute_rejected":true,
        "refresh_and_bind_succeeded":true,
        "disable_changed_only_enabled_and_epoch":true,
        "accounts_unchanged_after_rejection":true,
        "issuer_disabled":true,
        "issuer_execute_rejected":true,
        "issuer_disable_changed_only_enabled_epoch_status":true,
        "issuer_accounts_unchanged_after_rejection":true,
        "expected_custom_error":POLICY_ERROR,
        "addresses":{
            "config":plan.addresses().config.to_string(),
            "issuer":plan.addresses().issuer.to_string(),
            "head":plan.addresses().head.to_string(),
            "request":plan.addresses().request.to_string(),
            "queue":plan.addresses().queue.to_string()
        },
        "source_finalized_slot":source_slot,
        "eligible_finalized_slot":eligible_slot,
        "disabled_finalized_slot":disabled_finalized_slot,
        "rejected_finalized_slot":rejected_finalized_slot,
        "issuer_eligible_finalized_slot":issuer_eligible_finalized_slot,
        "issuer_eligible_clock":issuer_eligible_clock,
        "issuer_disabled_finalized_slot":issuer_disabled_finalized_slot,
        "issuer_rejected_finalized_slot":issuer_rejected_finalized_slot,
        "refresh_transaction":{"signature":refresh_signature,"slot":refresh_slot},
        "bind_transaction":{"signature":bind_signature,"slot":bind_slot},
        "disable_transaction":{"signature":disable_signature,"slot":disable_slot,"finalized_slot":disabled_finalized_slot},
        "execute_transaction":{"signature":execute_signature,"slot":execute_slot,"custom_error":POLICY_ERROR,"finalized_slot":rejected_finalized_slot},
        "reenable_transaction":{"signature":reenable_signature,"slot":reenable_slot,"finalized_slot":reenabled_slot},
        "issuer_refresh_transaction":{"signature":issuer_refresh_signature,"slot":issuer_refresh_slot},
        "issuer_bind_transaction":{"signature":issuer_bind_signature,"slot":issuer_bind_slot,"finalized_slot":issuer_eligible_finalized_slot},
        "issuer_disable_transaction":{"signature":issuer_disable_signature,"slot":issuer_disable_slot,"finalized_slot":issuer_disabled_finalized_slot},
        "issuer_execute_transaction":{"signature":issuer_execute_signature,"slot":issuer_execute_slot,"custom_error":POLICY_ERROR,"finalized_slot":issuer_rejected_finalized_slot},
        "eligible_sha256":account_hashes(&eligible),
        "before_sha256":account_hashes(&before),
        "after_sha256":account_hashes(&after),
        "issuer_eligible_sha256":account_hashes(&issuer_eligible),
        "issuer_before_sha256":account_hashes(&issuer_before),
        "issuer_after_sha256":account_hashes(&issuer_after),
        "eligible_accounts":eligible_refs,
        "before_accounts":before_refs,
        "after_accounts":after_refs,
        "issuer_eligible_accounts":issuer_eligible_refs,
        "issuer_before_accounts":issuer_before_refs,
        "issuer_after_accounts":issuer_after_refs,
        "transactions":events
    });
    transport::new_json(
        &config
            .output_dir
            .join("disabled-config-negative-report.json"),
        &report,
    )?;
    Ok(())
}
