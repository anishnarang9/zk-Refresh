//! Loaded expired-status observations. External measurements and cleanup are absent.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_requires_strictly_past_expiry_and_bounded_age() {
        assert!(!expired_at(100, 115, 114).unwrap());
        assert!(!expired_at(100, 115, 115).unwrap());
        assert!(expired_at(100, 115, 116).unwrap());
        assert!(expired_at(100, 115, 400).unwrap());
        assert!(expired_at(100, 115, 401).is_err());
        assert!(expired_at(100, 115, 99).is_err());
        assert!(expired_at(100, 100, 116).is_err());
        assert!(expired_at(100, 401, 402).is_err());
    }

    #[test]
    fn finalized_error_requires_exact_execute_index_and_status_code() {
        assert!(check_error(&json!({"InstructionError":[1,{"Custom":705}]})).is_ok());
        assert!(check_error(&json!({"InstructionError":[0,{"Custom":705}]})).is_err());
        assert!(check_error(&json!({"InstructionError":[1,{"Custom":708}]})).is_err());
        assert!(check_error(&Value::Null).is_err());
    }
}

use super::*;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

const ACCOUNT_NAMES: [&str; 5] = ["config", "issuer", "head", "request", "queue"];
const STATUS_ERROR: u64 = zk_fresh_program::application_v3::AppError::Status as u64;

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key].as_str().with_context(|| format!("config {key}"))
}
fn path(value: &Value, key: &str) -> Result<PathBuf> {
    let path = PathBuf::from(text(value, key)?);
    ensure!(
        path.is_absolute() && fs::canonicalize(&path)? == path,
        "canonical {key} path required"
    );
    Ok(path)
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
fn expired_at(observed: i64, expires: i64, now: i64) -> Result<bool> {
    ensure!(
        observed >= 0
            && expires > observed
            && expires
                .checked_sub(observed)
                .context("status lifetime overflow")?
                <= 300,
        "bounded active status lifetime required"
    );
    ensure!(
        now >= observed && now.checked_sub(observed).context("status age overflow")? <= 300,
        "finalized observation age exceeds clean expired-status bound"
    );
    Ok(now > expires)
}
fn check_error(error: &Value) -> Result<()> {
    ensure!(
        *error == json!({"InstructionError":[1,{"Custom":705}]}),
        "exact Execute instruction 1 custom 705 required"
    );
    Ok(())
}
fn finalized_clock(rpc: &Rpc, minimum_slot: u64) -> Result<(u64, i64)> {
    let slot = rpc
        .call("getSlot", json!([{"commitment":"finalized"}]))?
        .as_u64()
        .context("finalized RPC slot")?;
    ensure!(
        slot > 0 && slot >= minimum_slot,
        "finalized RPC clock regressed"
    );
    let now = rpc
        .call("getBlockTime", json!([slot]))?
        .as_i64()
        .context("finalized RPC block time")?;
    ensure!(now >= 0, "nonnegative finalized RPC block time required");
    Ok((slot, now))
}
fn finalized_transaction(rpc: &Rpc, event: &Value, expected: Option<u64>) -> Result<Value> {
    let signature = event["signature"]
        .as_str()
        .context("transaction signature")?;
    let status = rpc.call(
        "getSignatureStatuses",
        json!([[signature],{"searchTransactionHistory":true}]),
    )?;
    let status = &status["value"][0];
    ensure!(
        status["confirmationStatus"] == "finalized",
        "transaction status must be finalized"
    );
    let recorded = rpc.call(
        "getTransaction",
        json!([signature,
        {"commitment":"finalized","encoding":"json","maxSupportedTransactionVersion":0}]),
    )?;
    let slot = recorded["slot"]
        .as_u64()
        .context("finalized transaction slot")?;
    ensure!(
        slot > 0
            && event["slot"].as_u64() == Some(slot)
            && status["slot"].as_u64() == Some(slot)
            && !recorded["meta"].is_null()
            && recorded["meta"]["err"] == status["err"]
            && recorded["meta"]["err"] == event["err"],
        "finalized transaction differs from observed submission"
    );
    if expected.is_some() {
        ensure!(
            expected == Some(STATUS_ERROR),
            "only Status negative permitted"
        );
        check_error(&recorded["meta"]["err"])?;
    } else {
        ensure!(
            recorded["meta"]["err"].is_null(),
            "publisher transaction failed at finalization"
        );
    }
    Ok(
        json!({"signature":signature,"slot":slot,"finalized":true,"error":recorded["meta"]["err"],
        "block_time":recorded["blockTime"]}),
    )
}
fn save_snapshot(output: &Path, phase: &str, accounts: &[Vec<u8>; 5]) -> Result<Vec<Value>> {
    let root = output.join(phase);
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    private_dir(&root)?;
    ACCOUNT_NAMES
        .iter()
        .zip(accounts)
        .map(|(name, bytes)| {
            let path = root.join(format!("{name}.bin"));
            transport::new_file(&path, bytes)?;
            Ok(json!({"path":path,"sha256":sha(bytes)}))
        })
        .collect()
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

pub fn expired_status_negative_from_env() -> Result<()> {
    let started = Instant::now();
    ensure!(
        transport::env("P5_V3_EXPIRED_STATUS_NEGATIVE_SCOPE")?
            == "part5-v3-expired-status-negative",
        "explicit expired-status scope required"
    );
    let config_path = PathBuf::from(transport::env("P5_V3_EXPIRED_STATUS_NEGATIVE_CONFIG")?);
    ensure!(
        config_path.is_absolute() && fs::canonicalize(&config_path)? == config_path,
        "canonical supervisor config required"
    );
    let config_sha = transport::env("P5_V3_EXPIRED_STATUS_NEGATIVE_CONFIG_SHA256")?;
    let config: Value =
        serde_json::from_slice(&transport::pinned(&config_path, &config_sha, 65536)?)?;
    ensure!(
        config["schema"] == "credential-v3-expired-status-negative-supervisor-v1"
            && config["scope"] == "part5-v3-expired-status-negative"
            && config["variant"]
                .as_u64()
                .is_some_and(|variant| variant < 8)
            && config["request_slot"] == "A"
            && config["owner"]
                .as_str()
                .is_some_and(|owner| !owner.is_empty())
            && config["outer_limits_required"]
                == json!({"runtime_seconds":180,"rss_bytes":4294967296u64,"storage_growth_bytes":268435456})
            && config["owner_process_limits"] == json!({"validators":1,"runners":1}),
        "exact bounded expired-status supervisor config required"
    );
    let lifetime = config["observation_lifetime_seconds"]
        .as_i64()
        .context("observation lifetime")?;
    let wait_seconds = config["wait_deadline_seconds"]
        .as_u64()
        .context("wait deadline")?;
    ensure!(
        (15..=30).contains(&lifetime) && (1..=60).contains(&wait_seconds),
        "bounded expiry and wait required"
    );
    let stage_root = path(&config, "stage_root")?;
    let output = path(&config, "output_dir")?;
    let control = path(&config, "control_output")?;
    let ledger = path(&config, "ledger")?;
    for directory in [&stage_root, &output, &control, &ledger] {
        private_dir(directory)?;
    }
    ensure!(
        output != control
            && output == transport::output()?
            && fs::read_dir(&output)?.next().is_none(),
        "fresh separate negative output required"
    );
    ensure!(
        transport::env("P5_V3_STAGE_ROOT")? == stage_root.to_string_lossy().as_ref()
            && transport::env("P5_QUEUE_PROGRAM")? == text(&config, "expected_program")?
            && transport::env("P5_QUEUE_GENESIS")? == text(&config, "expected_genesis")?
            && transport::env("P5_QUEUE_ELF_SHA256")? == text(&config, "expected_elf_sha256")?
            && PathBuf::from(transport::env("P5_QUEUE_ELF")?) == path(&config, "expected_elf")?,
        "supervised runtime differs from pinned config"
    );
    let mut inputs = serde_json::Map::new();
    for (key, digest_key, cap) in [
        ("freeze_report", "freeze_sha256", 1024 * 1024),
        ("stage_config", "stage_config_sha256", 65536),
        ("stage_status", "stage_status_sha256", 65536),
        ("stage_report", "stage_report_sha256", 65536),
        ("stage_plan", "stage_plan_sha256", 65536),
        ("source_receipt", "source_receipt_sha256", 65536),
        ("clone_receipt", "clone_receipt_sha256", 65536),
        ("full_proof_receipt", "full_proof_receipt_sha256", 65536),
        ("full_proof", "full_proof_sha256", 32 * 1024 * 1024),
        ("full_wire", "full_wire_sha256", 448),
        ("runner", "runner_sha256", 128 * 1024 * 1024),
        ("expected_elf", "expected_elf_sha256", 4 * 1024 * 1024),
    ] {
        let input_path = path(&config, key)?;
        let raw = transport::pinned(&input_path, text(&config, digest_key)?, cap)?;
        ensure!(!raw.is_empty(), "nonempty pinned input required");
        inputs.insert(key.into(), json!({"path":input_path,"sha256":sha(&raw)}));
    }
    let read_json = |key: &str, digest_key: &str| -> Result<Value> {
        Ok(serde_json::from_slice(&transport::pinned(
            &path(&config, key)?,
            text(&config, digest_key)?,
            1024 * 1024,
        )?)?)
    };
    let report = read_json("stage_report", "stage_report_sha256")?;
    let clone = read_json("clone_receipt", "clone_receipt_sha256")?;
    let plan: V3QueuePlan = serde_json::from_value(read_json("stage_plan", "stage_plan_sha256")?)?;
    ensure!(
        path(&config, "stage_report")? == stage_root.join("stage-report.json")
            && path(&config, "stage_plan")? == stage_root.join("plan.json")
            && report["schema"] == "part5-v3-local-stage-v1"
            && report["passed"] == true
            && report["training_only"] == true
            && report["application_effect"] == false
            && report["proof_created"] == false
            && report["registry_history_authenticated"] == true
            && report["allocation_history_authenticated"] == true
            && report["plan_sha256"] == config["stage_plan_sha256"]
            && report["program"] == config["expected_program"]
            && report["genesis"] == config["expected_genesis"]
            && report["loaded_program"]["elf_match"] == true
            && report["loaded_program"]["elf_sha256"] == config["expected_elf_sha256"],
        "pinned stage identity mismatch"
    );
    ensure!(
        clone["schema"] == "part5-v3-heldout-r0-ledger-clone-v1"
            && clone["stage_report_sha256"] == config["stage_report_sha256"]
            && clone["stage_status_sha256"] == config["stage_status_sha256"]
            && clone["source_stable"] == true
            && clone["copy_identical"] == true
            && clone["application_effect"] == false
            && clone["destination"].as_str() == Some(ledger.to_string_lossy().as_ref())
            && clone["source"]
                .as_str()
                .is_some_and(|source| source != ledger.to_string_lossy().as_ref()),
        "separate pinned R0 clone required"
    );
    let genesis = transport::pinned(
        &ledger.join("genesis.bin"),
        text(&config, "expected_genesis_sha256")?,
        16 * 1024 * 1024,
    )?;
    ensure!(!genesis.is_empty(), "pinned ledger genesis required");
    let wire = transport::pinned(
        &path(&config, "full_wire")?,
        text(&config, "full_wire_sha256")?,
        448,
    )?;
    ensure!(
        wire.len() == 448,
        "complete pinned Full Execute wire required"
    );
    let rpc = transport::local_rpc()?;
    let (program, genesis, loaded) = transport::domain(&rpc)?;
    ensure!(
        program == plan.program
            && genesis == plan.genesis
            && loaded["elf_sha256"] == config["expected_elf_sha256"]
            && loaded["elf_match"] == true,
        "loaded validator identity differs from plan"
    );
    let stage_slot = report["finalized_slot"]
        .as_u64()
        .context("stage finalized slot")?;
    let (initial_slot, initial) = finalized_accounts(&rpc, &plan, stage_slot)?;
    for (index, name) in ACCOUNT_NAMES.iter().enumerate() {
        let digest = report["account_sha256"][index]
            .as_str()
            .context("staged account digest")?;
        ensure!(
            transport::pinned(&stage_root.join(format!("{name}.bin")), digest, 4096)?
                == initial[index],
            "fresh cloned account differs from pinned R0 bytes"
        );
        let address = match index {
            0 => plan.addresses().config,
            1 => plan.addresses().issuer,
            2 => plan.addresses().head,
            3 => plan.addresses().request,
            _ => plan.addresses().queue,
        };
        ensure!(
            report[*name] == address.to_string(),
            "staged address mismatch"
        );
    }
    let c = Config::decode(&initial[0]).map_err(|e| anyhow::anyhow!("config codec {e:?}"))?;
    let i = Issuer::decode(&initial[1]).map_err(|e| anyhow::anyhow!("issuer codec {e:?}"))?;
    let h = PublisherHead::decode(&initial[2]).map_err(|e| anyhow::anyhow!("head codec {e:?}"))?;
    let r = Request::decode(&initial[3]).map_err(|e| anyhow::anyhow!("request codec {e:?}"))?;
    let q = Queue::decode(&initial[4]).map_err(|e| anyhow::anyhow!("queue codec {e:?}"))?;
    ensure!(
        c.enabled && i.enabled && r.state == RequestState::Finalized && q.entries.is_empty(),
        "enabled finalized unconsumed R0 request required"
    );
    let (context, root, issuer_hash, policy_id, _, _) = training_context()?;
    ensure!(
        plan.root == root && plan.issuer_hash == issuer_hash && plan.policy_id == policy_id,
        "registered R0 context differs from request"
    );
    validate_full_wire(&plan, &c, &r, context.not_before, context.not_after, &wire)?;
    let admin = transport::load_key(&stage_root, "admin.json", plan.admin)?;
    let publisher = transport::load_key(&stage_root, "publisher.json", plan.publisher)?;
    let source = transport::load_key(&stage_root, "source.json", plan.source)?;
    for name in ["admin.json", "publisher.json", "source.json"] {
        ensure!(
            fs::symlink_metadata(stage_root.join(name))?.uid() == unsafe { libc::geteuid() },
            "key owner mismatch"
        );
    }
    let mut events = Vec::new();
    let observation_deadline = Instant::now() + Duration::from_secs(20);
    let observed = loop {
        let now = transport::clock(&rpc)?;
        if now > i.observed_at {
            break now;
        }
        ensure!(
            Instant::now() < observation_deadline,
            "newer confirmed source clock deadline"
        );
        thread::sleep(Duration::from_millis(250));
    };
    let expires = observed.checked_add(lifetime).context("expiry overflow")?;
    ensure!(
        r.deadline > expires && context.not_before <= observed && context.not_after > expires,
        "request and credential must remain live beyond status expiry"
    );
    let sequence = i
        .sequence
        .checked_add(1)
        .context("source sequence overflow")?;
    let digest = source_digest(c.root, &i, observed, sequence);
    ensure!(digest != i.digest, "new source digest required");
    transport::send(
        &rpc,
        &admin,
        Some(&source),
        plan.observe(
            c.eligibility_epoch,
            i.eligibility_epoch,
            i.sequence,
            sequence,
            digest,
            true,
            observed,
            expires,
        ),
        "v3-expired-negative-active-source",
        None,
        &mut events,
    )?;
    let binding = V3HeadBinding {
        expected_config_epoch: c.eligibility_epoch,
        expected_issuer_epoch: i.eligibility_epoch,
        expected_root: c.root,
        expected_root_version: c.root_version,
        expected_source_sequence: sequence,
        expected_source_digest: digest,
        expected_publication_sequence: h.publication_sequence,
        expected_publication_digest: h.envelope_digest,
        next_publication_sequence: h
            .publication_sequence
            .checked_add(1)
            .context("publication sequence overflow")?,
        envelope_digest: head_digest(c.root, h.envelope_digest, digest, observed),
    };
    transport::send(
        &rpc,
        &admin,
        Some(&publisher),
        plan.bind_with_head(&binding),
        "v3-expired-negative-bind-head",
        None,
        &mut events,
    )?;
    let bind_barrier = transport::wait_finalized(&rpc, &events)?;
    let source_transaction = finalized_transaction(&rpc, &events[0], None)?;
    let bind_transaction = finalized_transaction(&rpc, &events[1], None)?;
    let source_time = source_transaction["block_time"]
        .as_i64()
        .context("finalized source block time")?;
    let bind_time = bind_transaction["block_time"]
        .as_i64()
        .context("finalized bind block time")?;
    ensure!(
        observed <= source_time && source_time <= bind_time && bind_time < expires,
        "finalized source and successful head bind must precede status expiry"
    );
    let (bound_slot, bound) = finalized_accounts(&rpc, &plan, bind_barrier)?;
    let bound_issuer =
        Issuer::decode(&bound[1]).map_err(|e| anyhow::anyhow!("bound issuer codec {e:?}"))?;
    let bound_head =
        PublisherHead::decode(&bound[2]).map_err(|e| anyhow::anyhow!("bound head codec {e:?}"))?;
    bound_issuer
        .binding_current(&c)
        .map_err(|e| anyhow::anyhow!("issuer binding {e:?}"))?;
    ensure!(
        bound[0] == initial[0]
            && bound[3..] == initial[3..]
            && bound_issuer.status_valid
            && bound_issuer.enabled
            && bound_issuer.observed_at == observed
            && bound_issuer.expires_at == expires
            && bound_issuer.sequence == sequence
            && bound_issuer.digest == digest
            && bound_head.config == plan.addresses().config
            && bound_head.issuer == plan.addresses().issuer
            && bound_head.publisher == c.publisher
            && bound_head.root == c.root
            && bound_head.root_version == c.root_version
            && bound_head.source_sequence == sequence
            && bound_head.source_digest == digest
            && bound_head.config_epoch == c.eligibility_epoch
            && bound_head.issuer_epoch == bound_issuer.eligibility_epoch
            && bound_head.publication_sequence == binding.next_publication_sequence
            && bound_head.envelope_digest == binding.envelope_digest,
        "active bound state differs from exact request"
    );
    let wait_started = Instant::now();
    let deadline = wait_started + Duration::from_secs(wait_seconds);
    let (expiry_slot, expiry_now) = loop {
        ensure!(
            Instant::now() < deadline,
            "finalized RPC expiry wait deadline"
        );
        let (slot, now) = finalized_clock(&rpc, bound_slot)?;
        ensure!(
            Instant::now() < deadline,
            "finalized RPC expiry wait deadline"
        );
        if expired_at(observed, expires, now)? {
            break (slot, now);
        }
        thread::sleep(Duration::from_millis(250));
    };
    let wait_elapsed = wait_started.elapsed().as_secs_f64();
    let (before_slot, before) = finalized_accounts(&rpc, &plan, expiry_slot)?;
    ensure!(
        before == bound,
        "bound application accounts changed while waiting for expiry"
    );
    let before_refs = save_snapshot(&output, "before", &before)?;
    let (submit_clock_slot, submit_now) = finalized_clock(&rpc, before_slot)?;
    ensure!(
        expired_at(observed, expires, submit_now)?
            && submit_now <= r.deadline
            && submit_now >= context.not_before
            && submit_now <= context.not_after,
        "clean expired-status submit preconditions failed"
    );
    transport::send(
        &rpc,
        &admin,
        None,
        plan.execute(&wire)?,
        "v3-expired-negative-valid-full-execute",
        Some(STATUS_ERROR),
        &mut events,
    )?;
    ensure!(
        events.len() == 3,
        "exactly one source, bind and Execute transaction required"
    );
    let execute_barrier = transport::wait_finalized(&rpc, &events)?;
    let transaction = finalized_transaction(&rpc, &events[2], Some(STATUS_ERROR))?;
    let execution_now = transaction["block_time"]
        .as_i64()
        .context("finalized Execute block time")?;
    ensure!(
        execution_now >= submit_now
            && expired_at(observed, expires, execution_now)?
            && execution_now <= r.deadline
            && execution_now <= context.not_after,
        "Execute block time violates clean expiry or live request bound"
    );
    let (after_slot, after) = finalized_accounts(&rpc, &plan, execute_barrier)?;
    ensure!(
        after == before,
        "rejected Execute changed finalized application accounts"
    );
    let after_refs = save_snapshot(&output, "after", &after)?;
    let (_, _, loaded_after) = transport::domain(&rpc)?;
    ensure!(
        loaded_after == loaded,
        "loaded identity changed during negative run"
    );
    let snapshots: Vec<Value> = ACCOUNT_NAMES.iter().enumerate().map(|(index, name)|
        json!({"name":name,"before":before_refs[index],"after":after_refs[index]})).collect();
    // The supervisor must bind this file's hash, live RPC rechecks, external owner
    // measurements and post-exit cleanup before constructing final evidence.
    let candidate = json!({
        "schema":"credential-v3-expired-status-negative-rust-candidate-v1",
        "config_ref":{"path":config_path,"sha256":config_sha},
        "identities":{"freeze":config["freeze_sha256"],"genesis":config["expected_genesis_sha256"],
            "loaded_elf":config["expected_elf_sha256"],"stage":config["stage_report_sha256"],
            "clone":config["clone_receipt_sha256"],"full_proof":config["full_proof_receipt_sha256"],
            "full_wire":config["full_wire_sha256"]},
        "input_refs":inputs,
        "source_refs":{"full_proof":{"path":path(&config,"full_proof_receipt")?,"sha256":config["full_proof_receipt_sha256"]},
            "full_wire":{"path":path(&config,"full_wire")?,"sha256":config["full_wire_sha256"]}},
        "program":config["expected_program"],"genesis":config["expected_genesis"],
        "loaded_program_before":loaded,"loaded_program_after":loaded_after,
        "clock":{"observed_at":observed,"expires_at":expires,"now":submit_now,"rpc_finalized":true},
        "clock_observations":{"expiry_slot":expiry_slot,"expiry_now":expiry_now,
            "submit_slot":submit_clock_slot,"execution_now":execution_now},
        "preconditions":{"status_active":bound_issuer.status_valid,"issuer_active":bound_issuer.enabled,
            "head_bound":true,"request_live":true,"full_wire_statement_matches":true},
        "transaction":{"signature":transaction["signature"],"slot":transaction["slot"],
            "finalized":transaction["finalized"],"error":transaction["error"]},
        "publisher_transactions":{"source":source_transaction,"bind":bind_transaction},
        "account_slots":{"initial":initial_slot,"bound":bound_slot,"before":before_slot,"after":after_slot},
        "snapshots":snapshots,"runner_observations":{"pid":std::process::id(),
            "elapsed_seconds":started.elapsed().as_secs_f64(),"clock_wait_seconds":wait_elapsed},
        "external_finalization_required":true,"full_proof_verified_in_rust":false,"application_effect":false
    });
    transport::new_json(
        &output.join("expired-status-negative-report.json"),
        &candidate,
    )?;
    Ok(())
}
