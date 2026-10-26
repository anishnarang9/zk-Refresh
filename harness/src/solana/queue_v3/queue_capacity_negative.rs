//! Runtime facts only. The external owner supplies process bounds and post-exit cleanup.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_error_requires_exact_execute_index_and_ordinal() {
        assert!(capacity_error(&json!({"InstructionError":[1,{"Custom":708}]})).is_ok());
        for value in [
            Value::Null,
            json!({"InstructionError":[0,{"Custom":708}]}),
            json!({"InstructionError":[1,{"Custom":705}]}),
            json!({"InstructionError":[1,{"Custom":708}],"extra":true}),
        ] {
            assert!(capacity_error(&value).is_err());
        }
    }

    #[test]
    fn queue_requires_exact_order_distinctness_and_rejected_absence() {
        let expected: Vec<Pubkey> = (0..64).map(|_| Pubkey::new_unique()).collect();
        let rejected = Pubkey::new_unique();
        assert!(queue_exact(&expected, &expected, rejected).is_ok());
        assert!(queue_exact(&expected[..63], &expected, rejected).is_err());
        let mut changed = expected.clone();
        changed.swap(0, 1);
        assert!(queue_exact(&changed, &expected, rejected).is_err());
        changed[1] = changed[0];
        assert!(queue_exact(&changed, &changed, rejected).is_err());
        assert!(queue_exact(&expected, &expected, expected[0]).is_err());
    }

    #[test]
    fn proof_receipt_requires_exact_request_action_wire_and_complete_full_checks() {
        let input: Input = serde_json::from_value(json!({
            "request_address":"request-65", "action_sha256":"a".repeat(64),
            "request_account":"/private/request.bin", "request_sha256":"b".repeat(64),
            "proof_receipt":"/private/proof-receipt.json", "proof_receipt_sha256":"c".repeat(64),
            "full_wire":"/private/full-wire.bin", "full_wire_sha256":"d".repeat(64)
        }))
        .unwrap();
        let receipt = json!({"schema":"part5-v3-queue-capacity-full-proof-v1",
            "mode":"campaign-coalesced-full-k0", "request_address":input.request_address,
            "request_sha256":input.request_sha256, "action_sha256":input.action_sha256,
            "wire":{"path":input.full_wire,"sha256":input.full_wire_sha256},
            "full_wire_verified":true,"complete_relation_checked":true});
        assert!(check_proof_receipt(&receipt, &input).is_ok());
        for field in ["request_address", "request_sha256", "action_sha256", "mode"] {
            let mut wrong = receipt.clone();
            wrong[field] = json!("different");
            assert!(check_proof_receipt(&wrong, &input).is_err());
        }
        for field in ["full_wire_verified", "complete_relation_checked"] {
            let mut wrong = receipt.clone();
            wrong[field] = json!(false);
            assert!(check_proof_receipt(&wrong, &input).is_err());
        }
        let mut wrong = receipt.clone();
        wrong["wire"]["sha256"] = json!("e".repeat(64));
        assert!(check_proof_receipt(&wrong, &input).is_err());
    }

    #[test]
    fn wire_verification_rejects_a_complete_invalid_proof() {
        assert!(verify_wire(&[0; 448]).is_err());
        assert!(verify_wire(&[0; 447]).is_err());
    }
}

use super::*;
use std::collections::BTreeSet;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use zk_fresh_program::application_v3::{AppError, QUEUE_CAPACITY};

const NAMES: [&str; 5] = ["config", "issuer", "head", "request", "queue"];
const SCOPE: &str = "part5-v3-loaded-queue-capacity-negative";

#[derive(Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Input {
    request_address: String,
    action_sha256: String,
    request_account: PathBuf,
    request_sha256: String,
    proof_receipt: PathBuf,
    proof_receipt_sha256: String,
    full_wire: PathBuf,
    full_wire_sha256: String,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Reference {
    path: PathBuf,
    sha256: String,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SignerReference {
    path: PathBuf,
    public_key: String,
    sha256: String,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Signers {
    payer: SignerReference,
    admin: SignerReference,
    source: SignerReference,
    publisher: SignerReference,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Finalization {
    request_address: String,
    signature: String,
    slot: u64,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    schema: String,
    program: String,
    genesis: String,
    genesis_sha256: String,
    elf_sha256: String,
    stage_report: Reference,
    signers: Signers,
    inputs: Vec<Input>,
    request_finalizations: Vec<Finalization>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CapacityConfig {
    schema: String,
    scope: String,
    runner_test: String,
    cohort_id: String,
    cohort_freeze_sha256: String,
    cohort_manifest_sha256: String,
    stage_report_sha256: String,
    clone_receipt_sha256: String,
    ledger: PathBuf,
    program: String,
    genesis: String,
    genesis_sha256: String,
    elf_sha256: String,
    input_count: usize,
    queue_capacity: usize,
    inputs: Vec<Input>,
    fixture_manifest: PathBuf,
    fixture_manifest_sha256: String,
    output_dir: PathBuf,
    outer_limits_required: Value,
}
fn sha(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}
fn private_dir(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && fs::canonicalize(path)? == path
            && m.is_dir()
            && m.permissions().mode() & 0o7777 == 0o700
            && m.uid() == unsafe { libc::geteuid() },
        "canonical owner-only directory required"
    );
    Ok(())
}
fn private_pin(path: &Path, digest: &str, cap: u64) -> Result<Vec<u8>> {
    private_dir(path.parent().context("private file parent")?)?;
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && fs::canonicalize(path)? == path
            && m.is_file()
            && m.permissions().mode() & 0o7777 == 0o600
            && m.nlink() == 1
            && m.uid() == unsafe { libc::geteuid() },
        "canonical owner-only single-link file required"
    );
    let bytes = transport::pinned(path, digest, cap)?;
    ensure!(!bytes.is_empty(), "nonempty pinned file required");
    Ok(bytes)
}
fn key(reference: &SignerReference) -> Result<Keypair> {
    let raw = private_pin(&reference.path, &reference.sha256, 1024)?;
    let bytes: Vec<u8> = serde_json::from_slice(&raw)?;
    let key = Keypair::from_bytes(&bytes)?;
    ensure!(
        key.pubkey().to_string() == reference.public_key,
        "fixture signer public key differs"
    );
    Ok(key)
}
fn capacity_error(error: &Value) -> Result<()> {
    ensure!(
        *error == json!({"InstructionError":[1,{"Custom":708}]}),
        "exact finalized instruction 1 Custom 708 required"
    );
    Ok(())
}
fn queue_exact(actual: &[Pubkey], expected: &[Pubkey], rejected: Pubkey) -> Result<()> {
    ensure!(
        actual == expected
            && actual.len() <= QUEUE_CAPACITY
            && actual.iter().collect::<BTreeSet<_>>().len() == actual.len()
            && !actual.contains(&rejected),
        "queue differs from exact distinct fill history"
    );
    Ok(())
}
fn check_proof_receipt(receipt: &Value, input: &Input) -> Result<()> {
    ensure!(
        receipt["schema"] == "part5-v3-queue-capacity-full-proof-v1"
            && receipt["mode"] == "campaign-coalesced-full-k0"
            && receipt["request_address"] == input.request_address
            && receipt["request_sha256"] == input.request_sha256
            && receipt["action_sha256"] == input.action_sha256
            && receipt["wire"]["path"].as_str() == input.full_wire.to_str()
            && receipt["wire"]["sha256"] == input.full_wire_sha256
            && receipt["full_wire_verified"] == true
            && receipt["complete_relation_checked"] == true,
        "exact request/action/wire-bound complete Full proof receipt required"
    );
    Ok(())
}
fn verify_wire(wire: &[u8]) -> Result<[[u8; 32]; 6]> {
    ensure!(wire.len() == 448, "exact Full wire length required");
    let inputs: Vec<[u8; 32]> = wire[..192]
        .chunks_exact(32)
        .map(|word| word.try_into().expect("exact word"))
        .collect();
    let inputs: [[u8; 32]; 6] = inputs
        .try_into()
        .map_err(|_| anyhow::anyhow!("public count"))?;
    let proof: &[u8; 256] = wire[192..].try_into()?;
    zk_fresh_program::application_runtime_v3::verify(&inputs, proof)
        .map_err(|e| anyhow::anyhow!("independent Full proof verification failed: {e:?}"))?;
    Ok(inputs)
}
fn plan(program: [u8; 32], c: &Config, i: &Issuer, r: &Request) -> V3QueuePlan {
    V3QueuePlan {
        program,
        genesis: c.genesis,
        admin: c.admin.to_bytes(),
        publisher: c.publisher.to_bytes(),
        source: i.source.to_bytes(),
        creator: r.creator.to_bytes(),
        seed: c.seed,
        nonce: r.nonce,
        recipient: r.recipient.to_bytes(),
        issuer_hash: r.issuer_hash,
        aki: i.aki,
        root: c.root,
        policy_id: c.policy_id,
        deadline: r.deadline,
        payload: r.payload.clone(),
    }
}
fn wire_times(wire: &[u8]) -> Result<(i64, i64)> {
    ensure!(
        wire.len() == 448 && wire[64..88] == [0; 24] && wire[96..120] == [0; 24],
        "bounded signed validity public words required"
    );
    Ok((
        i64::try_from(u64::from_be_bytes(wire[88..96].try_into()?))?,
        i64::try_from(u64::from_be_bytes(wire[120..128].try_into()?))?,
    ))
}
fn clock(rpc: &Rpc, minimum: u64) -> Result<(u64, i64)> {
    let slot = rpc
        .call("getSlot", json!([{"commitment":"finalized"}]))?
        .as_u64()
        .context("finalized clock slot")?;
    ensure!(slot > 0 && slot >= minimum, "finalized clock regressed");
    let now = rpc
        .call("getBlockTime", json!([slot]))?
        .as_i64()
        .context("finalized block time")?;
    ensure!(now >= 0, "nonnegative finalized block time required");
    Ok((slot, now))
}
// Reopen the finalized signed transaction and check the actual instruction and account order.
fn transaction(
    rpc: &Rpc,
    signature: &str,
    slot: u64,
    instruction: &Instruction,
    negative: bool,
) -> Result<Value> {
    let status = rpc.call(
        "getSignatureStatuses",
        json!([[signature],{"searchTransactionHistory":true}]),
    )?;
    let status = &status["value"][0];
    ensure!(
        slot > 0
            && status["confirmationStatus"] == "finalized"
            && status["slot"].as_u64() == Some(slot),
        "finalized signature/slot required"
    );
    let record = rpc.call(
        "getTransaction",
        json!([signature,
        {"encoding":"base64","commitment":"finalized","maxSupportedTransactionVersion":0}]),
    )?;
    ensure!(
        record["slot"].as_u64() == Some(slot)
            && !record["meta"].is_null()
            && record["meta"]["err"] == status["err"],
        "finalized transaction status mismatch"
    );
    let encoded = record["transaction"][0]
        .as_str()
        .context("finalized encoded transaction")?;
    ensure!(
        encoded.len() <= 2048 && record["transaction"][1] == "base64",
        "bounded legacy transaction required"
    );
    let tx: solana_sdk::transaction::Transaction =
        bincode::deserialize(&STANDARD.decode(encoded)?)?;
    tx.verify()?;
    ensure!(
        tx.signatures.first().map(ToString::to_string).as_deref() == Some(signature)
            && tx.message.instructions.len() == 2,
        "exact signed two-instruction transaction required"
    );
    let ix = &tx.message.instructions[1];
    ensure!(
        tx.message.account_keys.get(ix.program_id_index as usize) == Some(&instruction.program_id)
            && ix.data == instruction.data
            && ix.accounts.len() == instruction.accounts.len(),
        "finalized application instruction differs"
    );
    for (index, expected) in ix.accounts.iter().zip(&instruction.accounts) {
        let index = usize::from(*index);
        ensure!(
            tx.message.account_keys.get(index) == Some(&expected.pubkey)
                && tx.message.is_signer(index) == expected.is_signer
                && tx.message.is_maybe_writable(index, None) == expected.is_writable,
            "finalized ordered account privilege differs"
        );
    }
    let first = &tx.message.instructions[0];
    ensure!(
        tx.message.account_keys.get(first.program_id_index as usize)
            == Some(&solana_sdk::compute_budget::id()),
        "instruction zero must be compute budget"
    );
    if negative {
        capacity_error(&record["meta"]["err"])?;
    } else {
        ensure!(
            record["meta"]["err"].is_null(),
            "finalized application transaction failed"
        );
    }
    Ok(json!({"signature":signature,"slot":slot,"finalized":true,
        "rpc_error":record["meta"]["err"],"block_time":record["blockTime"]}))
}
fn send(
    rpc: &Rpc,
    payer: &Keypair,
    signer: Option<&Keypair>,
    instruction: Instruction,
    label: &str,
    negative: bool,
    events: &mut Vec<Value>,
) -> Result<(u64, Value)> {
    transport::send(
        rpc,
        payer,
        signer,
        instruction.clone(),
        label,
        if negative {
            Some(AppError::Capacity as u64)
        } else {
            None
        },
        events,
    )?;
    let barrier = transport::wait_finalized(rpc, events)?;
    let event = events.last().context("submitted event")?;
    let signature = event["signature"].as_str().context("submitted signature")?;
    let slot = event["slot"].as_u64().context("submitted slot")?;
    Ok((
        barrier,
        transaction(rpc, signature, slot, &instruction, negative)?,
    ))
}
fn save(output: &Path, relative: &str, bytes: &[u8]) -> Result<Value> {
    let target = output.join(relative);
    transport::new_file(&target, bytes)?;
    Ok(json!({"path":relative,"sha256":sha(bytes)}))
}
fn mkdir(root: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(root)?;
    private_dir(root)
}
fn decode_c(raw: &[u8]) -> Result<Config> {
    Config::decode(raw).map_err(|e| anyhow::anyhow!("config codec {e:?}"))
}
fn decode_i(raw: &[u8]) -> Result<Issuer> {
    Issuer::decode(raw).map_err(|e| anyhow::anyhow!("issuer codec {e:?}"))
}
fn decode_h(raw: &[u8]) -> Result<PublisherHead> {
    PublisherHead::decode(raw).map_err(|e| anyhow::anyhow!("head codec {e:?}"))
}
fn decode_r(raw: &[u8]) -> Result<Request> {
    Request::decode(raw).map_err(|e| anyhow::anyhow!("request codec {e:?}"))
}
fn decode_q(raw: &[u8]) -> Result<Queue> {
    Queue::decode(raw).map_err(|e| anyhow::anyhow!("queue codec {e:?}"))
}

fn preconditions(p: &V3QueuePlan, accounts: &[Vec<u8>; 5], wire: &[u8], now: i64) -> Result<Value> {
    let c = decode_c(&accounts[0])?;
    let i = decode_i(&accounts[1])?;
    let h = decode_h(&accounts[2])?;
    let r = decode_r(&accounts[3])?;
    let q = decode_q(&accounts[4])?;
    let (not_before, not_after) = wire_times(wire)?;
    validate_full_wire(p, &c, &r, not_before, not_after, wire)?;
    i.fresh(&c, now)
        .map_err(|e| anyhow::anyhow!("issuer freshness {e:?}"))?;
    i.binding_current(&c)
        .map_err(|e| anyhow::anyhow!("issuer binding {e:?}"))?;
    let a = p.addresses();
    ensure!(
        c.enabled
            && i.enabled
            && i.status_valid
            && i.observed_at <= now
            && now < i.expires_at
            && i.expires_at <= i.observed_at.checked_add(300).context("expiry overflow")?
            && now < r.deadline
            && not_before <= now
            && now < not_after
            && h.config == a.config
            && h.issuer == a.issuer
            && h.publisher == c.publisher
            && h.root == c.root
            && h.root_version == c.root_version
            && h.source_sequence == i.sequence
            && h.source_digest == i.digest
            && h.config_epoch == c.eligibility_epoch
            && h.issuer_epoch == i.eligibility_epoch
            && h.committed_at >= i.observed_at
            && h.committed_at <= now
            && q.config == a.config
            && r.metas.len() == 2,
        "clean capacity Execute freshness/binding/deadline preconditions failed"
    );
    let instruction = p.execute(wire)?;
    for (meta, actual) in r.metas.iter().zip(&instruction.accounts[3..]) {
        ensure!(
            meta.key == actual.pubkey
                && meta.flags == 2
                && meta.owner == instruction.program_id
                && actual.is_writable
                && !actual.is_signer,
            "exact request relevant account owner/order/privileges required"
        );
    }
    Ok(
        json!({"status_active":true,"issuer_active":true,"head_bound":true,
        "request_live":true,"full_wire_valid":true,"observed_at":i.observed_at,
        "expires_at":i.expires_at,"now":now,"request_deadline":r.deadline}),
    )
}
// Refresh uses the same authenticated source and publisher transaction APIs as Full Execute.
fn refresh(
    rpc: &Rpc,
    p: &V3QueuePlan,
    payer: &Keypair,
    source: &Keypair,
    publisher: &Keypair,
    minimum: u64,
    events: &mut Vec<Value>,
    refreshes: &mut Vec<Value>,
) -> Result<u64> {
    let (_, accounts) = finalized_accounts(rpc, p, minimum)?;
    let c = decode_c(&accounts[0])?;
    let i = decode_i(&accounts[1])?;
    let h = decode_h(&accounts[2])?;
    let clock_deadline = Instant::now() + Duration::from_secs(20);
    let observed = loop {
        let observed = transport::clock(rpc)?;
        if observed > i.observed_at {
            break observed;
        }
        ensure!(
            Instant::now() < clock_deadline,
            "newer source clock deadline"
        );
        thread::sleep(Duration::from_millis(250));
    };
    let expires = observed
        .checked_add(300)
        .context("status expiry overflow")?;
    let sequence = i
        .sequence
        .checked_add(1)
        .context("source sequence overflow")?;
    let digest: [u8; 32] = Sha256::digest(
        [
            b"part5-v3-queue-capacity-source-v1".as_slice(),
            &c.root,
            &i.issuer_hash,
            &i.digest,
            &sequence.to_be_bytes(),
            &observed.to_be_bytes(),
        ]
        .concat(),
    )
    .into();
    let (_, source_tx) = send(
        rpc,
        payer,
        Some(source),
        p.observe(
            c.eligibility_epoch,
            i.eligibility_epoch,
            i.sequence,
            sequence,
            digest,
            true,
            observed,
            expires,
        ),
        "v3-capacity-active-source",
        false,
        events,
    )?;
    let envelope: [u8; 32] = Sha256::digest(
        [
            b"part5-v3-queue-capacity-head-v1".as_slice(),
            &c.root,
            &h.envelope_digest,
            &digest,
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
        expected_source_sequence: sequence,
        expected_source_digest: digest,
        expected_publication_sequence: h.publication_sequence,
        expected_publication_digest: h.envelope_digest,
        next_publication_sequence: h
            .publication_sequence
            .checked_add(1)
            .context("publication overflow")?,
        envelope_digest: envelope,
    };
    let (barrier, bind_tx) = send(
        rpc,
        payer,
        Some(publisher),
        p.bind_with_head(&binding),
        "v3-capacity-bind-head",
        false,
        events,
    )?;
    ensure!(
        source_tx["block_time"]
            .as_i64()
            .is_some_and(|t| observed <= t && t < expires)
            && bind_tx["block_time"]
                .as_i64()
                .is_some_and(|t| observed <= t && t < expires),
        "refresh must finalize within active window"
    );
    refreshes.push(json!({"observed_at":observed,"expires_at":expires,
        "source":source_tx,"bind":bind_tx}));
    Ok(barrier)
}

pub fn queue_capacity_negative_from_env() -> Result<()> {
    let started = Instant::now();
    let staging = std::env::var_os("P5_V3_QUEUE_CAPACITY_STAGE_CONFIG").is_some();
    let (path_env, hash_env) = if staging {
        ensure!(
            std::env::var_os("P5_V3_QUEUE_CAPACITY_NEGATIVE_CONFIG").is_none(),
            "ambiguous capacity phase"
        );
        (
            "P5_V3_QUEUE_CAPACITY_STAGE_CONFIG",
            "P5_V3_QUEUE_CAPACITY_STAGE_CONFIG_SHA256",
        )
    } else {
        (
            "P5_V3_QUEUE_CAPACITY_NEGATIVE_CONFIG",
            "P5_V3_QUEUE_CAPACITY_NEGATIVE_CONFIG_SHA256",
        )
    };
    let config_path = PathBuf::from(transport::env(path_env)?);
    let config_sha = transport::env(hash_env)?;
    let raw = private_pin(&config_path, &config_sha, 1024 * 1024)?;
    let dispatch: Value = serde_json::from_slice(&raw)?;
    if dispatch["schema"] == "part5-v3-queue-capacity-stage-config-v1" {
        ensure!(staging, "explicit stage config environment required");
        return prepare_requests(&raw, &config_path, &config_sha);
    }
    ensure!(
        transport::env("P5_V3_QUEUE_CAPACITY_NEGATIVE_SCOPE")? == SCOPE,
        "explicit bounded queue-capacity scope required"
    );
    ensure!(!staging, "stage config cannot select capacity fill");
    let config: CapacityConfig = serde_json::from_slice(&raw)?;
    ensure!(
        config.schema == "part5-v3-queue-capacity-negative-config-v1"
            && config.scope == SCOPE
            && config.runner_test == "root_pinned_queue_v3_queue_capacity_negative"
            && !config.cohort_id.is_empty()
            && config.cohort_id.len() <= 128
            && config.input_count == 65
            && config.queue_capacity == QUEUE_CAPACITY
            && config.inputs.len() == 65
            && config.outer_limits_required
                == json!({"runtime_seconds":3600,"rss_bytes":4294967296u64,
            "storage_growth_bytes":17179869184u64}),
        "exact bounded capacity configuration required"
    );
    for digest in [
        &config.cohort_freeze_sha256,
        &config.cohort_manifest_sha256,
        &config.stage_report_sha256,
        &config.clone_receipt_sha256,
        &config.genesis_sha256,
        &config.elf_sha256,
    ] {
        transport::unhex(digest)?;
    }
    private_dir(&config.output_dir)?;
    private_dir(&config.ledger)?;
    ensure!(
        config.output_dir == transport::output()?
            && fs::read_dir(&config.output_dir)?.next().is_none(),
        "fresh owner-only output directory required"
    );
    ensure!(
        transport::env("P5_QUEUE_PROGRAM")? == config.program
            && transport::env("P5_QUEUE_GENESIS")? == config.genesis
            && transport::env("P5_QUEUE_ELF_SHA256")? == config.elf_sha256,
        "supervised runtime identity differs from config"
    );
    transport::pinned(
        &config.ledger.join("genesis.bin"),
        &config.genesis_sha256,
        16 * 1024 * 1024,
    )?;
    let fixture: Fixture = serde_json::from_slice(&private_pin(
        &config.fixture_manifest,
        &config.fixture_manifest_sha256,
        1024 * 1024,
    )?)?;
    ensure!(
        fixture.schema == "part5-v3-queue-capacity-fixture-v1"
            && fixture.program == config.program
            && fixture.genesis == config.genesis
            && fixture.genesis_sha256 == config.genesis_sha256
            && fixture.elf_sha256 == config.elf_sha256
            && fixture.stage_report.sha256 == config.stage_report_sha256
            && fixture.inputs == config.inputs
            && fixture.request_finalizations.len() == 65,
        "fixture differs from exact pinned capacity input catalog"
    );
    let stage: Value = serde_json::from_slice(&private_pin(
        &fixture.stage_report.path,
        &fixture.stage_report.sha256,
        1024 * 1024,
    )?)?;
    ensure!(
        stage["schema"] == "part5-v3-local-stage-v1"
            && stage["passed"] == true
            && stage["program"] == config.program
            && stage["genesis"] == config.genesis
            && stage["loaded_program"]["elf_match"] == true
            && stage["loaded_program"]["elf_sha256"] == config.elf_sha256,
        "accepted loaded stage identity required"
    );
    let stage_root = fixture
        .stage_report
        .path
        .parent()
        .context("stage directory")?;
    let staged = |index: usize, name: &str| -> Result<Vec<u8>> {
        private_pin(
            &stage_root.join(format!("{name}.bin")),
            stage["account_sha256"][index]
                .as_str()
                .context("stage account digest")?,
            4096,
        )
    };
    let staged_c = decode_c(&staged(0, "config")?)?;
    let staged_i = decode_i(&staged(1, "issuer")?)?;
    let payer = key(&fixture.signers.payer)?;
    let admin = key(&fixture.signers.admin)?;
    let source = key(&fixture.signers.source)?;
    let publisher = key(&fixture.signers.publisher)?;
    ensure!(
        admin.pubkey() == staged_c.admin
            && source.pubkey() == staged_i.source
            && publisher.pubkey() == staged_c.publisher,
        "fixture signers differ from authenticated state"
    );
    let rpc = transport::local_rpc()?;
    let (program, genesis, loaded) = transport::domain(&rpc)?;
    ensure!(
        Pubkey::new_from_array(program).to_string() == config.program
            && Hash::new_from_array(genesis).to_string() == config.genesis
            && genesis == staged_c.genesis
            && loaded["elf_match"] == true
            && loaded["elf_sha256"] == config.elf_sha256,
        "loaded identity differs from fixture"
    );
    let output = &config.output_dir;
    mkdir(&output.join("fills"))?;
    mkdir(&output.join("before"))?;
    mkdir(&output.join("after"))?;
    let mut plans = Vec::with_capacity(65);
    let mut wires = Vec::with_capacity(65);
    let mut finalizations = Vec::with_capacity(65);
    let mut addresses = BTreeSet::new();
    let mut actions = BTreeSet::new();
    let mut finalization_signatures = BTreeSet::new();
    let mut minimum = stage["finalized_slot"]
        .as_u64()
        .context("stage finalization slot")?;
    // Validate the entire prepared fixture before any runtime mutation, including
    // the rejected proof whose pairing check the full queue would otherwise skip.
    for (index, input) in config.inputs.iter().enumerate() {
        let finalization = &fixture.request_finalizations[index];
        ensure!(
            finalization.request_address == input.request_address
                && finalization.slot > 0
                && finalization_signatures.insert(finalization.signature.clone()),
            "distinct exact finalized request history required"
        );
        let pinned_request = private_pin(
            &input.request_account,
            &input.request_sha256,
            REQUEST_LEN as u64,
        )?;
        let r = decode_r(&pinned_request)?;
        ensure!(
            r.state == RequestState::Finalized,
            "fixture request must be finalized unconsumed"
        );
        let p = plan(program, &staged_c, &staged_i, &r);
        let a = p.addresses();
        ensure!(
            a.request.to_string() == input.request_address
                && addresses.insert(a.request)
                && a.config.to_string() == stage["config"].as_str().context("stage config")?
                && a.issuer.to_string() == stage["issuer"].as_str().context("stage issuer")?
                && a.head.to_string() == stage["head"].as_str().context("stage head")?
                && a.queue.to_string() == stage["queue"].as_str().context("stage queue")?,
            "distinct request PDAs in one exact application domain required"
        );
        let action = zk_fresh_program::application_v3::action_hash(
            &Pubkey::new_from_array(program),
            &staged_c,
            &r,
        )
        .map_err(|e| anyhow::anyhow!("fixture action {e:?}"))?;
        // The public word is SHA-256 reduced modulo Fr by action_hash;
        // do not hash its 32-byte encoding a second time.
        ensure!(
            hex::encode(action) == input.action_sha256 && actions.insert(action),
            "distinct exact application action bindings required"
        );
        let proof_receipt: Value = serde_json::from_slice(&private_pin(
            &input.proof_receipt,
            &input.proof_receipt_sha256,
            256 * 1024,
        )?)?;
        check_proof_receipt(&proof_receipt, input)?;
        let wire = private_pin(&input.full_wire, &input.full_wire_sha256, 448)?;
        verify_wire(&wire)?;
        let (not_before, not_after) = wire_times(&wire)?;
        validate_full_wire(&p, &staged_c, &r, not_before, not_after, &wire)?;
        let (slot, live) = finalized_accounts(&rpc, &p, minimum.max(finalization.slot))?;
        ensure!(
            live[3] == pinned_request
                && live[0] == staged(0, "config")?
                && live[1] == staged(1, "issuer")?
                && live[2] == staged(2, "head")?
                && live[4] == staged(4, "queue")?
                && decode_q(&live[4])?.entries.is_empty(),
            "fresh fixture clone differs from pinned finalized request/application bytes"
        );
        let tx = transaction(
            &rpc,
            &finalization.signature,
            finalization.slot,
            &p.finalize(),
            false,
        )?;
        finalizations.push(tx);
        minimum = slot;
        plans.push(p);
        wires.push(wire);
    }
    let rejected = plans[64].addresses().request;
    let mut expected = Vec::with_capacity(64);
    let mut events = Vec::new();
    let mut refreshes = Vec::new();
    let mut fills = Vec::with_capacity(64);
    // All proof work is finished before the first active observation. Refresh
    // again with a 90-second safety margin; deadlines still fail closed.
    minimum = refresh(
        &rpc,
        &plans[0],
        &payer,
        &source,
        &publisher,
        minimum,
        &mut events,
        &mut refreshes,
    )?;
    for index in 0..65 {
        ensure!(
            started.elapsed() < Duration::from_secs(3500),
            "bounded capacity runner deadline"
        );
        let p = &plans[index];
        let input = &config.inputs[index];
        let (mut before_slot, mut before) = finalized_accounts(&rpc, p, minimum)?;
        let (_, mut now) = clock(&rpc, before_slot)?;
        let issuer = decode_i(&before[1])?;
        if now.checked_add(90).context("refresh margin overflow")? >= issuer.expires_at {
            minimum = refresh(
                &rpc,
                p,
                &payer,
                &source,
                &publisher,
                before_slot,
                &mut events,
                &mut refreshes,
            )?;
            (before_slot, before) = finalized_accounts(&rpc, p, minimum)?;
            (_, now) = clock(&rpc, before_slot)?;
        }
        ensure!(
            sha(&before[3]) == input.request_sha256,
            "request changed since validated fixture"
        );
        let before_q = decode_q(&before[4])?;
        queue_exact(&before_q.entries, &expected, rejected)?;
        let conditions = preconditions(p, &before, &wires[index], now)?;
        // Recheck pinned wire bytes and pairing immediately before submission.
        ensure!(
            private_pin(&input.full_wire, &input.full_wire_sha256, 448)? == wires[index],
            "Full wire changed during fill"
        );
        verify_wire(&wires[index])?;
        let instruction = p.execute(&wires[index])?;
        if index < 64 {
            let relative = format!("fills/{index:02}");
            mkdir(&output.join(&relative))?;
            let request_before = save(
                output,
                &format!("{relative}/request-before.bin"),
                &before[3],
            )?;
            let queue_before = save(output, &format!("{relative}/queue-before.bin"), &before[4])?;
            let (barrier, tx) = send(
                &rpc,
                &payer,
                None,
                instruction,
                "v3-capacity-fill-full",
                false,
                &mut events,
            )?;
            let (after_slot, after) = finalized_accounts(&rpc, p, barrier)?;
            let mut consumed = decode_r(&before[3])?;
            consumed.state = RequestState::Consumed;
            expected.push(p.addresses().request);
            let q = decode_q(&after[4])?;
            queue_exact(&q.entries, &expected, rejected)?;
            ensure!(
                before[..3] == after[..3]
                    && after[3] == consumed.encode()
                    && q.config == before_q.config,
                "fill changed unexpected application bytes"
            );
            let execution_now = tx["block_time"].as_i64().context("fill block time")?;
            ensure!(execution_now >= now, "fill block time regressed");
            preconditions(p, &before, &wires[index], execution_now)?;
            let request_after = save(output, &format!("{relative}/request-after.bin"), &after[3])?;
            let queue_after = save(output, &format!("{relative}/queue-after.bin"), &after[4])?;
            fills.push(json!({"request_address":input.request_address,"signature":tx["signature"],
                "slot":tx["slot"],"finalized":true,"consumed":true,
                "queue_after_addresses":q.entries.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "request_before_sha256":sha(&before[3]),"request_after_sha256":sha(&after[3]),
                "queue_before_sha256":sha(&before[4]),"queue_after_sha256":sha(&after[4]),
                "snapshots":{"request_before":request_before,"request_after":request_after,
                    "queue_before":queue_before,"queue_after":queue_after},
                "account_slots":{"before":before_slot,"after":after_slot},
                "preconditions":conditions,"execution_now":execution_now}));
            minimum = after_slot;
        } else {
            ensure!(
                before_q.entries.len() == QUEUE_CAPACITY,
                "exactly 64 fills before rejection required"
            );
            let mut before_refs = Vec::new();
            for (name, bytes) in NAMES.iter().zip(&before) {
                before_refs.push(save(output, &format!("before/{name}.bin"), bytes)?);
            }
            let (barrier, tx) = send(
                &rpc,
                &payer,
                None,
                instruction,
                "v3-capacity-reject-65-full",
                true,
                &mut events,
            )?;
            let (after_slot, after) = finalized_accounts(&rpc, p, barrier)?;
            ensure!(
                after == before,
                "capacity rejection changed one of five finalized application accounts"
            );
            let after_q = decode_q(&after[4])?;
            queue_exact(&after_q.entries, &expected, rejected)?;
            let execution_now = tx["block_time"].as_i64().context("rejection block time")?;
            ensure!(execution_now >= now, "rejection block time regressed");
            preconditions(p, &before, &wires[index], execution_now)?;
            let mut snapshots = Vec::new();
            for (account_index, (name, bytes)) in NAMES.iter().zip(&after).enumerate() {
                snapshots.push(json!({"name":name,"address":p.execute(&wires[index])?.accounts[account_index].pubkey.to_string(),
                    "before":before_refs[account_index],"after":save(output,&format!("after/{name}.bin"),bytes)?}));
            }
            let (after_program, after_genesis, loaded_after) = transport::domain(&rpc)?;
            ensure!(
                after_program == program && after_genesis == genesis && loaded_after == loaded,
                "loaded application identity changed during capacity run"
            );
            let report = json!({"schema":"part5-v3-queue-capacity-negative-rust-report-v1",
                "scope":SCOPE,"runner_test":config.runner_test,"rust_config_sha256":config_sha,
                "config_ref":{"path":config_path,"sha256":config_sha},
                "fixture_manifest":{"path":config.fixture_manifest,"sha256":config.fixture_manifest_sha256},
                "cohort_id":config.cohort_id,"cohort_freeze_sha256":config.cohort_freeze_sha256,
                "cohort_manifest_sha256":config.cohort_manifest_sha256,
                "stage_report_sha256":config.stage_report_sha256,"clone_receipt_sha256":config.clone_receipt_sha256,
                "program":config.program,"genesis":config.genesis,"genesis_sha256":config.genesis_sha256,
                "loaded_program":loaded,"loaded_program_after":loaded_after,
                "inputs":config.inputs,"request_finalizations":finalizations,
                "fill_history":fills,"refresh_transactions":refreshes,
                "before_queue_addresses":before_q.entries.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "after_queue_addresses":after_q.entries.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "rejected_request":{"request_address":input.request_address,"signature":tx["signature"],
                    "slot":tx["slot"],"finalized":true,"consumed":false,"rpc_error":tx["rpc_error"]},
                "preconditions":conditions,"execution_now":execution_now,"snapshots":snapshots,
                "account_slots":{"before":before_slot,"after":after_slot},
                "runner_observations":{"pid":std::process::id(),"elapsed_seconds":started.elapsed().as_secs_f64()},
                "full_proofs_verified_in_rust":65,"successful_fill_count":64,"queue_capacity":64,
                "rejection_application_effect":false,"setup_application_effect":true,
                "external_finalization_required":true});
            let raw = serde_json::to_vec_pretty(&report)?;
            ensure!(
                raw.len() <= 1024 * 1024,
                "bounded capacity runtime report required"
            );
            transport::new_file(&output.join("queue-capacity-negative-report.json"), &raw)?;
        }
    }
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StageConfig {
    schema: String,
    scope: String,
    program: String,
    genesis: String,
    elf_sha256: String,
    stage_report: Reference,
    plan: Reference,
    signers: Signers,
    creator: SignerReference,
    nonce_seed: String,
    request_deadline: i64,
    credential_not_after: i64,
    proof_owner_limit_seconds: u64,
    output_dir: PathBuf,
}
fn prepare_requests(raw: &[u8], config_path: &Path, config_sha: &str) -> Result<()> {
    let started = Instant::now();
    let config: StageConfig = serde_json::from_slice(raw)?;
    ensure!(
        config.schema == "part5-v3-queue-capacity-stage-config-v1"
            && config.scope == "part5-v3-queue-capacity-stage"
            && transport::env("P5_V3_QUEUE_CAPACITY_STAGE_SCOPE")?
                == "part5-v3-queue-capacity-stage",
        "explicit capacity request staging required"
    );
    let seed = transport::unhex(&config.nonce_seed)?;
    private_dir(&config.output_dir)?;
    ensure!(
        config.output_dir == transport::output()?
            && fs::read_dir(&config.output_dir)?.next().is_none(),
        "fresh capacity staging output required"
    );
    let stage: Value = serde_json::from_slice(&private_pin(
        &config.stage_report.path,
        &config.stage_report.sha256,
        1024 * 1024,
    )?)?;
    let baseline: V3QueuePlan =
        serde_json::from_slice(&private_pin(&config.plan.path, &config.plan.sha256, 8192)?)?;
    ensure!(
        stage["schema"] == "part5-v3-local-stage-v1"
            && stage["passed"] == true
            && stage["plan_sha256"] == config.plan.sha256
            && stage["program"] == config.program
            && stage["genesis"] == config.genesis,
        "pinned accepted baseline required"
    );
    let payer = key(&config.signers.payer)?;
    let admin = key(&config.signers.admin)?;
    let source = key(&config.signers.source)?;
    let publisher = key(&config.signers.publisher)?;
    let creator = key(&config.creator)?;
    ensure!(
        admin.pubkey().to_bytes() == baseline.admin
            && source.pubkey().to_bytes() == baseline.source
            && publisher.pubkey().to_bytes() == baseline.publisher
            && creator.pubkey().to_bytes() == baseline.creator
            && payer.pubkey() != creator.pubkey(),
        "exact baseline fixture signers required"
    );
    let rpc = transport::local_rpc()?;
    let (program, genesis, loaded) = transport::domain(&rpc)?;
    ensure!(
        program == baseline.program
            && genesis == baseline.genesis
            && loaded["elf_match"] == true
            && loaded["elf_sha256"] == config.elf_sha256
            && stage["loaded_program"] == loaded,
        "capacity staging loaded identity drift"
    );
    let minimum = stage["finalized_slot"]
        .as_u64()
        .context("baseline finalized slot")?;
    let (mut barrier, initial) = finalized_accounts(&rpc, &baseline, minimum)?;
    for (index, bytes) in initial.iter().enumerate() {
        ensure!(
            stage["account_sha256"][index] == sha(bytes),
            "baseline application bytes differ"
        );
    }
    ensure!(
        decode_q(&initial[4])?.entries.is_empty()
            && decode_r(&initial[3])?.state == RequestState::Finalized,
        "baseline queue empty and request finalized required"
    );
    let c = decode_c(&initial[0])?;
    let (_, prepare_now) = clock(&rpc, barrier)?;
    ensure!(
        config.proof_owner_limit_seconds > 0
            && config.proof_owner_limit_seconds <= 43200
            && prepare_now
                .checked_add(i64::try_from(config.proof_owner_limit_seconds)? + 7200)
                .is_some_and(|bound| bound <= config.request_deadline)
            && config.request_deadline <= config.credential_not_after
            && config.request_deadline
                <= prepare_now
                    .checked_add(86400)
                    .context("deadline overflow")?,
        "predeclared proof and fill owner windows must fit bounded request/credential validity"
    );
    let mut rows = Vec::new();
    let mut addresses = BTreeSet::new();
    let mut events = Vec::new();
    for index in 0u64..65 {
        ensure!(
            started.elapsed() < Duration::from_secs(3400),
            "capacity staging deadline"
        );
        let mut p = baseline.clone();
        let transactions;
        p.deadline = config.request_deadline;
        {
            p.nonce = Sha256::digest(
                [
                    b"part5-v3-capacity-nonce-v1".as_slice(),
                    &seed,
                    &index.to_be_bytes(),
                ]
                .concat(),
            )
            .into();
            ensure!(
                rpc.account(&p.addresses().request)?.is_none(),
                "capacity request PDA already exists"
            );
            let first = events.len();
            transport::send(
                &rpc,
                &payer,
                Some(&creator),
                p.create()?,
                "v3-capacity-create",
                None,
                &mut events,
            )?;
            let mut instructions = vec![p.create()?];
            for (chunk_index, chunk) in p.payload.chunks(512).enumerate() {
                let instruction = p.upload_payload(chunk_index * 512, chunk)?;
                transport::send(
                    &rpc,
                    &payer,
                    Some(&creator),
                    instruction.clone(),
                    "v3-capacity-upload",
                    None,
                    &mut events,
                )?;
                instructions.push(instruction);
            }
            for instruction in [p.upload_metas(), p.finalize()] {
                transport::send(
                    &rpc,
                    &payer,
                    Some(&creator),
                    instruction.clone(),
                    "v3-capacity-finalize-setup",
                    None,
                    &mut events,
                )?;
                instructions.push(instruction);
            }
            barrier = transport::wait_finalized(&rpc, &events)?;
            transactions = events[first..]
                .iter()
                .zip(&instructions)
                .map(|(event, instruction)| {
                    transaction(
                        &rpc,
                        event["signature"].as_str().context("setup signature")?,
                        event["slot"].as_u64().context("setup slot")?,
                        instruction,
                        false,
                    )
                })
                .collect::<Result<Vec<_>>>()?;
        }
        let (slot, accounts) = finalized_accounts(&rpc, &p, barrier)?;
        ensure!(
            accounts[..3] == initial[..3] && accounts[4] == initial[4],
            "request preparation changed config/issuer/head/queue"
        );
        let r = decode_r(&accounts[3])?;
        ensure!(
            r.state == RequestState::Finalized
                && r.nonce == p.nonce
                && r.payload == p.payload
                && r.deadline == p.deadline
                && r.config == p.addresses().config
                && r.creator == creator.pubkey()
                && addresses.insert(p.addresses().request),
            "exact distinct finalized request required"
        );
        let request_name = format!("request-{index:02}.bin");
        let plan_name = format!("plan-{index:02}.json");
        let request_ref = save(&config.output_dir, &request_name, &accounts[3])?;
        transport::new_json(&config.output_dir.join(&plan_name), &p)?;
        let plan_raw = fs::read(config.output_dir.join(&plan_name))?;
        let action =
            zk_fresh_program::application_v3::action_hash(&Pubkey::new_from_array(program), &c, &r)
                .map_err(|e| anyhow::anyhow!("prepared action {e:?}"))?;
        rows.push(json!({"request_address":p.addresses().request.to_string(),"action_sha256":hex::encode(action),
            "request_account":config.output_dir.join(&request_name),"request_sha256":request_ref["sha256"],
            "plan":{"path":config.output_dir.join(&plan_name),"sha256":sha(&plan_raw)},
            "finalization":transactions.last().context("Finalize fact")?,"transactions":transactions,
            "finalized_account_slot":slot}));
        barrier = slot;
    }
    let (_, _, loaded_after) = transport::domain(&rpc)?;
    ensure!(
        loaded_after == loaded,
        "capacity staging loaded identity changed"
    );
    transport::new_json(
        &config.output_dir.join("capacity-preparation-report.json"),
        &json!({
        "schema":"part5-v3-queue-capacity-preparation-rust-v1","passed":true,
        "config_ref":{"path":config_path,"sha256":config_sha},"stage_report_sha256":config.stage_report.sha256,
        "program":config.program,"genesis":config.genesis,"loaded_program":loaded,"inputs":rows,
        "finalized_slot":barrier,"request_count":65,"queue_empty":true,"application_effect":false,
        "request_preparation_effect":true,"request_deadline":config.request_deadline,
        "credential_not_after":config.credential_not_after,"proof_owner_limit_seconds":config.proof_owner_limit_seconds,
        "preparation_clock":prepare_now,"elapsed_seconds":started.elapsed().as_secs_f64(),
        "external_finalization_required":true}),
    )?;
    Ok(())
}
