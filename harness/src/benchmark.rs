use crate::{
    fixtures::{field_decimal, load_fixtures, write_json},
    policy::{accept, verify_authorization, ActionContext, AuthorizationState, Policy},
    prover::{self, unix_ms, ProofResult},
    registry::Registry,
    solana,
};
use anyhow::{ensure, Result};
use serde_json::{json, Value};
use std::{fs, time::Instant};
pub fn run() -> Result<()> {
    let fixtures = load_fixtures()?;
    ensure!(
        fixtures.credentials.len() >= 2,
        "Need Alice and Bob fixtures"
    );
    let mut registry = Registry::new(fixtures.clone())?;
    let initial_time = chrono::Utc::now().timestamp();
    registry.snapshot(initial_time)?;
    use solana_sdk::pubkey::Pubkey;
    let program = Pubkey::new_from_array([1; 32]);
    let registry_id = Pubkey::new_from_array([2; 32]);
    let recipient = Pubkey::new_from_array([4; 32]);
    let action_id = [3; 32];
    let action = solana::action_digest(&program, &registry_id, &recipient, &action_id);
    let context = ActionContext {
        program,
        registry: registry_id,
        recipient,
        action_id,
    };
    let old_input = registry.input(0, action)?;
    let mut events = vec![
        json!({"event":"snapshot-captured","atUnixMs":unix_ms(),"root":field_decimal(&registry.root()),"version":0}),
    ];
    let mut update_ms = 0;
    let old_proof = {
        let mut update = || -> Result<()> {
            registry.revoke(1, chrono::Utc::now().timestamp())?;
            update_ms = unix_ms();
            events.push(json!({"event":"bob-revoked","atUnixMs":update_ms,"root":field_decimal(&registry.root()),"version":registry.version}));
            Ok(())
        };
        prover::prove(&old_input, "alice-before-bob-revocation", Some(&mut update))?
    };
    ensure!(
        old_proof.proving_started_unix_ms <= update_ms
            && update_ms < old_proof.proving_finished_unix_ms,
        "Root update did not overlap actual proving; do not report a during-proving result"
    );
    println!(
        "Old-root proof verified. Proving {:.3}s; root changed during proving.",
        old_proof.timings.proving_ms / 1000.
    );
    let mut cases = vec![];
    let now = chrono::Utc::now().timestamp();
    check(
        &mut cases,
        "bob-revocation-strict",
        &old_proof,
        &old_proof.public_signals,
        &registry,
        Policy::Strict,
        now,
        "stale-root",
        false,
    )?;
    check(
        &mut cases,
        "bob-revocation-historical",
        &old_proof,
        &old_proof.public_signals,
        &registry,
        Policy::Historical,
        now,
        if now - initial_time <= 300 {
            "accepted"
        } else {
            "stale-root"
        },
        false,
    )?;
    let mut substituted = old_proof.public_signals.clone();
    substituted[0] = field_decimal(&registry.root());
    check(
        &mut cases,
        "substituted-current-root",
        &old_proof,
        &substituted,
        &registry,
        Policy::Strict,
        now,
        "invalid-proof",
        false,
    )?;
    let mut app = AuthorizationState::default();
    let old_verified =
        verify_authorization(&old_proof.proof, &old_proof.public_signals, "local-app-old")?
            .unwrap();
    ensure!(
        app.accept(&old_verified, &registry, Policy::Strict, now, context)?
            .reason
            == "stale-root"
            && !app.is_consumed(&registry_id, &action_id),
        "Failed stale proof consumed action"
    );
    let fresh = prover::prove(
        &registry.input(0, action)?,
        "alice-after-bob-revocation",
        None,
    )?;
    let now = chrono::Utc::now().timestamp();
    check(
        &mut cases,
        "regenerated-current-root",
        &fresh,
        &fresh.public_signals,
        &registry,
        Policy::Strict,
        now,
        "accepted",
        false,
    )?;
    let verified =
        verify_authorization(&fresh.proof, &fresh.public_signals, "local-app-fresh")?.unwrap();
    for (name, invalid_context) in [
        (
            "wrong-recipient",
            ActionContext {
                recipient: Pubkey::new_from_array([5; 32]),
                ..context
            },
        ),
        (
            "wrong-action",
            ActionContext {
                action_id: [6; 32],
                ..context
            },
        ),
    ] {
        let decision = app.accept(&verified, &registry, Policy::Strict, now, invalid_context)?;
        ensure!(
            decision.reason == "action-mismatch"
                && !app.is_consumed(&registry_id, &action_id)
                && !app.is_consumed(&registry_id, &invalid_context.action_id),
            "Invalid action context consumed action"
        );
        cases.push(json!({"name":name,"cryptographicallyValid":true,"accepted":false,"reason":decision.reason,"actionConsumed":false}));
    }
    ensure!(
        app.accept(&verified, &registry, Policy::Strict, now, context)?
            .accepted,
        "Valid authorization rejected"
    );
    let replay = app.accept(&verified, &registry, Policy::Strict, now, context)?;
    ensure!(
        replay.reason == "already-used",
        "Successful action replay accepted"
    );
    cases.push(json!({"name":"replay-after-success","cryptographicallyValid":true,"accepted":false,"reason":replay.reason,"actionConsumed":true}));
    registry.revoke(0, now)?;
    events.push(json!({"event":"alice-revoked","atUnixMs":unix_ms(),"root":field_decimal(&registry.root()),"version":registry.version}));
    check(
        &mut cases,
        "own-revocation-strict",
        &fresh,
        &fresh.public_signals,
        &registry,
        Policy::Strict,
        now,
        "stale-root",
        false,
    )?;
    let publication = registry.history[1].published_at;
    check(
        &mut cases,
        "own-revocation-historical",
        &fresh,
        &fresh.public_signals,
        &registry,
        Policy::Historical,
        now,
        if now - publication <= 300 {
            "accepted"
        } else {
            "stale-root"
        },
        false,
    )?;
    check(
        &mut cases,
        "historical-window-exceeded",
        &fresh,
        &fresh.public_signals,
        &registry,
        Policy::Historical,
        publication + 301,
        "stale-root",
        true,
    )?;
    let mut unchanged = Registry::new(fixtures.clone())?;
    unchanged.snapshot(initial_time)?;
    check(
        &mut cases,
        "signed-certificate-expired",
        &old_proof,
        &old_proof.public_signals,
        &unchanged,
        Policy::Strict,
        fixtures.not_after + 1,
        "expired",
        true,
    )?;
    ensure!(
        cases.last().unwrap()["reason"] == "expired",
        "Expiration must be the rejection cause"
    );
    check(
        &mut cases,
        "signed-certificate-not-yet-valid",
        &old_proof,
        &old_proof.public_signals,
        &unchanged,
        Policy::Strict,
        fixtures.not_before - 1,
        "not-yet-valid",
        true,
    )?;
    ensure!(
        cases.last().unwrap()["reason"] == "not-yet-valid",
        "Validity start must be the rejection cause"
    );
    let revoked = registry.input(0, action)?;
    ensure!(
        prover::witness(&revoked, "benchmark-revoked-current").is_err(),
        "Revoked current-root witness passed"
    );
    ensure!(
        fs::read_to_string("artifacts/witnesses/benchmark-revoked-current.log")?
            .contains("Error in template"),
        "Expected circuit constraint failure"
    );
    cases.push(json!({"name":"own-revocation-current-witness","accepted":false,"reason":"unsatisfied-circuit","proofGenerated":false}));
    let proofs = [old_proof, fresh];
    let mut file_bytes = json!({});
    for file in [
        "artifacts/circuit/credential.r1cs",
        "artifacts/circuit/credential_js/credential.wasm",
        "artifacts/setup/credential_final.zkey",
    ] {
        file_bytes[file] = fs::metadata(file)?.len().into();
    }
    let setup: Value = serde_json::from_slice(&fs::read("artifacts/setup/setup.json")?)?;
    let limitations=["Fixed synthetic X.509 profile; no full PKIX chain validation.","Issuer and registry root publisher are trusted to issue eligible credentials and publish correct revocations.","Witnesses are constructed locally. A future witness service would observe queried credential slots unless private delivery is added.","Local expiry and root-window boundaries use explicitly controlled execution times; Solana expiry uses its Clock sysvar.",
        "Two proof samples are a feasibility baseline, not a workload distribution.","snarkjs CLI cold-process timings include Node/backend startup; setup is measured separately.",
        "Single-party phase-two development setup; not production authorization."];
    let evidence = json!({"harness":"Rust","createdAtUnix":chrono::Utc::now().timestamp(),"backend":{"prover":"snarkjs 0.7.6 CLI","parallelBackend":true,"simultaneousProofJobs":1},
        "host":{"os":std::env::consts::OS,"logicalCpus":std::thread::available_parallelism()?.get()},"setup":setup,"fileBytes":file_bytes,"events":events,"cases":cases,"proofs":proofs,"limitations":limitations});
    write_json("results/local-benchmark.json", &evidence, false)?;
    let mut report=String::from("# Credential freshness baseline\n\nRust harness, Circom circuits, snarkjs Groth16. A proof remains valid for its original root. State policy controls whether the application accepts it.\n\n| Scenario | Proof valid | Accepted | Reason |\n| --- | --- | --- | --- |\n");
    for case in &cases {
        report.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            case["name"].as_str().unwrap(),
            case["cryptographicallyValid"],
            case["accepted"],
            case["reason"].as_str().unwrap()
        ));
    }
    report.push_str("\n| Proof | Witness seconds | Proving seconds | Verify seconds | Prover peak MiB |\n| --- | ---: | ---: | ---: | ---: |\n");
    for (index, proof) in proofs.iter().enumerate() {
        report.push_str(&format!(
            "| {} | {:.3} | {:.3} | {:.3} | {:.1} |\n",
            index + 1,
            proof.timings.witness_ms / 1000.,
            proof.timings.proving_ms / 1000.,
            proof.timings.verification_ms / 1000.,
            proof.timings.peak_rss_bytes as f64 / 1048576.
        ));
    }
    report.push_str("\nThe Bob root update was observed between the prover's `Building ABC` event and independently recorded process completion. Setup is excluded. Peak RSS comes from the prover child process, with OS-specific units converted to bytes. Witness and verify timings include their own cold CLI startup.\n\n");
    for item in limitations {
        report.push_str(&format!("- {item}\n"));
    }
    fs::write("results/local-benchmark.md", report)?;
    println!("Local benchmark passed. See results/local-benchmark.md");
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn check(
    cases: &mut Vec<Value>,
    name: &str,
    proof: &ProofResult,
    signals: &[String],
    registry: &Registry,
    policy: Policy,
    now: i64,
    expected_reason: &str,
    controlled: bool,
) -> Result<()> {
    let start = Instant::now();
    let verified = prover::verify(&proof.proof, signals, name)?;
    let (accepted, reason) = if verified {
        let decision = accept(signals, registry, policy, now)?;
        (decision.accepted, decision.reason)
    } else {
        (false, "invalid-proof")
    };
    ensure!(
        verified == (expected_reason != "invalid-proof"),
        "{name}: wrong cryptographic validity; expected policy outcomes require a real valid proof"
    );
    ensure!(
        reason == expected_reason,
        "{name}: expected {expected_reason}, received {reason}"
    );
    cases.push(json!({"name":name,"policy":policy,"executionTime":now,"clock":if controlled{"controlled"}else{"wall"},
        "cryptographicallyValid":verified,"accepted":accepted,"reason":reason,"proofRoot":signals[0],"currentRoot":field_decimal(&registry.root()),"currentVersion":registry.version,
        "verificationAndPolicyMs":start.elapsed().as_secs_f64()*1000.}));
    Ok(())
}
