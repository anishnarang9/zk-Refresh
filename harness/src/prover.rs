use crate::fixtures::write_json;
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
static BUSY: AtomicBool = AtomicBool::new(false);
pub struct ProverPermit;
impl Drop for ProverPermit {
    fn drop(&mut self) {
        BUSY.store(false, Ordering::SeqCst);
    }
}
pub fn acquire_prover() -> Result<ProverPermit> {
    ensure!(
        BUSY.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok(),
        "Only one proving job may run at a time"
    );
    Ok(ProverPermit)
}
pub fn parse_peak_rss(text: &str, mac: bool) -> Result<u64> {
    for line in text.lines() {
        if mac && line.contains("maximum resident set size") {
            return Ok(line
                .split_whitespace()
                .next()
                .context("Missing peak RSS")?
                .parse()?);
        }
        if !mac && line.contains("Maximum resident set size (kbytes)") {
            return Ok(line
                .rsplit(':')
                .next()
                .context("Missing peak RSS")?
                .trim()
                .parse::<u64>()?
                * 1024);
        }
    }
    bail!("Prover completed without a peak-memory measurement")
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Timings {
    pub witness_ms: f64,
    pub proving_ms: f64,
    pub verification_ms: f64,
    pub peak_rss_bytes: u64,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct ProofResult {
    pub proof: Value,
    pub public_signals: Vec<String>,
    pub verified: bool,
    pub timings: Timings,
    pub proving_started_unix_ms: u128,
    pub proving_finished_unix_ms: u128,
}
pub fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}
pub fn cli(args: &[&str], log: &Path) -> Result<()> {
    if let Some(parent) = log.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = File::create(log)?;
    let status = Command::new("node")
        .arg("node_modules/snarkjs/build/cli.cjs")
        .args(args)
        .stdout(Stdio::from(file.try_clone()?))
        .stderr(Stdio::from(file))
        .status()?;
    ensure!(status.success(), "snarkjs failed; see {}", log.display());
    Ok(())
}
pub fn witness(input: &Value, name: &str) -> Result<PathBuf> {
    ensure!(
        name.chars()
            .all(|value| value.is_ascii_alphanumeric() || value == '-' || value == '_')
            && !name.is_empty(),
        "Invalid artifact name"
    );
    let dir = PathBuf::from("artifacts/witnesses");
    fs::create_dir_all(&dir)?;
    let input_path = dir.join(format!("{name}-input.json"));
    let output = dir.join(format!("{name}.wtns"));
    write_json(&input_path, input, true)?;
    cli(
        &[
            "wtns",
            "calculate",
            "artifacts/circuit/credential_js/credential.wasm",
            input_path.to_str().unwrap(),
            output.to_str().unwrap(),
        ],
        &dir.join(format!("{name}.log")),
    )?;
    Ok(output)
}
pub fn prove(
    input: &Value,
    name: &str,
    mut on_started: Option<&mut dyn FnMut() -> Result<()>>,
) -> Result<ProofResult> {
    let _permit = acquire_prover()?;
    ensure!(
        !name.is_empty()
            && name
                .chars()
                .all(|value| value.is_ascii_alphanumeric() || value == '-' || value == '_'),
        "Invalid artifact name"
    );
    ensure!(
        Path::new("artifacts/setup/credential_final.zkey").exists(),
        "Run setup first"
    );
    let folder = PathBuf::from("artifacts/proofs").join(name);
    fs::create_dir_all(&folder)?;
    let input_path = folder.join("input.json");
    let witness_path = folder.join("witness.wtns");
    write_json(&input_path, input, true)?;
    let witness_start = Instant::now();
    cli(
        &[
            "wtns",
            "calculate",
            "artifacts/circuit/credential_js/credential.wasm",
            input_path.to_str().unwrap(),
            witness_path.to_str().unwrap(),
        ],
        &folder.join("witness.log"),
    )?;
    let witness_ms = witness_start.elapsed().as_secs_f64() * 1000.;
    let proof_path = folder.join("proof.json");
    let signals_path = folder.join("public.json");
    let log_path = folder.join("proving.log");
    File::create(&log_path)?;
    let log = OpenOptions::new().append(true).open(&log_path)?;
    let mac = cfg!(target_os = "macos");
    let proving_start = Instant::now();
    use std::os::unix::process::CommandExt;
    let mut child = Command::new("/usr/bin/time")
        .process_group(0)
        .arg(if mac { "-l" } else { "-v" })
        .arg("node")
        .arg("node_modules/snarkjs/build/cli.cjs")
        .args([
            "groth16",
            "prove",
            "artifacts/setup/credential_final.zkey",
            witness_path.to_str().unwrap(),
            proof_path.to_str().unwrap(),
            signals_path.to_str().unwrap(),
            "-v",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::from(log.try_clone()?))
        .spawn()?;
    let stdout = child.stdout.take().context("Missing prover output")?;
    let process_group = child.id() as i32;
    let (completed_tx, completed_rx) = mpsc::channel();
    let waiter = thread::spawn(move || {
        let status = child.wait();
        let _ = completed_tx.send((
            status,
            unix_ms(),
            proving_start.elapsed().as_secs_f64() * 1000.,
        ));
    });
    let (sender, receiver) = mpsc::channel();
    let mut output = OpenOptions::new().append(true).open(&log_path)?;
    let reader = thread::spawn(move || -> Result<()> {
        for line in BufReader::new(stdout).lines() {
            let line = line?;
            if line.contains("Building ABC") {
                let _ = sender.send(unix_ms());
            }
            writeln!(output, "{line}")?;
        }
        Ok(())
    });
    let mut actual_start = None;
    let (status, finished, proving_ms) = loop {
        if actual_start.is_none() {
            if let Ok(time) = receiver.try_recv() {
                actual_start = Some(time);
                if let Some(callback) = on_started.as_mut() {
                    if let Err(error) = callback() {
                        unsafe {
                            libc::kill(-process_group, libc::SIGTERM);
                        }
                        let _ = waiter.join();
                        let _ = reader.join();
                        return Err(error);
                    }
                }
            }
        }
        if let Ok(completed) = completed_rx.try_recv() {
            break completed;
        }
        thread::sleep(Duration::from_millis(20));
    };
    waiter
        .join()
        .map_err(|_| anyhow::anyhow!("Prover waiter panicked"))?;
    reader
        .join()
        .map_err(|_| anyhow::anyhow!("Prover output reader panicked"))??;
    ensure!(
        status?.success(),
        "Proving failed; see {}",
        log_path.display()
    );
    let started = actual_start
        .or_else(|| receiver.try_recv().ok())
        .context("Proving phase did not start")?;
    ensure!(
        on_started.is_none() || actual_start.is_some(),
        "Root update callback did not run during proving"
    );
    let proof: Value = serde_json::from_slice(&fs::read(&proof_path)?)?;
    let public_signals: Vec<String> = serde_json::from_slice(&fs::read(&signals_path)?)?;
    ensure!(public_signals.len() == 5, "Expected five public inputs");
    let verify_start = Instant::now();
    cli(
        &[
            "groth16",
            "verify",
            "artifacts/setup/verification_key.json",
            signals_path.to_str().unwrap(),
            proof_path.to_str().unwrap(),
        ],
        &folder.join("verify.log"),
    )?;
    let result = ProofResult {
        proof,
        public_signals,
        verified: true,
        timings: Timings {
            witness_ms,
            proving_ms,
            verification_ms: verify_start.elapsed().as_secs_f64() * 1000.,
            peak_rss_bytes: parse_peak_rss(&fs::read_to_string(&log_path)?, mac)?,
        },
        proving_started_unix_ms: started,
        proving_finished_unix_ms: finished,
    };
    write_json(folder.join("result.json"), &result, false)?;
    fs::remove_file(witness_path)?;
    fs::remove_file(input_path)?;
    Ok(result)
}
pub fn verify(proof: &Value, signals: &[String], name: &str) -> Result<bool> {
    ensure!(
        name.chars()
            .all(|value| value.is_ascii_alphanumeric() || value == '-' || value == '_'),
        "Invalid artifact name"
    );
    if signals.len() != 5 {
        return Ok(false);
    }
    let folder = PathBuf::from("artifacts/verification").join(name);
    fs::create_dir_all(&folder)?;
    let proof_path = folder.join("proof.json");
    let signals_path = folder.join("public.json");
    write_json(&proof_path, proof, false)?;
    write_json(&signals_path, &signals, false)?;
    let log = folder.join("verify.log");
    let result = cli(
        &[
            "groth16",
            "verify",
            "artifacts/setup/verification_key.json",
            signals_path.to_str().unwrap(),
            proof_path.to_str().unwrap(),
        ],
        &log,
    );
    match result {
        Ok(()) => Ok(true),
        Err(error) => {
            let text = fs::read_to_string(log)?;
            if text.contains("Invalid proof")
                || text.contains("Public inputs are not valid")
                || text.contains("Proof commitments are not valid")
            {
                Ok(false)
            } else {
                Err(error)
            }
        }
    }
}
