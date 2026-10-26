use crate::{fixtures::write_json, prover};
use anyhow::{ensure, Context, Result};
use num_bigint::BigUint;
use openssl::hash::{Hasher, MessageDigest};
use rand::RngCore;
use serde_json::{json, Value};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
    time::Instant,
};
const PTAU: &str = "artifacts/setup/ppot_0080_20.ptau";
const SOURCE: &str =
    "https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_20.ptau";
const PIN: &str="117b49e5570b4490b9377962c295e369506116e1db6ee035a7a28bcd83011366297bc486ca8df6cb62f247e2fd0f52d44c892ea4f033393457fbb264a59c75ac";
pub fn hash_file(path: &str, name: &str) -> Result<String> {
    let mut hash =
        Hasher::new(MessageDigest::from_name(name).context("Hash algorithm unavailable")?)?;
    let mut file = File::open(path)?;
    let mut buffer = vec![0; 1024 * 1024];
    loop {
        let len = file.read(&mut buffer)?;
        if len == 0 {
            break;
        }
        hash.update(&buffer[..len])?;
    }
    Ok(hex::encode(hash.finish()?))
}
pub fn run(verify_ceremony: bool) -> Result<()> {
    fs::create_dir_all("artifacts/setup")?;
    if !Path::new(PTAU).exists() {
        let temporary = format!("{PTAU}.partial");
        ensure!(
            Command::new("curl")
                .args([
                    "--fail",
                    "--location",
                    "--retry",
                    "3",
                    "--output",
                    &temporary,
                    SOURCE
                ])
                .status()?
                .success(),
            "Public ceremony download failed"
        );
        fs::rename(temporary, PTAU)?;
    }
    ensure!(
        hash_file(PTAU, "blake2b512")? == PIN,
        "Powers of Tau checksum differs from the project pin"
    );
    let start = Instant::now();
    let mut ceremony_verified = false;
    if verify_ceremony {
        prover::cli(
            &["powersoftau", "verify", PTAU],
            Path::new("artifacts/setup/ptau-verification.log"),
        )?;
        ceremony_verified = true;
    }
    let final_key = "artifacts/setup/credential_final.zkey";
    let initial = "artifacts/setup/credential_initial.zkey";
    if !Path::new(final_key).exists() {
        prover::cli(
            &[
                "groth16",
                "setup",
                "artifacts/circuit/credential.r1cs",
                PTAU,
                initial,
            ],
            Path::new("artifacts/setup/initial-key.log"),
        )?;
        let log = File::create("artifacts/setup/contribution.log")?;
        let mut child = Command::new("node")
            .arg("node_modules/snarkjs/build/cli.cjs")
            .args([
                "zkey",
                "contribute",
                initial,
                final_key,
                "--name=ZK Fresh development contribution",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?;
        // Entropy stays in process memory and stdin, never in command-line arguments.
        let mut entropy = [0; 64];
        rand::rngs::OsRng.fill_bytes(&mut entropy);
        let mut stdin = child.stdin.take().context("Missing contribution input")?;
        stdin.write_all(hex::encode(entropy).as_bytes())?;
        stdin.write_all(b"\n")?;
        drop(stdin);
        ensure!(child.wait()?.success(), "Development contribution failed");
    }
    prover::cli(
        &["zkv", "artifacts/circuit/credential.r1cs", PTAU, final_key],
        Path::new("artifacts/setup/rust-key-verification.log"),
    )?;
    prover::cli(
        &["zkev", final_key, "artifacts/setup/verification_key.json"],
        Path::new("artifacts/setup/export-key.log"),
    )?;
    export_rust_key()?;
    let old: Value = fs::read("artifacts/setup/setup.json")
        .ok()
        .and_then(|data| serde_json::from_slice(&data).ok())
        .unwrap_or(json!({}));
    write_json(
        "artifacts/setup/setup.json",
        &json!({"source":SOURCE,"blake2b512":PIN,"pinProvenance":"Project pin computed from ceremony organizer's HTTPS file; not an organizer-published checksum.",
        "developmentOnly":true,"phaseTwoContributors":1,"ceremonyTranscriptVerifiedLocally":ceremony_verified||old["ceremonyTranscriptVerifiedLocally"]==true,
        "setupAndVerificationMs":start.elapsed().as_secs_f64()*1000.,"originalKeySetupMs":old["keySetupMs"],"r1csSha256":hash_file("artifacts/circuit/credential.r1cs","sha256")?,
        "zkeySha256":hash_file(final_key,"sha256")?,"verificationKeySha256":hash_file("artifacts/setup/verification_key.json","sha256")?,"checkedAtUnix":chrono::Utc::now().timestamp(),"harness":"Rust"}),
        false,
    )?;
    println!("Development setup verified against the circuit; Rust verification key exported.");
    Ok(())
}
pub fn export_rust_key() -> Result<()> {
    let key: Value = serde_json::from_slice(&fs::read("artifacts/setup/verification_key.json")?)?;
    ensure!(
        key["nPublic"] == 5 && key["IC"].as_array().map(Vec::len) == Some(6),
        "Expected five public inputs"
    );
    fn coord(value: &Value) -> Result<Vec<u8>> {
        let integer = BigUint::parse_bytes(
            value.as_str().context("Invalid key coordinate")?.as_bytes(),
            10,
        )
        .context("Invalid key integer")?;
        let base = BigUint::parse_bytes(
            b"21888242871839275222246405745257275088696311157297823662689037894645226208583",
            10,
        )
        .unwrap();
        ensure!(integer < base, "Noncanonical key coordinate");
        let bytes = integer.to_bytes_be();
        let mut output = vec![0; 32];
        output[32 - bytes.len()..].copy_from_slice(&bytes);
        Ok(output)
    }
    fn g1(value: &Value) -> Result<Vec<u8>> {
        Ok([coord(&value[0])?, coord(&value[1])?].concat())
    }
    fn g2(value: &Value) -> Result<Vec<u8>> {
        Ok([
            coord(&value[0][1])?,
            coord(&value[0][0])?,
            coord(&value[1][1])?,
            coord(&value[1][0])?,
        ]
        .concat())
    }
    let points = key["IC"]
        .as_array()
        .unwrap()
        .iter()
        .map(g1)
        .collect::<Result<Vec<_>>>()?;
    fs::write("program/src/generated_vk.rs",format!("// Generated by the Rust harness. Development setup only.\nuse groth16_solana::groth16::Groth16Verifyingkey;\npub const VK_ENABLED: bool = true;\npub const VERIFYING_KEY: Groth16Verifyingkey<'static> = Groth16Verifyingkey {{\n nr_pubinputs: 5,\n vk_alpha_g1: {:?},\n vk_beta_g2: {:?},\n vk_gamme_g2: {:?},\n vk_delta_g2: {:?},\n vk_ic: &{:?},\n}};\n",g1(&key["vk_alpha_1"])?,g2(&key["vk_beta_2"])?,g2(&key["vk_gamma_2"])?,g2(&key["vk_delta_2"])?,points))?;
    Ok(())
}
