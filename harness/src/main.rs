use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};
use zk_fresh_benchmark::{
    fixtures::{create_fixtures, field_from_decimal, load_fixtures, write_json, write_profile},
    prover,
    registry::Registry,
    solana,
};
fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    ensure!(
        Path::new("initial-spec.md").exists() && Path::new("circuits/credential.circom").exists(),
        "Run from the Zk-fresh project root"
    );
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("fixtures") => {
            let count=args.get(1).map(|value|value.parse()).transpose()?.unwrap_or(2);
            let now=chrono::Utc::now().timestamp(); let fixtures=create_fixtures(count,now-3600,now+86400)?;
            write_json("artifacts/fixtures.json",&fixtures,true)?; write_profile()?;
            println!("Generated {count} Rust X.509 credential fixtures.");
        }
        Some("compile") => {
            write_profile()?; fs::create_dir_all("artifacts/circuit")?;
            ensure!(Command::new("circom").args(["circuits/credential.circom","--r1cs","--wasm","--sym","-l","node_modules","--O1","-o","artifacts/circuit"]).status()?.success(),"Circom compilation failed");
        }
        Some("witness-check") => witness_check()?,
        Some("benchmark") => zk_fresh_benchmark::benchmark::run()?,
        Some("setup") => zk_fresh_benchmark::setup::run(args.iter().any(|value|value=="--verify-ceremony"))?,
        Some("solana-local") => solana::run_local()?,
        Some("solana-devnet") => solana::run_devnet(args.iter().any(|value|value=="--deploy"))?,
        Some("prove") => {
            let input:Value=serde_json::from_slice(&fs::read(args.get(1).ok_or_else(||anyhow::anyhow!("Supply input JSON path"))?)?)?;
            let result=prover::prove(&input,args.get(2).map(String::as_str).unwrap_or("manual"),None)?;
            println!("{}",serde_json::to_string_pretty(&json!({"verified":result.verified,"timings":result.timings}))?);
        }
        _=>bail!("Commands: fixtures [count], compile, setup [--verify-ceremony], witness-check, benchmark, solana-local, solana-devnet [--deploy], prove INPUT NAME"),
    }
    Ok(())
}
fn witness_check() -> Result<()> {
    let mut registry = Registry::new(load_fixtures()?)?;
    registry.snapshot(chrono::Utc::now().timestamp())?;
    let input = registry.input(0, field_from_decimal("123")?)?;
    let start = std::time::Instant::now();
    prover::witness(&input, "rust-valid")?;
    println!(
        "Valid Rust witness generated in {:.3} seconds.",
        start.elapsed().as_secs_f64()
    );
    let mut negatives = Vec::new();
    let mut changed = input.clone();
    changed["tbs"][137] = (changed["tbs"][137].as_u64().unwrap() ^ 1).into();
    negatives.push(("organization", changed));
    let mut changed = input.clone();
    changed["notAfter"] = (registry.fixtures.credentials[0].not_after + 1)
        .to_string()
        .into();
    negatives.push(("validity", changed));
    let mut changed = input.clone();
    let first = changed["issuerSignature"][0]
        .as_str()
        .unwrap()
        .parse::<num_bigint::BigUint>()?;
    changed["issuerSignature"][0] = (first + num_bigint::BigUint::from(1u8)).to_string().into();
    negatives.push(("signature", changed));
    let mut changed = input.clone();
    changed["actionHash"] = "124".into();
    negatives.push(("action", changed));
    for (name, first) in [("negative-serial", 128), ("nonminimal-serial", 0)] {
        let mut changed = input.clone();
        changed["tbs"][11] = first.into();
        negatives.push((name, changed));
    }
    if registry.fixtures.credentials.len() > 1 {
        let other = registry.input(1, field_from_decimal("123")?)?;
        let mut changed = input.clone();
        for field in ["slot", "siblings", "pathIndices"] {
            changed[field] = other[field].clone();
        }
        negatives.push(("mixed-holder-path", changed));
    }
    registry.revoke(0, chrono::Utc::now().timestamp())?;
    negatives.push((
        "revoked-current-root",
        registry.input(0, field_from_decimal("123")?)?,
    ));
    for (name, invalid) in negatives {
        ensure!(
            prover::witness(&invalid, &format!("rust-rejected-{name}")).is_err(),
            "Invalid {name} witness accepted"
        );
        let log = fs::read_to_string(format!("artifacts/witnesses/rust-rejected-{name}.log"))?;
        ensure!(
            log.contains("Error in template"),
            "Negative {name} did not fail a circuit constraint"
        );
        println!("Rejected: {name}");
    }
    write_json(
        "results/witness-checks.json",
        &json!({"validWitness":true,"rejectedInvalidWitnesses":8,"harness":"Rust","checkedAtUnix":chrono::Utc::now().timestamp()}),
        false,
    )?;
    Ok(())
}
