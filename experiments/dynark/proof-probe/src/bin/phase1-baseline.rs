//! Bounded Phase 1 experiment; preserves the original probe and vendor.
use anyhow::{ensure, Context, Result};
use ark_bn254::{Bn254, Fr};
use ark_ff::UniformRand;
use ark_poly::EvaluationDomain;
use ark_relations::r1cs::{ConstraintMatrices, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use clap::Parser;
use dynark::r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};
use dynark::{data_structures::Cache, Groth16, Proof, ProvingKey, UpdatingKey};
use dynark_proof_probe::{deltas, ordinary_proof, ordinary_vk, read_r1cs, read_wtns, satisfied};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::{
    fs::{DirBuilder, File},
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

fn full_without_cache(
    pk: &ProvingKey<Bn254>,
    m: &ConstraintMatrices<Fr>,
    w: &[Fr],
    rng: &mut rand::rngs::OsRng,
) -> std::result::Result<Proof<Bn254>, SynthesisError> {
    let ni = m.num_instance_variables;
    let domain = ark_poly::GeneralEvaluationDomain::<Fr>::new(m.num_constraints)
        .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
    let (a, b, c) = dynark::utils::lagrange_of_dense_vec(m, w)?;
    let q = LibsnarkReduction::compute_quotient::<Fr, ark_poly::GeneralEvaluationDomain<Fr>>(
        &domain, a, b, c,
    )?;
    Groth16::<Bn254>::create_proof_with_assignment(
        pk,
        Fr::rand(rng),
        Fr::rand(rng),
        &q,
        &w[..ni],
        &w[ni..],
    )
}
#[derive(Parser)]
struct Args {
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value_t = 4)]
    threads: usize,
    #[arg(long, default_value_t = 30)]
    repetitions: usize,
    #[arg(long, default_value_t = 10)]
    refresh_repetitions: usize,
    #[arg(long, default_value_t = 1)]
    warmup: usize,
}
fn hash(p: &Path) -> Result<String> {
    let mut f = File::open(p)?;
    let mut h = Sha256::new();
    let mut b = [0; 65536];
    loop {
        let n = f.read(&mut b)?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}
fn usage(who: i32) -> (f64, f64, u64) {
    let mut u = std::mem::MaybeUninit::<libc::rusage>::uninit();
    unsafe {
        if libc::getrusage(who, u.as_mut_ptr()) != 0 {
            return (0., 0., 0);
        }
        let u = u.assume_init();
        let secs = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
        (
            secs(u.ru_utime),
            secs(u.ru_stime),
            if cfg!(target_os = "macos") {
                u.ru_maxrss as u64
            } else {
                u.ru_maxrss as u64 * 1024
            },
        )
    }
}
fn current_rss() -> Option<u64> {
    let o = Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()?;
    String::from_utf8(o.stdout)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(|n| n * 1024)
}
struct Clock {
    wall: Instant,
    own: (f64, f64, u64),
    child: (f64, f64, u64),
}
impl Clock {
    fn start() -> Self {
        Self {
            wall: Instant::now(),
            own: usage(libc::RUSAGE_SELF),
            child: usage(libc::RUSAGE_CHILDREN),
        }
    }
    fn finish(self) -> Value {
        let wall = self.wall.elapsed().as_secs_f64() * 1000.;
        let own = usage(libc::RUSAGE_SELF);
        let child = usage(libc::RUSAGE_CHILDREN);
        json!({"wall_ms":wall,"process_user_cpu_ms":(own.0-self.own.0)*1000.,"process_system_cpu_ms":(own.1-self.own.1)*1000.,"child_user_cpu_ms":(child.0-self.child.0)*1000.,"child_system_cpu_ms":(child.1-self.child.1)*1000.,"lifetime_peak_rss_bytes":own.2,"current_rss_snapshot_bytes":current_rss()})
    }
}
fn flush(out: &Path, r: &Value) -> Result<()> {
    let p = out.join("report.tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&p)?;
    f.write_all(&serde_json::to_vec_pretty(r)?)?;
    f.sync_all()?;
    std::fs::rename(p, out.join("report.json"))?;
    Ok(())
}
fn bound(start: Instant) -> Result<()> {
    ensure!(
        start.elapsed().as_secs() < 35 * 60,
        "35 minute run bound exceeded"
    );
    ensure!(
        usage(libc::RUSAGE_SELF).2 <= 4 * 1024 * 1024 * 1024,
        "4 GiB lifetime RSS bound exceeded"
    );
    Ok(())
}
fn stage(out: &Path, r: &mut Value, name: &str, t: Clock, start: Instant) -> Result<()> {
    let m = t.finish();
    println!(
        "stage={name} wall_ms={} peak_rss_bytes={}",
        m["wall_ms"], m["lifetime_peak_rss_bytes"]
    );
    std::io::stdout().flush()?;
    r["stages"][name] = m;
    r["last_completed_stage"] = json!(name);
    flush(out, r)?;
    bound(start)
}
fn save<T: CanonicalSerialize>(out: &Path, name: &str, v: &T) -> Result<Value> {
    let p = out.join(name);
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&p)?;
    let mut w = BufWriter::new(f);
    v.serialize_compressed(&mut w)?;
    w.flush()?;
    let bytes = std::fs::metadata(&p)?.len();
    Ok(json!({"path":name,"bytes":bytes,"sha256":hash(&p)?}))
}
fn verify(
    pvk: &ordinary::PreparedVerifyingKey<Bn254>,
    p: &Proof<Bn254>,
    w: &[Fr],
    ni: usize,
) -> Result<bool> {
    Ok(ordinary::Groth16::<Bn254>::verify_proof(
        pvk,
        &ordinary_proof(p),
        &w[1..ni],
    )?)
}
fn identity(paths: &[PathBuf]) -> Result<Value> {
    let mut entries = Vec::new();
    for p in paths {
        entries.push(json!({"path":p,"sha256":hash(p)?,"bytes":std::fs::metadata(p)?.len()}));
    }
    Ok(json!(entries))
}
fn run(a: &Args, r: &mut Value) -> Result<()> {
    let start = Instant::now();
    let paths: Vec<PathBuf> = [
        "artifacts/circuit/credential.r1cs",
        "artifacts/circuit/credential_js/credential.wasm",
        "artifacts/dynark/witnesses/near-before.wtns",
        "artifacts/dynark/witnesses/near-after.wtns",
        "artifacts/dynark/witnesses/near-after-input.json",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect();
    let frozen = identity(&paths)?;
    r["input_identity"] = frozen.clone();
    r["build_identity"] = identity(&[
        std::env::current_exe()?,
        PathBuf::from("experiments/dynark/proof-probe/src/bin/phase1-baseline.rs"),
        PathBuf::from("experiments/dynark/proof-probe/Cargo.lock"),
    ])?;
    let t = Clock::start();
    let m = read_r1cs(&paths[0])?;
    let before = read_wtns(&paths[2])?;
    let after = read_wtns(&paths[3])?;
    let ni = m.num_instance_variables;
    ensure!(ni == 6, "expected one constant and five public inputs");
    satisfied(&m, &before)?;
    satisfied(&m, &after)?;
    r["circuit"] =
        json!({"constraints":m.num_constraints,"wires":before.len(),"public_signals":ni-1});
    stage(&a.output, r, "import_and_satisfaction", t, start)?;
    let t = Clock::start();
    let ds = deltas(&before, &after);
    let (di, dw): (Vec<_>, Vec<_>) = ds.iter().copied().partition(|(i, _)| *i < ni);
    r["assignment_deltas"] = json!(ds.len());
    stage(&a.output, r, "assignment_delta_only", t, start)?;
    let mut rng = rand::rngs::OsRng;
    let t = Clock::start();
    let (pk, vk, domain) = Groth16::<Bn254>::groth16_setup_dynark(m.clone(), &mut rng)?;
    r["circuit"]["domain_size"] = json!(domain.size());
    stage(&a.output, r, "development_setup", t, start)?;
    let pvk = ordinary::prepare_verifying_key(&ordinary_vk(&vk));
    let t = Clock::start();
    let full = full_without_cache(&pk, &m, &after, &mut rng)?;
    ensure!(
        verify(&pvk, &full, &after, ni)?,
        "no-cache real-circuit equivalence failed"
    );
    stage(&a.output, r, "real_circuit_comparator_smoke", t, start)?;
    let t = Clock::start();
    let uk = Groth16::<Bn254>::generate_updating_keys(&m, &domain, &pk)?;
    stage(&a.output, r, "updating_key_generation", t, start)?;
    let t = Clock::start();
    let (initial, mut cache) =
        Groth16::<Bn254>::prove_dynark(&pk, &m, &before[..ni], &before[ni..], &mut rng)?;
    ensure!(verify(&pvk, &initial, &before, ni)?, "initial proof failed");
    stage(&a.output, r, "initial_full_proof", t, start)?;
    let t = Clock::start();
    Groth16::<Bn254>::process_dynark(&uk, &m, &before[..ni], &before[ni..], &mut cache)?;
    stage(&a.output, r, "private_cache_preparation", t, start)?;
    let t = Clock::start();
    for (name, meta) in [
        ("proving_key", save(&a.output, "proving-key.bin", &pk)?),
        ("updating_key", save(&a.output, "updating-key.bin", &uk)?),
        ("cache", save(&a.output, "retained-cache.bin", &cache)?),
        (
            "ordinary_vk",
            save(&a.output, "ordinary-vk.bin", &ordinary_vk(&vk))?,
        ),
        (
            "initial_proof",
            save(&a.output, "initial-proof.bin", &ordinary_proof(&initial))?,
        ),
        (
            "before_public",
            save(
                &a.output,
                "before-public-inputs.bin",
                &before[1..ni].to_vec(),
            )?,
        ),
        (
            "after_public",
            save(&a.output, "after-public-inputs.bin", &after[1..ni].to_vec())?,
        ),
    ] {
        r["retained_artifacts"][name] = meta;
    }
    let retained: u64 = r["retained_artifacts"]
        .as_object()
        .unwrap()
        .values()
        .map(|v| v["bytes"].as_u64().unwrap())
        .sum();
    ensure!(
        retained <= 2 * 1024 * 1024 * 1024,
        "retention bound exceeded"
    );
    stage(&a.output, r, "serialize_matching_package", t, start)?;
    drop((pk, uk, cache));
    let t = Clock::start();
    for name in ["updating_key", "cache"] {
        let meta = &r["retained_artifacts"][name];
        ensure!(
            hash(&a.output.join(meta["path"].as_str().unwrap()))? == meta["sha256"],
            "reload artifact hash mismatch"
        );
    }
    let uk = UpdatingKey::<Bn254>::deserialize_compressed(BufReader::new(File::open(
        a.output.join("updating-key.bin"),
    )?))?;
    let cache = Cache::<Bn254>::deserialize_compressed(BufReader::new(File::open(
        a.output.join("retained-cache.bin"),
    )?))?;
    ensure!(
        ordinary_vk(&uk.pk.vk) == ordinary_vk(&vk),
        "reloaded setup key mismatch"
    );
    ensure!(
        cache.domain == domain && cache.num_instance == ni,
        "reloaded cache layout mismatch"
    );
    stage(&a.output, r, "reload_matching_package", t, start)?;
    let mut last: Option<Proof<Bn254>> = None;
    for rep in 0..a.warmup + a.repetitions {
        let order = if rep % 2 == 0 {
            vec!["full_no_cache", "full_cache", "update"]
        } else {
            vec!["update", "full_cache", "full_no_cache"]
        };
        let mut sample = json!({"index":rep,"warmup":rep<a.warmup,"order":order});
        for mode in order {
            let t = Clock::start();
            let p = match mode {
                "full_no_cache" => full_without_cache(&uk.pk, &m, &after, &mut rng)?,
                "full_cache" => {
                    let (p, unused) = Groth16::<Bn254>::prove_dynark(
                        &uk.pk,
                        &m,
                        &after[..ni],
                        &after[ni..],
                        &mut rng,
                    )?;
                    drop(unused);
                    p
                }
                _ => Groth16::<Bn254>::update_dynark(&uk, &m, &di, &dw, &cache)?,
            };
            sample[mode] = t.finish();
            let t = Clock::start();
            ensure!(verify(&pvk, &p, &after, ni)?, "proof sample failed");
            sample[format!("{mode}_verify")] = t.finish();
            if mode == "update" {
                ensure!(
                    !verify(&pvk, &p, &before, ni)?,
                    "stale public root accepted"
                );
                ensure!(
                    !verify(&pvk, &initial, &after, ni)?,
                    "old proof/new root accepted"
                );
                let mut wrong = after.clone();
                wrong[5] += Fr::from(1);
                ensure!(!verify(&pvk, &p, &wrong, ni)?, "altered action accepted");
                if let Some(prev) = last.as_ref() {
                    ensure!(prev != &p, "randomized update repeated exact proof");
                }
                last = Some(p);
            }
            bound(start)?;
        }
        r["proof_samples"].as_array_mut().unwrap().push(sample);
        flush(&a.output, r)?;
        println!("proof_pair={rep} complete");
        std::io::stdout().flush()?;
    }
    r["correctness"] = json!({"all_proofs_ordinary_verified":true,"stale_root_rejected":true,"altered_action_rejected":true,"old_proof_new_root_rejected":true,"fresh_randomization_distinct":true,"same_setup_after_reload":true});
    for rep in 0..a.warmup + a.refresh_repetitions {
        let order = if rep % 2 == 0 {
            vec!["full_no_cache", "update"]
        } else {
            vec!["update", "full_no_cache"]
        };
        let mut pair = json!({"index":rep,"warmup":rep<a.warmup,"order":order});
        for mode in order {
            let output = a.output.join(format!("refresh-{rep}-{mode}.wtns"));
            let total = Clock::start();
            let t = Clock::start();
            let result = Command::new("node")
                .args(["node_modules/snarkjs/build/cli.cjs", "wtns", "calculate"])
                .arg(&paths[1])
                .arg(&paths[4])
                .arg(&output)
                .output()?;
            let witness = t.finish();
            let log = a.output.join(format!("refresh-{rep}-{mode}.log"));
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(log)?
                .write_all(&[result.stdout.as_slice(), result.stderr.as_slice()].concat())?;
            ensure!(
                result.status.success(),
                "witness process failed with {}",
                result.status
            );
            std::fs::set_permissions(&output, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
            let t = Clock::start();
            let w = read_wtns(&output)?;
            ensure!(
                w.len() == before.len() && w[0] == Fr::from(1),
                "regenerated witness shape mismatch"
            );
            let import = t.finish();
            let t = Clock::start();
            let (d_i, d_w) = if mode == "update" {
                let ds = deltas(&before, &w);
                ds.into_iter().partition(|(j, _)| *j < ni)
            } else {
                (Vec::new(), Vec::new())
            };
            let delta = t.finish();
            let t = Clock::start();
            let p = if mode == "update" {
                Groth16::<Bn254>::update_dynark(&uk, &m, &d_i, &d_w, &cache)?
            } else {
                full_without_cache(&uk.pk, &m, &w, &mut rng)?
            };
            let proving = t.finish();
            let t = Clock::start();
            let mut encoded = Vec::new();
            ordinary_proof(&p).serialize_compressed(&mut encoded)?;
            let encoding = t.finish();
            let t = Clock::start();
            ensure!(verify(&pvk, &p, &w, ni)?, "refresh proof failed");
            let verification = t.finish();
            let elapsed = total.finish();
            ensure!(
                hash(&output)? == frozen[3]["sha256"],
                "regenerated witness hash mismatch"
            );
            pair[mode] = json!({"total":elapsed,"witness":witness,"import_validation":import,"assignment_delta":delta,"proof":proving,"encoding":encoding,"verification":verification,"synchronous_cache_maintenance_ms":0.,"encoded_proof_bytes":encoded.len(),"witness_hash_matches":true});
            if mode == "update" {
                last = Some(p);
            }
            bound(start)?;
        }
        r["refresh_samples"].as_array_mut().unwrap().push(pair);
        flush(&a.output, r)?;
        println!("refresh_pair={rep} complete");
        std::io::stdout().flush()?;
    }
    r["retained_artifacts"]["updated_proof"] = save(
        &a.output,
        "updated-proof.bin",
        &ordinary_proof(&last.context("no update samples")?),
    )?;
    let retained_total: u64 = std::fs::read_dir(&a.output)?
        .map(|entry| entry.and_then(|e| e.metadata()).map(|m| m.len()))
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .sum();
    ensure!(
        retained_total <= 2 * 1024 * 1024 * 1024,
        "total retained files exceed 2 GiB"
    );
    r["total_retained_bytes"] = json!(retained_total);
    ensure!(identity(&paths)? == frozen, "input mutation detected");
    r["input_identity_unchanged"] = json!(true);
    r["status"] = json!("complete");
    r["total_run_wall_ms"] = json!(start.elapsed().as_secs_f64() * 1000.);
    flush(&a.output, r)
}
fn main() -> Result<()> {
    let a = Args::parse();
    ensure!(
        a.threads == 4
            && a.repetitions > 0
            && a.repetitions <= 30
            && a.refresh_repetitions <= 10
            && a.warmup == 1,
        "experiment bounds/configuration mismatch"
    );
    DirBuilder::new()
        .mode(0o700)
        .create(&a.output)
        .context("unique output directory required")?;
    rayon::ThreadPoolBuilder::new()
        .num_threads(a.threads)
        .build_global()?;
    let mut r = json!({"schema":1,"experiment":"E1/E2","status":"running","threads":a.threads,"repetitions":a.repetitions,"refresh_repetitions":a.refresh_repetitions,"warmup":a.warmup,"proof_samples":[],"refresh_samples":[],"stages":{},"retained_artifacts":{},"correctness":{},"limits":{"wall_seconds":2100,"rss_bytes":4294967296_u64,"retained_bytes":2147483648_u64},"limitations":["Development setup; no original-zkey or deployed-key reuse","Anchored immutable cache; zero synchronous maintenance applies only to this anchored mode","Local refresh excludes path acquisition, network and Solana execution","Import validates encoding/count/constant; full R1CS satisfaction is preflight only","Resource snapshots include metric collection overhead in outer refresh wall; child maximum/live memory and stage allocation tracing unavailable","Proof encoding is arkworks compressed, not Solana encoding","Generated witness hash diagnostic outside timed refresh"]});
    flush(&a.output, &r)?;
    if let Err(e) = run(&a, &mut r) {
        r["status"] = json!("failed");
        r["error"] = json!(format!("{e:#}"));
        flush(&a.output, &r)?;
        return Err(e);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use dynark_proof_probe::{ordinary_proof, ordinary_vk};
    fn tiny() -> (ConstraintMatrices<Fr>, Vec<Fr>) {
        let mut a = vec![vec![(Fr::from(1), 8)], vec![(Fr::from(1), 1)]];
        let mut b = vec![vec![(Fr::from(1), 8)], vec![(Fr::from(1), 0)]];
        let mut c = vec![vec![(Fr::from(1), 1)], vec![(Fr::from(1), 1)]];
        for j in 2..6 {
            a.push(vec![(Fr::from(1), j)]);
            b.push(vec![(Fr::from(1), 0)]);
            c.push(vec![(Fr::from(1), j)]);
        }
        (
            ConstraintMatrices {
                num_instance_variables: 6,
                num_witness_variables: 3,
                num_constraints: 6,
                a_num_non_zero: 6,
                b_num_non_zero: 6,
                c_num_non_zero: 6,
                a,
                b,
                c,
            },
            vec![
                Fr::from(1),
                Fr::from(9),
                Fr::from(2),
                Fr::from(4),
                Fr::from(5),
                Fr::from(6),
                Fr::from(0),
                Fr::from(0),
                Fr::from(3),
            ],
        )
    }
    #[test]
    fn no_cache_prover_uses_full_instance_and_verifies_non_square_five_public_relation() {
        let (m, w) = tiny();
        let mut rng = rand::rngs::OsRng;
        let (pk, vk, _) = Groth16::<Bn254>::groth16_setup_dynark(m.clone(), &mut rng).unwrap();
        let pvk = ordinary::prepare_verifying_key(&ordinary_vk(&vk));
        let p = full_without_cache(&pk, &m, &w, &mut rng).expect("no-cache comparator missing");
        assert!(
            ordinary::Groth16::<Bn254>::verify_proof(&pvk, &ordinary_proof(&p), &w[1..6]).unwrap()
        );
        let mut wrong = w[1..6].to_vec();
        wrong[4] += Fr::from(1);
        assert!(
            !ordinary::Groth16::<Bn254>::verify_proof(&pvk, &ordinary_proof(&p), &wrong).unwrap()
        );
        let (cached, _) =
            Groth16::<Bn254>::prove_dynark(&pk, &m, &w[..6], &w[6..], &mut rng).unwrap();
        assert!(
            ordinary::Groth16::<Bn254>::verify_proof(&pvk, &ordinary_proof(&cached), &w[1..6])
                .unwrap()
        );
    }
    #[test]
    fn direct_vendor_matrix_wrapper_rejects_due_to_constant_one_mismatch() {
        use ark_ff::UniformRand;
        let (m, w) = tiny();
        let mut rng = rand::rngs::OsRng;
        let (pk, vk, _) = Groth16::<Bn254>::groth16_setup_dynark(m.clone(), &mut rng).unwrap();
        let p = Groth16::<Bn254>::generate_proof_with_matrices(
            &pk,
            Fr::rand(&mut rng),
            Fr::rand(&mut rng),
            &m,
            6,
            6,
            &w,
        )
        .unwrap();
        let pvk = ordinary::prepare_verifying_key(&ordinary_vk(&vk));
        assert!(
            !ordinary::Groth16::<Bn254>::verify_proof(&pvk, &ordinary_proof(&p), &w[1..6]).unwrap()
        );
    }
}
