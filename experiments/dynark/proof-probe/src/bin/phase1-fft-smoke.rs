//! Bounded E3 diagnostic on public toy vectors; never prepares credential keys.
use anyhow::{ensure, Result};
use ark_bn254::{Bn254, Fr, G1Projective};
use ark_ec::{PrimeGroup, CurveGroup};
use ark_ff::Zero;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use dynark::{dynamic_cache::FullCache, fft_handler::{CustomParaFFT, SqrtFftStatus, sqrt_fft_fw_field, sqrt_fft_fw_g1}, ProvingKey, UpdatingKey, VerifyingKey};
use serde_json::{json, Value};
use std::{fs::{File, OpenOptions}, path::PathBuf, process::{Command, Stdio}, time::{Duration, Instant}};

fn field_case(n: usize, budget: usize, inverse: bool) -> Value {
    let domain = GeneralEvaluationDomain::<Fr>::new(n).unwrap();
    let half = GeneralEvaluationDomain::<Fr>::new(1 << (n.trailing_zeros() / 2)).unwrap();
    let info = CustomParaFFT::<Bn254>::new(n, domain.group_gen());
    let original: Vec<Fr> = (0..n).map(|i| Fr::from((i * i + 17) as u64)).collect();
    let mut input = if inverse { domain.fft(&original) } else { original };
    let expected = if inverse { domain.ifft(&input) } else { domain.fft(&input) };
    let mut mem = vec![Fr::zero(); n];
    let mut status = SqrtFftStatus::new(inverse);
    let start = Instant::now();
    let initial = input.clone();
    let zero_result = sqrt_fft_fw_field::<Bn254>(&half, &info, &mut input, &mut status, &mut mem, 0);
    let zero_unchanged = input == initial && zero_result == (false, 0);
    let mut completed = false;
    let mut calls = 0;
    while calls < 2000 && !completed {
        calls += 1;
        completed = sqrt_fft_fw_field::<Bn254>(&half, &info, &mut input, &mut status, &mut mem, budget.max(1)).0;
    }
    json!({"type":"Fr","n":n,"requested_step_budget":budget,"execution_step_budget":budget.max(1),"inverse":inverse,"zero_budget_unchanged":zero_unchanged,"completed":completed,"calls":calls,"matches_arkworks":completed && input==expected,"mismatched_elements":input.iter().zip(&expected).filter(|(a,b)| a!=b).count(),"elapsed_ms":start.elapsed().as_secs_f64()*1000.})
}

fn group_case(n: usize, budget: usize, inverse: bool) -> Value {
    let domain = GeneralEvaluationDomain::<Fr>::new(n).unwrap();
    let half = GeneralEvaluationDomain::<Fr>::new(1 << (n.trailing_zeros() / 2)).unwrap();
    let info = CustomParaFFT::<Bn254>::new(n, domain.group_gen());
    let original: Vec<G1Projective> = (0..n).map(|i| G1Projective::generator() * Fr::from((i * i + 17) as u64)).collect();
    let mut input = if inverse { domain.fft(&original) } else { original };
    let expected = if inverse { domain.ifft(&input) } else { domain.fft(&input) };
    let mut mem = vec![G1Projective::zero(); n];
    let mut status = SqrtFftStatus::new(inverse);
    let start = Instant::now();
    let initial = input.clone();
    let zero_result = sqrt_fft_fw_g1::<Bn254>(&half, &info, &mut input, &mut status, &mut mem, 0);
    let zero_unchanged = input == initial && zero_result == (false, 0);
    let mut completed = false;
    let mut calls = 0;
    while calls < 2000 && !completed {
        calls += 1;
        completed = sqrt_fft_fw_g1::<Bn254>(&half, &info, &mut input, &mut status, &mut mem, budget.max(1)).0;
    }
    json!({"type":"G1","n":n,"requested_step_budget":budget,"execution_step_budget":budget.max(1),"inverse":inverse,"zero_budget_unchanged":zero_unchanged,"completed":completed,"calls":calls,"matches_arkworks":completed && input==expected,"mismatched_elements":input.iter().zip(&expected).filter(|(a,b)| a!=b).count(),"elapsed_ms":start.elapsed().as_secs_f64()*1000.})
}

fn remainder_child() {
    let n = 2052;
    let point = G1Projective::generator();
    let zero_affine = G1Projective::zero().into_affine();
    let pk = ProvingKey::<Bn254> { vk: VerifyingKey::default(), beta_g1: zero_affine, delta_g1: zero_affine, u_g1: vec![], v_g1: vec![], v_g2: vec![], tau_powers_g1: vec![], t_p_g1: vec![] };
    let uk = UpdatingKey { pk, lagrange_truncated: vec![point;n], p: vec![point;n], w: vec![], w_reverse: vec![], w_for_q: vec![], w_reverse_for_q: vec![], a_matrix_cols: vec![], b_matrix_cols: vec![] };
    let mut cache = FullCache::<Bn254>::new(n, vec![Fr::from(1);n], vec![Fr::from(2);n], vec![point;n], vec![point;n]);
    println!("remainder_child_started n={n} step_budget=2 batch_size=2048");
    let result = cache.step_forward(&uk, 2);
    println!("remainder_child_returned {result:?}");
}

fn peak_rss() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    unsafe {
        if libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) != 0 { return 0; }
        let value = usage.assume_init().ru_maxrss as u64;
        if cfg!(target_os="macos") { value } else { value * 1024 }
    }
}

fn main() -> Result<()> {
    if std::env::args().any(|a| a == "--remainder-child") { remainder_child(); return Ok(()); }
    let out = PathBuf::from(std::env::args().nth(1).ok_or_else(|| anyhow::anyhow!("usage: phase1-fft-smoke UNIQUE_OUTPUT_DIRECTORY"))?);
    std::fs::create_dir(&out)?;
    rayon::ThreadPoolBuilder::new().num_threads(2).build_global()?;
    let start = Instant::now();
    let mut cases = vec![];
    for n in [16,32,64,128,256] {
        for budget in [0,1,2,31] {
            for inverse in [false,true] {
                cases.push(field_case(n,budget,inverse));
                cases.push(group_case(n,budget,inverse));
                ensure!(start.elapsed()<Duration::from_secs(55),"diagnostic runtime limit");
                ensure!(peak_rss()<256*1024*1024,"diagnostic RSS limit");
            }
        }
    }
    let child_log = OpenOptions::new().write(true).create_new(true).open(out.join("remainder-child.log"))?;
    let child_err = child_log.try_clone()?;
    let mut child = Command::new(std::env::current_exe()?).arg("--remainder-child").env("RAYON_NUM_THREADS","2").stdout(Stdio::from(child_log)).stderr(Stdio::from(child_err)).spawn()?;
    let child_start = Instant::now();
    let (timed_out, exit) = loop {
        if let Some(status) = child.try_wait()? { break (false,status.code()); }
        if child_start.elapsed()>=Duration::from_secs(2) { child.kill()?; let status=child.wait()?; break (true,status.code()); }
        std::thread::sleep(Duration::from_millis(10));
    };
    let report = json!({"experiment":"E3","schema":1,"reference_commit":"c73a380df86d8f5d195f1e20c8a1d86a7dce084b","scope":"public toy field/G1 vectors; no setup, keys with toxic waste, credential witnesses, proofs or vendor fixes","rayon_threads":2,"cases":cases,"remainder_case":{"n":2052,"step_budget":2,"timeout_seconds":2,"timed_out":timed_out,"exit_code":exit,"elapsed_ms":child_start.elapsed().as_secs_f64()*1000.,"classification":if timed_out {"toy_reconstruction_liveness_timeout"} else {"returned_or_crashed_inspect_log"}},"runtime_ms":start.elapsed().as_secs_f64()*1000.,"parent_peak_rss_bytes":peak_rss(),"limitations":["does not execute a fully dynamic proof","actual m=648156 failure remains static code derivation","step budget zero first checks no mutation, then completes using budget one","RSS covers parent process; child peak not measured"]});
    serde_json::to_writer_pretty(File::create(out.join("report.json"))?,&report)?;
    println!("{}",json!({"cases":report["cases"].as_array().unwrap().len(),"matching":report["cases"].as_array().unwrap().iter().filter(|c|c["matches_arkworks"]==true).count(),"remainder_timeout":timed_out,"runtime_ms":report["runtime_ms"],"parent_peak_rss_bytes":report["parent_peak_rss_bytes"]}));
    Ok(())
}
