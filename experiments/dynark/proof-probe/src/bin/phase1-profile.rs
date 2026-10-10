//! E4 diagnostic only: retained matching package, no setup or UK generation.
use anyhow::{ensure, Context, Result};
use ark_bn254::{Bn254, Fr};
use ark_ff::{UniformRand, Zero};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::{ConstraintMatrices, Matrix, SynthesisError};
use ark_serialize::CanonicalDeserialize;
use clap::Parser;
use dynark::{
    data_structures::Cache,
    r1cs_to_qap::{LibsnarkReduction, R1CSToQAP},
    Groth16, Proof, ProvingKey, UpdatingKey,
};
use dynark_proof_probe::{
    deltas, evaluate, ordinary_proof, ordinary_vk, read_r1cs, read_wtns, satisfied,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    fs::{DirBuilder, File, OpenOptions},
    io::{BufReader, Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering::SeqCst},
        Arc, Condvar, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

struct Tracked {
    live: AtomicU64,
    peak: AtomicU64,
    allocated: AtomicU64,
    freed: AtomicU64,
    allocs: AtomicU64,
    frees: AtomicU64,
    reallocs: AtomicU64,
    realloc_old: AtomicU64,
    realloc_new: AtomicU64,
}
impl Tracked {
    const fn new() -> Self {
        Self {
            live: AtomicU64::new(0),
            peak: AtomicU64::new(0),
            allocated: AtomicU64::new(0),
            freed: AtomicU64::new(0),
            allocs: AtomicU64::new(0),
            frees: AtomicU64::new(0),
            reallocs: AtomicU64::new(0),
            realloc_old: AtomicU64::new(0),
            realloc_new: AtomicU64::new(0),
        }
    }
    fn add_live(&self, n: u64) {
        let live = self.live.fetch_add(n, SeqCst) + n;
        self.peak.fetch_max(live, SeqCst);
    }
    fn allocated(&self, n: usize) {
        self.allocated.fetch_add(n as u64, SeqCst);
        self.allocs.fetch_add(1, SeqCst);
        self.add_live(n as u64);
    }
    fn snapshot(&self) -> [u64; 8] {
        [
            self.live.load(SeqCst),
            self.allocated.load(SeqCst),
            self.freed.load(SeqCst),
            self.allocs.load(SeqCst),
            self.frees.load(SeqCst),
            self.reallocs.load(SeqCst),
            self.realloc_old.load(SeqCst),
            self.realloc_new.load(SeqCst),
        ]
    }
}
unsafe impl GlobalAlloc for Tracked {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            self.allocated(l.size());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(l);
        if !p.is_null() {
            self.allocated(l.size());
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        self.live.fetch_sub(l.size() as u64, SeqCst);
        self.freed.fetch_add(l.size() as u64, SeqCst);
        self.frees.fetch_add(1, SeqCst);
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        let q = System.realloc(p, l, n);
        if !q.is_null() {
            self.reallocs.fetch_add(1, SeqCst);
            self.realloc_old.fetch_add(l.size() as u64, SeqCst);
            self.realloc_new.fetch_add(n as u64, SeqCst);
            self.allocated.fetch_add(n as u64, SeqCst);
            self.freed.fetch_add(l.size() as u64, SeqCst);
            if n >= l.size() {
                self.add_live((n - l.size()) as u64);
            } else {
                self.live.fetch_sub((l.size() - n) as u64, SeqCst);
            }
        }
        q
    }
}
#[global_allocator]
static HEAP: Tracked = Tracked::new();

fn allocator_check() -> Result<Value> {
    let t = Tracked::new();
    let l = Layout::from_size_align(32, 8)?;
    unsafe {
        let p = t.alloc(l);
        ensure!(!p.is_null(), "allocator self-test alloc failed");
        ensure!(t.live.load(SeqCst) == 32, "alloc tracking");
        let p = t.realloc(p, l, 96);
        ensure!(!p.is_null(), "allocator self-test realloc failed");
        ensure!(t.live.load(SeqCst) == 96, "grow tracking");
        let l = Layout::from_size_align(96, 8)?;
        let p = t.realloc(p, l, 16);
        ensure!(!p.is_null(), "allocator self-test shrink failed");
        ensure!(t.live.load(SeqCst) == 16, "shrink tracking");
        t.dealloc(p, Layout::from_size_align(16, 8)?);
        let p = t.alloc_zeroed(Layout::from_size_align(8, 8)?);
        ensure!(!p.is_null(), "zero alloc failed");
        ensure!(*p == 0, "zero alloc contents");
        t.dealloc(p, Layout::from_size_align(8, 8)?);
    }
    let s = t.snapshot();
    ensure!(
        s[0] == 0 && s[1] == s[2] && s[5] == 2 && t.peak.load(SeqCst) == 96,
        "allocator balance/peak failure"
    );
    Ok(
        json!({"passed":true,"requested_live_after_drop":s[0],"cumulative_allocated":s[1],"cumulative_freed":s[2],"successful_reallocs":s[5],"peak":t.peak.load(SeqCst)}),
    )
}

fn usage() -> (f64, f64, u64) {
    unsafe {
        let mut r = std::mem::MaybeUninit::<libc::rusage>::uninit();
        if libc::getrusage(libc::RUSAGE_SELF, r.as_mut_ptr()) != 0 {
            return (0., 0., 0);
        }
        let r = r.assume_init();
        let time = |v: libc::timeval| v.tv_sec as f64 + v.tv_usec as f64 / 1e6;
        (
            time(r.ru_utime),
            time(r.ru_stime),
            if cfg!(target_os = "macos") {
                r.ru_maxrss as u64
            } else {
                r.ru_maxrss as u64 * 1024
            },
        )
    }
}
fn rss(pid: u32) -> Option<u64> {
    let o = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    String::from_utf8(o.stdout)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(|v| v * 1024)
}
struct Meter {
    time: Instant,
    cpu: (f64, f64, u64),
    heap: [u64; 8],
    rss: Option<u64>,
}
impl Meter {
    fn start() -> Self {
        let rss = rss(std::process::id());
        let cpu = usage();
        let heap = HEAP.snapshot();
        HEAP.peak.store(heap[0], SeqCst);
        Self {
            time: Instant::now(),
            cpu,
            heap,
            rss,
        }
    }
    fn finish(self) -> Value {
        let wall = self.time.elapsed().as_secs_f64() * 1000.;
        let cpu = usage();
        let h = HEAP.snapshot();
        let peak = HEAP.peak.load(SeqCst);
        json!({"wall_ms":wall,"user_cpu_ms":(cpu.0-self.cpu.0)*1000.,"system_cpu_ms":(cpu.1-self.cpu.1)*1000.,"lifetime_peak_rss_bytes":cpu.2,"rss_before_bytes":self.rss,"rss_after_bytes":rss(std::process::id()),"requested_live_before_bytes":self.heap[0],"requested_live_after_bytes":h[0],"requested_live_peak_bytes":peak,"requested_peak_above_start_bytes":peak.saturating_sub(self.heap[0]),"allocated_requested_bytes":h[1]-self.heap[1],"freed_requested_bytes":h[2]-self.heap[2],"allocation_calls":h[3]-self.heap[3],"deallocation_calls":h[4]-self.heap[4],"successful_reallocation_calls":h[5]-self.heap[5],"reallocation_old_requested_bytes":h[6]-self.heap[6],"reallocation_new_requested_bytes":h[7]-self.heap[7]})
    }
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
fn file(p: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(p)?)
}
fn write_json(p: &Path, v: &Value) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(p)?;
    serde_json::to_writer_pretty(&mut f, v)?;
    f.flush()?;
    Ok(())
}
fn flush(out: &Path, r: &Value) -> Result<()> {
    write_json(&out.join("report.tmp"), r)?;
    std::fs::rename(out.join("report.tmp"), out.join("report.json"))?;
    Ok(())
}
fn stage(out: &Path, r: &mut Value, name: &str, m: Meter) -> Result<()> {
    let v = m.finish();
    println!(
        "stage={name} wall_ms={} live={} peak={}",
        v["wall_ms"], v["requested_live_after_bytes"], v["requested_live_peak_bytes"]
    );
    std::io::stdout().flush()?;
    r["stages"][name] = v;
    r["last_completed_stage"] = json!(name);
    flush(out, r)
}

#[derive(Parser)]
struct Args {
    #[arg(long)]
    package: Option<PathBuf>,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value_t = 4)]
    threads: usize,
    #[arg(long, default_value_t = 10)]
    sample_seconds: u64,
    #[arg(long, default_value_t = 20)]
    max_full: usize,
    #[arg(long, default_value_t = 100)]
    max_updates: usize,
    #[arg(long)]
    private_preparation_once: bool,
    #[arg(long)]
    witness_once: bool,
    #[arg(long, default_value_t = 900)]
    wall_limit_seconds: u64,
    #[arg(long, hide = true)]
    watchdog_pid: Option<u32>,
}
fn descendants(rows: &[(u32, u32, u64)], pid: u32) -> Vec<(u32, u64)> {
    let mut found = vec![(pid, 0)];
    loop {
        let mut changed = false;
        for &(p, pp, r) in rows {
            if p != pid && !found.iter().any(|x| x.0 == p) && found.iter().any(|x| x.0 == pp) {
                found.push((p, r));
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    found.remove(0);
    found
}
fn process_rows() -> Result<Vec<(u32, u32, u64)>> {
    let o = Command::new("ps")
        .args(["-axo", "pid=,ppid=,rss="])
        .output()?;
    ensure!(o.status.success(), "watchdog ps failed");
    let s = String::from_utf8(o.stdout)?;
    Ok(s.lines()
        .filter_map(|l| {
            let mut p = l.split_whitespace();
            Some((
                p.next()?.parse().ok()?,
                p.next()?.parse().ok()?,
                p.next()?.parse::<u64>().ok()? * 1024,
            ))
        })
        .collect())
}
fn retained_bytes(p: &Path) -> Result<u64> {
    let mut n = 0;
    for e in std::fs::read_dir(p)? {
        let e = e?;
        let m = e.metadata()?;
        n += if m.is_dir() {
            retained_bytes(&e.path())?
        } else {
            m.len()
        };
    }
    Ok(n)
}
fn watchdog(a: &Args, pid: u32) -> Result<()> {
    let start = Instant::now();
    let mut samples = Vec::new();
    let mut stop = None;
    loop {
        let rows = process_rows()?;
        let parent = match rows.iter().find(|r| r.0 == pid) {
            Some(v) => v.2,
            None => break,
        };
        let mine = std::process::id();
        let children: Vec<_> = descendants(&rows, pid)
            .into_iter()
            .filter(|v| v.0 != mine && !descendants(&rows, mine).iter().any(|x| x.0 == v.0))
            .collect();
        let max_child = children.iter().map(|v| v.1).max().unwrap_or(0);
        let bytes = retained_bytes(&a.output)?;
        samples.push(json!({"elapsed_seconds":start.elapsed().as_secs_f64(),"parent_rss_bytes":parent,"max_owned_child_rss_bytes":max_child,"owned_children":children,"retained_bytes":bytes}));
        if start.elapsed().as_secs() >= a.wall_limit_seconds {
            stop = Some("wall_limit")
        } else if parent > 4 * 1024 * 1024 * 1024 {
            stop = Some("parent_rss_limit")
        } else if max_child > 1024 * 1024 * 1024 {
            stop = Some("child_rss_limit")
        } else if bytes > 512 * 1024 * 1024 {
            stop = Some("retained_limit")
        }
        write_json(
            &a.output.join("watchdog.json"),
            &json!({"pid":pid,"watchdog_pid":mine,"stop":stop,"samples":samples}),
        )?;
        if stop.is_some() {
            unsafe {
                libc::kill(-(pid as i32), libc::SIGKILL);
            }
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }
    Ok(())
}
struct Guard {
    child: Child,
    done: PathBuf,
}
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = std::fs::write(&self.done, []);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn sample_spawn(out: &Path, label: &str, seconds: u64) -> Result<Child> {
    let log = file(&out.join(format!("{label}-sample-command.log")))?;
    Ok(Command::new("/usr/bin/sample")
        .arg(std::process::id().to_string())
        .arg(seconds.to_string())
        .arg("1")
        .arg("-mayDie")
        .arg("-file")
        .arg(out.join(format!("{label}-sample.txt")))
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .spawn()?)
}
fn sample_wait(child: Result<Child>, label: &str, seconds: u64) -> Value {
    match child {
        Ok(mut child) => match child.wait() {
            Ok(s) => {
                json!({"label":label,"duration_seconds":seconds,"exit_code":s.code(),"success":s.success()})
            }
            Err(e) => json!({"label":label,"error":e.to_string()}),
        },
        Err(e) => json!({"label":label,"error":e.to_string()}),
    }
}
fn full(
    pk: &ProvingKey<Bn254>,
    m: &ConstraintMatrices<Fr>,
    w: &[Fr],
) -> std::result::Result<Proof<Bn254>, SynthesisError> {
    let domain = GeneralEvaluationDomain::<Fr>::new(m.num_constraints)
        .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
    let (a, b, c) = dynark::utils::lagrange_of_dense_vec(m, w)?;
    let q =
        LibsnarkReduction::compute_quotient::<Fr, GeneralEvaluationDomain<Fr>>(&domain, a, b, c)?;
    let mut rng = rand::rngs::OsRng;
    let ni = m.num_instance_variables;
    Groth16::<Bn254>::create_proof_with_assignment(
        pk,
        Fr::rand(&mut rng),
        Fr::rand(&mut rng),
        &q,
        &w[..ni],
        &w[ni..],
    )
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
fn census_matrix(
    matrix: &Matrix<Fr>,
    ds: &[(usize, Fr)],
    before: &[Fr],
    after: &[Fr],
) -> Result<Value> {
    let mut dense = vec![Fr::zero(); before.len()];
    for (i, d) in ds {
        dense[*i] = *d;
    }
    let change = evaluate(matrix, &dense);
    let a = evaluate(matrix, before);
    let b = evaluate(matrix, after);
    ensure!(
        a.iter()
            .zip(&b)
            .zip(&change)
            .all(|((a, b), d)| *b - *a == *d),
        "dense delta census mismatch"
    );
    let mut entries = 0;
    let mut touched = 0;
    let mut canceled = 0;
    for (row, d) in matrix.iter().zip(&change) {
        let count = row.iter().filter(|(_, j)| !dense[*j].is_zero()).count();
        entries += count;
        if count > 0 {
            touched += 1;
            if d.is_zero() {
                canceled += 1
            }
        }
    }
    Ok(
        json!({"touched_matrix_entries":entries,"distinct_touched_rows":touched,"touched_rows_canceled_to_zero":canceled,"true_nonzero_row_changes":change.iter().filter(|x|!x.is_zero()).count()}),
    )
}
fn check_sparse(
    cols: &Vec<Vec<(usize, Fr)>>,
    sparse: &[(usize, Fr)],
    matrix: &Matrix<Fr>,
    ds: &[(usize, Fr)],
) -> Result<Value> {
    let mut dense = vec![Fr::zero(); cols.len()];
    for (i, d) in ds {
        dense[*i] = *d;
    }
    let expected = evaluate(matrix, &dense);
    let mut got = vec![Fr::zero(); matrix.len()];
    for (i, d) in sparse {
        ensure!(*i < got.len(), "sparse row out of bounds");
        got[*i] += *d;
    }
    ensure!(got == expected, "sparse vs dense delta mismatch");
    Ok(
        json!({"returned_rows_including_zeros":sparse.len(),"returned_zero_rows":sparse.iter().filter(|x|x.1.is_zero()).count(),"sparse_equals_dense":true}),
    )
}
fn load<T: CanonicalDeserialize>(p: &Path) -> Result<T> {
    Ok(T::deserialize_compressed(BufReader::new(File::open(p)?))?)
}
fn protected_identity() -> Result<Value> {
    let baseline: Value =
        serde_json::from_reader(File::open("results/dynark/phase-1/baseline-freeze.json")?)?;
    let mut checked = 0;
    for entry in baseline["entries"].as_array().context("baseline entries")? {
        let p = Path::new(entry["path"].as_str().context("path")?);
        ensure!(
            hash(p)? == entry["sha256"].as_str().context("hash")?,
            "baseline changed {}",
            p.display()
        );
        ensure!(
            format!("0o{:o}", std::fs::metadata(p)?.permissions().mode() & 0o777)
                == entry["mode"].as_str().context("mode")?,
            "baseline mode changed {}",
            p.display()
        );
        checked += 1;
    }
    ensure!(
        hash(Path::new(
            "experiments/dynark/proof-probe/src/bin/phase1-baseline.rs"
        ))? == "2cfc91338433ca8f022196325cb70d506673efc12b0ebf7b89049e0e7551b529",
        "E2 source changed"
    );
    ensure!(
        hash(Path::new(
            "experiments/dynark/proof-probe/target/release/phase1-baseline"
        ))? == "ac864557c42fff1cd680da3b7f793e9b35660601b4f61f0300a6ac9f8e84837f",
        "E2 binary changed"
    );
    Ok(
        json!({"baseline_entries_checked":checked,"hash_and_mode_mismatches":0,"e2_source_binary_unchanged":true}),
    )
}

fn run(a: &Args, r: &mut Value) -> Result<()> {
    ensure!(
        a.threads == 4
            && a.sample_seconds == 10
            && a.max_full > 0
            && a.max_full <= 20
            && a.max_updates > 0
            && a.max_updates <= 100
            && a.wall_limit_seconds <= 900,
        "approved bounds exceeded"
    );
    ensure!(
        a.private_preparation_once && a.witness_once,
        "E4 requires prep and witness exactly once"
    );
    let package = a.package.as_ref().context("--package required")?;
    r["preservation_before"] = protected_identity()?;
    r["allocator_self_test"] = allocator_check()?;
    r["source_sha256"] = json!(hash(Path::new(
        "experiments/dynark/proof-probe/src/bin/phase1-profile.rs"
    ))?);
    r["binary_sha256"] = json!(hash(&std::env::current_exe()?)?);
    r["cargo_lock_sha256"] = json!(hash(Path::new(
        "experiments/dynark/proof-probe/Cargo.lock"
    ))?);
    let e2: Value = serde_json::from_reader(File::open("results/dynark/phase-1/e2-report.json")?)?;
    for key in [
        "updating_key",
        "cache",
        "ordinary_vk",
        "initial_proof",
        "before_public",
        "after_public",
    ] {
        let v = &e2["retained_artifacts"][key];
        let p = package.join(v["path"].as_str().context("artifact path")?);
        ensure!(
            hash(&p)? == v["sha256"].as_str().context("artifact hash")?,
            "package identity mismatch {key}"
        );
        ensure!(
            std::fs::metadata(&p)?.permissions().mode() & 0o777 == 0o600,
            "package mode mismatch"
        );
    }
    for v in e2["input_identity"].as_array().context("inputs")? {
        ensure!(
            hash(Path::new(v["path"].as_str().context("input path")?))?
                == v["sha256"].as_str().context("input hash")?,
            "input identity mismatch"
        );
    }
    r["package_identities"] = e2["retained_artifacts"].clone();
    r["input_identities"] = e2["input_identity"].clone();
    flush(&a.output, r)?;
    rayon::ThreadPoolBuilder::new()
        .num_threads(a.threads)
        .build_global()?;
    let t = Meter::start();
    let m = read_r1cs(Path::new("artifacts/circuit/credential.r1cs"))?;
    let before = read_wtns(Path::new("artifacts/dynark/witnesses/near-before.wtns"))?;
    let after = read_wtns(Path::new("artifacts/dynark/witnesses/near-after.wtns"))?;
    let ni = m.num_instance_variables;
    ensure!(
        ni == 6 && before[0] == Fr::from(1) && after[0] == Fr::from(1),
        "constant/schema mismatch"
    );
    satisfied(&m, &before)?;
    satisfied(&m, &after)?;
    stage(&a.output, r, "import_satisfaction", t)?;
    let t = Meter::start();
    let uk: UpdatingKey<Bn254> = load(&package.join("updating-key.bin"))?;
    stage(&a.output, r, "load_updating_key_including_pk", t)?;
    let t = Meter::start();
    let cache: Cache<Bn254> = load(&package.join("retained-cache.bin"))?;
    stage(&a.output, r, "load_private_cache", t)?;
    let vk: ordinary::VerifyingKey<Bn254> = load(&package.join("ordinary-vk.bin"))?;
    let initial: ordinary::Proof<Bn254> = load(&package.join("initial-proof.bin"))?;
    ensure!(ordinary_vk(&uk.pk.vk) == vk, "key mismatch");
    ensure!(
        cache.num_instance == ni
            && cache.domain.size() == 1048576
            && uk.pk.vk.num_constraints == m.num_constraints,
        "cache/domain mismatch"
    );
    let pvk = ordinary::prepare_verifying_key(&vk);
    ensure!(
        ordinary::Groth16::<Bn254>::verify_proof(&pvk, &initial, &before[1..ni])?,
        "anchor proof rejected"
    );
    let anchored = Proof {
        a_g1: cache.a_g1,
        b_g2: cache.b_g2,
        c_g1: cache.c_g1,
    };
    ensure!(ordinary_proof(&anchored) == initial, "cache proof mismatch");
    r["structural_estimates"] = json!({"note":"capacity times element size is structural estimate, not live memory profiling","anchor_assignment_capacity_bytes":before.capacity()*std::mem::size_of::<Fr>(),"target_assignment_capacity_bytes":after.capacity()*std::mem::size_of::<Fr>(),"cache_q_a_capacity_bytes":cache.q_a.capacity()*std::mem::size_of::<ark_bn254::G1Projective>(),"cache_q_b_capacity_bytes":cache.q_b.capacity()*std::mem::size_of::<ark_bn254::G1Projective>(),"padded_domain":cache.domain.size()});
    let t = Meter::start();
    let ds = deltas(&before, &after);
    let (di, dw): (Vec<_>, Vec<_>) = ds.iter().copied().partition(|x| x.0 < ni);
    stage(&a.output, r, "assignment_delta", t)?;
    let t = Meter::start();
    let (sa, sb) =
        dynark::utils::improved_lagrange_sparse_get(&uk.a_matrix_cols, &uk.b_matrix_cols, &ds)?;
    r["census"] = json!({"assignment_support":ds.len(),"instance_support":di.len(),"auxiliary_support":dw.len(),"A":census_matrix(&m.a,&ds,&before,&after)?,"B":census_matrix(&m.b,&ds,&before,&after)?,"C":census_matrix(&m.c,&ds,&before,&after)?,"implementation_A":check_sparse(&uk.a_matrix_cols,&sa,&m.a,&ds)?,"implementation_B":check_sparse(&uk.b_matrix_cols,&sb,&m.b,&ds)?});
    drop((sa, sb));
    stage(&a.output, r, "diagnostic_census", t)?;
    for mode in ["full", "update"] {
        let child = sample_spawn(&a.output, mode, a.sample_seconds);
        let start = Instant::now();
        let max = if mode == "full" {
            a.max_full
        } else {
            a.max_updates
        };
        let mut samples = Vec::new();
        for index in 0..max {
            let t = Meter::start();
            let p = if mode == "full" {
                full(&uk.pk, &m, &after)?
            } else {
                Groth16::<Bn254>::update_dynark(&uk, &m, &di, &dw, &cache)?
            };
            let resource = t.finish();
            let t = Meter::start();
            ensure!(
                verify(&pvk, &p, &after, ni)?,
                "profile {mode} proof rejected"
            );
            ensure!(!verify(&pvk, &p, &before, ni)?, "stale root accepted");
            let mut wrong = after.clone();
            wrong[5] += Fr::from(1);
            ensure!(!verify(&pvk, &p, &wrong, ni)?, "wrong action accepted");
            drop(wrong);
            let verification = t.finish();
            samples.push(json!({"index":index,"proof":resource,"verification_with_rejection_checks":verification}));
            if start.elapsed() >= Duration::from_secs(a.sample_seconds) {
                break;
            }
        }
        r["proof_diagnostics"][mode] = json!({"samples":samples,"loop_elapsed_ms":start.elapsed().as_secs_f64()*1000.,"sample_command":sample_wait(child,mode,a.sample_seconds),"timing_classification":"instrumented diagnostic repetitions, not a latency distribution"});
        flush(&a.output, r)?;
    }
    let mut target = Cache {
        domain: cache.domain,
        num_instance: cache.num_instance,
        r: cache.r,
        s: cache.s,
        q_a: Vec::new(),
        q_b: Vec::new(),
        a_g1: cache.a_g1,
        b_g1: cache.b_g1,
        b_g2: cache.b_g2,
        c_g1: cache.c_g1,
    };
    let done = Arc::new((Mutex::new(false), Condvar::new()));
    let sampler_done = done.clone();
    let out = a.output.clone();
    let sec = a.sample_seconds;
    let sampler = thread::spawn(move || {
        let mut reports = Vec::new();
        let sample_origin = Instant::now();
        for index in 0..15 {
            if index > 0 {
                let (g, c) = &*sampler_done;
                let v = g.lock().unwrap();
                let (v, _) = c
                    .wait_timeout_while(v, Duration::from_secs(50), |v| !*v)
                    .unwrap();
                if *v {
                    break;
                }
            }
            let label = format!("private-preparation-{index}");
            let started = sample_origin.elapsed().as_secs_f64();
            let mut report = sample_wait(sample_spawn(&out, &label, sec), &label, sec);
            report["window_started_since_sampler_start_seconds"] = json!(started);
            report["window_finished_since_sampler_start_seconds"] =
                json!(sample_origin.elapsed().as_secs_f64());
            reports.push(report);
        }
        reports
    });
    let t = Meter::start();
    Groth16::<Bn254>::process_dynark(&uk, &m, &before[..ni], &before[ni..], &mut target)?;
    let prep = t.finish();
    {
        let (g, c) = &*done;
        *g.lock().unwrap() = true;
        c.notify_all();
    }
    let samples = sampler
        .join()
        .map_err(|_| anyhow::anyhow!("sampler thread failed"))?;
    r["stages"]["private_preparation_once"] = prep;
    r["private_preparation_samples"] = json!(samples);
    r["last_completed_stage"] = json!("private_preparation_once");
    flush(&a.output, r)?;
    let t = Meter::start();
    ensure!(
        target.q_a == cache.q_a && target.q_b == cache.q_b,
        "private projection exact equality failed"
    );
    r["projection_equality"] = json!({"q_a_exact":true,"q_b_exact":true,"q_a_len":target.q_a.len(),"q_b_len":target.q_b.len(),"additional_retained_oracle":"original cache remains live; stage peak includes it"});
    let p = Groth16::<Bn254>::update_dynark(&uk, &m, &di, &dw, &target)?;
    ensure!(verify(&pvk, &p, &after, ni)?, "reprepared update rejected");
    drop(target);
    stage(&a.output, r, "projection_equality_replay_and_drop", t)?;
    let witness = a.output.join("witness-once.wtns");
    let stdout = file(&a.output.join("witness-stdout.log"))?;
    let stderr = file(&a.output.join("witness-time-stderr.log"))?;
    let t = Meter::start();
    let mut child = Command::new("/usr/bin/time")
        .args([
            "-l",
            "node",
            "node_modules/snarkjs/build/cli.cjs",
            "wtns",
            "calculate",
            "artifacts/circuit/credential_js/credential.wasm",
            "artifacts/dynark/witnesses/near-after-input.json",
        ])
        .arg(&witness)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()?;
    let pid = child.id();
    let start = Instant::now();
    let mut child_samples = Vec::new();
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        let rows = process_rows()?;
        let members = descendants(&rows, pid);
        let parent_rss = rows.iter().find(|v| v.0 == std::process::id()).map(|v| v.2);
        let owned_max = members.iter().map(|v| v.1).max().unwrap_or(0);
        ensure!(owned_max <= 1024 * 1024 * 1024, "witness child memory cap");
        child_samples.push(json!({"elapsed_ms":start.elapsed().as_secs_f64()*1000.,"parent_rss_bytes":parent_rss,"time_wrapper_rss_bytes":rows.iter().find(|v|v.0==pid).map(|v|v.2),"witness_descendants":members}));
        thread::sleep(Duration::from_millis(100));
    };
    let timing = t.finish();
    ensure!(status.success(), "witness child failed {status}");
    std::fs::set_permissions(&witness, std::fs::Permissions::from_mode(0o600))?;
    let time_text = std::fs::read_to_string(a.output.join("witness-time-stderr.log"))?;
    let maxrss = time_text
        .lines()
        .find(|l| l.contains("maximum resident set size"))
        .and_then(|l| l.split_whitespace().next()?.parse::<u64>().ok())
        .context("Darwin child maximum resident set size missing")?;
    ensure!(
        maxrss <= 1024 * 1024 * 1024,
        "witness direct maxRSS exceeds bound"
    );
    ensure!(
        hash(&witness)? == hash(Path::new("artifacts/dynark/witnesses/near-after.wtns"))?,
        "witness hash mismatch"
    );
    r["witness_child"] = json!({"exit_code":status.code(),"direct_max_rss_bytes":maxrss,"max_rss_units":"Darwin time -l bytes","samples":child_samples,"parent_stage":timing,"witness_hash_matches":true,"command":["/usr/bin/time","-l","node","node_modules/snarkjs/build/cli.cjs","wtns","calculate","artifacts/circuit/credential_js/credential.wasm","artifacts/dynark/witnesses/near-after-input.json",witness.to_str().unwrap()]});
    flush(&a.output, r)?;
    let t = Meter::start();
    let w = read_wtns(&witness)?;
    satisfied(&m, &w)?;
    let p = Groth16::<Bn254>::update_dynark(&uk, &m, &di, &dw, &cache)?;
    ensure!(
        verify(&pvk, &p, &w, ni)?,
        "regenerated witness proof rejected"
    );
    drop(w);
    stage(&a.output, r, "witness_import_validation_update_verify", t)?;
    let t = Meter::start();
    drop((uk, cache, m, before, after, ds, di, dw, pvk, vk, initial));
    stage(&a.output, r, "drop_owned_crypto_state", t)?;
    r["preservation_after"] = protected_identity()?;
    for key in [
        "updating_key",
        "cache",
        "ordinary_vk",
        "initial_proof",
        "before_public",
        "after_public",
    ] {
        let v = &e2["retained_artifacts"][key];
        ensure!(
            hash(&package.join(v["path"].as_str().context("artifact path")?))?
                == v["sha256"].as_str().context("artifact hash")?,
            "package changed during run {key}"
        );
    }
    let h = HEAP.snapshot();
    ensure!(
        h[1].checked_sub(h[2]) == Some(h[0]),
        "global allocator conservation failed after state drop"
    );
    r["allocator_final_conservation"] = json!({"passed":true,"requested_live_bytes":h[0],"cumulative_allocated_bytes":h[1],"cumulative_freed_bytes":h[2],"note":"remaining heap includes Rayon runtime, report/arguments and process support; not claimed zero"});
    r["correctness"] = json!({"anchor_accepted":true,"all_diagnostic_proofs_verified":true,"stale_root_rejected":true,"wrong_action_rejected":true,"reprepared_projection_vectors_exact":true,"reprepared_update_accepted":true,"regenerated_witness_exact_hash":true});
    Ok(())
}

fn main() -> Result<()> {
    let a = Args::parse();
    // This new group contains only this run and children it launches. The
    // watchdog starts in its own group, so it can kill the run even if ps fails.
    let isolated = unsafe {
        let pid = libc::getpid();
        (libc::getpgrp() == pid || libc::setpgid(0, 0) == 0) && libc::getpgrp() == pid
    };
    if !isolated {
        if let Some(pid) = a.watchdog_pid {
            unsafe {
                libc::kill(-(pid as i32), libc::SIGKILL);
            }
        }
        anyhow::bail!("cannot isolate diagnostic process group");
    }
    if let Some(pid) = a.watchdog_pid {
        let result = watchdog(&a, pid);
        if result.is_err() {
            unsafe {
                libc::kill(-(pid as i32), libc::SIGKILL);
            }
        }
        return result;
    }
    unsafe {
        libc::umask(0o077);
    }
    DirBuilder::new().mode(0o700).create(&a.output)?;
    let log = file(&a.output.join("watchdog-command.log"))?;
    let child = Command::new(std::env::current_exe()?)
        .arg("--watchdog-pid")
        .arg(std::process::id().to_string())
        .arg("--output")
        .arg(&a.output)
        .arg("--wall-limit-seconds")
        .arg(a.wall_limit_seconds.to_string())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .spawn()?;
    let _guard = Guard {
        child,
        done: a.output.join("run-ended"),
    };
    let start = Instant::now();
    let mut r = json!({"schema":1,"experiment":"E4","status":"running","pid":std::process::id(),"threads":a.threads,"argv":std::env::args().collect::<Vec<_>>(),"stages":{},"proof_diagnostics":{},"limits":{"wall_seconds":900,"parent_rss_bytes":4294967296_u64,"child_rss_bytes":1073741824_u64,"retained_bytes":536870912_u64},"limitations":["System GlobalAlloc tracks requested Rust heap bytes only; not allocator metadata/rounding/native memory/stacks or physical footprint","Instrumented diagnostic repetitions are not E2 latency samples","Private preparation retains original projections as an additional oracle; reported stage peak includes this baseline","Native sampled stack share is not exact per-kernel CPU or allocation attribution","No public updating-key generation/setup allocation profile; no fully dynamic reconstruction","Single witness run establishes diagnostic maxRSS only; no distribution or device qualification","Private/stack/raw witness files protected; only aggregates suitable for local report"]});
    flush(&a.output, &r)?;
    let result = run(&a, &mut r);
    if result.is_err() {
        if let Ok(rows) = process_rows() {
            for (pid, _) in descendants(&rows, std::process::id()).iter().rev() {
                if *pid != _guard.child.id() {
                    unsafe {
                        libc::kill(*pid as i32, libc::SIGKILL);
                    }
                }
            }
        }
    }
    r["total_wall_ms"] = json!(start.elapsed().as_secs_f64() * 1000.);
    r["status"] = json!(if result.is_ok() { "complete" } else { "failed" });
    if let Err(e) = &result {
        r["error"] = json!(format!("{e:#}"));
    }
    r["retained_bytes_before_final_write"] = json!(retained_bytes(&a.output).ok());
    let saved = flush(&a.output, &r);
    if result.is_err() || saved.is_err() {
        eprintln!("diagnostic failed; terminating owned run process group; result={result:?}; report={saved:?}");
        unsafe {
            libc::kill(-(std::process::id() as i32), libc::SIGKILL);
        }
    }
    saved?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn allocator_grow_shrink_zero_drop_balance() {
        assert_eq!(allocator_check().unwrap()["passed"], true);
    }
    #[test]
    fn descendant_walk_finds_time_node_but_not_peers() {
        let rows = vec![(10, 1, 20), (11, 10, 30), (12, 11, 40), (13, 1, 50)];
        assert_eq!(descendants(&rows, 10), vec![(11, 30), (12, 40)]);
    }
    #[test]
    fn census_distinguishes_touch_cancel_and_true_support() {
        let matrix = vec![
            vec![(Fr::from(1), 1), (Fr::from(1), 2)],
            vec![(Fr::from(2), 1)],
        ];
        let before = vec![Fr::from(1), Fr::from(3), Fr::from(5)];
        let after = vec![Fr::from(1), Fr::from(4), Fr::from(4)];
        let v = census_matrix(&matrix, &deltas(&before, &after), &before, &after).unwrap();
        assert_eq!(v["touched_matrix_entries"], 3);
        assert_eq!(v["distinct_touched_rows"], 2);
        assert_eq!(v["touched_rows_canceled_to_zero"], 1);
        assert_eq!(v["true_nonzero_row_changes"], 1);
    }
}
