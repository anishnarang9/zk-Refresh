//! Bounded public synthetic microbenchmarks. No package, key or witness input.
//! Build separately with --cfg t4_alloc_diag for diagnostic allocator hooks.
#![allow(unexpected_cfgs)]
#[path = "../cross.rs"]
#[allow(dead_code)]
mod cross;

use ark_bn254::{Fr, G1Projective as G1};
use ark_ec::PrimeGroup;
use ark_ff::{batch_inversion, AdditiveGroup, Field, PrimeField, Zero};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use cross::{CrossCoefficients, CrossLimits, CrossMethod};
#[cfg(t4_alloc_diag)]
use cross::{CrossPhase, CrossPhaseEvent};
use dynark_bn254::Error;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    hint::black_box,
    io::{BufReader, BufWriter, Read, Write},
    mem::size_of,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const LARGE_N: usize = 1 << 20;
const SEED: u64 = 0x54345f43524f5353;
const PAIR_CAP: usize = 250_000_000;
const CASE_PAIR_CAP: usize = 6_000_000;
const GROUP_CAP: usize = 750_000;
const PLANNED_PAIRS: usize = 248_980_606;
const TIMING_PAIRS: usize = 240_428_847;
const DIAGNOSTIC_PAIRS: usize = 8_551_759;
const PLANNED_GROUP_BOUND: usize = 657_438;
const BASIS_CALLS: usize = 20_094;
const LIMITS: CrossLimits = CrossLimits {
    max_domain: LARGE_N,
    max_input_entries: 4_800,
    max_union_support: 4_760,
    max_fft_size: 32_768,
    max_allocation_bytes: 320 * 1024 * 1024,
    max_pair_visits: CASE_PAIR_CAP,
};

#[cfg(t4_alloc_diag)]
mod allocations {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
    pub struct DiagnosticAllocator;
    static LIVE: AtomicUsize = AtomicUsize::new(0);
    static TRAFFIC: AtomicUsize = AtomicUsize::new(0);
    static FREED: AtomicUsize = AtomicUsize::new(0);
    static ALLOCS: AtomicUsize = AtomicUsize::new(0);
    static DEALLOCS: AtomicUsize = AtomicUsize::new(0);
    static REALLOCS: AtomicUsize = AtomicUsize::new(0);
    static LIFETIME_PEAK: AtomicUsize = AtomicUsize::new(0);
    static WHOLE_PEAK: AtomicUsize = AtomicUsize::new(0);
    static PHASE_PEAK: AtomicUsize = AtomicUsize::new(0);
    fn allocated(bytes: usize) {
        let live = LIVE.fetch_add(bytes, Relaxed) + bytes;
        TRAFFIC.fetch_add(bytes, Relaxed);
        LIFETIME_PEAK.fetch_max(live, Relaxed);
        WHOLE_PEAK.fetch_max(live, Relaxed);
        PHASE_PEAK.fetch_max(live, Relaxed);
    }
    fn freed(bytes: usize) {
        LIVE.fetch_sub(bytes, Relaxed);
        FREED.fetch_add(bytes, Relaxed);
    }
    unsafe impl GlobalAlloc for DiagnosticAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let p = System.alloc(layout);
            if !p.is_null() {
                ALLOCS.fetch_add(1, Relaxed);
                allocated(layout.size());
            }
            p
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            let p = System.alloc_zeroed(layout);
            if !p.is_null() {
                ALLOCS.fetch_add(1, Relaxed);
                allocated(layout.size());
            }
            p
        }
        unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
            System.dealloc(p, layout);
            DEALLOCS.fetch_add(1, Relaxed);
            freed(layout.size());
        }
        unsafe fn realloc(&self, p: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            let out = System.realloc(p, layout, new_size);
            if !out.is_null() {
                REALLOCS.fetch_add(1, Relaxed);
                freed(layout.size());
                allocated(new_size);
            }
            out
        }
    }
    #[derive(Clone, Copy, Default)]
    pub struct Snapshot {
        pub live: usize,
        pub traffic: usize,
        pub freed: usize,
        pub allocs: usize,
        pub deallocs: usize,
        pub reallocs: usize,
        pub whole_peak: usize,
        pub phase_peak: usize,
        pub lifetime_peak: usize,
    }
    pub fn snapshot() -> Snapshot {
        Snapshot {
            live: LIVE.load(Relaxed),
            traffic: TRAFFIC.load(Relaxed),
            freed: FREED.load(Relaxed),
            allocs: ALLOCS.load(Relaxed),
            deallocs: DEALLOCS.load(Relaxed),
            reallocs: REALLOCS.load(Relaxed),
            whole_peak: WHOLE_PEAK.load(Relaxed),
            phase_peak: PHASE_PEAK.load(Relaxed),
            lifetime_peak: LIFETIME_PEAK.load(Relaxed),
        }
    }
    pub fn reset_whole() {
        WHOLE_PEAK.store(LIVE.load(Relaxed), Relaxed);
    }
    pub fn reset_phase() {
        PHASE_PEAK.store(LIVE.load(Relaxed), Relaxed);
    }
}
#[cfg(t4_alloc_diag)]
#[global_allocator]
static ALLOCATOR: allocations::DiagnosticAllocator = allocations::DiagnosticAllocator;

#[derive(Default)]
struct Ledger {
    pairs: usize,
    groups: usize,
}
impl Ledger {
    fn pair(&mut self, a: usize, b: usize) -> Result<()> {
        let pairs = a.checked_mul(b).ok_or("pair overflow")?;
        let total = self.pairs.checked_add(pairs).ok_or("pair total overflow")?;
        if pairs > CASE_PAIR_CAP || total > PAIR_CAP {
            return Err("pair cap".into());
        }
        self.pairs = total;
        Ok(())
    }
    fn group(&mut self, calls: usize) -> Result<()> {
        let total = self
            .groups
            .checked_add(calls)
            .ok_or("group total overflow")?;
        if total > GROUP_CAP {
            return Err("group cap".into());
        }
        self.groups = total;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Shape {
    name: &'static str,
    n: usize,
    a: usize,
    b: usize,
    overlap: bool,
    measured: usize,
    warm: usize,
}
fn schedule() -> Vec<Shape> {
    let mut shapes = Vec::with_capacity(18);
    for (name, d) in [
        ("tiny0", 0),
        ("tiny1", 1),
        ("tiny2", 2),
        ("tiny4", 4),
        ("tiny8", 8),
        ("tiny16", 16),
        ("tiny32", 32),
        ("tiny64", 64),
        ("tiny128", 128),
    ] {
        shapes.push(Shape {
            name,
            n: 128,
            a: d,
            b: d,
            overlap: true,
            measured: 30,
            warm: 2,
        });
    }
    shapes.extend([
        Shape {
            name: "uneven128x1",
            n: 128,
            a: 128,
            b: 1,
            overlap: true,
            measured: 30,
            warm: 2,
        },
        Shape {
            name: "uneven1x128",
            n: 128,
            a: 1,
            b: 128,
            overlap: true,
            measured: 30,
            warm: 2,
        },
        Shape {
            name: "far",
            n: LARGE_N,
            a: 239,
            b: 237,
            overlap: false,
            measured: 30,
            warm: 2,
        },
        Shape {
            name: "middle",
            n: LARGE_N,
            a: 1195,
            b: 1185,
            overlap: false,
            measured: 30,
            warm: 2,
        },
        Shape {
            name: "near",
            n: LARGE_N,
            a: 2390,
            b: 2370,
            overlap: false,
            measured: 30,
            warm: 2,
        },
        Shape {
            name: "intermediate128",
            n: LARGE_N,
            a: 128,
            b: 128,
            overlap: true,
            measured: 2,
            warm: 0,
        },
        Shape {
            name: "intermediate256",
            n: LARGE_N,
            a: 256,
            b: 256,
            overlap: true,
            measured: 2,
            warm: 0,
        },
        Shape {
            name: "intermediate512",
            n: LARGE_N,
            a: 512,
            b: 512,
            overlap: true,
            measured: 2,
            warm: 0,
        },
        Shape {
            name: "intermediate1024",
            n: LARGE_N,
            a: 1024,
            b: 1024,
            overlap: true,
            measured: 2,
            warm: 0,
        },
    ]);
    shapes
}
fn verify_schedule() -> Result<()> {
    let (mut timing, mut diagnostic, mut group_bound, mut basis) = (0usize, 0usize, 0usize, 0usize);
    for s in schedule() {
        let pairs = s.a.checked_mul(s.b).ok_or("schedule overflow")?;
        if pairs > CASE_PAIR_CAP {
            return Err("schedule per-case cap".into());
        }
        let overlap = if s.overlap { s.a.min(s.b) } else { 0 };
        let union = s.a + s.b - overlap;
        if union > LIMITS.max_union_support || s.a + s.b > LIMITS.max_input_entries {
            return Err("schedule support cap".into());
        }
        timing += pairs * (s.measured + s.warm + 1);
        diagnostic += pairs;
        basis += 2 * union;
        // Each separate process constructs its own basis once.
        group_bound +=
            (s.a + s.b + overlap + union + overlap) * (s.measured + s.warm + 2) + 4 * union;
    }
    if (timing, diagnostic, timing + diagnostic, group_bound, basis)
        != (
            TIMING_PAIRS,
            DIAGNOSTIC_PAIRS,
            PLANNED_PAIRS,
            PLANNED_GROUP_BOUND,
            BASIS_CALLS,
        )
    {
        return Err("schedule constants disagree".into());
    }
    Ok(())
}
/// Public deterministic full-width SHA256-to-Fr reduction, not a production RNG
/// or uniform cryptographic sampler. A zero reduction is mapped to one so the
/// preregistered nonzero support counts remain exact. Basis scalars use this
/// same declared distribution, with distinct stream identifiers.
fn public_scalar(i: usize, stream: u64) -> Fr {
    let mut hash = Sha256::new();
    hash.update(b"DYNARK-T4-SYNTHETIC-V1");
    hash.update(SEED.to_le_bytes());
    hash.update(stream.to_le_bytes());
    hash.update((i as u64).to_le_bytes());
    let scalar = Fr::from_le_bytes_mod_order(&hash.finalize());
    if scalar.is_zero() {
        Fr::ONE
    } else {
        scalar
    }
}
struct Input {
    a: Vec<(usize, Fr)>,
    b: Vec<(usize, Fr)>,
    indices: Vec<usize>,
    a_slots: Vec<usize>,
    b_slots: Vec<usize>,
    overlap_slots: Vec<usize>,
}
fn input(shape: Shape) -> Input {
    let index = |k: usize| {
        if shape.n == 128 {
            k
        } else {
            (k * 65537 + 173) % shape.n
        }
    };
    let mut a = (0..shape.a)
        .map(|i| (index(i), public_scalar(i, 1)))
        .collect::<Vec<_>>();
    let mut b = (0..shape.b)
        .map(|i| {
            (
                index(if shape.overlap { i } else { i + shape.a }),
                public_scalar(i, 2),
            )
        })
        .collect::<Vec<_>>();
    a.sort_unstable_by_key(|x| x.0);
    b.sort_unstable_by_key(|x| x.0);
    let mut indices = a.iter().chain(&b).map(|x| x.0).collect::<Vec<_>>();
    indices.sort_unstable();
    indices.dedup();
    let a_slots = a
        .iter()
        .map(|x| indices.binary_search(&x.0).unwrap())
        .collect();
    let b_slots = b
        .iter()
        .map(|x| indices.binary_search(&x.0).unwrap())
        .collect();
    let overlap_slots = a
        .iter()
        .filter(|x| b.binary_search_by_key(&x.0, |y| y.0).is_ok())
        .map(|x| indices.binary_search(&x.0).unwrap())
        .collect();
    Input {
        a,
        b,
        indices,
        a_slots,
        b_slots,
        overlap_slots,
    }
}

struct AcceptedCoefficients {
    left: Vec<Fr>,
    right: Vec<Fr>,
    diagonal: Vec<Fr>,
}
/// The accepted normalized precomputed-weight loop, without candidate conversion.
/// Group arithmetic is separately measured; diagonal products are stored here.
fn accepted(weights: &[Fr], input: &Input) -> AcceptedCoefficients {
    let n = weights.len();
    let mut left = vec![Fr::ZERO; input.a.len()];
    let mut right = vec![Fr::ZERO; input.b.len()];
    let mut diagonal = Vec::with_capacity(input.overlap_slots.len());
    for (ai, (i, x)) in input.a.iter().enumerate() {
        for (bj, (j, y)) in input.b.iter().enumerate() {
            if i == j {
                diagonal.push(*x * *y);
            } else {
                left[ai] += *y * weights[(n + j - i) % n];
                right[bj] += *x * weights[(n + i - j) % n];
            }
        }
    }
    for ((_, x), c) in input.a.iter().zip(&mut left) {
        *c *= x;
    }
    for ((_, y), c) in input.b.iter().zip(&mut right) {
        *c *= y;
    }
    AcceptedCoefficients {
        left,
        right,
        diagonal,
    }
}
fn equal(input: &Input, old: &AcceptedCoefficients, fast: &CrossCoefficients) -> Result<()> {
    if fast.indices != input.indices || old.diagonal.len() != input.overlap_slots.len() {
        return Err("synthetic output shape mismatch".into());
    }
    let mut l = vec![Fr::ZERO; input.indices.len()];
    let mut d = vec![Fr::ZERO; input.indices.len()];
    for (slot, c) in input.a_slots.iter().zip(&old.left) {
        l[*slot] += c;
    }
    for (slot, c) in input.b_slots.iter().zip(&old.right) {
        l[*slot] += c;
    }
    for (slot, c) in input.overlap_slots.iter().zip(&old.diagonal) {
        d[*slot] = *c;
    }
    if fast.lagrange != l || fast.diagonal != d {
        return Err("synthetic coefficient mismatch".into());
    }
    if fast.stats.fft_max_size > cross::required_fft_size(input.indices.len())? {
        return Err("observed FFT exceeds preflight".into());
    }
    Ok(())
}
fn timed<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let start = Instant::now();
    let out = black_box(f());
    (out, start.elapsed())
}
fn ns(d: Duration) -> u128 {
    d.as_nanos()
}
fn field_pair(
    shape: Shape,
    input: &Input,
    weights: &[Fr],
    index: usize,
    kind: &str,
    ledger: &mut Ledger,
) -> Result<(AcceptedCoefficients, CrossCoefficients)> {
    ledger.pair(input.a.len(), input.b.len())?;
    let domain = GeneralEvaluationDomain::<Fr>::new(shape.n).ok_or("domain")?;
    let old = || accepted(black_box(weights), black_box(input));
    let fast = || {
        cross::cross_coefficients(
            black_box(&domain),
            black_box(weights),
            black_box(&input.a),
            black_box(&input.b),
            CrossMethod::Fast,
            LIMITS,
        )
    };
    let ((old, old_time), (fast, fast_time)) = if index % 2 == 0 {
        (timed(old), timed(fast))
    } else {
        let f = timed(fast);
        let q = timed(old);
        (q, f)
    };
    let fast = fast?;
    equal(input, &old, &fast)?;
    println!("{{\"event\":\"field_pair\",\"case\":\"{}\",\"kind\":\"{}\",\"sample\":{},\"order\":\"{}\",\"accepted_weighted_ns\":{},\"fast_whole_ns\":{},\"pairs\":{},\"equal\":true,\"fft_max\":{},\"fft_elements\":{},\"preflight_bytes\":{},\"accepted_returned_bytes\":{},\"fast_returned_bytes\":{}}}",
        shape.name,kind,index,if index%2==0 {"accepted_fast"} else {"fast_accepted"},
        ns(old_time),ns(fast_time),input.a.len()*input.b.len(),fast.stats.fft_max_size,
        fast.stats.fft_total_elements,fast.stats.preflight_allocation_bytes,
        (old.left.capacity()+old.right.capacity()+old.diagonal.capacity())*size_of::<Fr>(),
        fast.indices.capacity()*size_of::<usize>()+(fast.lagrange.capacity()+fast.diagonal.capacity())*size_of::<Fr>());
    Ok((old, fast))
}

struct Basis {
    l: Vec<G1>,
    d: Vec<G1>,
}
fn basis(input: &Input, ledger: &mut Ledger) -> Result<Basis> {
    ledger.group(2 * input.indices.len())?;
    let mut l = Vec::with_capacity(input.indices.len());
    let mut d = Vec::with_capacity(input.indices.len());
    for i in &input.indices {
        l.push(G1::generator() * public_scalar(*i, 3));
        d.push(G1::generator() * public_scalar(*i, 4));
    }
    Ok(Basis { l, d })
}
fn accepted_group(input: &Input, old: &AcceptedCoefficients, basis: &Basis) -> G1 {
    let mut out = G1::zero();
    for (slot, c) in input.overlap_slots.iter().zip(&old.diagonal) {
        out += basis.d[*slot] * *c;
    }
    for (slot, c) in input.a_slots.iter().zip(&old.left) {
        out += basis.l[*slot] * *c;
    }
    for (slot, c) in input.b_slots.iter().zip(&old.right) {
        out += basis.l[*slot] * *c;
    }
    out
}
fn grouped(fast: &CrossCoefficients, basis: &Basis) -> G1 {
    let mut out = G1::zero();
    for ((l, d), (lc, dc)) in basis
        .l
        .iter()
        .zip(&basis.d)
        .zip(fast.lagrange.iter().zip(&fast.diagonal))
    {
        if !lc.is_zero() {
            out += *l * *lc;
        }
        if !dc.is_zero() {
            out += *d * *dc;
        }
    }
    out
}
struct GroupMeasurement {
    output: G1,
    time: Duration,
    #[cfg(t4_alloc_diag)]
    before: allocations::Snapshot,
    #[cfg(t4_alloc_diag)]
    after: allocations::Snapshot,
}
fn measure_group(f: impl FnOnce() -> G1) -> GroupMeasurement {
    #[cfg(t4_alloc_diag)]
    allocations::reset_whole();
    #[cfg(t4_alloc_diag)]
    let before = allocations::snapshot();
    let (output, time) = timed(f);
    GroupMeasurement {
        output,
        time,
        #[cfg(t4_alloc_diag)]
        before,
        #[cfg(t4_alloc_diag)]
        after: allocations::snapshot(),
    }
}
fn group_pair(
    shape: Shape,
    input: &Input,
    old: &AcceptedCoefficients,
    fast: &CrossCoefficients,
    basis: &Basis,
    index: usize,
    kind: &str,
    ledger: &mut Ledger,
) -> Result<()> {
    let accepted_calls = input.a.len() + input.b.len() + old.diagonal.len();
    let grouped_calls = fast
        .lagrange
        .iter()
        .chain(&fast.diagonal)
        .filter(|c| !c.is_zero())
        .count();
    ledger.group(accepted_calls + grouped_calls)?;
    let q = || measure_group(|| accepted_group(black_box(input), black_box(old), black_box(basis)));
    let f = || measure_group(|| grouped(black_box(fast), black_box(basis)));
    let (q, f) = if index % 2 == 0 {
        (q(), f())
    } else {
        let f = f();
        let q = q();
        (q, f)
    };
    if q.output != f.output {
        return Err("synthetic group mismatch".into());
    }
    println!("{{\"event\":\"synthetic_group_pair\",\"case\":\"{}\",\"kind\":\"{}\",\"sample\":{},\"order\":\"{}\",\"accepted_separate_ns\":{},\"grouped_ns\":{},\"accepted_calls\":{},\"grouped_calls\":{},\"equal\":true,\"product_encoding\":false}}",
        shape.name,kind,index,if index%2==0 {"accepted_grouped"} else {"grouped_accepted"},ns(q.time),ns(f.time),accepted_calls,grouped_calls);
    #[cfg(t4_alloc_diag)]
    println!("{{\"event\":\"diagnostic_synthetic_group_allocation\",\"case\":\"{}\",\"accepted\":{},\"grouped\":{},\"product_encoding\":false}}",
        shape.name,allocation_json(q.before,q.after,false),allocation_json(f.before,f.after,false));
    Ok(())
}

fn hash_file(path: &Path) -> Result<String> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut hash = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(hash.finalize().iter().map(|b| format!("{b:02x}")).collect())
}
struct HashedReader<R> {
    reader: R,
    hash: Sha256,
    received: usize,
    remaining: usize,
}
impl<R: Read> Read for HashedReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let bounded = bytes.len().min(self.remaining);
        if bounded == 0 {
            return Ok(0);
        }
        let n = self.reader.read(&mut bytes[..bounded])?;
        self.hash.update(&bytes[..n]);
        self.received += n;
        self.remaining -= n;
        Ok(n)
    }
}
fn require_private_dir(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("table directory must be private and direct".into());
    }
    Ok(())
}
fn prepare(dir: &Path) -> Result<()> {
    if dir.exists() {
        return Err("prepare requires fresh directory".into());
    }
    fs::create_dir(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    require_private_dir(dir)?;
    for n in [128, LARGE_N] {
        let domain = GeneralEvaluationDomain::<Fr>::new(n).ok_or("domain")?;
        let start = Instant::now();
        let mut weights = vec![Fr::ZERO; n];
        let root = domain.group_gen();
        let mut power = root;
        for value in weights.iter_mut().skip(1) {
            *value = Fr::ONE - power;
            power *= root;
        }
        // The zero denominator at index zero remains zero. ark_ff's prod
        // temporary capacity is <=N fields; no N-element roots are retained.
        batch_inversion(&mut weights);
        let mut power = root;
        for value in weights.iter_mut().skip(1) {
            *value *= power * domain.size_inv();
            power *= root;
        }
        let construction = start.elapsed();
        let path = dir.join(format!("weights-{n}.fr"));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        let start = Instant::now();
        let mut writer = BufWriter::new(file);
        for value in &weights {
            value.serialize_compressed(&mut writer)?;
        }
        writer.flush()?;
        drop(writer);
        let storage_time = start.elapsed();
        let hash = hash_file(&path)?;
        println!("{{\"event\":\"public_table_prepared\",\"n\":{},\"construction_ns\":{},\"storage_ns\":{},\"retained_bytes\":{},\"live_structural_bytes\":{},\"sha256\":\"{}\",\"public\":true}}",
            n,ns(construction),ns(storage_time),n*size_of::<Fr>(),2*n*size_of::<Fr>(),hash);
    }
    Ok(())
}
fn load_table(dir: &Path, n: usize, expected: &str) -> Result<Vec<Fr>> {
    require_private_dir(dir)?;
    if expected.len() != 64 || !expected.bytes().all(|x| x.is_ascii_hexdigit()) {
        return Err("expected SHA256 format".into());
    }
    let path = dir.join(format!("weights-{n}.fr"));
    if fs::symlink_metadata(&path)?.file_type().is_symlink() {
        return Err("public table path symlink".into());
    }
    let file = File::open(&path)?;
    // All shape/mode checks and bytes below concern this one opened descriptor.
    let meta = file.metadata()?;
    let field_bytes = Fr::ZERO.compressed_size();
    let expected_bytes = n.checked_mul(field_bytes).ok_or("table size overflow")?;
    if !meta.is_file()
        || meta.permissions().mode() & 0o077 != 0
        || meta.uid() != fs::metadata(dir)?.uid()
        || meta.len() != expected_bytes as u64
    {
        return Err("public table file shape/mode".into());
    }
    let start = Instant::now();
    let read_bound = expected_bytes
        .checked_add(1)
        .ok_or("table EOF bound overflow")?;
    let mut reader = HashedReader {
        reader: BufReader::new(file.take(read_bound as u64)),
        hash: Sha256::new(),
        received: 0,
        remaining: read_bound,
    };
    let mut weights = Vec::with_capacity(n);
    for _ in 0..n {
        weights.push(Fr::deserialize_compressed(&mut reader)?);
    }
    let mut trailing = [0u8; 1];
    if reader.read(&mut trailing)? != 0 || reader.received != expected_bytes {
        return Err("public table exact vector/EOF".into());
    }
    let hash: String = reader
        .hash
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if hash != expected.to_ascii_lowercase() {
        return Err("public table SHA256 mismatch".into());
    }
    if !weights[0].is_zero() {
        return Err("public weight zero".into());
    }
    println!("{{\"event\":\"public_table_loaded\",\"n\":{},\"load_verify_ns\":{},\"retained_bytes\":{},\"sha256\":\"{}\"}}",n,ns(start.elapsed()),weights.capacity()*size_of::<Fr>(),hash);
    Ok(weights)
}

#[cfg(t4_alloc_diag)]
fn allocation_json(
    before: allocations::Snapshot,
    after: allocations::Snapshot,
    phase: bool,
) -> String {
    format!("{{\"start_live\":{},\"end_live\":{},\"peak_live\":{},\"peak_additional\":{},\"requested_bytes\":{},\"freed_bytes\":{},\"alloc_calls\":{},\"dealloc_calls\":{},\"realloc_calls\":{},\"lifetime_peak\":{}}}",
        before.live,after.live,if phase {after.phase_peak} else {after.whole_peak},
        (if phase {after.phase_peak} else {after.whole_peak}).saturating_sub(before.live),
        after.traffic-before.traffic,after.freed-before.freed,after.allocs-before.allocs,
        after.deallocs-before.deallocs,after.reallocs-before.reallocs,after.lifetime_peak)
}
#[cfg(t4_alloc_diag)]
struct PhaseRecord {
    phase: CrossPhase,
    time: Duration,
    before: allocations::Snapshot,
    after: allocations::Snapshot,
}
#[cfg(t4_alloc_diag)]
struct DiagnosticSummary {
    phase_count: usize,
    whole: Duration,
    phase_sum: Duration,
    residual: Duration,
}
#[cfg(t4_alloc_diag)]
fn diagnostic_pair(
    shape: Shape,
    input: &Input,
    weights: &[Fr],
    ledger: &mut Ledger,
) -> Result<(AcceptedCoefficients, CrossCoefficients, DiagnosticSummary)> {
    ledger.pair(input.a.len(), input.b.len())?;
    let domain = GeneralEvaluationDomain::<Fr>::new(shape.n).ok_or("domain")?;
    let mut records = Vec::<PhaseRecord>::with_capacity(16);
    let mut open = None;
    let mut observed = || -> Result<_> {
        allocations::reset_whole();
        let before = allocations::snapshot();
        let start = Instant::now();
        let out = cross::cross_coefficients_observed(
            &domain,
            weights,
            &input.a,
            &input.b,
            CrossMethod::Fast,
            LIMITS,
            |phase, event| match event {
                CrossPhaseEvent::Start => {
                    assert!(open.is_none(), "overlapping diagnostic phases");
                    allocations::reset_phase();
                    open = Some((phase, Instant::now(), allocations::snapshot()));
                }
                CrossPhaseEvent::End => {
                    let (started, time, before) =
                        open.take().expect("missing diagnostic phase start");
                    assert_eq!(started, phase);
                    let after = allocations::snapshot();
                    records.push(PhaseRecord {
                        phase,
                        time: time.elapsed(),
                        before,
                        after,
                    });
                }
            },
        )?;
        let whole = start.elapsed();
        let after = allocations::snapshot();
        if open.is_some() {
            return Err("unclosed diagnostic phase".into());
        }
        Ok((out, whole, before, after))
    };
    let old = || {
        allocations::reset_whole();
        let before = allocations::snapshot();
        let (out, time) = timed(|| accepted(weights, input));
        (out, time, before, allocations::snapshot())
    };
    // Alternate the one diagnostic pair by the schedule's public case position.
    let position = schedule()
        .iter()
        .position(|s| s.name == shape.name)
        .unwrap();
    let ((old, old_time, old_before, old_after), (fast, whole, before, after)) =
        if position % 2 == 0 {
            (old(), observed()?)
        } else {
            let f = observed()?;
            let q = old();
            (q, f)
        };
    equal(input, &old, &fast)?;
    let phases: Duration = records.iter().map(|r| r.time).sum();
    let residual = whole
        .checked_sub(phases)
        .ok_or("diagnostic phases exceed whole call")?;
    let summary = DiagnosticSummary {
        phase_count: records.len(),
        whole,
        phase_sum: phases,
        residual,
    };
    println!("{{\"event\":\"diagnostic_whole\",\"case\":\"{}\",\"order\":\"{}\",\"accepted_ns\":{},\"fast_observed_ns\":{},\"phase_sum_ns\":{},\"residual_ns\":{},\"accepted_allocation\":{},\"fast_allocation\":{},\"equal\":true}}",
        shape.name,if position%2==0 {"accepted_fast"} else {"fast_accepted"},ns(old_time),ns(whole),ns(phases),ns(residual),allocation_json(old_before,old_after,false),allocation_json(before,after,false));
    for record in records {
        println!("{{\"event\":\"diagnostic_phase\",\"case\":\"{}\",\"phase\":\"{:?}\",\"ns\":{},\"allocation\":{}}}",shape.name,record.phase,ns(record.time),allocation_json(record.before,record.after,true));
    }
    Ok((old, fast, summary))
}

fn run(dir: &Path, hash128: &str, hash_large: &str, diagnostic: bool) -> Result<()> {
    verify_schedule()?;
    let weights128 = load_table(dir, 128, hash128)?;
    let weights_large = load_table(dir, LARGE_N, hash_large)?;
    let mut ledger = Ledger::default();
    let wall = Instant::now();
    println!("{{\"event\":\"schedule\",\"seed\":{},\"scalar_distribution\":\"SHA256 little-endian reduction mod Fr; zero maps to one\",\"scalar_domain\":\"DYNARK-T4-SYNTHETIC-V1\",\"coefficient_streams\":[1,2],\"basis_streams\":[3,4],\"diagnostic\":{},\"planned_pairs\":{},\"invocation_expected_pairs\":{},\"group_cap\":{},\"synthetic\":true,\"credential_supports\":false,\"accepted_conversion_paid_ns\":0}}",
        SEED,diagnostic,PLANNED_PAIRS,if diagnostic {DIAGNOSTIC_PAIRS} else {TIMING_PAIRS},GROUP_CAP);
    for shape in schedule() {
        #[cfg(t4_alloc_diag)]
        allocations::reset_whole();
        #[cfg(t4_alloc_diag)]
        let input_before = allocations::snapshot();
        let start = Instant::now();
        let input = input(shape);
        let input_time = start.elapsed();
        #[cfg(t4_alloc_diag)]
        let input_after = allocations::snapshot();
        let input_bytes = (input.a.capacity() + input.b.capacity()) * size_of::<(usize, Fr)>()
            + (input.indices.capacity()
                + input.a_slots.capacity()
                + input.b_slots.capacity()
                + input.overlap_slots.capacity())
                * size_of::<usize>();
        let weights = if shape.n == 128 {
            &weights128
        } else {
            &weights_large
        };
        println!("{{\"event\":\"public_input\",\"case\":\"{}\",\"n\":{},\"a\":{},\"b\":{},\"union\":{},\"overlap\":{},\"input_preparation_ns\":{},\"retained_bytes\":{}}}",shape.name,shape.n,input.a.len(),input.b.len(),input.indices.len(),input.overlap_slots.len(),ns(input_time),input_bytes);
        #[cfg(t4_alloc_diag)]
        println!(
            "{{\"event\":\"diagnostic_input_allocation\",\"case\":\"{}\",\"allocation\":{}}}",
            shape.name,
            allocation_json(input_before, input_after, false)
        );
        let (old, fast) = if diagnostic {
            #[cfg(t4_alloc_diag)]
            {
                let (old, fast, summary) = diagnostic_pair(shape, &input, weights, &mut ledger)?;
                if summary.phase_count < 5 || summary.whole != summary.phase_sum + summary.residual
                {
                    return Err("diagnostic summary mismatch".into());
                }
                (old, fast)
            }
            #[cfg(not(t4_alloc_diag))]
            {
                return Err("diagnostic requires separate allocator build".into());
            }
        } else {
            field_pair(shape, &input, weights, 0, "equality", &mut ledger)?
        };
        #[cfg(t4_alloc_diag)]
        allocations::reset_whole();
        #[cfg(t4_alloc_diag)]
        let basis_before = allocations::snapshot();
        let start = Instant::now();
        let basis = basis(&input, &mut ledger)?;
        let basis_time = start.elapsed();
        #[cfg(t4_alloc_diag)]
        let basis_after = allocations::snapshot();
        let group_bytes = (basis.l.capacity() + basis.d.capacity()) * size_of::<G1>();
        if group_bytes > 32 * 1024 * 1024 {
            return Err("synthetic basis retained cap".into());
        }
        println!("{{\"event\":\"synthetic_basis\",\"case\":\"{}\",\"construction_ns\":{},\"construction_calls\":{},\"retained_bytes\":{},\"product_material\":false}}",shape.name,ns(basis_time),2*input.indices.len(),group_bytes);
        #[cfg(t4_alloc_diag)]
        println!(
            "{{\"event\":\"diagnostic_basis_allocation\",\"case\":\"{}\",\"allocation\":{}}}",
            shape.name,
            allocation_json(basis_before, basis_after, false)
        );
        let group_index = if diagnostic {
            schedule()
                .iter()
                .position(|s| s.name == shape.name)
                .unwrap()
        } else {
            0
        };
        group_pair(
            shape,
            &input,
            &old,
            &fast,
            &basis,
            group_index,
            if diagnostic { "diagnostic" } else { "equality" },
            &mut ledger,
        )?;
        if !diagnostic {
            for index in 0..shape.warm {
                let _ = field_pair(shape, &input, weights, index, "warmup", &mut ledger)?;
                group_pair(
                    shape,
                    &input,
                    &old,
                    &fast,
                    &basis,
                    index,
                    "warmup",
                    &mut ledger,
                )?;
            }
            for index in 0..shape.measured {
                let _ = field_pair(shape, &input, weights, index, "measured", &mut ledger)?;
                group_pair(
                    shape,
                    &input,
                    &old,
                    &fast,
                    &basis,
                    index,
                    "measured",
                    &mut ledger,
                )?;
            }
        }
    }
    let expected = if diagnostic {
        DIAGNOSTIC_PAIRS
    } else {
        TIMING_PAIRS
    };
    if ledger.pairs != expected {
        return Err("completed pair ledger mismatch".into());
    }
    println!("{{\"event\":\"complete\",\"pairs\":{},\"group_calls\":{},\"case_wall_ns\":{},\"planned_inclusive_pairs\":{},\"allocation_instrumented\":{}}}",ledger.pairs,ledger.groups,ns(wall.elapsed()),PLANNED_PAIRS,cfg!(t4_alloc_diag));
    Ok(())
}
fn main() -> Result<()> {
    verify_schedule()?;
    let args = std::env::args().collect::<Vec<_>>();
    match args.get(1).map(String::as_str) {
        Some("prepare") if args.len()==3 && !cfg!(t4_alloc_diag)=>prepare(Path::new(&args[2])),
        Some("timing") if args.len()==5 && !cfg!(t4_alloc_diag)=>run(Path::new(&args[2]),&args[3],&args[4],false),
        Some("diagnostic") if args.len()==5 && cfg!(t4_alloc_diag)=>run(Path::new(&args[2]),&args[3],&args[4],true),
        _=>Err("usage: uninstrumented prepare NEW_PRIVATE_DIR | uninstrumented timing TABLE_DIR SHA128 SHA1048576 | allocator diagnostic TABLE_DIR SHA128 SHA1048576".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_schedule_and_preflight_ledgers() {
        verify_schedule().unwrap();
        let mut ledger = Ledger::default();
        assert!(ledger.pair(CASE_PAIR_CAP + 1, 1).is_err());
        assert_eq!(ledger.pairs, 0);
        ledger.pairs = PAIR_CAP;
        assert!(ledger.pair(1, 1).is_err());
        assert_eq!(ledger.pairs, PAIR_CAP);
        assert!(ledger.group(GROUP_CAP + 1).is_err());
        assert_eq!(ledger.groups, 0);
    }
    #[test]
    fn bounded_reader_hashes_exact_received_bytes() {
        let data = [0x41u8; 32];
        let mut reader = HashedReader {
            reader: std::io::Cursor::new(data),
            hash: Sha256::new(),
            received: 0,
            remaining: 17,
        };
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, &data[..17]);
        assert_eq!(reader.received, 17);
        assert_eq!(reader.remaining, 0);
        assert_eq!(reader.hash.finalize(), Sha256::digest(&data[..17]));
    }
    #[test]
    fn public_schedule_inputs_preserve_exact_nonzero_shapes() {
        for shape in schedule() {
            let data = input(shape);
            assert_eq!(data.a.len(), shape.a);
            assert_eq!(data.b.len(), shape.b);
            let overlap = if shape.overlap {
                shape.a.min(shape.b)
            } else {
                0
            };
            assert_eq!(data.overlap_slots.len(), overlap);
            assert_eq!(data.indices.len(), shape.a + shape.b - overlap);
            for rows in [&data.a, &data.b] {
                assert!(rows.iter().all(|(i, x)| *i < shape.n && !x.is_zero()));
                assert!(rows.windows(2).all(|x| x[0].0 < x[1].0));
            }
        }
        assert!(public_scalar(0, 1).into_bigint().0[1..]
            .iter()
            .any(|x| *x != 0));
        assert_ne!(public_scalar(0, 1), public_scalar(0, 2));
    }
    #[cfg(t4_alloc_diag)]
    #[test]
    fn tiny_diagnostic_recorder_completes_without_overlapping_phases() {
        let shape = schedule().into_iter().find(|s| s.name == "tiny1").unwrap();
        let data = input(shape);
        let domain = GeneralEvaluationDomain::<Fr>::new(shape.n).unwrap();
        let weights = (0..shape.n)
            .map(|i| {
                if i == 0 {
                    Fr::ZERO
                } else {
                    let x = domain.element(i);
                    x * domain.size_inv() / (Fr::ONE - x)
                }
            })
            .collect::<Vec<_>>();
        let mut ledger = Ledger::default();
        let (old, fast, summary) = diagnostic_pair(shape, &data, &weights, &mut ledger).unwrap();
        equal(&data, &old, &fast).unwrap();
        let ordinary = cross::cross_coefficients(
            &domain,
            &weights,
            &data.a,
            &data.b,
            CrossMethod::Fast,
            LIMITS,
        )
        .unwrap();
        assert_eq!(ordinary.indices, fast.indices);
        assert_eq!(ordinary.lagrange, fast.lagrange);
        assert_eq!(ordinary.diagonal, fast.diagonal);
        assert_eq!(ordinary.stats, fast.stats);
        assert_eq!(ledger.pairs, 1);
        assert_eq!(summary.phase_count, 5);
        assert_eq!(summary.whole, summary.phase_sum + summary.residual);
        assert!(summary.whole >= summary.phase_sum);
    }
    #[test]
    fn accepted_separate_and_grouped_public_outputs_match() {
        let shape = Shape {
            name: "test",
            n: 8,
            a: 5,
            b: 3,
            overlap: true,
            measured: 0,
            warm: 0,
        };
        // Explicit normalized sorted supports; the public large-domain mapping
        // is not used for this small independent comparator test.
        let input = Input {
            a: vec![
                (0, Fr::from(2u64)),
                (1, Fr::from(3u64)),
                (2, Fr::from(4u64)),
                (3, Fr::from(5u64)),
                (4, Fr::from(6u64)),
            ],
            b: vec![
                (0, Fr::from(7u64)),
                (1, Fr::from(8u64)),
                (2, Fr::from(9u64)),
            ],
            indices: vec![0, 1, 2, 3, 4],
            a_slots: vec![0, 1, 2, 3, 4],
            b_slots: vec![0, 1, 2],
            overlap_slots: vec![0, 1, 2],
        };
        let domain = GeneralEvaluationDomain::<Fr>::new(shape.n).unwrap();
        let weights = (0..shape.n)
            .map(|i| {
                if i == 0 {
                    Fr::ZERO
                } else {
                    let x = domain.element(i);
                    x * domain.size_inv() / (Fr::ONE - x)
                }
            })
            .collect::<Vec<_>>();
        let old = accepted(&weights, &input);
        let fast = cross::cross_coefficients(
            &domain,
            &weights,
            &input.a,
            &input.b,
            CrossMethod::Fast,
            LIMITS,
        )
        .unwrap();
        equal(&input, &old, &fast).unwrap();
        let mut ledger = Ledger::default();
        let basis = basis(&input, &mut ledger).unwrap();
        assert_eq!(accepted_group(&input, &old, &basis), grouped(&fast, &basis));
        assert_eq!(ledger.groups, 10);
    }
}
