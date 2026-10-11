//! Standalone public-synthetic GLV reuse experiment; never a product backend.
//! Build diagnostics with --cfg glv_alloc in a separate target directory.
#![allow(unexpected_cfgs)]
use ark_bn254::{g1::Config, Fq, Fr, G1Projective};
use ark_ec::{scalar_mul::glv::GLVConfig, AdditiveGroup, CurveGroup, PrimeGroup};
use ark_ff::{BitIteratorBE, FftField, Field, PrimeField, Zero};
use std::{hint::black_box, mem::size_of, time::Instant};

type Decomposition = ((bool, Fr), (bool, Fr));

// Deliberately identical to ark-ec 0.5.0 glv_mul_projective after decomposition.
// Do not optimize or fix the pinned bit traversal in this ablation.
fn cached_mul(p: G1Projective, decomposition: Decomposition) -> G1Projective {
    let ((sgn_k1, k1), (sgn_k2, k2)) = decomposition;
    let mut b1 = p;
    let mut b2 = Config::endomorphism(&p);
    if !sgn_k1 {
        b1 = -b1;
    }
    if !sgn_k2 {
        b2 = -b2;
    }
    let b1b2 = b1 + b2;
    let iter_k1 = BitIteratorBE::new(k1.into_bigint());
    let iter_k2 = BitIteratorBE::new(k2.into_bigint());
    let mut res = G1Projective::zero();
    let mut skip_zeros = true;
    for pair in iter_k1.zip(iter_k2) {
        if skip_zeros && pair == (false, false) {
            skip_zeros = false;
            continue;
        }
        res.double_in_place();
        match pair {
            (true, false) => res += b1,
            (false, true) => res += b2,
            (true, true) => res += b1b2,
            (false, false) => {}
        }
    }
    res
}

fn public_scalars(n: usize) -> Vec<Fr> {
    let root = Fr::get_root_of_unity(n as u64).expect("supported domain");
    let mut out = Vec::with_capacity(2 * n + 1);
    for direction in [root, root.inverse().unwrap()] {
        let mut value = Fr::ONE;
        for _ in 0..n {
            out.push(value);
            value *= direction;
        }
    }
    out.push(Fr::from(n as u64).inverse().unwrap());
    out
}

fn table(scalars: &[Fr]) -> Vec<Decomposition> {
    scalars
        .iter()
        .map(|s| Config::scalar_decomposition(*s))
        .collect()
}

fn fixture(count: usize) -> Vec<G1Projective> {
    // Deterministic public pseudorandom-looking subgroup multiples; not secrets.
    let mut state = 0x51a7_ee12_badc_0ffe_u64;
    (0..count)
        .map(|i| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let p = G1Projective::generator() * Fr::from(state);
            if i % 4 == 0 {
                G1Projective::zero()
            } else if i % 4 == 1 {
                G1Projective::generator()
            } else if i % 4 == 2 {
                p
            } else {
                rescale(p, Fq::from(i as u64 + 2))
            }
        })
        .collect()
}

fn rescale(p: G1Projective, z: Fq) -> G1Projective {
    let z2 = z.square();
    G1Projective::new_unchecked(p.x * z2, p.y * z2 * z, p.z * z)
}

fn selected_indices(n: usize) -> Vec<usize> {
    // Exercise both directions, normalization and 1/-1 across the domain.
    let count = n.min(32);
    let mut out = Vec::with_capacity(2 * count + 1);
    for i in 0..count {
        out.push(i * n / count);
        out.push(n + i * n / count);
    }
    out.push(2 * n);
    out
}

fn work(
    points: &[G1Projective],
    scalars: &[Fr],
    indices: &[usize],
    cached: Option<&[Decomposition]>,
    repeats: usize,
) -> G1Projective {
    let mut sum = G1Projective::zero();
    for _ in 0..repeats {
        for (p, &j) in points.iter().zip(indices) {
            sum += match cached {
                Some(entries) => cached_mul(black_box(*p), black_box(entries[j])),
                None => black_box(*p) * black_box(scalars[j]),
            };
        }
    }
    black_box(sum)
}

#[cfg(glv_alloc)]
mod allocations {
    use std::{
        alloc::{GlobalAlloc, Layout, System},
        sync::atomic::{AtomicU64, Ordering::Relaxed},
    };
    static LIVE: AtomicU64 = AtomicU64::new(0);
    static PEAK: AtomicU64 = AtomicU64::new(0);
    static TRAFFIC: AtomicU64 = AtomicU64::new(0);
    static CALLS: AtomicU64 = AtomicU64::new(0);
    fn allocated(bytes: usize) {
        CALLS.fetch_add(1, Relaxed);
        TRAFFIC.fetch_add(bytes as u64, Relaxed);
        let live = LIVE.fetch_add(bytes as u64, Relaxed) + bytes as u64;
        PEAK.fetch_max(live, Relaxed);
    }
    pub struct Tracker;
    unsafe impl GlobalAlloc for Tracker {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            let p = System.alloc(l);
            if !p.is_null() {
                allocated(l.size());
            }
            p
        }
        unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
            let p = System.alloc_zeroed(l);
            if !p.is_null() {
                allocated(l.size());
            }
            p
        }
        unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
            System.dealloc(p, l);
            LIVE.fetch_sub(l.size() as u64, Relaxed);
        }
        unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
            let q = System.realloc(p, l, n);
            if !q.is_null() {
                LIVE.fetch_sub(l.size() as u64, Relaxed);
                allocated(n);
            }
            q
        }
    }
    pub fn begin() -> (u64, u64, u64) {
        let live = LIVE.load(Relaxed);
        PEAK.store(live, Relaxed);
        (live, TRAFFIC.load(Relaxed), CALLS.load(Relaxed))
    }
    pub fn end(start: (u64, u64, u64)) -> (i128, u64, u64, u64, u64) {
        let live = LIVE.load(Relaxed);
        (
            live as i128 - start.0 as i128,
            PEAK.load(Relaxed).saturating_sub(start.0),
            TRAFFIC.load(Relaxed) - start.1,
            CALLS.load(Relaxed) - start.2,
            live,
        )
    }
}
#[cfg(glv_alloc)]
#[global_allocator]
static ALLOCATOR: allocations::Tracker = allocations::Tracker;

// POSIX clock() is process CPU; this standalone runner supports macOS/Linux
// where CLOCKS_PER_SEC is 1,000,000. Wall and sampled tree RSS come separately.
#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe extern "C" {
    fn clock() -> std::ffi::c_long;
}
fn cpu() -> i64 {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        unsafe { clock() as i64 }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        -1
    }
}

fn timed<T>(f: impl FnOnce() -> T) -> (T, u128, i64) {
    let cpu_start = cpu();
    let wall = Instant::now();
    let value = f();
    let ns = wall.elapsed().as_nanos();
    (value, ns, cpu() - cpu_start)
}

#[cfg(glv_alloc)]
fn diagnostic(scalars: &[Fr], points: &[G1Projective], indices: &[usize]) {
    let begin = allocations::begin();
    let entries = table(scalars);
    let a = allocations::end(begin);
    println!("{{\"kind\":\"allocation\",\"path\":\"construction\",\"live_delta\":{},\"peak_delta\":{},\"traffic\":{},\"calls\":{},\"live_absolute\":{}}}",a.0,a.1,a.2,a.3,a.4);
    for repeat in [1, 4] {
        for cached in [false, true] {
            let begin = allocations::begin();
            black_box(work(
                points,
                scalars,
                indices,
                cached.then_some(entries.as_slice()),
                repeat,
            ));
            let a = allocations::end(begin);
            println!("{{\"kind\":\"allocation\",\"path\":\"{}\",\"repeat\":{},\"live_delta\":{},\"peak_delta\":{},\"traffic\":{},\"calls\":{},\"live_absolute\":{}}}",if cached {"cached"} else {"pinned"},repeat,a.0,a.1,a.2,a.3,a.4);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("timing");
    let n: usize = args
        .get(2)
        .map(|s| s.parse().expect("N integer"))
        .unwrap_or(256);
    assert!(
        (1..=4096).contains(&n) && n.is_power_of_two(),
        "finite supported N"
    );
    assert!(mode == "timing" || mode == "diagnostic");
    assert_eq!(
        mode == "diagnostic",
        cfg!(glv_alloc),
        "diagnostic and timing require separate builds"
    );
    let indices = selected_indices(n);
    let batches = 30usize;
    let warmups = 2usize;
    let logical_multiplies = indices.len()
        + if mode == "timing" {
            (batches + warmups) * 2 * (1 + 4) * indices.len()
        } else {
            2 * (1 + 4) * indices.len()
        };
    assert!(
        logical_multiplies <= 100_000,
        "measured plus warmup work cap"
    );
    let scalars = public_scalars(n);
    let points = fixture(indices.len());
    println!("{{\"kind\":\"conditions\",\"mode\":\"{}\",\"n\":{},\"batches\":{},\"excluded_warmup_batches\":{},\"multipliers_per_repeat\":{},\"logical_multiplies_including_warmup\":{},\"table_entries\":{},\"entry_size\":{},\"table_structural_bytes\":{},\"scalar_fixture_bytes\":{},\"point_fixture_bytes\":{},\"cpu_ticks_per_second\":1000000,\"allocator_instrumented\":{},\"fixture_seed\":\"51a7ee12badc0ffe\",\"cache_identity\":\"BN254/ark-bn254=0.5.0/ark-ec=0.5.0/Fr-root-of-unity/powers-forward-inverse-plus-N-inverse/v1\"}}",mode,n,batches,warmups,indices.len(),logical_multiplies,scalars.len(),size_of::<Decomposition>(),scalars.len()*size_of::<Decomposition>(),scalars.len()*size_of::<Fr>(),points.len()*size_of::<G1Projective>(),cfg!(glv_alloc));
    #[cfg(glv_alloc)]
    {
        diagnostic(&scalars, &points, &indices);
    }
    #[cfg(not(glv_alloc))]
    {
        for batch in 0..(batches + warmups) {
            let (entries, construct_ns, construct_cpu) = timed(|| table(black_box(&scalars)));
            let retained_since = Instant::now();
            let retained_bytes = entries.capacity() * size_of::<Decomposition>();
            for repeat in [1, 4] {
                let order = if (batch + repeat) % 2 == 0 {
                    [false, true]
                } else {
                    [true, false]
                };
                let mut outputs = Vec::with_capacity(2);
                for cached in order {
                    let (out, wall_ns, cpu_ticks) = timed(|| {
                        work(
                            &points,
                            &scalars,
                            &indices,
                            cached.then_some(entries.as_slice()),
                            repeat,
                        )
                    });
                    outputs.push(out);
                    if batch >= warmups {
                        println!("{{\"kind\":\"sample\",\"batch\":{},\"repeat\":{},\"order\":\"{}\",\"path\":\"{}\",\"construction_wall_ns\":{},\"construction_cpu_ticks\":{},\"multiply_wall_ns\":{},\"multiply_cpu_ticks\":{},\"paid_total_wall_ns\":{},\"paid_total_cpu_ticks\":{}}}",batch-warmups,repeat,if order[0] {"cached-first"} else {"pinned-first"},if cached {"cached"} else {"pinned"},construct_ns,construct_cpu,wall_ns,cpu_ticks,wall_ns+if cached {construct_ns} else {0},cpu_ticks+if cached {construct_cpu} else {0});
                    }
                }
                assert_eq!(outputs[0], outputs[1], "same exact synthetic aggregate");
            }
            let retained_ns = retained_since.elapsed().as_nanos();
            let (_, drop_ns, drop_cpu) = timed(|| drop(entries));
            if batch >= warmups {
                println!("{{\"kind\":\"lifecycle\",\"batch\":{},\"retained_requested_structural_bytes\":{},\"vec_metadata_bytes\":{},\"resident_table_wall_ns\":{},\"resident_table_byte_nanoseconds\":{},\"drop_wall_ns\":{},\"drop_cpu_ticks\":{}}}",batch-warmups,retained_bytes,size_of::<Vec<Decomposition>>(),retained_ns,retained_ns*retained_bytes as u128,drop_ns,drop_cpu);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn signed((positive, value): (bool, Fr)) -> Fr {
        if positive {
            value
        } else {
            -value
        }
    }
    fn check(p: G1Projective, s: Fr) {
        let d = Config::scalar_decomposition(s);
        assert_eq!(signed(d.0) + Config::LAMBDA * signed(d.1), s);
        let expected = p * s;
        let actual = cached_mul(p, d);
        assert_eq!(actual, expected);
        assert_eq!(actual.into_affine(), expected.into_affine());
    }
    #[test]
    fn boundary_and_exceptional_points() {
        let points = fixture(16);
        let scalars = [Fr::ZERO, Fr::ONE, -Fr::ONE, -Fr::from(2u64), Fr::from(2u64)];
        for p in points {
            for s in scalars {
                check(p, s);
            }
        }
        let p = G1Projective::generator() * Fr::from(123456789u64);
        assert_eq!(rescale(p, Fq::from(7u64)), p);
        assert_eq!(Config::endomorphism(&p), p * Config::LAMBDA);
    }
    #[test]
    fn all_forward_inverse_twiddles_and_normalizers() {
        // Independent generator oracle for every table entry, plus fixture
        // equality on exceptional/rescaled points; <75k group multiplies.
        let domains = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096];
        let budget: usize = domains
            .iter()
            .map(|n| 2 * (2 * n + 1) + 5 * selected_indices(*n).len())
            .sum();
        assert!(budget < 75_000);
        for n in domains {
            let scalars = public_scalars(n);
            let entries = table(&scalars);
            for (s, d) in scalars.iter().zip(&entries) {
                assert_eq!(*d, Config::scalar_decomposition(*s));
                check(G1Projective::generator(), *s);
            }
            let indices = selected_indices(n);
            let points = fixture(indices.len());
            assert_eq!(
                work(&points, &scalars, &indices, None, 1),
                work(&points, &scalars, &indices, Some(&entries), 1)
            );
            for (p, j) in points.iter().zip(indices) {
                check(*p, scalars[j]);
            }
        }
    }
    #[test]
    fn randomized_public_scalars_and_projective_rescaling() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x51a7);
        use rand::RngCore;
        use rand::SeedableRng;
        for _ in 0..128 {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            let s = Fr::from_le_bytes_mod_order(&bytes);
            let p = G1Projective::generator() * Fr::from(rng.next_u64());
            check(p, s);
            check(rescale(p, Fq::from(rng.next_u64() | 1)), s);
        }
    }
}
