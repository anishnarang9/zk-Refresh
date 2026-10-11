use super::*;
use ark_bn254::Fq;
use ark_ec::PrimeGroup;
use ark_ff::{Field, PrimeField, UniformRand, Zero};
use ark_poly::GeneralEvaluationDomain;
use ark_serialize::CanonicalSerialize;
use rand::SeedableRng;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

const DOMAINS: [usize; 3] = [1024, 4096, 16384];
const CHUNKS: [usize; 4] = [1, 64, 1024, 8192];
const SEED: u64 = 0x5032453562;
const GROUP_CAP: u64 = 3_000_000;

#[derive(Default)]
struct Budget {
    total: u64,
    explicit: u64,
    fft_declared: u64,
    reconstruction_observed: u64,
    field_fft_butterflies: u64,
    field_fft_normalizations: u64,
    fft_root_multiplications: u64,
    fft_root_squarings: u64,
}
impl Budget {
    fn room(&self, count: u64) {
        assert!(self.total.checked_add(count).unwrap() <= GROUP_CAP);
    }
    fn charge(&mut self, count: u64) {
        self.room(count);
        self.total = self.total.checked_add(count).unwrap();
    }
    fn mul(&mut self, point: G1, scalar: Fr) -> G1 {
        self.charge(1);
        self.explicit += 1;
        point * scalar
    }
    fn roots(&mut self, n: usize) {
        // Pinned ark-poly parallel roots_of_unity: one split, both leaves <=7.
        let bits = n.ilog2() as u64 - 1;
        assert!((8..=13).contains(&bits));
        let lo = (bits + 1) / 2;
        let hi = bits - lo;
        self.fft_root_multiplications += (1 << bits) + (1 << lo) + (1 << hi) - 2;
        self.fft_root_squarings += bits;
    }
    fn group_fft(
        &mut self,
        domain: &GeneralEvaluationDomain<Fr>,
        data: &mut Vec<G1>,
        inverse: bool,
    ) {
        let n = domain.size();
        assert_eq!(data.len(), n);
        let count = (n * n.ilog2() as usize / 2 + if inverse { n } else { 0 }) as u64;
        // Full-width pinned arkworks FFT butterflies and inverse normalization.
        self.charge(count);
        self.fft_declared += count;
        self.roots(n);
        if inverse {
            domain.ifft_in_place(data);
        } else {
            domain.fft_in_place(data);
        }
    }
    fn field_fft(
        &mut self,
        domain: &GeneralEvaluationDomain<Fr>,
        data: &mut Vec<Fr>,
        inverse: bool,
    ) {
        let n = domain.size();
        assert_eq!(data.len(), n);
        self.field_fft_butterflies += (n * n.ilog2() as usize / 2) as u64;
        self.field_fft_normalizations += if inverse { n as u64 } else { 0 };
        self.roots(n);
        if inverse {
            domain.ifft_in_place(data);
        } else {
            domain.fft_in_place(data);
        }
    }
    fn observed(&mut self, count: u64) {
        assert!(count <= 4);
        self.charge(count);
        self.reconstruction_observed += count;
    }
}

struct Physical {
    groups: Vec<[Fq; 3]>,
    fields: Vec<Fr>,
}
impl Physical {
    fn capture(pool: &Pool) -> Self {
        let mut groups = reserved(4 * pool.n).unwrap();
        let mut fields = reserved(6 * pool.n).unwrap();
        for slot in &pool.g {
            groups.extend(slot.iter().map(|g| [g.x, g.y, g.z]));
        }
        for slot in &pool.f {
            fields.extend_from_slice(slot);
        }
        Self { groups, fields }
    }
    fn matches(&self, pool: &Pool) -> bool {
        pool.g
            .iter()
            .flatten()
            .zip(&self.groups)
            .all(|(g, p)| [g.x, g.y, g.z] == *p)
            && pool
                .f
                .iter()
                .flatten()
                .zip(&self.fields)
                .all(|(a, b)| a == b)
            && self.groups.len() == 4 * pool.n
            && self.fields.len() == 6 * pool.n
    }
    fn bytes(&self) -> usize {
        self.groups.capacity() * size_of::<[Fq; 3]>() + self.fields.capacity() * size_of::<Fr>()
    }
}

fn elapsed_stage(n: usize, name: &str, started: Instant) -> Duration {
    let elapsed = started.elapsed();
    println!(
        "T5_PILOT {{\"record\":\"stage\",\"n\":{n},\"name\":\"{name}\",\"wall_seconds\":{:.9}}}",
        elapsed.as_secs_f64()
    );
    elapsed
}
fn random_fields(n: usize, rng: &mut rand::rngs::StdRng, draws: &mut usize) -> Vec<Fr> {
    let mut values = reserved(n).unwrap();
    while values.len() < n {
        *draws += 1;
        let x = Fr::rand(rng);
        if !x.is_zero() {
            values.push(x);
        }
    }
    assert!(values
        .iter()
        .all(|x| x.into_bigint().as_ref()[1..].iter().any(|word| *word != 0)));
    values
}
fn fixture_hash(n: usize, values: [&[Fr]; 3]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"dynark/t5/e5b/public-fixture/v1");
    hash.update((n as u64).to_le_bytes());
    hash.update((SEED ^ n as u64).to_le_bytes());
    let mut encoding = reserved::<u8>(32).unwrap();
    for row in values {
        hash.update((row.len() as u64).to_le_bytes());
        for value in row {
            encoding.clear();
            value.serialize_compressed(&mut encoding).unwrap();
            assert_eq!(encoding.len(), 32);
            hash.update(&encoding);
        }
    }
    hash.finalize().iter().map(|x| format!("{x:02x}")).collect()
}

fn material(
    n: usize,
    domain: &GeneralEvaluationDomain<Fr>,
    scalars: Vec<Fr>,
    budget: &mut Budget,
) -> Tables {
    let package = crate::PackageIdentity {
        matrix_digest: [0; 32],
        circuit_digest: [0; 32],
        proving_key_digest: [0; 32],
        verifying_key_digest: [0; 32],
        package_digest: [0; 32],
    };
    let mut roots = reserved(n).unwrap();
    roots.push(Fr::ONE);
    for i in 1..n {
        roots.push(roots[i - 1] * domain.group_gen());
    }
    let mut weights = reserved(n).unwrap();
    weights.push(Fr::ZERO);
    for root in &roots[1..] {
        weights.push(*root * (Fr::ONE - root).inverse().unwrap() * domain.size_inv());
    }
    let mut lagrange = reserved(n).unwrap();
    for scalar in scalars {
        lagrange.push(budget.mul(G1::generator(), scalar));
    }
    let mut forward = weights.clone();
    budget.field_fft(domain, &mut forward, false);
    let mut reverse = (0..n).map(|i| weights[(n - i) % n]).collect::<Vec<_>>();
    budget.field_fft(domain, &mut reverse, false);
    let mut diagonal = lagrange.clone();
    budget.group_fft(domain, &mut diagonal, false);
    for (point, coefficient) in diagonal.iter_mut().zip(&forward) {
        *point = budget.mul(*point, *coefficient);
    }
    budget.group_fft(domain, &mut diagonal, true);
    let sum = weights.iter().copied().sum::<Fr>();
    for (point, base) in diagonal.iter_mut().zip(&lagrange) {
        *point = -(*point + budget.mul(*base, sum));
    }
    let public_bytes = (lagrange.capacity() + diagonal.capacity()) * size_of::<G1>()
        + (weights.capacity() + roots.capacity() + forward.capacity() + reverse.capacity())
            * size_of::<Fr>();
    Tables {
        package,
        uk: UpdatingMaterial(Arc::new(crate::anchored::MaterialInner {
            package,
            lagrange,
            weights,
            diagonal,
        })),
        roots,
        forward,
        reverse,
        inverse_n: domain.size_inv(),
        public_bytes,
        public_scan_entries: 0,
    }
}
fn eager(
    domain: &GeneralEvaluationDomain<Fr>,
    t: &Tables,
    row: &[Fr],
    budget: &mut Budget,
) -> Vec<G1> {
    let n = domain.size();
    assert_eq!(row.len(), n);
    let mut weighted =
        t.uk.0
            .lagrange
            .iter()
            .zip(row)
            .map(|(g, x)| budget.mul(*g, *x))
            .collect::<Vec<_>>();
    let mut kernel = t.uk.0.weights.clone();
    budget.field_fft(domain, &mut kernel, false);
    budget.group_fft(domain, &mut weighted, false);
    for (g, x) in weighted.iter_mut().zip(kernel) {
        *g = budget.mul(*g, x);
    }
    budget.group_fft(domain, &mut weighted, true);
    let mut reverse = (0..n)
        .map(|i| t.uk.0.weights[(n - i) % n])
        .collect::<Vec<_>>();
    let mut scalar = row.to_vec();
    budget.field_fft(domain, &mut reverse, false);
    budget.field_fft(domain, &mut scalar, false);
    for (x, y) in scalar.iter_mut().zip(reverse) {
        *x *= y;
    }
    budget.field_fft(domain, &mut scalar, true);
    for i in 0..n {
        weighted[i] +=
            budget.mul(t.uk.0.lagrange[i], scalar[i]) + budget.mul(t.uk.0.diagonal[i], row[i]);
    }
    weighted
}
fn phase_index(phase: ReconstructionPhase) -> usize {
    match phase {
        ReconstructionPhase::Materialize => 0,
        ReconstructionPhase::Prepare => 1,
        ReconstructionPhase::Forward => 2,
        ReconstructionPhase::Pointwise => 3,
        ReconstructionPhase::Inverse => 4,
        ReconstructionPhase::Scale => 5,
        ReconstructionPhase::Integrate => 6,
        _ => panic!("unexpected pilot action phase"),
    }
}

#[test]
#[ignore = "P2-E5b requires a release executable and a separately granted bounded queue"]
fn release_maintenance_budget_pilot() {
    assert!(!cfg!(debug_assertions), "pilot must use release profile");
    let planned: u64 = DOMAINS
        .iter()
        .map(|n| (5 * n * n.ilog2() as usize + 24 * n) as u64)
        .sum();
    assert_eq!(planned, 1_959_936);
    assert!(planned <= GROUP_CAP);
    let whole = Instant::now();
    let mut budget = Budget::default();
    for n in DOMAINS {
        let case = Instant::now();
        let k = n.ilog2() as usize;
        let w = work(n).unwrap();
        let expected_g = (2 * n * k + 10 * n) as u64;
        let expected_f = (2 * n * k + 4 * n) as u64;
        let inclusive_before = budget.total;
        let roots_before = (budget.fft_root_multiplications, budget.fft_root_squarings);
        let started = Instant::now();
        let domain = GeneralEvaluationDomain::<Fr>::new(n).unwrap();
        assert_eq!(domain.size(), n);
        assert!(matches!(domain, GeneralEvaluationDomain::Radix2(_)));
        elapsed_stage(n, "domain", started);
        let started = Instant::now();
        let mut rng = rand::rngs::StdRng::seed_from_u64(SEED ^ n as u64);
        let mut draws = 0;
        let a = random_fields(n, &mut rng, &mut draws);
        let b = random_fields(n, &mut rng, &mut draws);
        let l = random_fields(n, &mut rng, &mut draws);
        elapsed_stage(n, "dense_public_fields", started);
        let started = Instant::now();
        let digest = fixture_hash(n, [&a, &b, &l]);
        elapsed_stage(n, "fixture_identity", started);
        println!("T5_PILOT {{\"record\":\"fixture\",\"version\":1,\"n\":{n},\"seed\":{},\"rng\":\"rand-0.8.8/StdRng\",\"order\":\"A,B,L\",\"field_draws\":{draws},\"digest\":\"{digest}\"}}", SEED ^ n as u64);
        let started = Instant::now();
        let before = budget.total;
        let tables = material(n, &domain, l, &mut budget);
        assert_eq!(budget.total - before, (n * k + 4 * n) as u64);
        elapsed_stage(n, "public_material", started);
        let started = Instant::now();
        let before = budget.total;
        let qa = eager(&domain, &tables, &a, &mut budget);
        let qb = eager(&domain, &tables, &b, &mut budget);
        assert_eq!(budget.total - before, (2 * n * k + 10 * n) as u64);
        elapsed_stage(n, "two_eager_oracles", started);
        let started = Instant::now();
        let mut pool = Pool {
            n,
            g: std::array::from_fn(|_| vec![G1::zero(); n]),
            f: [
                a,
                b,
                vec![Fr::ZERO; n],
                vec![Fr::ZERO; n],
                vec![Fr::ZERO; n],
                vec![Fr::ZERO; n],
            ],
        };
        let roles = Roles::default();
        let empty = Arc::new(Vec::new());
        let mut builder = Builder {
            generation: 1,
            distance: 0,
            token: [1; 32],
            source: roles.active_f,
            overlays: [empty.clone(), empty.clone()],
            pending: [empty.clone(), empty],
            cursor: Cursor::frozen(),
        };
        let initial_cursor = builder.cursor.clone();
        let mut journal = Journal::empty(vec![0; (10 * n + 63) / 64]);
        elapsed_stage(n, "pool_marks_header", started);
        let started = Instant::now();
        let physical = Physical::capture(&pool);
        elapsed_stage(n, "physical_snapshot", started);
        let started = Instant::now();
        journal.reserve(n, w, 64 * 1024 * 1024).unwrap();
        elapsed_stage(n, "whole_rebuild_journal_reservation", started);
        let mut phase_actions = [0usize; 7];
        let mut phase_writes = [0usize; 7];
        let mut phase_wall = [Duration::ZERO; 7];
        let mut observer = |event| {
            match event {
                WorkEvent::Action(phase) => phase_actions[phase_index(phase)] += 1,
                WorkEvent::Write { phase, .. } => phase_writes[phase_index(phase)] += 1,
                _ => panic!("unexpected pilot scheduling event"),
            }
            false
        };
        let mut chunk = 0usize;
        let mut kernel_wall = Duration::ZERO;
        let mut logging_wall = Duration::ZERO;
        let mut max_pause = Duration::ZERO;
        while !builder.cursor.ready() {
            let quota = CHUNKS[chunk % CHUNKS.len()];
            let before = builder.cursor.clone();
            let end = w.min(before.done.checked_add(quota).unwrap());
            let begin = Instant::now();
            let mut segment = begin;
            while builder.cursor.done < end {
                let phase = builder.cursor.phase;
                let group_before = builder.cursor.group_scalar_calls;
                budget.room(4);
                step(
                    &mut pool,
                    &mut journal,
                    &roles,
                    &mut builder,
                    &tables,
                    &mut observer,
                )
                .unwrap();
                budget.observed(builder.cursor.group_scalar_calls - group_before);
                if builder.cursor.phase != phase {
                    let now = Instant::now();
                    phase_wall[phase_index(phase)] += now.duration_since(segment);
                    segment = now;
                }
            }
            let finish = Instant::now();
            if !builder.cursor.ready() {
                phase_wall[phase_index(builder.cursor.phase)] += finish.duration_since(segment);
            }
            let elapsed = finish.duration_since(begin);
            assert!(builder.cursor.done > before.done);
            kernel_wall += elapsed;
            max_pause = max_pause.max(elapsed);
            let started = Instant::now();
            println!("T5_PILOT {{\"record\":\"chunk\",\"n\":{n},\"chunk\":{chunk},\"quota\":{quota},\"start_phase\":\"{:?}\",\"end_phase\":\"{:?}\",\"start_actions\":{},\"end_actions\":{},\"group_calls\":{},\"field_calls\":{},\"wall_seconds\":{:.9}}}", before.phase, builder.cursor.phase, before.done, builder.cursor.done, builder.cursor.group_scalar_calls-before.group_scalar_calls, builder.cursor.field_mul_calls-before.field_mul_calls, elapsed.as_secs_f64());
            logging_wall += started.elapsed();
            chunk += 1;
        }
        drop(observer);
        assert_eq!(builder.cursor.done, w);
        assert_eq!(builder.cursor.group_scalar_calls, expected_g);
        assert_eq!(builder.cursor.field_mul_calls, expected_f);
        assert_eq!(
            phase_actions,
            [n, n, 4 * n + 2 * n * k, 4 * n, 4 * n + 2 * n * k, 4 * n, n]
        );
        assert_eq!(phase_actions.iter().sum::<usize>() + 1, w);
        assert_eq!(budget.total - inclusive_before, (5 * n * k + 24 * n) as u64);
        assert_eq!(journal.lengths(), (2 * n, 4 * n));
        assert_eq!(journal.group_logs, 2 * n);
        assert_eq!(journal.field_logs, 4 * n);
        let started = Instant::now();
        assert!(
            pool.g[roles.build_g[0]]
                .iter()
                .zip(&qa)
                .all(|(a, b)| a == b),
            "pilot qA mismatch n={n}"
        );
        assert!(
            pool.g[roles.build_g[1]]
                .iter()
                .zip(&qb)
                .all(|(a, b)| a == b),
            "pilot qB mismatch n={n}"
        );
        elapsed_stage(n, "complete_projection_equality", started);
        let started = Instant::now();
        let restored = journal.finish(&mut pool, true);
        builder.cursor = initial_cursor.clone();
        elapsed_stage(n, "rollback_and_logged_mark_clear", started);
        assert_eq!(restored, 6 * n);
        let started = Instant::now();
        assert!(
            physical.matches(&pool),
            "pilot physical rollback mismatch n={n}"
        );
        assert!(journal.marks.iter().all(|x| *x == 0));
        assert_eq!(journal.lengths(), (0, 0));
        assert_eq!(builder.cursor, initial_cursor);
        pool.validate(&roles, &builder).unwrap();
        validate_cursor(&builder.cursor, n, &builder.overlays).unwrap();
        elapsed_stage(n, "complete_physical_and_zero_mark_comparison", started);
        let phase_total = phase_wall.iter().copied().sum::<Duration>();
        let unattributed = kernel_wall.checked_sub(phase_total).unwrap();
        let phases = [
            ReconstructionPhase::Materialize,
            ReconstructionPhase::Prepare,
            ReconstructionPhase::Forward,
            ReconstructionPhase::Pointwise,
            ReconstructionPhase::Inverse,
            ReconstructionPhase::Scale,
            ReconstructionPhase::Integrate,
        ];
        for i in 0..7 {
            println!("T5_PILOT {{\"record\":\"phase\",\"n\":{n},\"phase\":\"{:?}\",\"actions\":{},\"write_events\":{},\"wall_seconds\":{:.9}}}", phases[i], phase_actions[i], phase_writes[i], phase_wall[i].as_secs_f64());
        }
        println!("T5_PILOT {{\"record\":\"algebra_and_traversal\",\"n\":{n},\"outside_kernel_fr_multiplications_analytical\":{},\"outside_kernel_fr_inversions\":{},\"outside_kernel_fr_add_sub_analytical\":{},\"outside_kernel_group_add_sub_analytical\":{},\"outside_kernel_group_negations\":{n},\"kernel_group_add_sub_analytical\":{},\"kernel_fr_add_sub_analytical\":{},\"fft_root_fr_multiplications_analytical\":{},\"fft_root_fr_squarings_analytical\":{},\"snapshot_coordinate_cells\":{},\"snapshot_fr_cells\":{},\"projection_comparisons\":{},\"mark_words_scanned_after_rollback\":{},\"all_noncounted_backend_work_in_stage_and_process_time\":true}}", 5*n*k+7*n-3, n-1, 10*n*k+2*n-1, 6*n*k+5*n, 4*n*k+4*n, 4*n*k, budget.fft_root_multiplications-roots_before.0, budget.fft_root_squarings-roots_before.1, 12*n, 6*n, 2*n, journal.marks.len());
        println!("T5_PILOT {{\"record\":\"case\",\"n\":{n},\"k\":{k},\"w\":{w},\"header_actions\":1,\"group_calls\":{expected_g},\"field_calls\":{expected_f},\"inclusive_group_calls\":{},\"chunk_count\":{chunk},\"kernel_wall_seconds\":{:.9},\"phase_wall_seconds\":{:.9},\"unattributed_kernel_wall_seconds\":{:.9},\"chunk_logging_wall_seconds\":{:.9},\"max_observed_chunk_pause_seconds\":{:.9},\"case_wall_seconds\":{:.9},\"pool_zero_cells\":{},\"source_fr_cells_moved\":{},\"pool_bytes\":{},\"public_material_bytes\":{},\"pilot_oracle_bytes\":{},\"pilot_snapshot_bytes\":{},\"retained_journal_bytes\":{},\"journal_group_preimages\":{},\"journal_field_preimages\":{},\"rollback_cells\":{restored},\"mark_clear_visits\":{restored},\"journal_spans_all_chunks\":true,\"q_equal\":true,\"physical_restored\":true}}", budget.total-inclusive_before, kernel_wall.as_secs_f64(), phase_total.as_secs_f64(), unattributed.as_secs_f64(), logging_wall.as_secs_f64(), max_pause.as_secs_f64(), case.elapsed().as_secs_f64(), 8*n, 2*n, pool.bytes(), tables.public_bytes, (qa.capacity()+qb.capacity())*size_of::<G1>(), physical.bytes(), journal.bytes(), journal.group_logs, journal.field_logs);
        let started = Instant::now();
        drop((qa, qb, physical, journal, builder, pool, tables));
        elapsed_stage(n, "case_buffer_deallocation", started);
    }
    assert_eq!(budget.total, planned);
    println!("T5_PILOT {{\"record\":\"total\",\"domains\":[1024,4096,16384],\"group_cap\":{GROUP_CAP},\"group_calls\":{},\"explicit_group_calls\":{},\"full_width_fft_declared_group_calls\":{},\"reconstruction_observed_group_calls\":{},\"public_oracle_field_fft_butterflies\":{},\"public_oracle_field_fft_normalizations\":{},\"public_oracle_fft_root_multiplications\":{},\"public_oracle_fft_root_squarings\":{},\"whole_wall_seconds\":{:.9}}}", budget.total, budget.explicit, budget.fft_declared, budget.reconstruction_observed, budget.field_fft_butterflies, budget.field_fft_normalizations, budget.fft_root_multiplications, budget.fft_root_squarings, whole.elapsed().as_secs_f64());
}
