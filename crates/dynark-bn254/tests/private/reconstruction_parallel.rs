use crate::reconstruction::{self, BatchWork, Builder, Cursor, Journal, Pool, Roles, Tables};
use crate::{
    dynamic::persistence_codec,
    persistence::{AdmissionMetrics, ExpectedContext, LoadPolicy, PersistenceError},
    Anchor, AnchorBinding, CircuitDescriptor, DynamicConfig, DynamicPreparation, DynamicState,
    DynamicStatus, Error, Limits, ReconstructionMaterial, ReconstructionPhase, Reduction,
    Transition, UpdateProgress, UpdatingMaterial, WorkEvent,
};
use ark_bn254::{Fr, G1Projective as G1};
use ark_ec::PrimeGroup;
use ark_ff::{AdditiveGroup, Field, UniformRand};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use rand::{rngs::StdRng, SeedableRng};
use std::{mem::size_of, sync::Arc};

#[path = "../dynamic_fixture.rs"]
mod fixture;

#[test]
fn prefetched_four_calls_survive_first_publication_failure_and_whole_transaction_rollback() {
    let package = fixture::package(8, 5, false);
    let source = fixture::assignment(5, 3, 2);
    let target = fixture::assignment(5, 4, 3);
    let uk = UpdatingMaterial::prepare(&package, Limits::small()).unwrap();
    let tables = ReconstructionMaterial::prepare(&package, &uk, Limits::small()).unwrap();
    let schema = vec!["x".to_owned()];
    let descriptor = CircuitDescriptor {
        r1cs_artifact_digest: [21; 32],
        witness_executable_digest: [22; 32],
        profile_digest: [23; 32],
        public_schema_digest: crate::public_schema_digest(&schema),
        public_schema: schema,
        reduction: Reduction::Original,
    };
    let context = ExpectedContext::new(
        &package,
        &tables,
        &descriptor,
        [3; 32],
        [1; 32],
        [2; 32],
        [4; 32],
        [5; 32],
    )
    .unwrap();
    let assignment = package
        .validate_assignment(&fixture::encode(&source), &source[1..2])
        .unwrap();
    let mut rng = StdRng::seed_from_u64(0x4241544348);
    let anchor = Anchor::create(
        &package,
        &uk,
        assignment,
        AnchorBinding::new(&package, [1; 32], [2; 32], 1),
        Limits::small(),
        &mut rng,
    )
    .unwrap();
    let mut config = DynamicConfig::small();
    config.threshold = 4;
    let mut preparation = DynamicPreparation::adopt(&package, &tables, anchor, config).unwrap();
    assert!(preparation.advance_preparation(usize::MAX).ready);
    let mut state = preparation.finish().unwrap();
    let first = Transition::new(
        &package,
        state.binding().unwrap(),
        2,
        &fixture::delta(&source, &target),
        &target[1..2],
        Limits::small(),
    )
    .unwrap();
    let proof = state.update(&first, &mut rng).unwrap();
    assert!(crate::test_fixture::verify(
        &package,
        &proof.proof,
        &target[1..2]
    ));
    let before = state.parallel_test_snapshot().unwrap();
    let committed_before = state.ledger();
    let reverse = Transition::new(
        &package,
        state.binding().unwrap(),
        3,
        &fixture::delta(&target, &source),
        &source[1..2],
        Limits::small(),
    )
    .unwrap();
    state.begin_update(&reverse, &mut rng).unwrap();
    let policy = LoadPolicy::small(config);
    assert!(matches!(
        persistence_codec::encode(&state, &context, &policy, &mut AdmissionMetrics::default()),
        Err(PersistenceError::Engine(Error::Busy))
    ));
    // The first update committed its alias promotion/header and left a frozen builder.
    // Eight materialize, eight prepare and eight bit-reversal actions reach a four-item tail.
    assert!(matches!(
        state.advance_update_with(24, |_| false).unwrap(),
        UpdateProgress::Pending { completed: 24, .. }
    ));
    let attempted_before = state.ledger();
    let mut cancelled = false;
    let result = state.parallel_test_advance_four(4, |event| {
        if matches!(
            event,
            WorkEvent::Write {
                phase: ReconstructionPhase::Forward,
                ordinal: 0
            }
        ) {
            cancelled = true;
            true
        } else {
            false
        }
    });
    assert!(cancelled && matches!(result, Err(Error::Cancelled)));
    assert!(
        state.parallel_test_snapshot().unwrap() == before,
        "all physical coordinates, marks, roots, roles and cursor must roll back"
    );
    assert_eq!(state.status(), DynamicStatus::DynamicReady);
    let after = state.ledger();
    assert_eq!(
        after.committed_reconstruction_actions,
        committed_before.committed_reconstruction_actions
    );
    assert_eq!(
        after.committed_group_scalar_calls,
        committed_before.committed_group_scalar_calls
    );
    assert_eq!(
        after.committed_field_mul_calls,
        committed_before.committed_field_mul_calls
    );
    assert!(after.rollback_cells > committed_before.rollback_cells);
    assert!(
        persistence_codec::encode(&state, &context, &policy, &mut AdmissionMetrics::default())
            .is_ok()
    );
    // The preserved red source recorded one; joined discarded work must now record four.
    assert_eq!(
        after.attempted_group_scalar_calls - attempted_before.attempted_group_scalar_calls,
        4,
        "joined four-call prefetch must remain attempted after first publication fails"
    );
    assert_eq!(
        after.attempted_reconstruction_actions - attempted_before.attempted_reconstruction_actions,
        4,
        "prefetched actions must not be inferred from the discarded cursor prefix"
    );
}

const N: usize = 32768;
const CALL_CAP: u64 = 2_000_000;

#[derive(Default)]
struct Calls(u64);
impl Calls {
    fn add(&mut self, count: u64) {
        self.0 = self.0.checked_add(count).unwrap();
        assert!(self.0 <= CALL_CAP, "finite requested scalar-call inventory");
    }
}

fn corpus(calls: &mut Calls) -> Vec<G1> {
    let mut rng = StdRng::seed_from_u64(0x42415443485f3831);
    (0..N)
        .map(|_| {
            let scalar = loop {
                let x = Fr::rand(&mut rng);
                if x != Fr::ZERO {
                    break x;
                }
            };
            calls.add(1);
            G1::generator() * scalar
        })
        .collect()
}

fn pool(points: &[G1], pattern: usize) -> Pool {
    Pool {
        n: points.len(),
        g: std::array::from_fn(|slot| {
            (0..points.len())
                .map(|i| {
                    if pattern == 1 && i % 8 != 0 || pattern == 2 {
                        G1::ZERO
                    } else {
                        points[(i + slot * 37) % points.len()]
                    }
                })
                .collect()
        }),
        f: std::array::from_fn(|slot| {
            (0..points.len())
                .map(|i| Fr::from((i + slot * 101) as u64))
                .collect()
        }),
    }
}

fn copy_pool(p: &Pool) -> Pool {
    Pool {
        n: p.n,
        g: p.g.clone(),
        f: p.f.clone(),
    }
}

fn exact_pool(a: &Pool, b: &Pool) {
    assert_eq!(a.n, b.n);
    for (a, b) in a.g.iter().zip(&b.g) {
        assert_eq!(a.len(), b.len());
        assert!(
            a.iter()
                .zip(b)
                .all(|(a, b)| [a.x, a.y, a.z] == [b.x, b.y, b.z]),
            "all raw projective coordinates, including untouched physical slots"
        );
    }
    assert_eq!(a.f, b.f);
}

fn builder(
    n: usize,
    phase: ReconstructionPhase,
    stream: usize,
    stage: usize,
    index: usize,
    roles: &Roles,
) -> Builder {
    let k = n.ilog2() as usize;
    let nk = n * k;
    let transform = n + nk / 2;
    let forward = 1 + 2 * n;
    let pointwise = forward + 4 * transform;
    let inverse = pointwise + 4 * n;
    let scale = inverse + 4 * transform;
    let partial = if stage == 0 {
        0
    } else {
        (stage - 1) * (n / 2) + index
    };
    let fft_g = stream.min(2) * nk / 2 + if stream < 2 { partial } else { 0 };
    let fft_f = stream.saturating_sub(2) * nk / 2 + if stream >= 2 { partial } else { 0 };
    let elements_g = stream.min(2) * n + if stream < 2 { index } else { 0 };
    let elements_f = stream.saturating_sub(2) * n + if stream >= 2 { index } else { 0 };
    let (done, g, f) = match phase {
        ReconstructionPhase::Forward | ReconstructionPhase::Inverse => (
            (if phase == ReconstructionPhase::Forward {
                forward
            } else {
                inverse
            }) + stream * transform
                + if stage == 0 { index } else { n + partial },
            (if phase == ReconstructionPhase::Forward {
                2 * n
            } else {
                4 * n + nk
            }) + fft_g,
            (if phase == ReconstructionPhase::Forward {
                0
            } else {
                2 * n + nk
            }) + fft_f,
        ),
        ReconstructionPhase::Pointwise | ReconstructionPhase::Scale => (
            (if phase == ReconstructionPhase::Scale {
                scale
            } else {
                pointwise
            }) + stream * n
                + index,
            (if phase == ReconstructionPhase::Scale {
                4 * n + 2 * nk
            } else {
                2 * n + nk
            }) + elements_g,
            (if phase == ReconstructionPhase::Scale {
                2 * n + 2 * nk
            } else {
                nk
            }) + elements_f,
        ),
        _ => panic!("finite arithmetic fixture phase"),
    };
    let cursor = Cursor::persistence_new(
        phase,
        done,
        g as u64,
        f as u64,
        [stream, index, stage, 0, 0],
    );
    let maps = [Arc::new(Vec::new()), Arc::new(Vec::new())];
    reconstruction::validate_cursor(&cursor, n, &maps).unwrap();
    Builder {
        generation: 1,
        distance: 0,
        token: [7; 32],
        source: roles.active_f,
        overlays: maps.clone(),
        pending: maps,
        cursor,
    }
}

fn journal(n: usize, actions: usize) -> Journal {
    let mut j = Journal::empty(vec![0; (10 * n).div_ceil(64)]);
    j.reserve(n, actions, 32 * 1024 * 1024).unwrap();
    j
}

fn paired(
    points: &[G1],
    tables: &Tables,
    pattern: usize,
    roles: Roles,
    start: Builder,
    budget: usize,
    room: usize,
    calls: &mut Calls,
) -> usize {
    let mut serial = pool(points, pattern);
    let mut candidate = copy_pool(&serial);
    let mut sb = start.clone();
    let mut cb = start;
    let mut sj = journal(points.len(), budget);
    let mut cj = journal(points.len(), budget);
    let mut references = Vec::new();
    if budget == 8192
        && room >= 8192 * size_of::<[G1; 2]>()
        && reconstruction::group_batch_plan(&candidate, &roles, &cb, tables, budget, 8192)
            .unwrap()
            .is_some()
    {
        let domain = GeneralEvaluationDomain::<Fr>::new(points.len()).unwrap();
        let [stream, index, stage, _, _] = cb.cursor.persistence_parts();
        let slot = roles.build_g[stream];
        if cb.cursor.phase == ReconstructionPhase::Scale {
            for offset in [0, 1, 2, 3, 4095, 4096, 8190, 8191] {
                let i = index + offset;
                calls.add(1);
                references.push((
                    slot,
                    i,
                    candidate.g[slot][i] * Fr::from(points.len() as u64).inverse().unwrap(),
                ));
            }
        } else {
            for offset in [0, 1, 4095, 8191] {
                let i = index + offset;
                let width = 1usize << stage;
                let half = width / 2;
                let left = (i / half) * width + i % half;
                let power = (i % half) * (points.len() / width);
                let root = domain.group_gen().pow([power as u64]);
                let root = if cb.cursor.phase == ReconstructionPhase::Inverse {
                    root.inverse().unwrap()
                } else {
                    root
                };
                let u = candidate.g[slot][left];
                calls.add(1);
                let v = candidate.g[slot][left + half] * root;
                references.push((slot, left, u + v));
                references.push((slot, left + half, u - v));
            }
        }
    }
    let mut batches = 0;
    let before = sb.cursor.group_scalar_calls;
    for _ in 0..budget {
        reconstruction::step(&mut serial, &mut sj, &roles, &mut sb, tables, &mut |_| {
            false
        })
        .unwrap();
    }
    calls.add(sb.cursor.group_scalar_calls - before);
    let mut left = budget;
    while left > 0 {
        if let Some(plan) = reconstruction::group_batch_plan(
            &candidate,
            &roles,
            &cb,
            tables,
            left,
            reconstruction::GROUP_BATCH_LEN,
        )
        .unwrap()
        {
            let mut work = BatchWork::default();
            if reconstruction::group_batch(
                &mut candidate,
                &mut cj,
                &roles,
                &mut cb,
                tables,
                plan,
                room,
                &mut |_| false,
                &mut work,
            )
            .unwrap()
            {
                assert_eq!(work.attempted_actions, 8192);
                assert_eq!(work.requested_group_calls, 8192);
                assert_eq!(work.published_actions, 8192);
                assert!(work.scratch_capacity_bytes >= 8192 * size_of::<[G1; 2]>());
                assert!(work.scratch_capacity_bytes <= room);
                calls.add(work.requested_group_calls);
                left -= work.published_actions;
                batches += 1;
                continue;
            }
            assert_eq!(work.attempted_actions, 0);
            assert_eq!(
                work.requested_group_calls, 0,
                "rejected allocation performs no arithmetic"
            );
            assert_eq!(work.published_actions, 0);
            assert_eq!(work.scratch_capacity_bytes, 0);
        }
        let before = cb.cursor.group_scalar_calls;
        reconstruction::step(
            &mut candidate,
            &mut cj,
            &roles,
            &mut cb,
            tables,
            &mut |_| false,
        )
        .unwrap();
        calls.add(cb.cursor.group_scalar_calls - before);
        left -= 1;
    }
    exact_pool(&serial, &candidate);
    for (slot, index, value) in references {
        let got = candidate.g[slot][index];
        assert_eq!(
            [got.x, got.y, got.z],
            [value.x, value.y, value.z],
            "independently derived selected output"
        );
    }
    assert_eq!(sb.cursor, cb.cursor);
    assert_eq!(sb.source, cb.source);
    assert_eq!(sj.marks, cj.marks);
    assert_eq!(sj.lengths(), cj.lengths());
    assert_eq!(
        (sj.group_logs, sj.field_logs),
        (cj.group_logs, cj.field_logs)
    );
    assert_eq!(
        sj.finish(&mut serial, true),
        cj.finish(&mut candidate, true)
    );
    exact_pool(&serial, &candidate);
    assert!(sj.persistence_clean() && cj.persistence_clean());
    batches
}

#[test]
fn production_sized_batches_match_serial_physical_state_cursor_and_recycled_roles() {
    let mut calls = Calls::default();
    let points = corpus(&mut calls);
    let tables = Tables::parallel_test(N);
    let mut cases = 0;
    for threads in [1, 2, 4] {
        let workers = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap();
        assert_eq!(workers.current_num_threads(), threads);
        workers.install(|| {
            for (phase, stage) in [
                (ReconstructionPhase::Forward, 1),
                (ReconstructionPhase::Forward, 10),
                (ReconstructionPhase::Inverse, 15),
                (ReconstructionPhase::Scale, 0),
            ] {
                for stream in 0..2 {
                    let roles = if stream == 0 {
                        Roles::default()
                    } else {
                        Roles {
                            active_g: [2, 3],
                            build_g: [0, 1],
                            active_f: [2, 3],
                            build_f: [0, 1],
                        }
                    };
                    for pattern in 0..3 {
                        let start = builder(N, phase, stream, stage, 4096, &roles);
                        assert_eq!(
                            paired(
                                &points,
                                &tables,
                                pattern,
                                roles.clone(),
                                start,
                                8192,
                                2 * 1024 * 1024,
                                &mut calls
                            ),
                            1
                        );
                        cases += 1;
                    }
                }
            }
        });
    }
    assert_eq!(cases, 72);
    assert_eq!(calls.0, 1_212_776);
    println!(
        "BATCH_GATE matrix_cases={cases} requested_group_calls={}",
        calls.0
    );
}

#[test]
fn budgets_tails_ineligible_phases_and_scratch_refusal_keep_serial_results() {
    let mut calls = Calls::default();
    let points = corpus(&mut calls);
    let tables = Tables::parallel_test(N);
    let roles = Roles::default();
    for phase in [
        ReconstructionPhase::Forward,
        ReconstructionPhase::Inverse,
        ReconstructionPhase::Scale,
    ] {
        let stage = if phase == ReconstructionPhase::Scale {
            0
        } else {
            15
        };
        let tail = if phase == ReconstructionPhase::Scale {
            N
        } else {
            N / 2
        };
        for budget in [0, 1, 8191, 8192, 8193] {
            let start = builder(N, phase, 1, stage, tail - 8192, &roles);
            assert_eq!(
                paired(
                    &points,
                    &tables,
                    0,
                    roles.clone(),
                    start,
                    budget,
                    2 * 1024 * 1024,
                    &mut calls
                ),
                usize::from(budget >= 8192)
            );
        }
        let start = builder(N, phase, 0, stage, tail - 8191, &roles);
        assert_eq!(
            paired(
                &points,
                &tables,
                1,
                roles.clone(),
                start,
                8191,
                2 * 1024 * 1024,
                &mut calls
            ),
            0
        );
        let start = builder(N, phase, 0, stage, 0, &roles);
        assert_eq!(
            paired(
                &points,
                &tables,
                0,
                roles.clone(),
                start,
                8192,
                8192 * size_of::<[G1; 2]>() - 1,
                &mut calls
            ),
            0
        );
    }
    let p = pool(&points, 0);
    for (phase, stream, stage) in [
        (ReconstructionPhase::Forward, 0, 0),
        (ReconstructionPhase::Inverse, 1, 0),
        (ReconstructionPhase::Forward, 2, 1),
        (ReconstructionPhase::Inverse, 3, 15),
        (ReconstructionPhase::Pointwise, 0, 0),
        (ReconstructionPhase::Scale, 2, 0),
    ] {
        let start = builder(N, phase, stream, stage, 0, &roles);
        assert!(
            reconstruction::group_batch_plan(&p, &roles, &start, &tables, 8192, 8192)
                .unwrap()
                .is_none()
        );
    }
    // Eligible malformed metadata is an error, not an admission fallback.
    let mut start = builder(N, ReconstructionPhase::Forward, 0, 1, 0, &roles);
    start.cursor.group_scalar_calls += 1;
    assert!(reconstruction::group_batch_plan(&p, &roles, &start, &tables, 8192, 8192).is_err());
    assert_eq!(calls.0, 278538);
    println!("BATCH_GATE boundary_requested_group_calls={}", calls.0);
}

#[test]
fn joined_full_batch_failures_preserve_published_prefix_and_both_preimages() {
    let mut calls = Calls::default();
    let points = corpus(&mut calls);
    let tables = Tables::parallel_test(N);
    let roles = Roles::default();
    for fail_at in [0, 8191] {
        for ordinal in [0, 1] {
            let mut p = pool(&points, 0);
            let original = copy_pool(&p);
            let mut b = builder(N, ReconstructionPhase::Forward, 0, 15, 0, &roles);
            let mut j = journal(N, 8193);
            // This earlier progress belongs to the same journal/whole transaction.
            reconstruction::step(&mut p, &mut j, &roles, &mut b, &tables, &mut |_| false).unwrap();
            calls.add(1);
            let before = b.cursor.clone();
            let plan = reconstruction::group_batch_plan(&p, &roles, &b, &tables, 8192, 8192)
                .unwrap()
                .unwrap();
            let mut action = 0;
            let mut work = BatchWork::default();
            let result = reconstruction::group_batch(
                &mut p,
                &mut j,
                &roles,
                &mut b,
                &tables,
                plan,
                2 * 1024 * 1024,
                &mut |event| {
                    if matches!(event, WorkEvent::Action(_)) {
                        action += 1;
                    }
                    matches!(event, WorkEvent::Write { ordinal: o, .. } if o == ordinal)
                        && action == fail_at + 1
                },
                &mut work,
            );
            assert!(matches!(result, Err(Error::Cancelled)));
            calls.add(work.requested_group_calls);
            assert_eq!(work.requested_group_calls, 8192);
            assert_eq!(work.attempted_actions, 8192);
            assert_eq!(work.published_actions, fail_at);
            assert_eq!(b.cursor.done, before.done + fail_at);
            assert_eq!(
                b.cursor.group_scalar_calls,
                before.group_scalar_calls + fail_at as u64
            );
            assert_eq!(
                j.lengths().0,
                2 * (fail_at + 2),
                "both preimages precede first store"
            );
            assert_eq!(j.finish(&mut p, true), 2 * (fail_at + 2));
            exact_pool(&p, &original);
            assert!(j.persistence_clean());
        }
    }
    // One free journal cell cannot admit either store of a two-cell butterfly.
    let mut p = pool(&points, 0);
    let original = copy_pool(&p);
    let mut b = builder(N, ReconstructionPhase::Forward, 0, 1, 0, &roles);
    let before = b.cursor.clone();
    let mut j = Journal::parallel_test_one_group_cell(N);
    let plan = reconstruction::group_batch_plan(&p, &roles, &b, &tables, 8192, 8192)
        .unwrap()
        .unwrap();
    let mut work = BatchWork::default();
    assert!(matches!(
        reconstruction::group_batch(
            &mut p,
            &mut j,
            &roles,
            &mut b,
            &tables,
            plan,
            2 * 1024 * 1024,
            &mut |_| false,
            &mut work
        ),
        Err(Error::Bound("group journal capacity"))
    ));
    calls.add(work.requested_group_calls);
    assert_eq!(work.requested_group_calls, 8192);
    assert_eq!(work.published_actions, 0);
    assert_eq!(b.cursor, before);
    exact_pool(&p, &original);
    assert_eq!(j.lengths(), (1, 0));
    assert_eq!(j.finish(&mut p, true), 1);
    assert_eq!(calls.0, 73732);
    println!("BATCH_GATE failure_requested_group_calls={}", calls.0);
}

struct Real {
    package: crate::PublicPackage,
    tables: ReconstructionMaterial,
    context: ExpectedContext,
    config: DynamicConfig,
    state: DynamicState,
    source: Vec<Fr>,
    target: Vec<Fr>,
    rng: StdRng,
}
impl Real {
    fn new(threshold: u64) -> Self {
        let package = fixture::package(8, 5, false);
        let source = fixture::assignment(5, 3, 2);
        let target = fixture::assignment(5, 4, 3);
        let uk = UpdatingMaterial::prepare(&package, Limits::small()).unwrap();
        let tables = ReconstructionMaterial::prepare(&package, &uk, Limits::small()).unwrap();
        let schema = vec!["x".to_owned()];
        let descriptor = CircuitDescriptor {
            r1cs_artifact_digest: [21; 32],
            witness_executable_digest: [22; 32],
            profile_digest: [23; 32],
            public_schema_digest: crate::public_schema_digest(&schema),
            public_schema: schema,
            reduction: Reduction::Original,
        };
        let context = ExpectedContext::new(
            &package,
            &tables,
            &descriptor,
            [3; 32],
            [1; 32],
            [2; 32],
            [4; 32],
            [5; 32],
        )
        .unwrap();
        let mut rng = StdRng::seed_from_u64(0x5245414c42415443);
        let assignment = package
            .validate_assignment(&fixture::encode(&source), &source[1..2])
            .unwrap();
        let anchor = Anchor::create(
            &package,
            &uk,
            assignment,
            AnchorBinding::new(&package, [1; 32], [2; 32], 1),
            Limits::small(),
            &mut rng,
        )
        .unwrap();
        let mut config = DynamicConfig::small();
        config.threshold = threshold;
        let mut prep = DynamicPreparation::adopt(&package, &tables, anchor, config).unwrap();
        assert!(prep.advance_preparation(usize::MAX).ready);
        let state = prep.finish().unwrap();
        Self {
            package,
            tables,
            context,
            config,
            state,
            source,
            target,
            rng,
        }
    }
    fn transition(&self, from: &[Fr], to: &[Fr]) -> Transition {
        Transition::new(
            &self.package,
            self.state.binding().unwrap(),
            self.state.binding().unwrap().generation + 1,
            &fixture::delta(from, to),
            &to[1..2],
            Limits::small(),
        )
        .unwrap()
    }
    fn alias_then_reverse(&mut self) -> Vec<u8> {
        let first = self.transition(&self.source, &self.target);
        let proof = self.state.update(&first, &mut self.rng).unwrap();
        verify_statement(&self.package, &proof, &self.target[1..2]);
        let before = self.state.parallel_test_snapshot().unwrap();
        let reverse = self.transition(&self.target, &self.source);
        self.state.begin_update(&reverse, &mut self.rng).unwrap();
        assert!(matches!(
            self.state.advance_update_with(24, |_| false).unwrap(),
            UpdateProgress::Pending { completed: 24, .. }
        ));
        before
    }
    fn recover(&self, publics: &[Fr]) -> DynamicState {
        use crate::persistence::{
            ProviderCapability, ProviderSnapshot, Reservation, SessionStatus, SyncTier,
        };
        let policy = LoadPolicy::small(self.config);
        let bytes = persistence_codec::encode(
            &self.state,
            &self.context,
            &policy,
            &mut AdmissionMetrics::default(),
        )
        .unwrap();
        let provider = ProviderSnapshot {
            context: self.context.digest(),
            session: self.context.session_id(),
            session_epoch: 1,
            key_id: [7; 32],
            key_epoch: 1,
            status: SessionStatus::Active,
            capability: ProviderCapability::ProcessLifetime,
            enrollment_authorized: true,
            receipt: None,
            unresolved: None,
        };
        let (header, _) = crate::persistence::wire::header(
            &self.state,
            &self.context,
            &provider,
            Reservation {
                nonce: [8; 12],
                commit_id: [9; 32],
            },
            bytes.len(),
            SyncTier::FileAndDirectory,
        )
        .unwrap();
        let mut metrics = AdmissionMetrics::default();
        metrics.buffer_capacity = bytes.capacity();
        persistence_codec::decode(
            &bytes,
            &header,
            &self.package,
            &self.tables,
            &self.context,
            &policy,
            publics,
            &mut metrics,
        )
        .unwrap()
    }
}

fn verify_statement(
    package: &crate::PublicPackage,
    statement: &crate::ProofStatement,
    publics: &[Fr],
) {
    assert!(crate::test_fixture::verify(
        package,
        &statement.proof,
        publics
    ));
    let mut wrong = publics.to_vec();
    wrong[0] += Fr::from(1u64);
    assert!(!crate::test_fixture::verify(
        package,
        &statement.proof,
        &wrong
    ));
}

#[test]
fn actual_state_scratch_caps_callback_order_and_invalid_base_are_distinct() {
    let mut real = Real::new(4);
    let before = real.alias_then_reverse();
    real.state.cancel_update().unwrap();
    for mode in 0..4 {
        let reverse = real.transition(&real.target, &real.source);
        real.state.begin_update(&reverse, &mut real.rng).unwrap();
        real.state.advance_update_with(24, |_| false).unwrap();
        let mut config = real.config;
        let (base, public) = real.state.parallel_test_pending_bytes().unwrap();
        match mode {
            0 => config.max_private_bytes = base,
            1 => config.max_global_bytes = base + public,
            2 => config.max_private_bytes = base - 1,
            3 => {}
            _ => unreachable!(),
        }
        real.state.parallel_test_set_config(config);
        let ledger = real.state.ledger();
        let mut hit = false;
        let cancel = |event| {
            if matches!(
                event,
                WorkEvent::Write {
                    phase: ReconstructionPhase::Forward,
                    ordinal: 0
                }
            ) {
                hit = true;
                true
            } else {
                false
            }
        };
        let result = if mode == 3 {
            real.state.advance_update_with(4, cancel)
        } else {
            real.state.parallel_test_advance_four(4, cancel)
        };
        if mode == 2 {
            assert!(matches!(
                result,
                Err(Error::Bound("private structural bytes"))
            ));
            assert!(!hit);
        } else {
            assert!(matches!(result, Err(Error::Cancelled)) && hit);
        }
        let after = real.state.ledger();
        assert_eq!(
            after.attempted_group_scalar_calls - ledger.attempted_group_scalar_calls,
            u64::from(mode != 2),
            "scratch refusal or public callback reaches only one serial multiply"
        );
        assert_eq!(
            after.attempted_reconstruction_actions - ledger.attempted_reconstruction_actions,
            u64::from(mode != 2)
        );
        assert_eq!(
            after.committed_reconstruction_actions,
            ledger.committed_reconstruction_actions
        );
        real.state.parallel_test_set_config(real.config);
        assert_eq!(real.state.parallel_test_snapshot().unwrap(), before);
    }
    let restored = real.recover(&real.target[1..2]);
    assert_eq!(
        restored.parallel_test_canonical_snapshot().unwrap(),
        real.state.parallel_test_canonical_snapshot().unwrap()
    );
}

#[test]
fn actual_state_zero_budget_cancel_between_calls_and_attempt_saturation_preserve_root() {
    let mut real = Real::new(4);
    let before = real.alias_then_reverse();
    let ledger = real.state.ledger();
    assert!(matches!(
        real.state.advance_update(0).unwrap(),
        UpdateProgress::Pending { completed: 24, .. }
    ));
    assert_eq!(real.state.ledger(), ledger);
    assert!(matches!(
        real.state.parallel_test_advance_four(4, |_| false).unwrap(),
        UpdateProgress::Pending { completed: 28, .. }
    ));
    assert_eq!(
        real.state.ledger().attempted_group_scalar_calls - ledger.attempted_group_scalar_calls,
        4
    );
    real.state.cancel_update().unwrap();
    assert_eq!(real.state.parallel_test_snapshot().unwrap(), before);
    let restored = real.recover(&real.target[1..2]);
    assert_eq!(
        restored.parallel_test_canonical_snapshot().unwrap(),
        real.state.parallel_test_canonical_snapshot().unwrap()
    );
    let reverse = real.transition(&real.target, &real.source);
    real.state.begin_update(&reverse, &mut real.rng).unwrap();
    real.state.advance_update_with(24, |_| false).unwrap();
    real.state.parallel_test_saturate_attempts();
    let ledger = real.state.ledger();
    assert!(matches!(
        real.state.parallel_test_advance_four(4, |event| matches!(
            event,
            WorkEvent::Write {
                phase: ReconstructionPhase::Forward,
                ordinal: 0
            }
        )),
        Err(Error::Cancelled)
    ));
    let after = real.state.ledger();
    assert!(after.saturated);
    assert_eq!(after.attempted_group_scalar_calls, u64::MAX);
    assert_eq!(after.attempted_reconstruction_actions, u64::MAX);
    assert_eq!(
        after.committed_group_scalar_calls,
        ledger.committed_group_scalar_calls
    );
    assert_eq!(real.state.parallel_test_snapshot().unwrap(), before);
}

#[test]
fn committed_partial_reconstruction_recovers_and_recycled_promotion_rolls_back() {
    let mut serial = Real::new(5);
    let mut batch = Real::new(5);
    let targets = [
        fixture::assignment(5, 4, 3),
        fixture::assignment(5, 5, 4),
        fixture::assignment(5, 6, 2),
    ];
    let mut source = serial.source.clone();
    for (round, target) in targets.iter().enumerate() {
        let st = serial.transition(&source, target);
        let bt = batch.transition(&source, target);
        if round == 2 {
            let before = batch.state.parallel_test_snapshot().unwrap();
            batch.state.begin_update(&bt, &mut batch.rng).unwrap();
            let mut promoted = false;
            let mut writes = 0;
            assert!(matches!(
                batch.state.parallel_test_advance_four(usize::MAX, |event| {
                    if event == WorkEvent::Promotion {
                        promoted = true;
                    }
                    if promoted
                        && matches!(
                            event,
                            WorkEvent::Write {
                                phase: ReconstructionPhase::Forward,
                                ordinal: 0
                            }
                        )
                    {
                        writes += 1;
                        return writes == 3;
                    }
                    false
                }),
                Err(Error::Cancelled)
            ));
            assert!(promoted && writes == 3);
            assert_eq!(batch.state.parallel_test_snapshot().unwrap(), before);
            let restored = batch.recover(&source[1..2]);
            assert_eq!(
                restored.parallel_test_canonical_snapshot().unwrap(),
                batch.state.parallel_test_canonical_snapshot().unwrap()
            );
        }
        serial.state.begin_update(&st, &mut serial.rng).unwrap();
        let sp = match serial
            .state
            .advance_update_with(usize::MAX, |_| false)
            .unwrap()
        {
            UpdateProgress::Committed(proof) => proof,
            _ => panic!("finite serial transaction"),
        };
        batch.state.begin_update(&bt, &mut batch.rng).unwrap();
        let bp = match batch
            .state
            .parallel_test_advance_four(usize::MAX, |_| false)
            .unwrap()
        {
            UpdateProgress::Committed(proof) => proof,
            _ => panic!("finite batch transaction"),
        };
        verify_statement(&serial.package, &sp, &target[1..2]);
        verify_statement(&batch.package, &bp, &target[1..2]);
        // Independent entropy is still sampled by both actual APIs; compare reconstruction state.
        // A failed batch above consumed additional proof randomness, so current proof coordinates differ.
        assert_eq!(serial.state.cycle_credit(), batch.state.cycle_credit());
        assert_eq!(
            serial.state.accepted_distance(),
            batch.state.accepted_distance()
        );
        let sl = serial.state.ledger();
        let bl = batch.state.ledger();
        assert_eq!(
            sl.committed_reconstruction_actions,
            bl.committed_reconstruction_actions
        );
        assert_eq!(
            sl.committed_group_scalar_calls,
            bl.committed_group_scalar_calls
        );
        assert_eq!(sl.committed_field_mul_calls, bl.committed_field_mul_calls);
        if round < 2 {
            assert_eq!(
                serial.state.parallel_test_canonical_snapshot().unwrap(),
                batch.state.parallel_test_canonical_snapshot().unwrap()
            );
        }
        let restored = batch.recover(&target[1..2]);
        assert_eq!(
            restored.parallel_test_canonical_snapshot().unwrap(),
            batch.state.parallel_test_canonical_snapshot().unwrap()
        );
        batch.state = restored;
        source = target.clone();
    }
    assert!(
        batch.state.ledger().attempted_group_scalar_calls
            > batch.state.ledger().committed_group_scalar_calls
    );
}

#[test]
fn actual_8192_api_routes_only_admitted_batches_and_cancellation_restores_original_state() {
    const DOMAIN: usize = 16384;
    assert_eq!(rayon::current_num_threads(), 4, "granted runtime profile");
    let package = fixture::package(DOMAIN, 6, false);
    assert_eq!(package.shape().domain_size, DOMAIN);
    let source = fixture::assignment(6, 3, 2);
    let mut target = source.clone();
    target[5] += Fr::from(1u64);
    let mut limits = Limits::small();
    limits.max_domain = DOMAIN;
    limits.max_matrix_entries = 65536;
    limits.max_allocation_bytes = 64 * 1024 * 1024;
    let uk = UpdatingMaterial::prepare(&package, limits).unwrap();
    let tables = ReconstructionMaterial::prepare(&package, &uk, limits).unwrap();
    let mut rng = StdRng::seed_from_u64(0x524f555445383139);
    let assignment = package
        .validate_assignment(&fixture::encode(&source), &source[1..2])
        .unwrap();
    let anchor = Anchor::create(
        &package,
        &uk,
        assignment,
        AnchorBinding::new(&package, [1; 32], [2; 32], 1),
        limits,
        &mut rng,
    )
    .unwrap();
    let mut config = DynamicConfig::small();
    config.threshold = 1;
    config.operation = limits;
    config.max_transaction_actions = 2_000_000;
    let mut prep = DynamicPreparation::adopt(&package, &tables, anchor, config).unwrap();
    assert!(prep.advance_preparation(usize::MAX).ready);
    let mut state = prep.finish().unwrap();
    let first = Transition::new(
        &package,
        state.binding().unwrap(),
        2,
        &fixture::delta(&source, &target),
        &target[1..2],
        limits,
    )
    .unwrap();
    let checked = first
        .validate_target(
            &package,
            &package
                .validate_assignment(&fixture::encode(&source), &source[1..2])
                .unwrap(),
        )
        .unwrap();
    assert_eq!(checked.rows.a.len(), 1);
    assert!(checked.rows.b.is_empty() && checked.rows.c.is_empty());
    let proof = state.update(&first, &mut rng).unwrap();
    verify_statement(&package, &proof, &target[1..2]);
    let before = state.parallel_test_snapshot().unwrap();
    let committed = state.ledger();
    for mode in 0..3 {
        let reverse = Transition::new(
            &package,
            state.binding().unwrap(),
            3,
            &fixture::delta(&target, &source),
            &source[1..2],
            limits,
        )
        .unwrap();
        state.begin_update(&reverse, &mut rng).unwrap();
        let prefix_ledger = state.ledger();
        assert!(matches!(state.advance_update(3*DOMAIN).unwrap(),
            UpdateProgress::Pending { completed, .. } if completed == 3*DOMAIN));
        assert_eq!(
            state.ledger().attempted_group_scalar_calls
                - prefix_ledger.attempted_group_scalar_calls,
            (2 * DOMAIN) as u64
        );
        let mut tight = config;
        if mode == 1 {
            let (base, _) = state.parallel_test_pending_bytes().unwrap();
            tight.max_private_bytes = base + 8192 * size_of::<[G1; 2]>() - 1;
            state.parallel_test_set_config(tight);
        }
        let joined = reconstruction::parallel_test_joined_batches();
        let ledger = state.ledger();
        let budget = if mode == 0 { 8191 } else { 8192 };
        assert!(matches!(state.advance_update(budget).unwrap(),
            UpdateProgress::Pending { completed, .. } if completed == 3*DOMAIN+budget));
        assert_eq!(
            reconstruction::parallel_test_joined_batches() - joined,
            u64::from(mode == 2)
        );
        assert_eq!(
            state.ledger().attempted_group_scalar_calls - ledger.attempted_group_scalar_calls,
            budget as u64
        );
        assert_eq!(
            state.ledger().attempted_reconstruction_actions
                - ledger.attempted_reconstruction_actions,
            budget as u64
        );
        state.cancel_update().unwrap();
        state.parallel_test_set_config(config);
        assert_eq!(state.parallel_test_snapshot().unwrap(), before);
        assert_eq!(
            state.ledger().committed_group_scalar_calls,
            committed.committed_group_scalar_calls
        );
        assert_eq!(state.status(), DynamicStatus::DynamicReady);
    }
    assert_eq!(
        state.ledger().attempted_group_scalar_calls - committed.attempted_group_scalar_calls,
        122879
    );
    println!("BATCH_GATE actual_domain={DOMAIN} routed_batches=1 serial_budget_refusals=1 scratch_refusals=1 prefix_group_calls=98304 window_group_calls=24575");
}
