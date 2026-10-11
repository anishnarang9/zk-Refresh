use super::*;
#[path = "selective_fixture.rs"]
mod fixture;
use crate::Reduction;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{AdditiveGroup, Field, PrimeField, UniformRand};
use ark_poly::EvaluationDomain;
use rand::SeedableRng;

fn state_for(
    p: &PublicPackage,
    uk: &UpdatingMaterial,
    z: &[Fr],
) -> (SelectiveState, SelectiveLedger) {
    let a = p
        .validate_assignment(&fixture::encode(z), &z[1..6])
        .unwrap();
    let (s, _, l) = SelectiveState::create(
        p,
        uk,
        a,
        AnchorBinding::new(p, [1; 32], [2; 32], 1),
        SelectiveConfig::small(),
        &mut rand::rngs::OsRng,
    )
    .unwrap();
    (s, l)
}

fn initialized(
    n: usize,
    reduction: Reduction,
) -> (
    PublicPackage,
    UpdatingMaterial,
    SelectiveState,
    SelectiveLedger,
    Vec<Fr>,
) {
    let p = fixture::package(n, reduction, 3);
    let z = fixture::assignment(&p, &[]);
    let uk = UpdatingMaterial::prepare(&p, Limits::small()).unwrap();
    let assignment = p
        .validate_assignment(&fixture::encode(&z), &z[1..6])
        .unwrap();
    let (s, proof, ledger) = SelectiveState::create(
        &p,
        &uk,
        assignment,
        AnchorBinding::new(&p, [1; 32], [2; 32], 1),
        SelectiveConfig::small(),
        &mut rand::rngs::OsRng,
    )
    .unwrap();
    fixture::verify(&p, &proof, &z);
    assert_eq!(ledger.stats().entry_rows, 0);
    assert_eq!(ledger.stats().attempts_started, 0);
    assert_eq!(s.cache_len(), 0);
    (p, uk, s, ledger, z)
}
fn transition(
    p: &PublicPackage,
    s: &SelectiveState,
    z: &[Fr],
    target: &[Fr],
    generation: u64,
) -> Transition {
    Transition::new(
        p,
        s.binding(),
        generation,
        &fixture::delta(z, target),
        &target[1..6],
        Limits::small(),
    )
    .unwrap()
}
// Independent schoolbook product and division by X^N-1.
fn polynomial_entry(p: &PublicPackage, rows: &[Fr], index: usize) -> G1 {
    let n = p.shape().domain_size;
    let a = p.0.domain.ifft(rows);
    let mut unit = vec![Fr::ZERO; n];
    unit[index] = Fr::ONE;
    let l = p.0.domain.ifft(&unit);
    let mut product = vec![Fr::ZERO; 2 * n - 1];
    for (i, x) in a.iter().enumerate() {
        for (j, y) in l.iter().enumerate() {
            product[i + j] += *x * *y;
        }
    }
    let mut q = vec![Fr::ZERO; n - 1];
    for i in (n..product.len()).rev() {
        let coefficient = product[i];
        q[i - n] = coefficient;
        product[i - n] += coefficient;
    }
    G1::msm_bigint(
        &p.0.pk.tau_powers_g1,
        &q.iter().map(|x| x.into_bigint()).collect::<Vec<_>>(),
    )
}
#[test]
fn typed_entries_match_eager_and_independent_polynomial_on_all_shapes() {
    for n in [8, 16, 32, 64, 128, 256] {
        for reduction in [Reduction::Original, Reduction::InstanceAugmentedA] {
            let (p, uk, mut s, mut ledger, z) = initialized(n, reduction);
            let last = p.shape().constraint_rows - 1;
            let target = fixture::assignment(&p, &[last]);
            let t = transition(&p, &s, &z, &target, 2);
            s.begin_update(&t, &mut ledger, &mut rand::rngs::OsRng)
                .unwrap();
            let before = ledger.stats();
            assert!(matches!(
                s.advance_update(0, &mut ledger).unwrap(),
                SelectiveProgress::Pending { .. }
            ));
            assert_eq!(ledger.stats(), before);
            let out = loop {
                match s.advance_update(7, &mut ledger).unwrap() {
                    SelectiveProgress::Pending { .. } => {}
                    SelectiveProgress::Committed { proof, .. } => break proof,
                }
            };
            fixture::verify(&p, &out, &target);
            let core = &s.anchor.as_ref().unwrap().core;
            let eager_a = uk.project(&p, &core.a);
            let eager_b = uk.project(&p, &core.b);
            for entry in s.cache.iter().flatten() {
                let rows = match entry.key.kind {
                    Projection::A => &core.a,
                    Projection::B => &core.b,
                };
                let eager = match entry.key.kind {
                    Projection::A => &eager_a,
                    Projection::B => &eager_b,
                };
                assert_eq!(entry.value, eager[entry.key.row]);
                assert_eq!(entry.value, polynomial_entry(&p, rows, entry.key.row));
            }
            for rows in [&core.a[..], &core.b[..]] {
                for row in [0, n - 1] {
                    let mut task = EntryTask::new(Key {
                        kind: Projection::A,
                        row,
                    });
                    let mut oracle_ledger = SelectiveLedger {
                        identity: s.session.clone(),
                        context: s.binding(),
                        stats: SelectiveStats::default(),
                    };
                    for _ in 0..n + 2 {
                        entry_step(&mut task, rows, &uk, n, &mut oracle_ledger).unwrap();
                    }
                    assert_eq!(task.group, polynomial_entry(&p, rows, row));
                    assert_eq!(oracle_ledger.stats().entry_rows, n);
                    assert_eq!(oracle_ledger.stats().entry_group_calls, n + 1);
                }
            }
            assert_eq!(ledger.stats().attempts_started, 2);
            assert_eq!(ledger.stats().entry_rows, 2 * n);
            assert_eq!(ledger.stats().entry_group_calls, 2 * (n + 1));
            assert_eq!(ledger.stats().entry_field_muls, 4 * (n - 1));
        }
    }
}

struct EntropyFailure {
    draw: usize,
    fail: usize,
}
impl CryptoRng for EntropyFailure {}
impl RngCore for EntropyFailure {
    fn next_u32(&mut self) -> u32 {
        panic!("infallible RNG")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("infallible RNG")
    }
    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("infallible RNG")
    }
    fn try_fill_bytes(&mut self, b: &mut [u8]) -> Result<(), rand::Error> {
        let draw = self.draw;
        self.draw += 1;
        if draw == self.fail {
            return Err(rand::Error::new(std::io::Error::other(
                "synthetic entropy failure",
            )));
        }
        b.fill(0);
        b[0] = 3;
        Ok(())
    }
}
fn snapshot(s: &SelectiveState) -> Vec<u8> {
    let mut b = Vec::new();
    s.current
        .assignment
        .values
        .serialize_compressed(&mut b)
        .unwrap();
    s.current.proof.proof.serialize_compressed(&mut b).unwrap();
    b.extend(s.current.binding.anchor_state);
    b.extend(s.current.binding.generation.to_le_bytes());
    b.extend(s.tick.to_le_bytes());
    for e in &s.cache {
        if let Some(e) = e {
            b.push(1);
            b.push(if e.key.kind == Projection::A { 0 } else { 1 });
            b.extend(e.key.row.to_le_bytes());
            b.extend(e.last_used.to_le_bytes());
            e.value.serialize_compressed(&mut b).unwrap();
        } else {
            b.push(0);
        }
    }
    b
}
#[test]
fn both_entropy_failures_and_late_computed_miss_fault_preserve_committed_state() {
    let (p, _, mut s, mut ledger, z) = initialized(16, Reduction::Original);
    let target = fixture::assignment(&p, &[0]);
    let t = transition(&p, &s, &z, &target, 2);
    let before = snapshot(&s);
    for fail in [0, 1] {
        assert!(matches!(
            s.begin_update(&t, &mut ledger, &mut EntropyFailure { draw: 0, fail }),
            Err(Error::Entropy { .. })
        ));
        assert_eq!(snapshot(&s), before);
        assert_eq!(ledger.stats().attempts_started, 0);
    }
    s.begin_update(&t, &mut ledger, &mut rand::rngs::OsRng)
        .unwrap();
    s.fault_after_actions = Some(p.shape().domain_size + 2);
    assert!(matches!(
        s.advance_update(100, &mut ledger),
        Err(Error::Cancelled)
    ));
    assert_eq!(snapshot(&s), before);
    assert_eq!(ledger.stats().attempts_started, 1);
    assert_eq!(ledger.stats().entries_completed, 1);
    s.fault_after_actions = None;
    fixture::verify(
        &p,
        &s.update(&t, &mut ledger, &mut rand::rngs::OsRng).unwrap(),
        &target,
    );
}
#[test]
fn third_miss_and_fifth_typed_demand_fallback_precede_dense_work() {
    let (p, _, mut s, mut ledger, z) = initialized(16, Reduction::Original);
    let target = fixture::assignment(&p, &[0, 1]);
    let t = transition(&p, &s, &z, &target, 2);
    s.begin_update(&t, &mut ledger, &mut rand::rngs::OsRng)
        .unwrap();
    assert_eq!(
        s.pending.as_ref().unwrap().reason,
        Some(SelectiveFullReason::Misses)
    );
    let before = snapshot(&s);
    let calls = ledger.stats().full_calls_started;
    assert!(matches!(
        s.advance_update(0, &mut ledger).unwrap(),
        SelectiveProgress::Pending {
            completed: 0,
            total: 1
        }
    ));
    assert_eq!(snapshot(&s), before);
    assert_eq!(ledger.stats().full_calls_started, calls);
    assert_eq!(ledger.stats().entry_rows, 0);
    assert_eq!(ledger.stats().attempts_started, 0);
    match s.advance_update(1, &mut ledger).unwrap() {
        SelectiveProgress::Committed { proof, mode, .. } => {
            fixture::verify(&p, &proof, &target);
            assert_eq!(mode, SelectiveStatus::FullOnly);
        }
        _ => panic!("positive full commit"),
    }

    let p = fixture::single_sided_package(16, Reduction::Original);
    let uk = UpdatingMaterial::prepare(&p, Limits::small()).unwrap();
    let mut z = fixture::assignment(&p, &[]);
    let a = p
        .validate_assignment(&fixture::encode(&z), &z[1..6])
        .unwrap();
    let (mut s, _, mut ledger) = SelectiveState::create(
        &p,
        &uk,
        a,
        AnchorBinding::new(&p, [1; 32], [2; 32], 1),
        SelectiveConfig::small(),
        &mut rand::rngs::OsRng,
    )
    .unwrap();
    for (i, flips) in [&[0][..], &[0, 1][..]].iter().enumerate() {
        let target = fixture::assignment(&p, flips);
        let t = transition(&p, &s, &z, &target, (i + 2) as u64);
        fixture::verify(
            &p,
            &s.update(&t, &mut ledger, &mut rand::rngs::OsRng).unwrap(),
            &target,
        );
        z = target;
    }
    let target = fixture::assignment(&p, &[0, 1, p.shape().constraint_rows - 1]);
    let t = transition(&p, &s, &z, &target, 4);
    let before = ledger.stats().entry_rows;
    s.begin_update(&t, &mut ledger, &mut rand::rngs::OsRng)
        .unwrap();
    assert_eq!(
        s.pending.as_ref().unwrap().reason,
        Some(SelectiveFullReason::Demand)
    );
    assert_eq!(ledger.stats().entry_rows, before);
    match s.advance_update(1, &mut ledger).unwrap() {
        SelectiveProgress::Committed { proof, .. } => fixture::verify(&p, &proof, &target),
        _ => panic!("full commit"),
    }
}
#[test]
fn lru_eviction_hits_reversals_and_eighth_started_attempt_then_ninth_full() {
    let p = fixture::single_sided_package(16, Reduction::Original);
    let uk = UpdatingMaterial::prepare(&p, Limits::small()).unwrap();
    let mut z = fixture::assignment(&p, &[]);
    let a = p
        .validate_assignment(&fixture::encode(&z), &z[1..6])
        .unwrap();
    let (mut s, _, mut ledger) = SelectiveState::create(
        &p,
        &uk,
        a,
        AnchorBinding::new(&p, [1; 32], [2; 32], 1),
        SelectiveConfig::small(),
        &mut rand::rngs::OsRng,
    )
    .unwrap();
    let mut generation = 2;
    for (round, row) in [0, 1, 2, 0].into_iter().enumerate() {
        for flips in [&[row][..], &[][..]] {
            let target = fixture::assignment(&p, flips);
            let t = transition(&p, &s, &z, &target, generation);
            fixture::verify(
                &p,
                &s.update(&t, &mut ledger, &mut rand::rngs::OsRng).unwrap(),
                &target,
            );
            generation += 1;
            z = target;
        }
        assert_eq!(ledger.stats().attempts_started, 2 * (round + 1));
        assert!(s.cache_len() <= 4);
    }
    assert!(!s.cache.iter().flatten().any(|e| e.key.row == 1));
    let target = fixture::assignment(&p, &[0]);
    let t = transition(&p, &s, &z, &target, generation);
    let rows = ledger.stats().entry_rows;
    fixture::verify(
        &p,
        &s.update(&t, &mut ledger, &mut rand::rngs::OsRng).unwrap(),
        &target,
    );
    assert_eq!(ledger.stats().entry_rows, rows);
    assert_eq!(ledger.stats().attempts_started, 8);
    z = target;
    generation += 1;
    let target = fixture::assignment(&p, &[]);
    let t = transition(&p, &s, &z, &target, generation);
    s.update(&t, &mut ledger, &mut rand::rngs::OsRng).unwrap();
    z = target;
    generation += 1;
    let target = fixture::assignment(&p, &[p.shape().constraint_rows - 1]);
    let t = transition(&p, &s, &z, &target, generation);
    s.begin_update(&t, &mut ledger, &mut rand::rngs::OsRng)
        .unwrap();
    assert_eq!(
        s.pending.as_ref().unwrap().reason,
        Some(SelectiveFullReason::Attempts)
    );
    match s.advance_update(1, &mut ledger).unwrap() {
        SelectiveProgress::Committed { proof, .. } => fixture::verify(&p, &proof, &target),
        _ => panic!("full commit"),
    }
    assert_eq!(ledger.stats().attempts_started, 8);
    assert_eq!(ledger.stats().entry_rows, rows);
    assert_eq!(s.status(), SelectiveStatus::FullOnly);
}
#[test]
fn c_only_public_change_and_noop_keep_zero_entry_work_original_and_exact_augmented_demand() {
    for reduction in [Reduction::Original, Reduction::InstanceAugmentedA] {
        let (p, _, mut s, mut ledger, z) = initialized(16, reduction);
        let mut target = z.clone();
        target[2] += Fr::ONE;
        *target.last_mut().unwrap() += Fr::ONE;
        let t = transition(&p, &s, &z, &target, 2);
        fixture::verify(
            &p,
            &s.update(&t, &mut ledger, &mut rand::rngs::OsRng).unwrap(),
            &target,
        );
        assert_eq!(
            ledger.stats().attempts_started,
            if reduction == Reduction::Original {
                0
            } else {
                1
            }
        );
        let before = ledger.stats().entry_rows;
        let proof = s.current.proof.proof.clone();
        let noop =
            Transition::new(&p, s.binding(), 3, &[], &target[1..6], Limits::small()).unwrap();
        fixture::verify(
            &p,
            &s.update(&noop, &mut ledger, &mut rand::rngs::OsRng)
                .unwrap(),
            &target,
        );
        assert_eq!(ledger.stats().entry_rows, before);
        assert_ne!(s.current.proof.proof, proof);
    }
}
#[test]
fn reload_and_holder_action_invalidation_lose_cache_without_refunding_external_ledger() {
    let (p, uk, mut s, mut ledger, z) = initialized(16, Reduction::Original);
    let target = fixture::assignment(&p, &[0]);
    let t = transition(&p, &s, &z, &target, 2);
    s.update(&t, &mut ledger, &mut rand::rngs::OsRng).unwrap();
    let before = snapshot(&s);
    let attempts = ledger.stats().attempts_started;
    s.begin_reload(&mut ledger, &mut rand::rngs::OsRng).unwrap();
    s.advance_update(0, &mut ledger).unwrap();
    assert_eq!(snapshot(&s), before);
    match s.advance_update(1, &mut ledger).unwrap() {
        SelectiveProgress::Committed { proof, .. } => fixture::verify(&p, &proof, &target),
        _ => panic!("reload commit"),
    }
    assert_eq!(s.status(), SelectiveStatus::FullOnly);
    assert_eq!(s.cache_len(), 0);
    assert_eq!(ledger.stats().attempts_started, attempts);
    let binding = s.binding();
    drop(s);
    let a = p
        .validate_assignment(&fixture::encode(&target), &target[1..6])
        .unwrap();
    let (mut s, proof) = SelectiveState::full_after_restart(
        &p,
        &uk,
        a,
        binding,
        SelectiveConfig::small(),
        &mut ledger,
        &mut rand::rngs::OsRng,
    )
    .unwrap();
    fixture::verify(&p, &proof, &target);
    assert_eq!(s.status(), SelectiveStatus::FullOnly);
    assert_eq!(ledger.stats().attempts_started, attempts);
    let a = p
        .validate_assignment(&fixture::encode(&z), &z[1..6])
        .unwrap();
    s.begin_full_for_binding(a, [8; 32], [9; 32], 3, &mut ledger, &mut rand::rngs::OsRng)
        .unwrap();
    match s.advance_update(1, &mut ledger).unwrap() {
        SelectiveProgress::Committed { proof, .. } => fixture::verify(&p, &proof, &z),
        _ => panic!("binding commit"),
    }
    assert_eq!(s.binding().credential, [8; 32]);
    assert_eq!(s.binding().action, [9; 32]);
    assert_eq!(s.status(), SelectiveStatus::FullOnly);
    assert!(matches!(
        s.update(&t, &mut ledger, &mut rand::rngs::OsRng),
        Err(Error::AnchorBinding)
    ));
}
#[test]
fn row_group_field_caps_fallback_and_private_caps_refuse_before_validation_entropy() {
    for which in 0..3 {
        let (p, _, mut s, mut ledger, z) = initialized(16, Reduction::Original);
        let target = fixture::assignment(&p, &[0]);
        if which == 0 {
            s.config.max_call_row_visits = 0;
        }
        if which == 1 {
            s.config.max_call_group_calls = 0;
        }
        if which == 2 {
            s.config.max_call_field_muls = 0;
        }
        let t = transition(&p, &s, &z, &target, 2);
        let before = ledger.stats().entry_rows;
        s.begin_update(&t, &mut ledger, &mut rand::rngs::OsRng)
            .unwrap();
        assert_eq!(
            s.pending.as_ref().unwrap().reason,
            Some(SelectiveFullReason::EntryWork)
        );
        match s.advance_update(1, &mut ledger).unwrap() {
            SelectiveProgress::Committed { proof, .. } => fixture::verify(&p, &proof, &target),
            _ => panic!("full commit"),
        }
        assert_eq!(ledger.stats().entry_rows, before);
    }
    let (p, _, mut s, mut ledger, z) = initialized(16, Reduction::Original);
    let target = fixture::assignment(&p, &[0]);
    let t = transition(&p, &s, &z, &target, 2);
    s.config.max_private_bytes = s.private_structural_bytes().unwrap();
    let before = ledger.stats();
    let image = snapshot(&s);
    let mut rng = EntropyFailure { draw: 0, fail: 0 };
    assert!(matches!(
        s.begin_update(&t, &mut ledger, &mut rng),
        Err(Error::Bound("selective private bytes"))
    ));
    assert_eq!(rng.draw, 0);
    assert_eq!(ledger.stats(), before);
    assert_eq!(snapshot(&s), image);
    s.config.max_private_bytes = 32 * 1024 * 1024;
    s.config.max_total_bytes =
        s.private_structural_bytes().unwrap() + s.shared_public_structural_bytes();
    assert!(matches!(
        s.begin_update(&t, &mut ledger, &mut rng),
        Err(Error::Bound("selective total bytes"))
    ));
    assert_eq!(ledger.stats(), before);
}
#[test]
fn cancellation_spends_started_attempt_but_preserves_cache_proof_generation_and_lru() {
    let (p, _, mut s, mut ledger, z) = initialized(16, Reduction::Original);
    let target = fixture::assignment(&p, &[0]);
    let t = transition(&p, &s, &z, &target, 2);
    let before = s.binding();
    let proof = s.current.proof.proof.clone();
    s.begin_update(&t, &mut ledger, &mut rand::rngs::OsRng)
        .unwrap();
    s.advance_update(3, &mut ledger).unwrap();
    assert_eq!(ledger.stats().attempts_started, 1);
    assert_eq!(ledger.stats().entry_rows, 3);
    s.cancel_update(&mut ledger).unwrap();
    assert_eq!(s.binding(), before);
    assert_eq!(s.current.proof.proof, proof);
    assert_eq!(s.cache_len(), 0);
    assert_eq!(s.tick, 0);
    fixture::verify(
        &p,
        &s.update(&t, &mut ledger, &mut rand::rngs::OsRng).unwrap(),
        &target,
    );
    assert_eq!(ledger.stats().attempts_started, 3);
}
#[test]
fn tiny_current_change_with_accumulated_anchor_demand_latches_full_before_entry_scan() {
    let (p, _, mut s, mut ledger, mut z) = initialized(16, Reduction::Original);
    for (i, flips) in [&[0][..], &[0, 1][..], &[0, 1, 2][..]].iter().enumerate() {
        let target = fixture::assignment(&p, flips);
        let t = transition(&p, &s, &z, &target, (i + 2) as u64);
        let prior_rows = ledger.stats().entry_rows;
        let out = s.update(&t, &mut ledger, &mut rand::rngs::OsRng).unwrap();
        fixture::verify(&p, &out, &target);
        if i == 2 {
            assert_eq!(ledger.stats().entry_rows, prior_rows);
            assert_eq!(s.status(), SelectiveStatus::FullOnly);
            assert_eq!(s.cache_len(), 0);
        }
        z = target;
    }
    let target = fixture::assignment(&p, &[]);
    let t = transition(&p, &s, &z, &target, 5);
    let prior = ledger.stats().entry_rows;
    fixture::verify(
        &p,
        &s.update(&t, &mut ledger, &mut rand::rngs::OsRng).unwrap(),
        &target,
    );
    assert_eq!(ledger.stats().entry_rows, prior);
    assert_eq!(s.status(), SelectiveStatus::FullOnly);
}

#[test]
fn common_randomizers_match_all_four_fresh_full_and_eager_anchor_components() {
    for reduction in [Reduction::Original, Reduction::InstanceAugmentedA] {
        let (p, uk, mut s, mut l, z) = initialized(32, reduction);
        let target = fixture::assignment(&p, &[0]);
        let t = transition(&p, &s, &z, &target, 2);
        s.begin_update(
            &t,
            &mut l,
            &mut EntropyFailure {
                draw: 0,
                fail: usize::MAX,
            },
        )
        .unwrap();
        assert!(matches!(
            s.advance_update(2 * (32 + 2), &mut l).unwrap(),
            SelectiveProgress::Pending { .. }
        ));
        let x = s.pending.as_ref().unwrap();
        let core = &s.anchor.as_ref().unwrap().core;
        let mut oracle = SelectiveLedger {
            identity: s.session.clone(),
            context: s.binding(),
            stats: SelectiveStats::default(),
        };
        let actual = correct(&p, &uk, core, x, &s.cache, s.config, &mut oracle).unwrap();
        let values = p
            .validate_assignment(&fixture::encode(&target), &target[1..6])
            .unwrap();
        let full = capture(&p, values, x.r, x.s).unwrap();
        assert_eq!(actual, (full.a_g1, full.b_g1, full.b_g2, full.c_g1));

        let values = p
            .validate_assignment(&fixture::encode(&z), &z[1..6])
            .unwrap();
        let eager_core = capture(&p, values, core.r, core.s).unwrap();
        let qa = uk.project(&p, &eager_core.a);
        let qb = uk.project(&p, &eager_core.b);
        let eager =
            crate::Anchor::from_parts(s.anchor.as_ref().unwrap().binding, eager_core, qa, qb)
                .unwrap();
        // Eager anchored raw comparator also covers B1, which the ordinary proof omits.
        let pk = &p.0.pk;
        let mut a = eager.core.a_g1 + pk.delta_g1 * (x.r - eager.core.r);
        let mut b1 = eager.core.b_g1 + pk.delta_g1 * (x.s - eager.core.s);
        let mut b2 = eager.core.b_g2 + pk.vk.delta_g2 * (x.s - eager.core.s);
        let mut private = G1::ZERO;
        for &(j, d) in &x.delta {
            a += pk.u_g1[j] * d;
            b1 += pk.v_g1[j] * d;
            b2 += pk.v_g2[j] * d;
            if j >= p.shape().instance_len {
                private += pk.t_p_g1[j - p.shape().instance_len] * d;
            }
        }
        let mut quotient = uk
            .cross(&x.rows.a, &x.rows.b, Limits::small().max_pair_work)
            .unwrap();
        for &(i, d) in &x.rows.a {
            quotient += eager.q_b[i] * d;
        }
        for &(i, d) in &x.rows.b {
            quotient += eager.q_a[i] * d;
        }
        let c = eager.core.c_g1 + a * x.s - eager.core.a_g1 * eager.core.s + b1 * x.r
            - eager.core.b_g1 * eager.core.r
            - pk.delta_g1 * (x.r * x.s - eager.core.r * eager.core.s)
            + private
            + quotient;
        assert_eq!(actual, (a, b1, b2, c));
        let et = Transition::new(
            &p,
            eager.binding(),
            2,
            &fixture::delta(&z, &target),
            &target[1..6],
            Limits::small(),
        )
        .unwrap();
        let ep = eager
            .update(
                &p,
                &uk,
                &et,
                Limits::small(),
                &mut EntropyFailure {
                    draw: 0,
                    fail: usize::MAX,
                },
            )
            .unwrap();
        match s.advance_update(1, &mut l).unwrap() {
            SelectiveProgress::Committed { proof, .. } => {
                assert_eq!(proof.proof, ep.proof);
                assert_eq!(
                    proof.proof,
                    statement(&full, s.binding(), target[1..6].to_vec()).proof
                );
                fixture::verify(&p, &proof, &target);
            }
            _ => panic!("proof commit"),
        }
    }
}

#[test]
fn zero_sparse_and_full_width_anchor_rows_have_exact_endpoint_entries() {
    let (p, uk, s, _, _) = initialized(32, Reduction::Original);
    let n = p.shape().domain_size;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x503245376f);
    let dense = (0..n).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
    let mut sparse = vec![Fr::ZERO; n];
    sparse[0] = Fr::from(7);
    sparse[n - 1] = Fr::from(13);
    for rows in [vec![Fr::ZERO; n], sparse, dense] {
        let eager = uk.project(&p, &rows);
        for row in [0, n - 1] {
            let mut task = EntryTask::new(Key {
                kind: Projection::B,
                row,
            });
            let mut l = SelectiveLedger {
                identity: s.session.clone(),
                context: s.binding(),
                stats: SelectiveStats::default(),
            };
            for _ in 0..n + 2 {
                entry_step(&mut task, &rows, &uk, n, &mut l).unwrap();
            }
            assert_eq!(task.group, eager[row]);
            assert_eq!(task.group, polynomial_entry(&p, &rows, row));
            assert_eq!(l.stats.entry_rows, n);
            assert_eq!(l.stats.entry_group_calls, n + 1);
            assert_eq!(l.stats.entry_field_muls, 2 * (n - 1));
            if rows.iter().all(|x| x.is_zero()) {
                assert!(task.group.is_zero());
            }
        }
    }
}

#[test]
fn every_streamed_action_boundary_cancels_without_installing_any_partial_state() {
    let p = fixture::package(8, Reduction::Original, 3);
    let uk = UpdatingMaterial::prepare(&p, Limits::small()).unwrap();
    let z = fixture::assignment(&p, &[]);
    let target = fixture::assignment(&p, &[0]);
    let total = 2 * (8 + 2) + 1;
    // Each prefix uses a distinct, explicitly cold session; no ticket is reset within a session.
    for prefix in 0..total {
        let (mut s, mut l) = state_for(&p, &uk, &z);
        let image = snapshot(&s);
        let t = transition(&p, &s, &z, &target, 2);
        s.begin_update(&t, &mut l, &mut rand::rngs::OsRng).unwrap();
        assert!(
            matches!(s.advance_update(prefix,&mut l).unwrap(),SelectiveProgress::Pending { completed,.. } if completed==prefix)
        );
        let charged = l.stats();
        s.advance_update(0, &mut l).unwrap();
        assert_eq!(l.stats(), charged);
        assert_eq!(snapshot(&s), image);
        s.cancel_update(&mut l).unwrap();
        assert_eq!(snapshot(&s), image);
        assert_eq!(
            l.stats.attempts_started,
            if prefix == 0 {
                0
            } else if prefix <= 10 {
                1
            } else {
                2
            }
        );
        assert_eq!(
            l.stats.entry_rows,
            prefix.min(8) + prefix.saturating_sub(10).min(8)
        );
        assert_eq!(s.status(), SelectiveStatus::Selective);
    }
    // A staged full proof is also cancellable before its sole positive commit action.
    let (mut s, mut l) = state_for(&p, &uk, &z);
    let image = snapshot(&s);
    let target = fixture::assignment(&p, &[0, 1]);
    let t = transition(&p, &s, &z, &target, 2);
    s.begin_update(&t, &mut l, &mut rand::rngs::OsRng).unwrap();
    assert_eq!(l.stats.full_calls_started, 2);
    s.advance_update(0, &mut l).unwrap();
    s.cancel_update(&mut l).unwrap();
    assert_eq!(snapshot(&s), image);
    assert_eq!(l.stats.full_calls_started, 2);
    assert_eq!(l.stats.entry_rows, 0);
}

#[test]
fn compact_assignment_and_fanout_preflight_use_exact_full_anchor_support() {
    for reduction in [Reduction::Original, Reduction::InstanceAugmentedA] {
        let p = fixture::compact_package(32, reduction);
        assert!(p.shape().assignment_len < p.shape().domain_size);
        let uk = UpdatingMaterial::prepare(&p, Limits::small()).unwrap();
        let z = fixture::assignment(&p, &[]);
        let (mut s, mut l) = state_for(&p, &uk, &z);
        let target = fixture::assignment(&p, &[0]);
        let t = transition(&p, &s, &z, &target, 2);
        fixture::verify(
            &p,
            &s.update(&t, &mut l, &mut rand::rngs::OsRng).unwrap(),
            &target,
        );
        assert_eq!(l.stats.attempts_started, 2);
        assert_eq!(s.status(), SelectiveStatus::Selective);

        let p = fixture::fanout_package(32, reduction);
        let uk = UpdatingMaterial::prepare(&p, Limits::small()).unwrap();
        let z = fixture::assignment(&p, &[]);
        let (mut s, mut l) = state_for(&p, &uk, &z);
        let target = fixture::assignment(&p, &[0]);
        let t = transition(&p, &s, &z, &target, 2);
        assert_eq!(t.normalized_count(), 1);
        s.begin_update(&t, &mut l, &mut rand::rngs::OsRng).unwrap();
        assert_eq!(
            s.pending.as_ref().unwrap().reason,
            Some(SelectiveFullReason::Demand)
        );
        assert_eq!(l.stats.entry_rows, 0);
        assert_eq!(l.stats.attempts_started, 0);
        match s.advance_update(1, &mut l).unwrap() {
            SelectiveProgress::Committed { proof, mode, .. } => {
                fixture::verify(&p, &proof, &target);
                assert_eq!(mode, SelectiveStatus::FullOnly);
            }
            _ => panic!("fanout full commit"),
        }
    }
}

#[test]
fn normalized_current_cap_identity_and_statement_errors_precede_entropy_and_entry_work() {
    let (p, _, mut s, mut l, z) = initialized(16, Reduction::Original);
    let target = fixture::assignment(&p, &[0, 1]);
    let t = transition(&p, &s, &z, &target, 2);
    s.config.operation.max_delta_entries = 1;
    let image = snapshot(&s);
    let stats = l.stats();
    let mut rng = EntropyFailure { draw: 0, fail: 0 };
    assert!(matches!(
        s.begin_update(&t, &mut l, &mut rng),
        Err(Error::Bound("selective current delta entries"))
    ));
    assert_eq!(l.stats(), stats);
    assert_eq!(rng.draw, 0);
    assert_eq!(snapshot(&s), image);
    s.config.operation.max_delta_entries = 4096;
    for which in 0..5 {
        let mut binding = s.binding();
        match which {
            0 => binding.credential[0] ^= 1,
            1 => binding.action[0] ^= 1,
            2 => binding.anchor_state[0] ^= 1,
            3 => binding.generation += 1,
            _ => binding.package.circuit_digest[0] ^= 1,
        }
        // The public constructor rejects package drift; other exact binding changes reach the engine.
        let t = Transition::new(
            &p,
            binding,
            binding.generation + 1,
            &fixture::delta(&z, &target),
            &target[1..6],
            Limits::small(),
        );
        if which == 4 {
            assert!(matches!(t, Err(Error::AnchorBinding)));
        } else {
            assert!(matches!(
                s.begin_update(&t.unwrap(), &mut l, &mut rng),
                Err(Error::AnchorBinding)
            ));
        }
        assert_eq!(l.stats(), stats);
        assert_eq!(snapshot(&s), image);
    }
    let mut wrong_public = target[1..6].to_vec();
    wrong_public[0] += Fr::ONE;
    let t = Transition::new(
        &p,
        s.binding(),
        2,
        &fixture::delta(&z, &target),
        &wrong_public,
        Limits::small(),
    )
    .unwrap();
    assert!(matches!(
        s.begin_update(&t, &mut l, &mut rng),
        Err(Error::PublicStatement)
    ));
    let mut invalid = z.clone();
    invalid[6] = Fr::from(2);
    let t = transition(&p, &s, &z, &invalid, 2);
    assert!(matches!(
        s.begin_update(&t, &mut l, &mut rng),
        Err(Error::Unsatisfied { .. })
    ));
    assert_eq!(rng.draw, 0);
    assert_eq!(l.stats.entry_rows, 0);
    assert_eq!(snapshot(&s), image);

    let (_, mut other) = state_for(&p, &s.uk, &z);
    let t = transition(&p, &s, &z, &target, 2);
    assert!(matches!(
        s.begin_update(&t, &mut other, &mut rng),
        Err(Error::AnchorBinding)
    ));
    assert_eq!(other.stats.updates_started, 0);
    assert_eq!(rng.draw, 0);
}

#[test]
fn anchor_touch_pair_correction_caps_choose_paid_full_or_refuse_its_allowance() {
    for which in 0..4 {
        let (p, _, mut s, mut l, z) = initialized(16, Reduction::Original);
        let target = fixture::assignment(&p, &[0]);
        let expected = match which {
            0 => {
                s.config.max_anchor_delta_entries = 0;
                SelectiveFullReason::AnchorDelta
            }
            1 => {
                s.config.max_touched_entries = 0;
                SelectiveFullReason::TouchedEntries
            }
            2 => {
                s.config.operation.max_pair_work = 0;
                SelectiveFullReason::PairWork
            }
            _ => {
                s.config.max_correction_group_calls = 0;
                SelectiveFullReason::CorrectionWork
            }
        };
        let t = transition(&p, &s, &z, &target, 2);
        s.begin_update(&t, &mut l, &mut rand::rngs::OsRng).unwrap();
        assert_eq!(s.pending.as_ref().unwrap().reason, Some(expected));
        assert_eq!(l.stats.entry_rows, 0);
        assert_eq!(l.stats.attempts_started, 0);
        match s.advance_update(1, &mut l).unwrap() {
            SelectiveProgress::Committed { proof, .. } => fixture::verify(&p, &proof, &target),
            _ => panic!("bounded full"),
        }
    }
    let (p, _, mut s, mut l, z) = initialized(16, Reduction::Original);
    s.config.max_full_calls = 1; // initial capture already spent the only allowed full call
    let target = fixture::assignment(&p, &[0, 1]);
    let t = transition(&p, &s, &z, &target, 2);
    let image = snapshot(&s);
    let mut rng = EntropyFailure { draw: 0, fail: 0 };
    assert!(matches!(
        s.begin_update(&t, &mut l, &mut rng),
        Err(Error::Bound("selective full calls"))
    ));
    assert_eq!(rng.draw, 0);
    assert_eq!(l.stats.entry_rows, 0);
    assert_eq!(l.stats.full_calls_started, 1);
    assert_eq!(snapshot(&s), image);
    s.config.operation.max_domain = 8;
    assert!(matches!(
        s.begin_update(&t, &mut l, &mut rng),
        Err(Error::Bound("domain/assignment"))
    ));
    assert_eq!(rng.draw, 0);
    assert_eq!(snapshot(&s), image);
}

#[test]
fn malformed_private_entry_cursor_rejects_before_an_operation_or_commit() {
    let (p, uk, mut s, mut l, z) = initialized(16, Reduction::Original);
    let target = fixture::assignment(&p, &[0]);
    let t = transition(&p, &s, &z, &target, 2);
    let image = snapshot(&s);
    s.begin_update(&t, &mut l, &mut rand::rngs::OsRng).unwrap();
    s.advance_update(1, &mut l).unwrap();
    let stats = l.stats();
    s.pending.as_mut().unwrap().task.as_mut().unwrap().next = 17;
    assert!(matches!(
        s.advance_update(1, &mut l),
        Err(Error::Bound("selective entry cursor"))
    ));
    assert_eq!(l.stats.entry_rows, stats.entry_rows);
    assert_eq!(l.stats.entry_group_calls, stats.entry_group_calls);
    assert_eq!(snapshot(&s), image);
    for (row, next, finish) in [(16, 0, 0), (0, 17, 0), (0, 16, 3)] {
        let mut task = EntryTask::new(Key {
            kind: Projection::A,
            row,
        });
        task.next = next;
        task.finish = finish;
        let before = l.stats();
        assert!(matches!(
            entry_step(&mut task, &[Fr::ZERO; 16], &uk, 16, &mut l),
            Err(Error::Bound("selective entry cursor"))
        ));
        assert_eq!(l.stats(), before);
    }
}

#[test]
fn zero_initial_full_allowance_rejects_before_rng_copy_or_capture() {
    let p = fixture::package(8, Reduction::Original, 3);
    let uk = UpdatingMaterial::prepare(&p, Limits::small()).unwrap();
    let z = fixture::assignment(&p, &[]);
    let a = p
        .validate_assignment(&fixture::encode(&z), &z[1..6])
        .unwrap();
    let mut config = SelectiveConfig::small();
    config.max_full_calls = 0;
    let mut rng = EntropyFailure { draw: 0, fail: 0 };
    assert!(matches!(
        SelectiveState::create(
            &p,
            &uk,
            a,
            AnchorBinding::new(&p, [1; 32], [2; 32], 1),
            config,
            &mut rng
        ),
        Err(Error::Bound("selective full calls"))
    ));
    assert_eq!(rng.draw, 0);
}

#[test]
fn failed_validation_reserves_matrix_and_current_gather_work_without_entropy_or_commit() {
    let (p, uk, mut s, mut l, z) = initialized(16, Reduction::Original);
    let mut invalid = z.clone();
    invalid[6] = Fr::from(2);
    let t = transition(&p, &s, &z, &invalid, 2);
    let image = snapshot(&s);
    let before = l.stats();
    let expected = current_touches(&p, &t).unwrap();
    let mut rng = EntropyFailure { draw: 0, fail: 0 };
    assert!(matches!(
        s.begin_update(&t, &mut l, &mut rng),
        Err(Error::Unsatisfied { .. })
    ));
    assert_eq!(
        l.stats.validation_entries_reserved - before.validation_entries_reserved,
        matrix_entries(&p).unwrap()
    );
    assert_eq!(
        l.stats.assignment_copied_elements_reserved - before.assignment_copied_elements_reserved,
        z.len()
    );
    assert_eq!(
        [
            l.stats.current_a_touched_entries_reserved,
            l.stats.current_b_touched_entries_reserved,
            l.stats.current_c_touched_entries_reserved
        ],
        expected
    );
    assert_eq!(l.stats.anchor_delta_scanned_elements, 0);
    assert_eq!(rng.draw, 0);
    assert_eq!(snapshot(&s), image);

    // Private fault injection into the opaque validated type exercises the full-validation error path.
    let a = ValidatedAssignment {
        package: p.identity(),
        values: invalid.clone(),
    };
    let before = l.stats();
    assert!(matches!(
        s.begin_full_for_binding(a, [3; 32], [4; 32], 2, &mut l, &mut rng),
        Err(Error::Unsatisfied { .. })
    ));
    assert_eq!(
        l.stats.validation_entries_reserved - before.validation_entries_reserved,
        matrix_entries(&p).unwrap()
    );
    assert_eq!(
        l.stats.assignment_copied_elements_reserved - before.assignment_copied_elements_reserved,
        z.len()
    );
    assert_eq!(
        l.stats.current_a_touched_entries_reserved,
        before.current_a_touched_entries_reserved
    );
    assert_eq!(
        l.stats.current_b_touched_entries_reserved,
        before.current_b_touched_entries_reserved
    );
    assert_eq!(
        l.stats.current_c_touched_entries_reserved,
        before.current_c_touched_entries_reserved
    );
    assert_eq!(rng.draw, 0);
    assert_eq!(snapshot(&s), image);
    let binding = s.binding();
    let a = ValidatedAssignment {
        package: p.identity(),
        values: invalid,
    };
    let before = l.stats();
    assert!(matches!(
        SelectiveState::full_after_restart(
            &p,
            &uk,
            a,
            binding,
            SelectiveConfig::small(),
            &mut l,
            &mut rng
        ),
        Err(Error::Unsatisfied { .. })
    ));
    assert_eq!(
        l.stats.validation_entries_reserved - before.validation_entries_reserved,
        matrix_entries(&p).unwrap()
    );
    assert_eq!(
        l.stats.assignment_copied_elements_reserved - before.assignment_copied_elements_reserved,
        z.len()
    );
    assert_eq!(rng.draw, 0);
    assert_eq!(snapshot(&s), image);
}

#[test]
fn successful_and_cancelled_dispatch_counts_both_anchor_scans_and_all_current_matrices() {
    let (p, _, mut s, mut l, z) = initialized(16, Reduction::Original);
    let mut target = z.clone();
    target[2] += Fr::ONE;
    *target.last_mut().unwrap() += Fr::ONE;
    let t = transition(&p, &s, &z, &target, 2);
    let image = snapshot(&s);
    let before = l.stats();
    let expected = current_touches(&p, &t).unwrap();
    assert!(expected[2] > 0);
    s.begin_update(&t, &mut l, &mut rand::rngs::OsRng).unwrap();
    assert_eq!(
        l.stats.anchor_delta_scanned_elements - before.anchor_delta_scanned_elements,
        2 * z.len()
    );
    assert_eq!(
        [
            l.stats.current_a_touched_entries_reserved,
            l.stats.current_b_touched_entries_reserved,
            l.stats.current_c_touched_entries_reserved
        ],
        expected
    );
    s.advance_update(0, &mut l).unwrap();
    s.cancel_update(&mut l).unwrap();
    assert_eq!(l.stats.anchor_delta_scanned_elements, 2 * z.len());
    assert_eq!(snapshot(&s), image);
    fixture::verify(
        &p,
        &s.update(&t, &mut l, &mut rand::rngs::OsRng).unwrap(),
        &target,
    );
    assert_eq!(l.stats.anchor_delta_scanned_elements, 4 * z.len());
    assert_eq!(
        [
            l.stats.current_a_touched_entries_reserved,
            l.stats.current_b_touched_entries_reserved,
            l.stats.current_c_touched_entries_reserved
        ],
        expected.map(|x| 2 * x)
    );
}
