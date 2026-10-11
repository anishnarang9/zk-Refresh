use ark_bn254::{Fr, G1Projective as G1};
use ark_ec::PrimeGroup;
use ark_ff::{AdditiveGroup, Field, Zero};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use dynark_bn254::Error;
use rand::{Rng, SeedableRng};
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicUsize, Ordering},
};

#[path = "../src/cross.rs"]
mod cross;
use cross::{
    cross_coefficients, cross_coefficients_observed, encode_cross, required_fft_size, CrossLimits,
    CrossMethod, CrossPhase, CrossPhaseEvent,
};

static PAIR_VISITS: AtomicUsize = AtomicUsize::new(0);
const CASE_CAP: usize = 1_000_000;
const INVOCATION_CAP: usize = 20_000_000;
// Two internal differential tests each independently cap themselves at 1m.
const UNIT_TEST_RESERVATION: usize = 2_000_000;
const FIELD_SEED: u64 = 0x7434_6669_656c_6431;
const QUOTIENT_SEED: u64 = 0x7434_7175_6f74_6931;

fn charge_pairs(a: usize, b: usize) {
    let pairs = a.checked_mul(b).expect("oracle pair overflow");
    assert!(
        pairs <= CASE_CAP,
        "oracle case exceeds predeclared pair cap"
    );
    PAIR_VISITS
        .try_update(Ordering::SeqCst, Ordering::SeqCst, |old| {
            old.checked_add(pairs)
                .filter(|n| *n <= INVOCATION_CAP - UNIT_TEST_RESERVATION)
        })
        .expect("oracle invocation pair cap");
}

fn limits() -> CrossLimits {
    CrossLimits {
        max_domain: 1024,
        max_input_entries: 4096,
        max_union_support: 1024,
        max_fft_size: 4096,
        max_allocation_bytes: 64 * 1024 * 1024,
        max_pair_visits: 1_000_000,
    }
}

fn weights(domain: &GeneralEvaluationDomain<Fr>) -> Vec<Fr> {
    (0..domain.size())
        .map(|i| {
            if i == 0 {
                Fr::ZERO
            } else {
                let x = domain.element(i);
                x / (Fr::ONE - x) * domain.size_inv()
            }
        })
        .collect()
}

#[test]
fn finite_part_matches_direct_field_sums() {
    let domain = GeneralEvaluationDomain::<Fr>::new(8).unwrap();
    let a = [(0, Fr::from(2)), (1, Fr::from(3)), (7, Fr::from(5))];
    let b = [(0, Fr::from(7)), (1, Fr::from(11)), (7, Fr::from(13))];
    let got = cross_coefficients(
        &domain,
        &weights(&domain),
        &a,
        &b,
        CrossMethod::Fast,
        limits(),
    )
    .unwrap();
    charge_pairs(a.len(), b.len());
    charge_pairs(a.len(), a.len());
    let mut expected = vec![Fr::ZERO; a.len()];
    for (slot, (i, ai)) in a.iter().enumerate() {
        let xi = domain.element(*i);
        for (j, bj) in &b {
            if i != j {
                let xj = domain.element(*j);
                expected[slot] += *ai * *bj * xj / (xi - xj) * domain.size_inv();
            }
        }
        for (j, aj) in &a {
            if i != j {
                let xj = domain.element(*j);
                expected[slot] += b[slot].1 * *aj * xj / (xi - xj) * domain.size_inv();
            }
        }
    }
    assert!(expected.iter().any(|x| !x.is_zero()));
    assert_eq!(got.indices, vec![0, 1, 7]);
    assert_eq!(got.lagrange, expected);
    assert_eq!(got.diagonal, vec![Fr::from(14), Fr::from(33), Fr::from(65)]);
}

fn normalized(raw: &[(usize, Fr)]) -> BTreeMap<usize, Fr> {
    let mut out = BTreeMap::<usize, Fr>::new();
    for (i, x) in raw {
        *out.entry(*i).or_default() += x;
    }
    out.retain(|_, x| !x.is_zero());
    out
}

fn direct(
    domain: &GeneralEvaluationDomain<Fr>,
    a: &[(usize, Fr)],
    b: &[(usize, Fr)],
) -> (Vec<usize>, Vec<Fr>, Vec<Fr>) {
    let a = normalized(a);
    let b = normalized(b);
    let indices = a
        .keys()
        .chain(b.keys())
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    charge_pairs(indices.len(), a.len());
    charge_pairs(indices.len(), b.len());
    let mut coefficients = Vec::new();
    let mut diagonal = Vec::new();
    for i in &indices {
        let ai = a.get(i).copied().unwrap_or(Fr::ZERO);
        let bi = b.get(i).copied().unwrap_or(Fr::ZERO);
        let xi = domain.element(*i);
        let conv = |values: &BTreeMap<usize, Fr>| {
            values
                .iter()
                .filter(|(j, _)| *j != i)
                .map(|(j, value)| {
                    let xj = domain.element(*j);
                    *value * xj / (xi - xj) * domain.size_inv()
                })
                .sum::<Fr>()
        };
        coefficients.push(ai * conv(&b) + bi * conv(&a));
        diagonal.push(ai * bi);
    }
    (indices, coefficients, diagonal)
}

fn check_field(domain: &GeneralEvaluationDomain<Fr>, a: &[(usize, Fr)], b: &[(usize, Fr)]) {
    let (indices, lagrange, diagonal) = direct(domain, a, b);
    for method in [
        CrossMethod::Quadratic,
        CrossMethod::Fast,
        CrossMethod::FastOrQuadratic,
    ] {
        if method == CrossMethod::Quadratic {
            charge_pairs(normalized(a).len(), normalized(b).len());
        }
        let got = cross_coefficients(domain, &weights(domain), a, b, method, limits()).unwrap();
        assert_eq!(got.domain_size, domain.size());
        assert_eq!(got.indices, indices);
        assert_eq!(got.lagrange, lagrange);
        assert_eq!(got.diagonal, diagonal);
        assert_eq!(got.stats.input_entries_a, a.len());
        assert_eq!(got.stats.input_entries_b, b.len());
        assert_eq!(got.stats.nonzero_a, normalized(a).len());
        assert_eq!(got.stats.nonzero_b, normalized(b).len());
        assert_eq!(got.stats.union_support, indices.len());
        assert!(got.stats.group_scalar_muls <= 2 * indices.len());
        assert!(got.stats.preflight_allocation_bytes <= limits().max_allocation_bytes);
        if method == CrossMethod::Quadratic {
            assert_eq!(
                got.stats.quadratic_pair_visits,
                normalized(a).len() * normalized(b).len()
            );
            assert_eq!(got.stats.fft_calls, 0);
        } else {
            assert_eq!(got.stats.quadratic_pair_visits, 0);
            assert_eq!(got.stats.used_method, CrossMethod::Fast);
            assert!(!got.stats.bounded_fallback);
            assert!(got.stats.fft_max_size <= required_fft_size(indices.len()).unwrap());
            if indices.len() > 1 {
                assert!(got.stats.fft_calls > 0);
                assert!(got.stats.polynomial_divisions > 0);
                assert_eq!(got.stats.derivative_evaluations, 4 * indices.len());
            }
        }
    }
}

#[test]
fn canonical_empty_singleton_overlap_disjoint_cancel_and_uneven_support() {
    for n in [2, 4, 8, 16, 32] {
        let d = GeneralEvaluationDomain::<Fr>::new(n).unwrap();
        let f = Fr::from;
        let cases = vec![
            (vec![], vec![]),
            (vec![(0, f(2))], vec![]),
            (vec![], vec![(n - 1, f(3))]),
            (vec![(n - 1, f(2))], vec![(n - 1, f(3))]),
            (vec![(0, f(2))], vec![(n - 1, f(3))]),
            (
                vec![(n - 1, f(2)), (0, f(7)), (0, -f(7)), (n - 1, f(1))],
                vec![(n - 1, f(3))],
            ),
            (
                vec![(0, f(2)), (0, -f(2))],
                vec![(n - 1, f(3)), (n - 1, -f(3))],
            ),
            (
                vec![(0, f(3)), (n - 1, f(5))],
                (0..n).map(|i| (i, f((i + 2) as u64))).collect(),
            ),
            (
                (0..n).rev().map(|i| (i, f((i + 1) as u64))).collect(),
                vec![(n - 1, f(4))],
            ),
        ];
        for (a, b) in cases {
            check_field(&d, &a, &b);
        }
    }
}

#[test]
fn randomized_normalized_coefficients_match_field_oracle() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(FIELD_SEED);
    let mut cases = 0;
    for n in [2, 4, 8, 16, 32, 64, 128] {
        let d = GeneralEvaluationDomain::<Fr>::new(n).unwrap();
        for _ in 0..16 {
            let a = (0..rng.gen_range(0..=2 * n))
                .map(|_| {
                    (
                        rng.gen_range(0..n),
                        Fr::from(rng.gen_range(0..19u64)) - Fr::from(9),
                    )
                })
                .collect::<Vec<_>>();
            let b = (0..rng.gen_range(0..=2 * n))
                .map(|_| {
                    (
                        rng.gen_range(0..n),
                        Fr::from(rng.gen_range(0..19u64)) - Fr::from(9),
                    )
                })
                .collect::<Vec<_>>();
            check_field(&d, &a, &b);
            cases += 1;
        }
    }
    println!("T4_FIELD seed={FIELD_SEED} cases={cases} domains=2,4,8,16,32,64,128");
}

// Independent Lagrange interpolation, schoolbook multiplication and long
// division by X^N-1. No FFT, candidate tree or vendor quotient routine is used.
fn lagrange_polynomial(domain: &GeneralEvaluationDomain<Fr>, i: usize) -> Vec<Fr> {
    let x_inv = domain.element(i).inverse().unwrap();
    let mut power = Fr::ONE;
    (0..domain.size())
        .map(|_| {
            let c = power * domain.size_inv();
            power *= x_inv;
            c
        })
        .collect()
}
fn dense_polynomial(domain: &GeneralEvaluationDomain<Fr>, raw: &[(usize, Fr)]) -> Vec<Fr> {
    let mut result = vec![Fr::ZERO; domain.size()];
    for (i, value) in raw {
        for (coefficient, basis) in result.iter_mut().zip(lagrange_polynomial(domain, *i)) {
            *coefficient += *value * basis;
        }
    }
    result
}
fn schoolbook_quotient(a: &[Fr], b: &[Fr], n: usize) -> Vec<Fr> {
    charge_pairs(a.len(), b.len());
    let mut product = vec![Fr::ZERO; 2 * n - 1];
    for (i, x) in a.iter().enumerate() {
        for (j, y) in b.iter().enumerate() {
            product[i + j] += *x * *y;
        }
    }
    let mut q = vec![Fr::ZERO; n - 1];
    for i in (n..product.len()).rev() {
        let value = product[i];
        q[i - n] = value;
        product[i - n] += value;
        product[i] = Fr::ZERO;
    }
    q
}
fn at(poly: &[Fr], x: Fr) -> Fr {
    poly.iter().rev().fold(Fr::ZERO, |acc, c| acc * x + *c)
}
fn public_basis(d: &GeneralEvaluationDomain<Fr>) -> (Vec<G1>, Vec<G1>) {
    let tau = Fr::from(23);
    let mut lagrange = Vec::new();
    let mut diagonal = Vec::new();
    for i in 0..d.size() {
        let li = lagrange_polynomial(d, i);
        lagrange.push(G1::generator() * at(&li[..d.size() - 1], tau));
        diagonal.push(G1::generator() * at(&schoolbook_quotient(&li, &li, d.size()), tau));
    }
    (lagrange, diagonal)
}

#[test]
fn encoded_quotient_matches_independent_dense_schoolbook_oracle() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(QUOTIENT_SEED);
    let mut cases = 0;
    for n in [2, 4, 8, 16, 32, 64] {
        let d = GeneralEvaluationDomain::<Fr>::new(n).unwrap();
        // Public synthetic basis only; this is not a trusted setup/proof trial.
        let (lagrange, diagonal) = public_basis(&d);
        for trial in 0..8 {
            let a = (0..n)
                .filter_map(|i| {
                    (trial == 0 || rng.gen_bool(0.5))
                        .then(|| (i, Fr::from(rng.gen_range(0..13u64))))
                })
                .collect::<Vec<_>>();
            let b = (0..n)
                .filter_map(|i| {
                    (trial == 0 || rng.gen_bool(0.5))
                        .then(|| (i, Fr::from(rng.gen_range(0..13u64))))
                })
                .collect::<Vec<_>>();
            let q = schoolbook_quotient(&dense_polynomial(&d, &a), &dense_polynomial(&d, &b), n);
            let expected = G1::generator() * at(&q, Fr::from(23));
            for method in [CrossMethod::Fast, CrossMethod::Quadratic] {
                if method == CrossMethod::Quadratic {
                    charge_pairs(normalized(&a).len(), normalized(&b).len());
                }
                let got = cross_coefficients(&d, &weights(&d), &a, &b, method, limits()).unwrap();
                assert_eq!(encode_cross(&got, &lagrange, &diagonal).unwrap(), expected);
            }
            cases += 1;
        }
        for (a, b) in [
            (vec![], vec![]),
            (vec![(n - 1, Fr::from(7))], vec![(n - 1, Fr::from(9))]),
        ] {
            let got =
                cross_coefficients(&d, &weights(&d), &a, &b, CrossMethod::Fast, limits()).unwrap();
            let q = schoolbook_quotient(&dense_polynomial(&d, &a), &dense_polynomial(&d, &b), n);
            assert_eq!(
                encode_cross(&got, &lagrange, &diagonal).unwrap(),
                G1::generator() * at(&q, Fr::from(23))
            );
        }
    }
    println!("T4_QUOTIENT seed={QUOTIENT_SEED} randomized_cases={cases} domains=2,4,8,16,32,64");
}

#[test]
fn typed_domain_input_support_fft_allocation_and_pair_failures() {
    let d = GeneralEvaluationDomain::<Fr>::new(8).unwrap();
    let a = [(0, Fr::ONE), (7, Fr::ONE)];
    let b = [(1, Fr::ONE), (7, Fr::ONE)];
    let mut cap = limits();
    cap.max_domain = 4;
    assert!(matches!(
        cross_coefficients(&d, &weights(&d), &a, &b, CrossMethod::Fast, cap),
        Err(Error::Bound("cross domain"))
    ));
    cap = limits();
    cap.max_input_entries = 3;
    assert!(matches!(
        cross_coefficients(&d, &weights(&d), &a, &b, CrossMethod::Fast, cap),
        Err(Error::Bound("cross input entries"))
    ));
    cap = limits();
    cap.max_union_support = 2;
    assert!(matches!(
        cross_coefficients(&d, &weights(&d), &a, &b, CrossMethod::Fast, cap),
        Err(Error::Bound("cross union support"))
    ));
    cap = limits();
    cap.max_fft_size = 4;
    assert!(matches!(
        cross_coefficients(&d, &weights(&d), &a, &b, CrossMethod::Fast, cap),
        Err(Error::Bound("cross FFT domain"))
    ));
    cap = limits();
    cap.max_allocation_bytes = 0;
    assert!(matches!(
        cross_coefficients(&d, &weights(&d), &a, &b, CrossMethod::FastOrQuadratic, cap),
        Err(Error::Bound("cross allocation"))
    ));
    cap = limits();
    cap.max_pair_visits = 3;
    assert!(matches!(
        cross_coefficients(&d, &weights(&d), &a, &b, CrossMethod::Quadratic, cap),
        Err(Error::Bound("cross pair work"))
    ));
    for method in [
        CrossMethod::Fast,
        CrossMethod::Quadratic,
        CrossMethod::FastOrQuadratic,
    ] {
        assert!(matches!(
            cross_coefficients(&d, &weights(&d), &[(8, Fr::ZERO)], &[], method, limits()),
            Err(Error::DeltaCoordinate)
        ));
    }
    assert!(required_fft_size(usize::MAX).is_err());
    assert!(required_fft_size(usize::MAX / 2).is_err());
    assert!(matches!(
        cross_coefficients(
            &GeneralEvaluationDomain::new(1).unwrap(),
            &weights(&GeneralEvaluationDomain::new(1).unwrap()),
            &[],
            &[],
            CrossMethod::Fast,
            limits()
        ),
        Err(Error::Shape(_))
    ));
}

#[test]
fn fallback_separately_preflights_pair_and_allocation_budgets() {
    let d = GeneralEvaluationDomain::<Fr>::new(8).unwrap();
    let a = [(0, Fr::ONE), (7, Fr::ONE)];
    let b = [(1, Fr::ONE), (7, Fr::ONE)];
    let mut cap = limits();
    cap.max_fft_size = 4;
    charge_pairs(a.len(), b.len());
    let got =
        cross_coefficients(&d, &weights(&d), &a, &b, CrossMethod::FastOrQuadratic, cap).unwrap();
    assert_eq!(got.stats.used_method, CrossMethod::Quadratic);
    assert!(got.stats.bounded_fallback);
    assert_eq!(got.stats.quadratic_pair_visits, 4);
    let expected = direct(&d, &a, &b);
    assert_eq!(got.lagrange, expected.1);
    cap.max_pair_visits = 3;
    assert!(matches!(
        cross_coefficients(&d, &weights(&d), &a, &b, CrossMethod::FastOrQuadratic, cap),
        Err(Error::Bound("cross pair work"))
    ));
    cap = limits();
    cap.max_allocation_bytes = got.stats.preflight_allocation_bytes;
    assert!(cross_coefficients(&d, &weights(&d), &a, &b, CrossMethod::Fast, cap).is_err());
    charge_pairs(a.len(), b.len());
    let fallback =
        cross_coefficients(&d, &weights(&d), &a, &b, CrossMethod::FastOrQuadratic, cap).unwrap();
    assert!(fallback.stats.bounded_fallback);
    cap.max_allocation_bytes -= 1;
    assert!(matches!(
        cross_coefficients(&d, &weights(&d), &a, &b, CrossMethod::FastOrQuadratic, cap),
        Err(Error::Bound("cross allocation"))
    ));
}

#[test]
fn encoding_rejects_malformed_vectors_and_indices_before_group_work() {
    let d = GeneralEvaluationDomain::<Fr>::new(8).unwrap();
    let (l, p) = public_basis(&d);
    let mut got = cross_coefficients(
        &d,
        &weights(&d),
        &[(0, Fr::ONE)],
        &[(0, Fr::ONE)],
        CrossMethod::Fast,
        limits(),
    )
    .unwrap();
    assert!(matches!(
        encode_cross(&got, &l[..7], &p),
        Err(Error::Shape(_))
    ));
    assert!(matches!(
        encode_cross(&got, &l, &p[..7]),
        Err(Error::Shape(_))
    ));
    got.indices[0] = 8;
    assert!(matches!(
        encode_cross(&got, &l, &p),
        Err(Error::DeltaCoordinate)
    ));
    got.indices[0] = 0;
    got.diagonal.clear();
    assert!(matches!(encode_cross(&got, &l, &p), Err(Error::Shape(_))));
    let mut got = cross_coefficients(
        &d,
        &weights(&d),
        &[(0, Fr::ONE), (1, Fr::ONE)],
        &[],
        CrossMethod::Fast,
        limits(),
    )
    .unwrap();
    got.indices[1] = 0;
    assert!(matches!(
        encode_cross(&got, &l, &p),
        Err(Error::DeltaCoordinate)
    ));
}

#[test]
fn weighted_quadratic_is_exactly_cartesian_for_uneven_support() {
    let d = GeneralEvaluationDomain::<Fr>::new(128).unwrap();
    let w = weights(&d);
    let a = (0..128)
        .map(|i| (i, Fr::from((i + 1) as u64)))
        .collect::<Vec<_>>();
    let b = [(127, Fr::from(9))];
    let mut cap = limits();
    cap.max_pair_visits = 128;
    charge_pairs(a.len(), b.len());
    let got = cross_coefficients(&d, &w, &a, &b, CrossMethod::Quadratic, cap).unwrap();
    assert_eq!(got.stats.quadratic_pair_visits, 128);
    assert_eq!(got.stats.union_support, 128);
    assert_eq!(got.lagrange, direct(&d, &a, &b).1);
    cap.max_pair_visits = 127;
    assert!(matches!(
        cross_coefficients(&d, &w, &a, &b, CrossMethod::Quadratic, cap),
        Err(Error::Bound("cross pair work"))
    ));
    let mut wrong = w.clone();
    wrong[0] = Fr::ONE;
    for method in [
        CrossMethod::Quadratic,
        CrossMethod::Fast,
        CrossMethod::FastOrQuadratic,
    ] {
        assert!(matches!(
            cross_coefficients(&d, &wrong, &a, &b, method, limits()),
            Err(Error::Shape("cross weights"))
        ));
        assert!(matches!(
            cross_coefficients(&d, &w[..127], &a, &b, method, limits()),
            Err(Error::Shape("cross weights"))
        ));
    }
}

#[test]
fn z_oracle_work_budget_report() {
    println!(
        "T4_ORACLE counted_pair_visits={} case_cap={CASE_CAP} invocation_cap={INVOCATION_CAP}",
        PAIR_VISITS.load(Ordering::SeqCst)
    );
    assert!(PAIR_VISITS.load(Ordering::SeqCst) + UNIT_TEST_RESERVATION <= INVOCATION_CAP);
}

#[test]
fn diagnostic_observer_preserves_exact_outputs_stats_and_ordered_boundaries() {
    let d = GeneralEvaluationDomain::<Fr>::new(8).unwrap();
    let w = weights(&d);
    let a = [
        (0, Fr::from(2)),
        (7, Fr::from(3)),
        (1, Fr::from(5)),
        (0, Fr::ONE),
        (0, -Fr::ONE),
    ];
    let b = [(1, Fr::from(7)), (7, Fr::from(11))];
    for method in [
        CrossMethod::Fast,
        CrossMethod::Quadratic,
        CrossMethod::FastOrQuadratic,
    ] {
        if method == CrossMethod::Quadratic {
            charge_pairs(normalized(&a).len(), 2 * normalized(&b).len());
        }
        let ordinary = cross_coefficients(&d, &w, &a, &b, method, limits()).unwrap();
        let mut trace = Vec::new();
        let observed =
            cross_coefficients_observed(&d, &w, &a, &b, method, limits(), |phase, event| {
                trace.push((phase, event))
            })
            .unwrap();
        assert_eq!(ordinary.domain_size, observed.domain_size);
        assert_eq!(ordinary.indices, observed.indices);
        assert_eq!(ordinary.lagrange, observed.lagrange);
        assert_eq!(ordinary.diagonal, observed.diagonal);
        assert_eq!(ordinary.stats, observed.stats);
        let mut phases = vec![
            CrossPhase::Preflight,
            CrossPhase::Normalize,
            CrossPhase::Preflight,
        ];
        if method == CrossMethod::Quadratic {
            phases.push(CrossPhase::Quadratic);
        } else {
            phases.extend([
                CrossPhase::Nodes,
                CrossPhase::ProductTree,
                CrossPhase::Numerators,
                CrossPhase::Derivatives,
                CrossPhase::RemainderEvaluation,
                CrossPhase::FinitePart,
            ]);
        }
        phases.push(CrossPhase::Collect);
        let expected = phases
            .into_iter()
            .flat_map(|p| [(p, CrossPhaseEvent::Start), (p, CrossPhaseEvent::End)])
            .collect::<Vec<_>>();
        assert_eq!(trace, expected);
    }
    let mut trace = Vec::new();
    let ordinary = cross_coefficients(&d, &w, &[], &[], CrossMethod::Fast, limits()).unwrap();
    let observed =
        cross_coefficients_observed(&d, &w, &[], &[], CrossMethod::Fast, limits(), |p, e| {
            trace.push((p, e))
        })
        .unwrap();
    assert_eq!(ordinary.stats, observed.stats);
    assert_eq!(ordinary.domain_size, observed.domain_size);
    assert_eq!(ordinary.indices, observed.indices);
    assert_eq!(ordinary.lagrange, observed.lagrange);
    assert_eq!(ordinary.diagonal, observed.diagonal);
    let expected = [
        CrossPhase::Preflight,
        CrossPhase::Normalize,
        CrossPhase::Preflight,
        CrossPhase::Nodes,
        CrossPhase::Collect,
    ]
    .into_iter()
    .flat_map(|p| [(p, CrossPhaseEvent::Start), (p, CrossPhaseEvent::End)])
    .collect::<Vec<_>>();
    assert_eq!(trace, expected);
    let mut cap = limits();
    cap.max_fft_size = 0;
    charge_pairs(normalized(&a).len(), 2 * normalized(&b).len());
    let ordinary = cross_coefficients(&d, &w, &a, &b, CrossMethod::FastOrQuadratic, cap).unwrap();
    let mut trace = Vec::new();
    let observed =
        cross_coefficients_observed(&d, &w, &a, &b, CrossMethod::FastOrQuadratic, cap, |p, e| {
            trace.push((p, e))
        })
        .unwrap();
    assert_eq!(ordinary.stats, observed.stats);
    assert_eq!(ordinary.domain_size, observed.domain_size);
    assert_eq!(ordinary.indices, observed.indices);
    assert_eq!(ordinary.lagrange, observed.lagrange);
    assert_eq!(ordinary.diagonal, observed.diagonal);
    assert!(trace.contains(&(CrossPhase::Quadratic, CrossPhaseEvent::Start)));
    assert!(!trace.iter().any(|(p, _)| *p == CrossPhase::ProductTree));
}
