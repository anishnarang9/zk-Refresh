//! Test-only same-key conformance for the independently derived cross kernel.
use crate::{
    anchored::{capture, Anchor},
    cross::{cross_coefficients, encode_cross, CrossLimits, CrossMethod},
    test_fixture as fixture, AnchorBinding, Limits, PublicPackage, Reduction, Transition,
    UpdatingMaterial,
};
use ark_bn254::{Bn254, Fr, G1Projective as G1, G2Projective as G2};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{AdditiveGroup, Field, PrimeField, Zero};
use ark_poly::EvaluationDomain;
use rand::SeedableRng;

fn cross_limits() -> CrossLimits {
    CrossLimits {
        max_domain: 1024,
        max_input_entries: 4096,
        max_union_support: 1024,
        max_fft_size: 4096,
        max_allocation_bytes: 64 * 1024 * 1024,
        max_pair_visits: 1_000_000,
    }
}
fn package(v: usize, rows: usize, reduction: Reduction) -> PublicPackage {
    let mut m = fixture::relation(v);
    while m.num_constraints < rows {
        m.a.push(vec![]);
        m.b.push(vec![]);
        m.c.push(vec![]);
        m.num_constraints += 1;
    }
    let mut reduced = m.clone();
    if reduction == Reduction::InstanceAugmentedA {
        for i in 0..2 {
            reduced.a.push(vec![(Fr::ONE, i)]);
            reduced.b.push(vec![]);
            reduced.c.push(vec![]);
        }
        reduced.num_constraints += 2;
        reduced.a_num_non_zero += 2;
    }
    // Synthetic, deterministic development setup is test-only.
    let pk = dynark::Groth16::<Bn254>::groth16_setup_dynark(
        reduced,
        &mut rand::rngs::StdRng::seed_from_u64(82),
    )
    .unwrap()
    .0;
    let descriptor = fixture::descriptor(reduction);
    let expected = PublicPackage::inspect_identity(&m, &descriptor, &pk).unwrap();
    PublicPackage::new(m, descriptor, pk, expected).unwrap()
}
fn polynomial(p: &PublicPackage, rows: &[Fr]) -> Vec<Fr> {
    // Independent explicit Lagrange interpolation, with no candidate FFT/tree.
    let n = p.shape().domain_size;
    let mut out = vec![Fr::ZERO; n];
    for (i, value) in rows.iter().enumerate() {
        let inverse = p.0.domain.element(i).inverse().unwrap();
        let mut power = Fr::ONE;
        for coefficient in &mut out {
            *coefficient += *value * power * p.0.domain.size_inv();
            power *= inverse;
        }
    }
    out
}
fn quotient(a: &[Fr], b: &[Fr], c: &[Fr], n: usize, total: &mut usize) -> Vec<Fr> {
    let pairs = a.len().checked_mul(b.len()).unwrap();
    assert!(pairs <= 1_000_000);
    *total = total.checked_add(pairs).unwrap();
    assert!(*total <= 20_000_000);
    let mut f = vec![Fr::ZERO; 2 * n - 1];
    for (i, x) in a.iter().enumerate() {
        for (j, y) in b.iter().enumerate() {
            f[i + j] += *x * *y;
        }
    }
    for (i, x) in c.iter().enumerate() {
        f[i] -= x;
    }
    let mut q = vec![Fr::ZERO; n - 1];
    for i in (n..f.len()).rev() {
        let v = f[i];
        q[i - n] = v;
        f[i - n] += v;
        f[i] = Fr::ZERO;
    }
    q
}
fn encode(p: &PublicPackage, q: &[Fr]) -> G1 {
    G1::msm_bigint(
        &p.0.pk.tau_powers_g1,
        &q.iter().map(|x| x.into_bigint()).collect::<Vec<_>>(),
    )
}

#[test]
fn candidate_same_key_quotient_all_raw_components_and_ordinary_proofs() {
    let mut pair_visits = 0;
    let mut cases = 0;
    for (rows, n) in [(5, 8), (9, 16)] {
        for v in [n - 3, n + 3] {
            for reduction in [Reduction::Original, Reduction::InstanceAugmentedA] {
                let p = package(v, rows, reduction);
                assert_eq!(p.shape().domain_size, n);
                let uk = UpdatingMaterial::prepare(&p, Limits::small()).unwrap();
                let hex = |d: [u8; 32]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
                let id = p.identity();
                println!("T4_PROOF_FIXTURE v={v} rows={rows} N={n} reduction={reduction:?} matrix={} circuit={} pk={} vk={} package={} setup_seed=82",hex(id.matrix_digest),hex(id.circuit_digest),hex(id.proving_key_digest),hex(id.verifying_key_digest),hex(id.package_digest));
                for (w, t, wn, tn) in [
                    (3, 2, 4, 1),
                    (4, 1, 3, 2),
                    (3, 2, 3, 2),
                    (3, 2, 2, 3),
                    (3, 2, 5, 4),
                    (3, 2, 3, 4),
                ] {
                    let z = fixture::assignment(v, w, t);
                    let mut target = fixture::assignment(v, wn, tn);
                    if v > n && wn == w && tn != t {
                        target[v - 1] = Fr::from(37);
                    }
                    let validated = p
                        .validate_assignment(&fixture::bytes(&z), &z[1..2])
                        .unwrap();
                    let core = capture(&p, validated, Fr::from(13), Fr::from(19)).unwrap();
                    let qa = uk.project(&p, &core.a);
                    let qb = uk.project(&p, &core.b);
                    let anchor = Anchor::from_parts(
                        AnchorBinding::new(&p, [1; 32], [2; 32], 7),
                        core,
                        qa,
                        qb,
                    )
                    .unwrap();
                    let binding = anchor.binding();
                    let mut raw = z
                        .iter()
                        .zip(&target)
                        .enumerate()
                        .skip(1)
                        .map(|(j, (x, y))| (j, fixture::bytes(&[*y - *x])[0]))
                        .collect::<Vec<_>>();
                    raw.push((2, fixture::bytes(&[Fr::ONE])[0]));
                    raw.push((2, fixture::bytes(&[-Fr::ONE])[0]));
                    let transition =
                        Transition::new(&p, binding, 8, &raw, &target[1..2], Limits::small())
                            .unwrap();
                    let prepared = transition
                        .validate_target(&p, &anchor.core.assignment)
                        .unwrap();
                    let mut da = vec![Fr::ZERO; n];
                    let mut db = vec![Fr::ZERO; n];
                    for (i, x) in &prepared.rows.a {
                        da[*i] = *x;
                    }
                    for (i, x) in &prepared.rows.b {
                        db[*i] = *x;
                    }
                    let crossq = quotient(
                        &polynomial(&p, &da),
                        &polynomial(&p, &db),
                        &[],
                        n,
                        &mut pair_visits,
                    );
                    let (ta, tb, tc) =
                        dynark::utils::lagrange_of_dense_vec(&p.0.matrices, &target).unwrap();
                    let (_, _, bc) =
                        dynark::utils::lagrange_of_dense_vec(&p.0.matrices, &z).unwrap();
                    let targetq = quotient(
                        &polynomial(&p, &ta),
                        &polynomial(&p, &tb),
                        &polynomial(&p, &tc),
                        n,
                        &mut pair_visits,
                    );
                    let baseq = quotient(
                        &polynomial(&p, &anchor.core.a),
                        &polynomial(&p, &anchor.core.b),
                        &polynomial(&p, &bc),
                        n,
                        &mut pair_visits,
                    );
                    let difference = targetq
                        .iter()
                        .zip(&baseq)
                        .map(|(x, y)| *x - *y)
                        .collect::<Vec<_>>();
                    let (r, s) = (Fr::from(23), Fr::from(29));
                    let full = capture(
                        &p,
                        p.validate_assignment(&fixture::bytes(&target), &target[1..2])
                            .unwrap(),
                        r,
                        s,
                    )
                    .unwrap();
                    for method in [CrossMethod::Fast, CrossMethod::Quadratic] {
                        if method == CrossMethod::Quadratic {
                            let pairs = prepared
                                .rows
                                .a
                                .len()
                                .checked_mul(prepared.rows.b.len())
                                .unwrap();
                            assert!(pairs <= 1_000_000);
                            pair_visits = pair_visits.checked_add(pairs).unwrap();
                            assert!(pair_visits <= 20_000_000);
                        }
                        let c = cross_coefficients(
                            &p.0.domain,
                            &uk.0.weights,
                            &prepared.rows.a,
                            &prepared.rows.b,
                            method,
                            cross_limits(),
                        )
                        .unwrap();
                        let cross = encode_cross(&c, &uk.0.lagrange, &uk.0.diagonal).unwrap();
                        assert_eq!(cross, encode(&p, &crossq));
                        let mut correction = cross;
                        for (i, x) in &prepared.rows.a {
                            correction += anchor.q_b[*i] * *x;
                        }
                        for (i, x) in &prepared.rows.b {
                            correction += anchor.q_a[*i] * *x;
                        }
                        assert_eq!(correction, encode(&p, &difference));
                        // Reviewed anchored correction, expressed in test-only code.
                        let pk = &p.0.pk;
                        let mut a = anchor.core.a_g1 + pk.delta_g1 * (r - anchor.core.r);
                        let mut b1 = anchor.core.b_g1 + pk.delta_g1 * (s - anchor.core.s);
                        let mut b2 = anchor.core.b_g2 + pk.vk.delta_g2 * (s - anchor.core.s);
                        let mut private = G1::zero();
                        for (j, x) in &transition.delta {
                            a += pk.u_g1[*j] * *x;
                            b1 += pk.v_g1[*j] * *x;
                            b2 += pk.v_g2[*j] * *x;
                            if *j >= p.shape().instance_len {
                                private += pk.t_p_g1[*j - p.shape().instance_len] * *x;
                            }
                        }
                        let c = anchor.core.c_g1 + a * s - anchor.core.a_g1 * anchor.core.s
                            + b1 * r
                            - anchor.core.b_g1 * anchor.core.r
                            - pk.delta_g1 * (r * s - anchor.core.r * anchor.core.s)
                            + private
                            + correction;
                        assert_eq!(a, full.a_g1);
                        assert_eq!(b1, full.b_g1);
                        assert_eq!(b2, full.b_g2);
                        assert_eq!(c, full.c_g1);
                        let proof = ordinary::Proof {
                            a: a.into_affine(),
                            b: b2.into_affine(),
                            c: c.into_affine(),
                        };
                        assert!(fixture::verify(&p, &proof, &target[1..2]));
                        assert!(!fixture::verify(&p, &proof, &[target[1] + Fr::ONE]));
                        let vendor = dynark::Groth16::<Bn254>::create_proof_with_assignment(
                            pk,
                            r,
                            s,
                            &targetq,
                            &target[..2],
                            &target[2..],
                        )
                        .unwrap();
                        assert_eq!(proof.a, vendor.a_g1);
                        assert_eq!(proof.b, vendor.b_g2);
                        assert_eq!(proof.c, vendor.c_g1);
                        let expected_b2 = pk.vk.beta_g2.into_group()
                            + G2::msm_bigint(
                                &pk.v_g2,
                                &target.iter().map(|x| x.into_bigint()).collect::<Vec<_>>(),
                            )
                            + pk.vk.delta_g2 * s;
                        assert_eq!(b2, expected_b2);
                    }
                    assert_eq!(anchor.binding(), binding);
                    cases += 1;
                }
            }
        }
    }
    println!("T4_SAME_KEY cases={cases} methods=fast,weighted_quadratic oracle_pair_visits={pair_visits} case_cap=1000000 invocation_cap=20000000");
}
