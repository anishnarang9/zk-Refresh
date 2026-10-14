use super::*;
use crate::{public_schema_digest, test_fixture, CircuitDescriptor, Reduction};
use ark_bn254::Bn254;
use ark_relations::r1cs::ConstraintMatrices;
use rand::{rngs::StdRng, SeedableRng};

fn serial_components(
    anchor: &Anchor,
    p: &PublicPackage,
    uk: &UpdatingMaterial,
    t: &Transition,
    rows: &crate::RowDeltas,
    r: Fr,
    s: Fr,
    cap: usize,
) -> Result<(G1, G1, G2, G1), Error> {
    let pk = &p.0.pk;
    let mut a = anchor.core.a_g1 + pk.delta_g1 * (r - anchor.core.r);
    let mut b1 = anchor.core.b_g1 + pk.delta_g1 * (s - anchor.core.s);
    let mut b2 = anchor.core.b_g2 + pk.vk.delta_g2 * (s - anchor.core.s);
    let mut private = G1::zero();
    for (j, x) in &t.delta {
        a += pk.u_g1[*j] * *x;
        b1 += pk.v_g1[*j] * *x;
        b2 += pk.v_g2[*j] * *x;
        if *j >= p.shape().instance_len {
            private += pk.t_p_g1[*j - p.shape().instance_len] * *x;
        }
    }
    let mut quotient = uk.cross(&rows.a, &rows.b, cap)?;
    for (i, x) in &rows.a {
        quotient += anchor.q_b[*i] * *x;
    }
    for (i, x) in &rows.b {
        quotient += anchor.q_a[*i] * *x;
    }
    let c = anchor.core.c_g1 + a * s - anchor.core.a_g1 * anchor.core.s + b1 * r
        - anchor.core.b_g1 * anchor.core.r
        - pk.delta_g1 * (r * s - anchor.core.r * anchor.core.s)
        + private
        + quotient;
    Ok((a, b1, b2, c))
}

fn package(reduction: Reduction) -> PublicPackage {
    let mut a = Vec::new();
    let mut b = Vec::new();
    let mut c = Vec::new();
    for j in 1..128 {
        if j < 6 || j % 2 == 0 && j != 6 {
            a.push(vec![(Fr::ONE, j)]);
            b.push(vec![(Fr::ONE, 0)]);
        } else {
            a.push(vec![(Fr::ONE, 0)]);
            b.push(vec![(Fr::ONE, j)]);
        }
        c.push(vec![(Fr::ONE, j)]);
    }
    let m = ConstraintMatrices {
        num_instance_variables: 6,
        num_witness_variables: 122,
        num_constraints: 127,
        a_num_non_zero: 127,
        b_num_non_zero: 127,
        c_num_non_zero: 127,
        a,
        b,
        c,
    };
    let names = ["root", "issuerHash", "notBefore", "notAfter", "actionHash"]
        .map(str::to_owned)
        .to_vec();
    let d = CircuitDescriptor {
        r1cs_artifact_digest: [41; 32],
        witness_executable_digest: [42; 32],
        profile_digest: [43; 32],
        public_schema_digest: public_schema_digest(&names),
        public_schema: names,
        reduction,
    };
    let mut reduced = m.clone();
    if reduction == Reduction::InstanceAugmentedA {
        for j in 0..6 {
            reduced.a.push(vec![(Fr::ONE, j)]);
            reduced.b.push(vec![]);
            reduced.c.push(vec![]);
        }
        reduced.num_constraints += 6;
        reduced.a_num_non_zero += 6;
    }
    let pk =
        dynark::Groth16::<Bn254>::groth16_setup_dynark(reduced, &mut StdRng::seed_from_u64(147))
            .unwrap()
            .0;
    let id = PublicPackage::inspect_identity(&m, &d, &pk).unwrap();
    PublicPackage::new(m, d, pk, id).unwrap()
}

fn anchor(p: &PublicPackage, u: &UpdatingMaterial, z: &[Fr]) -> Anchor {
    let assignment = p
        .validate_assignment(&test_fixture::bytes(z), &z[1..6])
        .unwrap();
    let core = capture(p, assignment, Fr::from(13), Fr::from(19)).unwrap();
    let qa = u.project(p, &core.a);
    let qb = u.project(p, &core.b);
    Anchor::from_parts(AnchorBinding::new(p, [1; 32], [2; 32], 7), core, qa, qb).unwrap()
}

fn raw_delta(z: &[Fr], target: &[Fr]) -> Vec<(usize, [u8; 32])> {
    z.iter()
        .zip(target)
        .enumerate()
        .skip(1)
        .filter(|(_, (a, b))| a != b)
        .map(|(i, (a, b))| (i, test_fixture::bytes(&[*b - *a])[0]))
        .collect()
}

fn check(
    p: &PublicPackage,
    u: &UpdatingMaterial,
    a: &Anchor,
    t: &Transition,
    target: &[Fr],
    threads: usize,
) {
    let prepared = t.validate_target(p, &a.core.assignment).unwrap();
    assert!(prepared.target.values == target);
    let expected = serial_components(
        a,
        p,
        u,
        t,
        &prepared.rows,
        Fr::from(29),
        Fr::from(31),
        65536,
    )
    .unwrap();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .unwrap();
    let actual = pool
        .install(|| a.update_components(p, u, t, &prepared.rows, Fr::from(29), Fr::from(31), 65536))
        .unwrap();
    assert!(
        expected == actual,
        "all four raw group components must match serial algebra"
    );
    let proof = ordinary::Proof {
        a: actual.0.into_affine(),
        b: actual.2.into_affine(),
        c: actual.3.into_affine(),
    };
    assert!(test_fixture::verify(p, &proof, &target[1..6]));
    for i in 1..6 {
        let mut wrong = target[1..6].to_vec();
        wrong[i - 1] += Fr::ONE;
        assert!(!test_fixture::verify(p, &proof, &wrong));
    }
}

#[test]
fn nonvacuous_five_publics_private_boundaries_and_one_sided_rows_equal_serial() {
    for reduction in [Reduction::Original, Reduction::InstanceAugmentedA] {
        let p = package(reduction);
        let u = UpdatingMaterial::prepare(&p, Limits::small()).unwrap();
        let z = (0..128)
            .map(|j| {
                if j == 0 {
                    Fr::ONE
                } else {
                    Fr::from(j as u64 + 2)
                }
            })
            .collect::<Vec<_>>();
        let a = anchor(&p, &u, &z);
        let before = a.state_commitment().unwrap();
        for kind in ["mixed", "A-only", "B-only", "empty"] {
            let mut target = z.clone();
            for j in 1..128 {
                let in_a = j < 6 || j % 2 == 0 && j != 6;
                if kind == "mixed" || kind == "A-only" && in_a || kind == "B-only" && !in_a {
                    target[j] += Fr::from((j % 7 + 1) as u64);
                }
            }
            let raw = raw_delta(&z, &target);
            let t =
                Transition::new(&p, a.binding(), 8, &raw, &target[1..6], Limits::small()).unwrap();
            let prepared = t.validate_target(&p, &a.core.assignment).unwrap();
            if kind == "mixed" {
                assert_eq!(t.normalized_count(), 127);
                assert!(
                    t.delta.iter().any(|(j, _)| *j == 6) && t.delta.iter().any(|(j, _)| *j == 127)
                );
                assert_eq!(t.delta.iter().filter(|(j, _)| *j < 6).count(), 5);
            }
            if kind == "A-only" || kind == "empty" {
                assert!(prepared.rows.b.is_empty());
            }
            if kind == "B-only" || kind == "empty" {
                assert!(prepared.rows.a.is_empty());
            }
            if kind == "mixed" || kind == "A-only" {
                assert!(!prepared.rows.a.is_empty());
                assert!(prepared.rows.a.iter().any(|(i, _)| !a.q_b[*i].is_zero()));
                assert!(!prepared
                    .rows
                    .a
                    .iter()
                    .map(|(i, x)| a.q_b[*i] * x)
                    .sum::<G1>()
                    .is_zero());
            }
            if kind == "mixed" || kind == "B-only" {
                assert!(!prepared.rows.b.is_empty());
                assert!(prepared.rows.b.iter().any(|(i, _)| !a.q_a[*i].is_zero()));
                assert!(!prepared
                    .rows
                    .b
                    .iter()
                    .map(|(i, x)| a.q_a[*i] * x)
                    .sum::<G1>()
                    .is_zero());
            }
            for threads in [1, 2, 4] {
                check(&p, &u, &a, &t, &target, threads);
            }
        }
        assert_eq!(a.state_commitment().unwrap(), before);
    }
}

#[test]
fn normalized_duplicates_cancellation_and_empty_sums_equal_serial() {
    for reduction in [Reduction::Original, Reduction::InstanceAugmentedA] {
        let p = package(reduction);
        let u = UpdatingMaterial::prepare(&p, Limits::small()).unwrap();
        let z = (0..128)
            .map(|j| {
                if j == 0 {
                    Fr::ONE
                } else {
                    Fr::from(j as u64 + 2)
                }
            })
            .collect::<Vec<_>>();
        let a = anchor(&p, &u, &z);
        let mut target = z.clone();
        for x in &mut target[1..] {
            *x += Fr::from(3);
        }
        let mut duplicated = Vec::new();
        for (j, _) in raw_delta(&z, &target) {
            duplicated.push((j, test_fixture::bytes(&[Fr::from(14)])[0]));
            duplicated.push((j, test_fixture::bytes(&[-Fr::from(11)])[0]));
        }
        duplicated.reverse();
        let mixed = Transition::new(
            &p,
            a.binding(),
            8,
            &duplicated,
            &target[1..6],
            Limits::small(),
        )
        .unwrap();
        assert_eq!(mixed.normalized_count(), 127);
        let cancelled = [
            (6, Fr::from(13)),
            (127, Fr::from(17)),
            (6, -Fr::from(13)),
            (127, -Fr::from(17)),
            (5, Fr::zero()),
        ]
        .map(|(j, x)| (j, test_fixture::bytes(&[x])[0]));
        let empty =
            Transition::new(&p, a.binding(), 8, &cancelled, &z[1..6], Limits::small()).unwrap();
        assert_eq!(empty.normalized_count(), 0);
        for threads in [1, 2, 4] {
            check(&p, &u, &a, &mixed, &target, threads);
            check(&p, &u, &a, &empty, &z, threads);
        }
    }
}
