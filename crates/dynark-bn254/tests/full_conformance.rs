//! Synthetic public development fixtures only. Deterministic setup/blinders never enter product APIs.
use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::CanonicalSerialize;
use dynark::r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};
use dynark_bn254::{
    prove, public_schema_digest, CircuitDescriptor, Error, PublicPackage, Reduction,
};
use rand::{CryptoRng, RngCore, SeedableRng};

fn matrices(
    k: usize,
    v: usize,
    a: Vec<Vec<(Fr, usize)>>,
    b: Vec<Vec<(Fr, usize)>>,
    c: Vec<Vec<(Fr, usize)>>,
) -> ConstraintMatrices<Fr> {
    ConstraintMatrices {
        num_instance_variables: k,
        num_witness_variables: v - k,
        num_constraints: a.len(),
        a_num_non_zero: a.iter().map(Vec::len).sum(),
        b_num_non_zero: b.iter().map(Vec::len).sum(),
        c_num_non_zero: c.iter().map(Vec::len).sum(),
        a,
        b,
        c,
    }
}
fn c_only() -> (ConstraintMatrices<Fr>, Vec<Fr>) {
    let mut a = vec![vec![(Fr::ONE, 2)]];
    let mut b = a.clone();
    let mut c = vec![vec![(Fr::ONE, 1)]];
    for _ in 0..4 {
        a.push(vec![]);
        b.push(vec![]);
        c.push(vec![]);
    }
    (
        matrices(2, 3, a, b, c),
        vec![Fr::ONE, Fr::from(9), Fr::from(3)],
    )
}
fn five() -> (ConstraintMatrices<Fr>, Vec<Fr>) {
    let mut a = vec![vec![(Fr::ONE, 8)], vec![(Fr::ONE, 1)]];
    let mut b = vec![vec![(Fr::ONE, 8)], vec![(Fr::ONE, 0)]];
    let mut c = vec![vec![(Fr::ONE, 1)], vec![(Fr::ONE, 1)]];
    for j in 2..6 {
        a.push(vec![(Fr::ONE, j)]);
        b.push(vec![(Fr::ONE, 0)]);
        c.push(vec![(Fr::ONE, j)]);
    }
    (
        matrices(6, 9, a, b, c),
        vec![1, 9, 2, 4, 5, 6, 0, 0, 3]
            .into_iter()
            .map(Fr::from)
            .collect(),
    )
}
fn descriptor(k: usize, reduction: Reduction) -> CircuitDescriptor {
    let public_schema = (1..k).map(|i| format!("public_{i}")).collect::<Vec<_>>();
    CircuitDescriptor {
        r1cs_artifact_digest: [11; 32],
        witness_executable_digest: [12; 32],
        profile_digest: [13; 32],
        public_schema_digest: public_schema_digest(&public_schema),
        public_schema,
        reduction,
    }
}
fn augmented(m: &ConstraintMatrices<Fr>, reduction: Reduction) -> ConstraintMatrices<Fr> {
    let mut n = m.clone();
    if reduction == Reduction::InstanceAugmentedA {
        for i in 0..m.num_instance_variables {
            n.a.push(vec![(Fr::ONE, i)]);
            n.b.push(vec![]);
            n.c.push(vec![]);
        }
        n.num_constraints += m.num_instance_variables;
        n.a_num_non_zero += m.num_instance_variables;
    }
    n
}
fn key(m: &ConstraintMatrices<Fr>, r: Reduction, seed: u64) -> dynark::ProvingKey<Bn254> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    dynark::Groth16::<Bn254>::groth16_setup_dynark(augmented(m, r), &mut rng)
        .unwrap()
        .0
}
fn package(m: &ConstraintMatrices<Fr>, r: Reduction, seed: u64) -> PublicPackage {
    let pk = key(m, r, seed);
    let d = descriptor(m.num_instance_variables, r);
    let expected = PublicPackage::inspect_identity(m, &d, &pk).unwrap();
    PublicPackage::new(m.clone(), d, pk, expected).unwrap()
}
fn bytes(values: &[Fr]) -> Vec<[u8; 32]> {
    values
        .iter()
        .map(|v| {
            let mut b = Vec::new();
            v.serialize_compressed(&mut b).unwrap();
            b.try_into().unwrap()
        })
        .collect()
}
fn verify(p: &PublicPackage, proof: &ordinary::Proof<Bn254>, statement: &[Fr]) -> bool {
    let pvk = ordinary::prepare_verifying_key(&p.ordinary_verifying_key());
    ordinary::Groth16::<Bn254>::verify_proof(&pvk, proof, statement).unwrap()
}
struct Scripted {
    calls: usize,
    fail_at: Option<usize>,
    reject: bool,
}
impl Scripted {
    fn good() -> Self {
        Self {
            calls: 0,
            fail_at: None,
            reject: false,
        }
    }
}
impl CryptoRng for Scripted {}
impl RngCore for Scripted {
    fn next_u32(&mut self) -> u32 {
        panic!("infallible RNG entrypoint forbidden")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("infallible RNG entrypoint forbidden")
    }
    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("infallible RNG entrypoint forbidden")
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rand::Error> {
        let i = self.calls;
        self.calls += 1;
        if self.fail_at == Some(i) {
            return Err(rand::Error::new(std::io::Error::other(
                "synthetic entropy unavailable",
            )));
        }
        dst.fill(if self.reject { 255 } else { 0 });
        if !self.reject {
            dst[0] = 17 + i as u8;
        }
        Ok(())
    }
}

#[test]
fn five_public_v_greater_than_n_and_non_power_rows_are_ordinary_valid() {
    let (m, z) = five();
    let p = package(&m, Reduction::Original, 1);
    assert_eq!(p.shape().constraint_rows, 6);
    assert_eq!(p.shape().domain_size, 8);
    assert!(p.shape().assignment_len > p.shape().domain_size);
    let a = p.validate_assignment(&bytes(&z), &z[1..6]).unwrap();
    let output = prove(&p, &a, 42, &mut rand::rngs::OsRng).unwrap();
    assert_eq!(output.public_values, z[1..6]);
    assert_eq!(output.generation, 42);
    assert_eq!(output.package, p.identity());
    assert!(verify(&p, &output.proof, &output.public_values));
    for j in 0..5 {
        let mut altered = output.public_values.clone();
        altered[j] += Fr::ONE;
        assert!(
            !verify(&p, &output.proof, &altered),
            "public coordinate {j}"
        );
    }
}

#[test]
fn c_only_public_and_equal_domain_reductions_are_distinct() {
    let (m, z) = c_only();
    let original = package(&m, Reduction::Original, 2);
    let aug = package(&m, Reduction::InstanceAugmentedA, 3);
    assert_eq!(original.shape().constraint_rows, 5);
    assert_eq!(original.shape().assignment_len, 3);
    assert_eq!(original.shape().domain_size, 8);
    assert_eq!(aug.shape().domain_size, 8);
    assert_eq!(aug.shape().reduction_rows, 7);
    assert_ne!(
        original.identity().circuit_digest,
        aug.identity().circuit_digest
    );
    for p in [&original, &aug] {
        let a = p.validate_assignment(&bytes(&z), &z[1..2]).unwrap();
        let output = prove(p, &a, 0, &mut rand::rngs::OsRng).unwrap();
        assert!(verify(p, &output.proof, &[Fr::from(9)]));
        assert!(!verify(p, &output.proof, &[Fr::from(10)]));
        let mut invalid = z.clone();
        invalid[1] = Fr::from(10);
        assert!(matches!(
            p.validate_assignment(&bytes(&invalid), &invalid[1..2]),
            Err(Error::Unsatisfied { row: 0 })
        ));
    }
    let a = original.validate_assignment(&bytes(&z), &z[1..2]).unwrap();
    let mut rng = Scripted::good();
    assert!(matches!(
        prove(&aug, &a, 0, &mut rng),
        Err(Error::AssignmentPackage)
    ));
    assert_eq!(rng.calls, 0);
    let pk = key(&m, Reduction::Original, 2);
    let trusted = original.identity();
    assert!(matches!(
        PublicPackage::new(
            m.clone(),
            descriptor(2, Reduction::InstanceAugmentedA),
            pk,
            trusted
        ),
        Err(Error::Key(_))
    ));
    // Deliberately cross the polynomial quotient and equal-size key outside product APIs.
    // Fixed public setup parameters distinguish reduction alone, rather than two independent ceremonies.
    use ark_ec::AffineRepr;
    let domain = GeneralEvaluationDomain::<Fr>::new(5).unwrap();
    let trapdoor = (
        Fr::from(23),
        Fr::from(29),
        Fr::from(31),
        Fr::from(37),
        Fr::from(41),
        ark_bn254::G1Affine::generator(),
        ark_bn254::G2Affine::generator(),
    );
    let ko =
        dynark::Groth16::<Bn254>::generate_prover_key_with_matrices(domain, &m, trapdoor).unwrap();
    let ma = augmented(&m, Reduction::InstanceAugmentedA);
    let ka =
        dynark::Groth16::<Bn254>::generate_prover_key_with_matrices(domain, &ma, trapdoor).unwrap();
    let ordinary_vk = |k: &dynark::ProvingKey<Bn254>| ordinary::VerifyingKey {
        alpha_g1: k.vk.alpha_g1,
        beta_g2: k.vk.beta_g2,
        gamma_g2: k.vk.gamma_g2,
        delta_g2: k.vk.delta_g2,
        gamma_abc_g1: k.vk.t_v_g1.clone(),
    };
    for (eval, key) in [(&ma, &ko), (&m, &ka)] {
        let (a, b, c) = dynark::utils::lagrange_of_dense_vec(eval, &z).unwrap();
        let q = LibsnarkReduction::compute_quotient::<Fr, GeneralEvaluationDomain<Fr>>(
            &domain, a, b, c,
        )
        .unwrap();
        let crossed = dynark::Groth16::<Bn254>::create_proof_with_assignment(
            key,
            Fr::from(17),
            Fr::from(18),
            &q,
            &z[..2],
            &z[2..],
        )
        .unwrap();
        let proof = ordinary::Proof {
            a: crossed.a_g1,
            b: crossed.b_g2,
            c: crossed.c_g1,
        };
        assert!(!ordinary::Groth16::<Bn254>::verify_proof(
            &ordinary::prepare_verifying_key(&ordinary_vk(key)),
            &proof,
            &z[1..2]
        )
        .unwrap());
    }
}

#[test]
fn no_cache_product_equals_dense_quotient_assignment_oracle() {
    for (m, z) in [c_only(), five()] {
        for reduction in [Reduction::Original, Reduction::InstanceAugmentedA] {
            let seed = 50;
            let pk = key(&m, reduction, seed);
            let p = package(&m, reduction, seed);
            let id = p.identity();
            assert_eq!(
                PublicPackage::inspect_identity(
                    &m,
                    &descriptor(m.num_instance_variables, reduction),
                    &pk
                )
                .unwrap(),
                id
            );
            let hex = |digest: [u8; 32]| {
                digest
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            };
            println!("T1_IDENTITY raw_rows={} assignment_len={} instance_len={} domain_size={} reduction={:?} matrix={} circuit={} pk={} vk={} package={}",
                p.shape().constraint_rows, p.shape().assignment_len, p.shape().instance_len, p.shape().domain_size, reduction,
                hex(id.matrix_digest), hex(id.circuit_digest), hex(id.proving_key_digest), hex(id.verifying_key_digest), hex(id.package_digest));
            let a = p
                .validate_assignment(&bytes(&z), &z[1..m.num_instance_variables])
                .unwrap();
            let mut rng = Scripted::good();
            let result = prove(&p, &a, 5, &mut rng).unwrap();
            assert_eq!(rng.calls, 2);
            let effective = augmented(&m, reduction);
            let (a, b, c) = dynark::utils::lagrange_of_dense_vec(&effective, &z).unwrap();
            let domain = GeneralEvaluationDomain::<Fr>::new(effective.num_constraints).unwrap();
            let q = LibsnarkReduction::compute_quotient::<Fr, GeneralEvaluationDomain<Fr>>(
                &domain, a, b, c,
            )
            .unwrap();
            assert_eq!(q.len(), domain.size());
            assert!(q.last().unwrap().is_zero());
            let raw = dynark::Groth16::<Bn254>::create_proof_with_assignment(
                &pk,
                Fr::from(17),
                Fr::from(18),
                &q,
                &z[..m.num_instance_variables],
                &z[m.num_instance_variables..],
            )
            .unwrap();
            assert_eq!(
                result.proof,
                ordinary::Proof {
                    a: raw.a_g1,
                    b: raw.b_g2,
                    c: raw.c_g1
                }
            );
            assert!(verify(&p, &result.proof, &result.public_values));
        }
    }
}

#[test]
fn malformed_assignment_and_constant_coordinate_are_typed() {
    let (m, z) = c_only();
    let p = package(&m, Reduction::Original, 4);
    let b = bytes(&z);
    assert!(matches!(
        p.validate_assignment(&b[..2], &z[1..2]),
        Err(Error::AssignmentCount)
    ));
    let mut long = b.clone();
    long.push([0; 32]);
    assert!(matches!(
        p.validate_assignment(&long, &z[1..2]),
        Err(Error::AssignmentCount)
    ));
    let mut bad = b.clone();
    bad[2] = [255; 32];
    assert!(matches!(
        p.validate_assignment(&bad, &z[1..2]),
        Err(Error::NonCanonicalField { coordinate: 2 })
    ));
    let mut modulus = b.clone();
    modulus[2] = Fr::MODULUS.to_bytes_le().try_into().unwrap();
    assert!(matches!(
        p.validate_assignment(&modulus, &z[1..2]),
        Err(Error::NonCanonicalField { coordinate: 2 })
    ));
    for value in [Fr::zero(), Fr::from(2)] {
        let mut wrong = z.clone();
        wrong[0] = value;
        assert!(matches!(
            p.validate_assignment(&bytes(&wrong), &z[1..2]),
            Err(Error::ConstantOne)
        ));
    }
    assert!(matches!(
        p.validate_assignment(&b, &[Fr::from(10)]),
        Err(Error::PublicStatement)
    ));
    assert!(matches!(
        p.validate_assignment(&b, &[]),
        Err(Error::PublicStatement)
    ));
    let mut wrong = z.clone();
    wrong[2] = Fr::from(4);
    assert!(matches!(
        p.validate_assignment(&bytes(&wrong), &z[1..2]),
        Err(Error::Unsatisfied { row: 0 })
    ));
}

#[test]
fn malformed_matrix_counts_indices_splits_and_domain_are_rejected() {
    let (m, _) = c_only();
    let pk = key(&m, Reduction::Original, 5);
    let d = descriptor(2, Reduction::Original);
    let expected = PublicPackage::inspect_identity(&m, &d, &pk).unwrap();
    let mut variants = Vec::new();
    let mut x = m.clone();
    x.a.pop();
    variants.push(x);
    let mut x = m.clone();
    x.a_num_non_zero += 1;
    variants.push(x);
    let mut x = m.clone();
    x.a[0][0].1 = 3;
    variants.push(x);
    let mut x = m.clone();
    x.b[0][0].1 = usize::MAX;
    variants.push(x);
    let mut x = m.clone();
    x.num_instance_variables = 0;
    variants.push(x);
    let mut x = m.clone();
    x.num_witness_variables = usize::MAX;
    variants.push(x);
    let mut x = m.clone();
    x.num_constraints = usize::MAX;
    variants.push(x);
    let mut x = m.clone();
    x.num_instance_variables = 3;
    x.num_witness_variables = 0;
    variants.push(x);
    for bad in variants {
        assert!(PublicPackage::new(bad, d.clone(), pk.clone(), expected).is_err());
    }
    let mut malformed = d.clone();
    malformed.public_schema.push("extra".into());
    assert!(matches!(
        PublicPackage::new(m.clone(), malformed, pk.clone(), expected),
        Err(Error::Schema(_))
    ));
    let mut malformed = d;
    malformed.public_schema_digest = [0; 32];
    assert!(matches!(
        PublicPackage::new(m, malformed, pk, expected),
        Err(Error::Schema(_))
    ));
}

#[test]
fn wrong_keys_queries_metadata_and_matrix_content_cannot_share_identity() {
    let (m, _) = c_only();
    let d = descriptor(2, Reduction::Original);
    let pk = key(&m, Reduction::Original, 6);
    let expected = PublicPackage::inspect_identity(&m, &d, &pk).unwrap();
    assert!(matches!(
        PublicPackage::new(
            m.clone(),
            d.clone(),
            key(&m, Reduction::Original, 7),
            expected
        ),
        Err(Error::IdentityMismatch)
    ));
    let mut other = d.clone();
    other.witness_executable_digest = [99; 32];
    assert!(matches!(
        PublicPackage::new(m.clone(), other, pk.clone(), expected),
        Err(Error::IdentityMismatch)
    ));
    let mut other = d.clone();
    other.profile_digest = [99; 32];
    assert!(matches!(
        PublicPackage::new(m.clone(), other, pk.clone(), expected),
        Err(Error::IdentityMismatch)
    ));
    let mut other = d.clone();
    other.r1cs_artifact_digest = [99; 32];
    assert!(matches!(
        PublicPackage::new(m.clone(), other, pk.clone(), expected),
        Err(Error::IdentityMismatch)
    ));
    let mut other = d.clone();
    other.public_schema[0] = "different".into();
    other.public_schema_digest = public_schema_digest(&other.public_schema);
    assert!(matches!(
        PublicPackage::new(m.clone(), other, pk.clone(), expected),
        Err(Error::IdentityMismatch)
    ));
    let mut changed = m.clone();
    changed.c[0][0].0 = Fr::from(2);
    assert!(matches!(
        PublicPackage::new(changed, d.clone(), pk.clone(), expected),
        Err(Error::IdentityMismatch)
    ));
    for i in 0..6 {
        let mut bad = pk.clone();
        match i {
            0 => {
                bad.u_g1.pop();
            }
            1 => {
                bad.v_g1.pop();
            }
            2 => {
                bad.v_g2.pop();
            }
            3 => {
                bad.t_p_g1.pop();
            }
            4 => {
                bad.vk.t_v_g1.pop();
            }
            _ => {
                bad.tau_powers_g1.pop();
            }
        }
        assert!(matches!(
            PublicPackage::new(m.clone(), d.clone(), bad, expected),
            Err(Error::Key(_))
        ));
    }
    let mut bad = pk;
    bad.vk.domain = GeneralEvaluationDomain::new(16).unwrap();
    assert!(matches!(
        PublicPackage::new(m, d, bad, expected),
        Err(Error::Key(_))
    ));
}

#[test]
fn entropy_failure_including_second_draw_returns_no_output_or_panic() {
    let (m, z) = c_only();
    let p = package(&m, Reduction::Original, 8);
    let a = p.validate_assignment(&bytes(&z), &z[1..2]).unwrap();
    let identity = p.identity();
    for fail_at in [0, 1] {
        let mut rng = Scripted {
            calls: 0,
            fail_at: Some(fail_at),
            reject: false,
        };
        let outcome =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prove(&p, &a, 0, &mut rng)));
        assert!(matches!(outcome,Ok(Err(Error::Entropy{draw,..})) if draw==fail_at));
        assert_eq!(rng.calls, fail_at + 1);
        assert_eq!(p.identity(), identity);
    }
    let output = prove(&p, &a, 0, &mut rand::rngs::OsRng).unwrap();
    assert!(verify(&p, &output.proof, &output.public_values));
}

#[test]
fn pathological_rng_has_a_bounded_rejection_failure() {
    let (m, z) = c_only();
    let p = package(&m, Reduction::Original, 9);
    let a = p.validate_assignment(&bytes(&z), &z[1..2]).unwrap();
    let mut rng = Scripted {
        calls: 0,
        fail_at: None,
        reject: true,
    };
    assert!(matches!(
        prove(&p, &a, 0, &mut rng),
        Err(Error::RejectionLimit { draw: 0 })
    ));
    assert_eq!(rng.calls, 128);
}

#[test]
fn immutable_package_clones_share_storage_and_os_randomness_refreshes() {
    let (m, z) = c_only();
    let p = package(&m, Reduction::Original, 10);
    let clone = p.clone();
    assert!(p.shares_storage_with(&clone));
    let a = p.validate_assignment(&bytes(&z), &z[1..2]).unwrap();
    let mut rng = rand::rngs::OsRng;
    let first = prove(&p, &a, 1, &mut rng).unwrap();
    let second = prove(&clone, &a, 2, &mut rng).unwrap();
    assert_ne!(first.proof, second.proof);
    assert!(verify(&p, &first.proof, &first.public_values));
    assert!(verify(&clone, &second.proof, &second.public_values));
}

#[test]
fn rejected_entropy_candidates_and_zero_samples_use_complete_proofs() {
    struct Candidates {
        calls: usize,
        second_exhausts: bool,
    }
    impl CryptoRng for Candidates {}
    impl RngCore for Candidates {
        fn next_u32(&mut self) -> u32 {
            panic!("unexpected infallible RNG use")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("unexpected infallible RNG use")
        }
        fn fill_bytes(&mut self, _: &mut [u8]) {
            panic!("unexpected infallible RNG use")
        }
        fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand::Error> {
            let call = self.calls;
            self.calls += 1;
            bytes.fill(
                if (self.second_exhausts && call > 0) || (!self.second_exhausts && call == 0) {
                    255
                } else {
                    0
                },
            );
            Ok(())
        }
    }
    let (m, z) = c_only();
    let p = package(&m, Reduction::Original, 11);
    let a = p.validate_assignment(&bytes(&z), &z[1..2]).unwrap();
    let mut rng = Candidates {
        calls: 0,
        second_exhausts: false,
    };
    let output = prove(&p, &a, 0, &mut rng).unwrap();
    assert_eq!(rng.calls, 3);
    assert!(verify(&p, &output.proof, &output.public_values));
    let mut rng = Candidates {
        calls: 0,
        second_exhausts: true,
    };
    assert!(matches!(
        prove(&p, &a, 0, &mut rng),
        Err(Error::RejectionLimit { draw: 1 })
    ));
    assert_eq!(rng.calls, 129);
}

#[test]
fn invalid_group_points_and_degenerate_denominators_are_rejected() {
    use ark_bn254::{Fq, G1Affine, G2Affine};
    use ark_ec::AffineRepr;
    let (m, _) = c_only();
    let d = descriptor(2, Reduction::Original);
    let pk = key(&m, Reduction::Original, 12);
    let expected = PublicPackage::inspect_identity(&m, &d, &pk).unwrap();
    let mut invalid = pk.clone();
    invalid.u_g1[0] = G1Affine::new_unchecked(Fq::from(1), Fq::from(1));
    assert!(matches!(
        PublicPackage::new(m.clone(), d.clone(), invalid, expected),
        Err(Error::Key(_))
    ));
    let mut invalid = pk.clone();
    invalid.vk.gamma_g2 = G2Affine::zero();
    assert!(matches!(
        PublicPackage::new(m.clone(), d.clone(), invalid, expected),
        Err(Error::Key(_))
    ));
    let mut invalid = pk;
    invalid.delta_g1 = G1Affine::zero();
    assert!(matches!(
        PublicPackage::new(m, d, invalid, expected),
        Err(Error::Key(_))
    ));
}

#[test]
fn sparse_duplicate_entries_and_zero_public_values_remain_valid() {
    let (mut m, mut z) = five();
    m.a[0] = vec![(Fr::from(2), 8), (-Fr::ONE, 8), (Fr::zero(), 7)];
    m.a_num_non_zero += 2;
    z[2..6].fill(Fr::zero());
    let p = package(&m, Reduction::Original, 13);
    let wrong_key = package(&m, Reduction::Original, 14);
    let a = p.validate_assignment(&bytes(&z), &z[1..6]).unwrap();
    let output = prove(&p, &a, 0, &mut rand::rngs::OsRng).unwrap();
    assert!(verify(&p, &output.proof, &output.public_values));
    assert!(!verify(&wrong_key, &output.proof, &output.public_values));
    for i in 0..5 {
        let mut changed = output.public_values.clone();
        changed[i] += Fr::ONE;
        assert!(!verify(&p, &output.proof, &changed));
    }
}
