mod support;
use ark_bn254::Fr;
use ark_ff::Field;
use dynark_bn254::{Anchor, AnchorBinding, Error, Limits, Reduction, Transition, UpdatingMaterial};

#[test]
fn randomized_anchored_updates_are_exact_statement_and_immutable() {
    for v in [5, 11] {
        for r in [Reduction::Original, Reduction::InstanceAugmentedA] {
            let p = support::package(v, r);
            let uk = UpdatingMaterial::prepare(&p, Limits::small()).unwrap();
            let z = support::assignment(v, 3, 2);
            let validated = p
                .validate_assignment(&support::bytes(&z), &z[1..2])
                .unwrap();
            let binding = AnchorBinding::new(&p, [1; 32], [2; 32], 7);
            let anchor = Anchor::create(
                &p,
                &uk,
                validated,
                binding,
                Limits::small(),
                &mut rand::rngs::OsRng,
            )
            .unwrap();
            let binding = anchor.binding();
            for target in [
                support::assignment(v, 4, 1),
                support::assignment(v, 3, 2),
                support::assignment(v, 2, 3),
            ] {
                let raw = z
                    .iter()
                    .zip(&target)
                    .enumerate()
                    .filter(|(i, _)| *i > 0)
                    .map(|(i, (a, b))| (i, support::bytes(&[*b - *a])[0]))
                    .collect::<Vec<_>>();
                let t =
                    Transition::new(&p, binding, 8, &raw, &target[1..2], Limits::small()).unwrap();
                let proof = anchor
                    .update(&p, &uk, &t, Limits::small(), &mut rand::rngs::OsRng)
                    .unwrap();
                assert!(support::verify(&p, &proof.proof, &target[1..2]));
                assert_eq!(proof.generation, 8);
                assert_eq!(binding, anchor.binding());
                assert!(!support::verify(&p, &proof.proof, &[target[1] + Fr::ONE]));
            }
            let mut wrong = binding;
            wrong.action = [3; 32];
            let t = Transition::new(&p, wrong, 8, &[], &z[1..2], Limits::small()).unwrap();
            assert!(matches!(
                anchor.update(&p, &uk, &t, Limits::small(), &mut rand::rngs::OsRng),
                Err(Error::AnchorBinding)
            ));
            assert_eq!(binding, anchor.binding());
        }
    }
}

#[test]
fn all_five_public_coordinates_are_validated_and_changed_action_is_explicit() {
    use ark_relations::r1cs::ConstraintMatrices;
    use dynark_bn254::{public_schema_digest, CircuitDescriptor, PublicPackage};
    use rand::SeedableRng;
    let mut a = vec![vec![(Fr::ONE, 6)]];
    let mut b = a.clone();
    let mut c = vec![vec![(Fr::ONE, 1)]];
    for j in 2..6 {
        a.push(vec![(Fr::ONE, j)]);
        b.push(vec![(Fr::ONE, 0)]);
        c.push(vec![(Fr::ONE, j)]);
    }
    let m = ConstraintMatrices {
        num_instance_variables: 6,
        num_witness_variables: 1,
        num_constraints: 5,
        a_num_non_zero: 5,
        b_num_non_zero: 5,
        c_num_non_zero: 5,
        a,
        b,
        c,
    };
    let names = ["root", "issuerHash", "notBefore", "notAfter", "actionHash"]
        .map(str::to_owned)
        .to_vec();
    let d = CircuitDescriptor {
        r1cs_artifact_digest: [1; 32],
        witness_executable_digest: [2; 32],
        profile_digest: [3; 32],
        public_schema_digest: public_schema_digest(&names),
        public_schema: names,
        reduction: Reduction::Original,
    };
    let pk = dynark::Groth16::<ark_bn254::Bn254>::groth16_setup_dynark(
        m.clone(),
        &mut rand::rngs::StdRng::seed_from_u64(47),
    )
    .unwrap()
    .0;
    let id = PublicPackage::inspect_identity(&m, &d, &pk).unwrap();
    let p = PublicPackage::new(m, d, pk, id).unwrap();
    let uk = UpdatingMaterial::prepare(&p, Limits::small()).unwrap();
    let z = [1, 9, 2, 3, 4, 5, 3].map(Fr::from).to_vec();
    let va = p
        .validate_assignment(&support::bytes(&z), &z[1..6])
        .unwrap();
    let anchor = Anchor::create(
        &p,
        &uk,
        va,
        AnchorBinding::new(&p, [1; 32], [2; 32], 7),
        Limits::small(),
        &mut rand::rngs::OsRng,
    )
    .unwrap();
    let target = [1, 16, 12, 13, 14, 15, 4].map(Fr::from).to_vec();
    let raw = z
        .iter()
        .zip(&target)
        .enumerate()
        .skip(1)
        .map(|(j, (x, y))| (j, support::bytes(&[*y - *x])[0]))
        .collect::<Vec<_>>();
    let tr = Transition::new(
        &p,
        anchor.binding(),
        8,
        &raw,
        &target[1..6],
        Limits::small(),
    )
    .unwrap();
    let proof = anchor
        .update(&p, &uk, &tr, Limits::small(), &mut rand::rngs::OsRng)
        .unwrap();
    assert!(support::verify(&p, &proof.proof, &target[1..6]));
    for i in 0..5 {
        let mut wrong = target[1..6].to_vec();
        wrong[i] += Fr::ONE;
        assert!(!support::verify(&p, &proof.proof, &wrong));
        let bad = Transition::new(&p, anchor.binding(), 8, &raw, &wrong, Limits::small()).unwrap();
        assert!(matches!(
            anchor.update(&p, &uk, &bad, Limits::small(), &mut rand::rngs::OsRng),
            Err(Error::PublicStatement)
        ));
    }
    // This is a mathematical fixture. Different application action binding requires a new anchor.
    let mut binding = anchor.binding();
    binding.action = [9; 32];
    let bad = Transition::new(&p, binding, 8, &raw, &target[1..6], Limits::small()).unwrap();
    assert!(matches!(
        anchor.update(&p, &uk, &bad, Limits::small(), &mut rand::rngs::OsRng),
        Err(Error::AnchorBinding)
    ));
}
