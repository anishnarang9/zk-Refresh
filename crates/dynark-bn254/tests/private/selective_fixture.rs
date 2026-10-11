use crate::{public_schema_digest, CircuitDescriptor, PublicPackage, Reduction};
use ark_bn254::{Bn254, Fr};
use ark_ff::Field;
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::CanonicalSerialize;
use rand::SeedableRng;

pub(super) fn encode(z: &[Fr]) -> Vec<[u8; 32]> {
    z.iter()
        .map(|x| {
            let mut out = Vec::new();
            x.serialize_compressed(&mut out).unwrap();
            out.try_into().unwrap()
        })
        .collect()
}
pub(super) fn delta(a: &[Fr], b: &[Fr]) -> Vec<(usize, [u8; 32])> {
    a.iter()
        .zip(b)
        .enumerate()
        .skip(1)
        .filter(|(_, (a, b))| a != b)
        .map(|(i, (a, b))| (i, encode(&[*b - *a])[0]))
        .collect()
}
// Dense satisfying sign flips, plus an independent C-only public value y=u.
// Augmented A rows include all six instances. These are public synthetic fixtures.
pub(super) fn package(n: usize, reduction: Reduction, extra: usize) -> PublicPackage {
    build(n, reduction, extra, false, 0)
}
pub(super) fn single_sided_package(n: usize, reduction: Reduction) -> PublicPackage {
    build(n, reduction, 3, true, 0)
}
pub(super) fn compact_package(n: usize, reduction: Reduction) -> PublicPackage {
    build(n, reduction, 3, false, 1)
}
pub(super) fn fanout_package(n: usize, reduction: Reduction) -> PublicPackage {
    build(n, reduction, 3, false, 2)
}
fn build(
    n: usize,
    reduction: Reduction,
    extra: usize,
    single_sided: bool,
    compact: u8,
) -> PublicPackage {
    let instances = 6;
    let rows = match reduction {
        Reduction::Original => n - 1,
        Reduction::InstanceAugmentedA => n - instances,
    };
    let v = if compact != 0 {
        9
    } else {
        instances + rows + extra
    };
    let mut a = vec![Vec::new(); rows];
    let mut b = a.clone();
    let mut c = a.clone();
    for i in 0..rows {
        a[i] = vec![(
            Fr::ONE,
            if compact != 0 {
                if i == 0 || compact == 2 {
                    6
                } else {
                    0
                }
            } else {
                instances + i
            },
        )];
        b[i] = a[i].clone();
        c[i] = vec![(Fr::ONE, 1)];
    }
    c[0].extend([
        (Fr::ONE, 2),
        (-Fr::ONE, v - 1),
        (Fr::ONE, 3),
        (Fr::ONE, 4),
        (Fr::ONE, 5),
        (-Fr::from(71), 0),
    ]);
    if single_sided {
        b[rows - 1].clear();
        c[rows - 1].clear();
    }
    // Empty B and zero anchor A/B rows are exercised by separate private entry oracles.
    let m = ConstraintMatrices {
        num_instance_variables: instances,
        num_witness_variables: v - instances,
        num_constraints: rows,
        a_num_non_zero: a.iter().map(Vec::len).sum(),
        b_num_non_zero: b.iter().map(Vec::len).sum(),
        c_num_non_zero: c.iter().map(Vec::len).sum(),
        a,
        b,
        c,
    };
    let reduced = if reduction == Reduction::InstanceAugmentedA {
        let mut out = m.clone();
        for j in 0..instances {
            out.a.push(vec![(Fr::ONE, j)]);
            out.b.push(Vec::new());
            out.c.push(Vec::new());
        }
        out.num_constraints += instances;
        out.a_num_non_zero += instances;
        out
    } else {
        m.clone()
    };
    let mut rng =
        rand::rngs::StdRng::seed_from_u64(0x5032453761 ^ n as u64 ^ ((extra as u64) << 16));
    let pk = dynark::Groth16::<Bn254>::groth16_setup_dynark(reduced, &mut rng)
        .unwrap()
        .0;
    let names = vec!["x", "y", "issuer", "before", "action"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let descriptor = CircuitDescriptor {
        r1cs_artifact_digest: [71; 32],
        witness_executable_digest: [72; 32],
        profile_digest: [73; 32],
        public_schema_digest: public_schema_digest(&names),
        public_schema: names,
        reduction,
    };
    let identity = PublicPackage::inspect_identity(&m, &descriptor, &pk).unwrap();
    PublicPackage::new(m, descriptor, pk, identity).unwrap()
}
pub(super) fn assignment(p: &PublicPackage, flips: &[usize]) -> Vec<Fr> {
    let mut z = vec![Fr::ONE; p.shape().assignment_len];
    z[2] = Fr::from(17);
    z[3] = Fr::from(19);
    z[4] = Fr::from(23);
    z[5] = Fr::from(29);
    *z.last_mut().unwrap() = Fr::from(17);
    for &i in flips {
        z[6 + i] = -Fr::ONE;
    }
    z
}
pub(super) fn verify(p: &PublicPackage, proof: &crate::ProofStatement, z: &[Fr]) {
    assert_eq!(proof.public_values, z[1..p.shape().instance_len]);
    let vk = ordinary::prepare_verifying_key(&p.ordinary_verifying_key());
    assert!(
        ordinary::Groth16::<Bn254>::verify_proof(&vk, &proof.proof, &proof.public_values).unwrap()
    );
    for i in 0..proof.public_values.len() {
        let mut wrong = proof.public_values.clone();
        wrong[i] += Fr::ONE;
        assert!(!ordinary::Groth16::<Bn254>::verify_proof(&vk, &proof.proof, &wrong).unwrap());
    }
}
