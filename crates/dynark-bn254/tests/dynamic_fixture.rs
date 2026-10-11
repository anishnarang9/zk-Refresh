#![allow(dead_code)]
use ark_bn254::{Bn254, Fr};
use ark_ff::Field;
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::CanonicalSerialize;
use dynark_bn254::{public_schema_digest, CircuitDescriptor, PublicPackage, Reduction};
use rand::SeedableRng;

pub fn encode(z: &[Fr]) -> Vec<[u8; 32]> {
    z.iter()
        .map(|x| {
            let mut b = Vec::new();
            x.serialize_compressed(&mut b).unwrap();
            b.try_into().unwrap()
        })
        .collect()
}
pub fn assignment(v: usize, w: u64, t: u64) -> Vec<Fr> {
    let mut z = vec![Fr::from(0u64); v];
    z[0] = Fr::ONE;
    z[1] = Fr::from(w * w);
    z[2] = Fr::from(w);
    z[3] = Fr::from(t);
    z[4] = Fr::from((w + t) * t);
    for (i, x) in z.iter_mut().enumerate().skip(5) {
        *x = Fr::from((i as u64 + w + t) % 11);
    }
    z
}
pub fn package(n: usize, v: usize, dense: bool) -> PublicPackage {
    let rows = if n == 2 { 2 } else { n - 1 };
    let mut a = vec![Vec::new(); rows];
    let mut b = a.clone();
    let mut c = a.clone();
    a[0] = vec![(Fr::ONE, 2)];
    b[0] = vec![(Fr::ONE, 2)];
    c[0] = vec![(Fr::ONE, 1)];
    a[1] = vec![(Fr::ONE, 2), (Fr::ONE, 3)];
    b[1] = vec![(Fr::ONE, 3)];
    c[1] = vec![(Fr::ONE, 4)];
    for i in 2..rows {
        match i % 3 {
            0 => {
                a[i] = if dense {
                    (2..v).map(|j| (Fr::from((j % 3 + 1) as u64), j)).collect()
                } else {
                    vec![(Fr::ONE, 2)]
                };
            }
            1 => {
                b[i] = vec![(Fr::ONE, 3)];
            }
            _ => {}
        }
    }
    if v > 5 && rows > 2 {
        a[2] = vec![(Fr::ONE, 5)];
    }
    let m = ConstraintMatrices {
        num_instance_variables: 2,
        num_witness_variables: v - 2,
        num_constraints: rows,
        a_num_non_zero: a.iter().map(Vec::len).sum(),
        b_num_non_zero: b.iter().map(Vec::len).sum(),
        c_num_non_zero: c.iter().map(Vec::len).sum(),
        a,
        b,
        c,
    };
    let mut rng = rand::rngs::StdRng::seed_from_u64(5000 + n as u64 + v as u64);
    let pk = dynark::Groth16::<Bn254>::groth16_setup_dynark(m.clone(), &mut rng)
        .unwrap()
        .0;
    let names = vec!["x".to_owned()];
    let desc = CircuitDescriptor {
        r1cs_artifact_digest: [21; 32],
        witness_executable_digest: [22; 32],
        profile_digest: [23; 32],
        public_schema_digest: public_schema_digest(&names),
        public_schema: names,
        reduction: Reduction::Original,
    };
    let id = PublicPackage::inspect_identity(&m, &desc, &pk).unwrap();
    PublicPackage::new(m, desc, pk, id).unwrap()
}
pub fn delta(a: &[Fr], b: &[Fr]) -> Vec<(usize, [u8; 32])> {
    a.iter()
        .zip(b)
        .enumerate()
        .skip(1)
        .filter(|(_, (x, y))| x != y)
        .map(|(j, (x, y))| (j, encode(&[*y - *x])[0]))
        .collect()
}

pub fn five_public_assignment(w: u64, t: u64) -> Vec<Fr> {
    [
        1,
        w * w,
        31 + w,
        50 + t,
        90 + t,
        101 + w + t,
        w,
        t,
        (w + t) * t,
    ]
    .into_iter()
    .map(Fr::from)
    .collect()
}
pub fn five_public_package(reduction: Reduction) -> PublicPackage {
    let mut a = vec![Vec::new(); 9];
    let mut b = a.clone();
    let mut c = a.clone();
    a[0] = vec![(Fr::ONE, 6)];
    b[0] = a[0].clone();
    c[0] = vec![(Fr::ONE, 1)];
    a[1] = vec![(Fr::ONE, 6), (Fr::ONE, 7)];
    b[1] = vec![(Fr::ONE, 7)];
    c[1] = vec![(Fr::ONE, 8)];
    for i in 2..9 {
        a[i] = vec![(Fr::ONE, 1 + i % 5)];
    }
    let m = ConstraintMatrices {
        num_instance_variables: 6,
        num_witness_variables: 3,
        num_constraints: 9,
        a_num_non_zero: a.iter().map(Vec::len).sum(),
        b_num_non_zero: b.iter().map(Vec::len).sum(),
        c_num_non_zero: c.iter().map(Vec::len).sum(),
        a,
        b,
        c,
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
    let mut rng = rand::rngs::StdRng::seed_from_u64(9031);
    let pk = dynark::Groth16::<Bn254>::groth16_setup_dynark(reduced, &mut rng)
        .unwrap()
        .0;
    let names = ["root", "issuerHash", "notBefore", "notAfter", "actionHash"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let descriptor = CircuitDescriptor {
        r1cs_artifact_digest: [41; 32],
        witness_executable_digest: [42; 32],
        profile_digest: [43; 32],
        public_schema_digest: public_schema_digest(&names),
        public_schema: names,
        reduction,
    };
    let identity = PublicPackage::inspect_identity(&m, &descriptor, &pk).unwrap();
    PublicPackage::new(m, descriptor, pk, identity).unwrap()
}
