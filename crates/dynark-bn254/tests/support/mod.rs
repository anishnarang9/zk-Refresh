#![allow(dead_code)]
use ark_bn254::{Bn254, Fr};
use ark_ff::Field;
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::CanonicalSerialize;
use dynark_bn254::{public_schema_digest, CircuitDescriptor, PublicPackage, Reduction};
use rand::SeedableRng;

pub fn bytes(z: &[Fr]) -> Vec<[u8; 32]> {
    z.iter()
        .map(|x| {
            let mut b = Vec::new();
            x.serialize_compressed(&mut b).unwrap();
            b.try_into().unwrap()
        })
        .collect()
}
pub fn relation(v: usize) -> ConstraintMatrices<Fr> {
    let a = vec![
        vec![(Fr::ONE, 2)],
        vec![(Fr::ONE, 2), (Fr::ONE, 3)],
        vec![],
        vec![(Fr::ONE, 3)],
        vec![],
    ];
    let b = vec![
        vec![(Fr::ONE, 2)],
        vec![(Fr::ONE, 3)],
        vec![(Fr::ONE, 2)],
        vec![],
        vec![],
    ];
    let c = vec![
        vec![(Fr::ONE, 1)],
        vec![(Fr::ONE, 4)],
        vec![],
        vec![],
        vec![],
    ];
    ConstraintMatrices {
        num_instance_variables: 2,
        num_witness_variables: v - 2,
        num_constraints: 5,
        a_num_non_zero: 4,
        b_num_non_zero: 3,
        c_num_non_zero: 2,
        a,
        b,
        c,
    }
}
pub fn assignment(v: usize, w: u64, t: u64) -> Vec<Fr> {
    let mut z = vec![Fr::from(0u64); v];
    z[0] = Fr::ONE;
    z[1] = Fr::from(w * w);
    z[2] = Fr::from(w);
    z[3] = Fr::from(t);
    z[4] = Fr::from((w + t) * t);
    z
}
pub fn descriptor(r: Reduction) -> CircuitDescriptor {
    let names = vec!["x".to_owned()];
    CircuitDescriptor {
        r1cs_artifact_digest: [11; 32],
        witness_executable_digest: [12; 32],
        profile_digest: [13; 32],
        public_schema_digest: public_schema_digest(&names),
        public_schema: names,
        reduction: r,
    }
}
pub fn package(v: usize, r: Reduction) -> PublicPackage {
    let m = relation(v);
    let mut reduced = m.clone();
    if r == Reduction::InstanceAugmentedA {
        for i in 0..2 {
            reduced.a.push(vec![(Fr::ONE, i)]);
            reduced.b.push(vec![]);
            reduced.c.push(vec![]);
        }
        reduced.num_constraints += 2;
        reduced.a_num_non_zero += 2;
    }
    let mut rng = rand::rngs::StdRng::seed_from_u64(82);
    let pk = dynark::Groth16::<Bn254>::groth16_setup_dynark(reduced, &mut rng)
        .unwrap()
        .0;
    let d = descriptor(r);
    let id = PublicPackage::inspect_identity(&m, &d, &pk).unwrap();
    PublicPackage::new(m, d, pk, id).unwrap()
}
pub fn verify(p: &PublicPackage, proof: &ordinary::Proof<Bn254>, public: &[Fr]) -> bool {
    ordinary::Groth16::<Bn254>::verify_proof(
        &ordinary::prepare_verifying_key(&p.ordinary_verifying_key()),
        proof,
        public,
    )
    .unwrap()
}
pub fn r1cs_bytes(m: &ConstraintMatrices<Fr>) -> Vec<u8> {
    use ark_ff::{BigInteger, PrimeField};
    let mut header = 32u32.to_le_bytes().to_vec();
    header.extend(Fr::MODULUS.to_bytes_le());
    for x in [
        m.num_instance_variables + m.num_witness_variables,
        0,
        m.num_instance_variables - 1,
        m.num_witness_variables,
    ] {
        header.extend((x as u32).to_le_bytes());
    }
    header.extend(((m.num_instance_variables + m.num_witness_variables) as u64).to_le_bytes());
    header.extend((m.num_constraints as u32).to_le_bytes());
    let mut rows = Vec::new();
    for i in 0..m.num_constraints {
        for matrix in [&m.a, &m.b, &m.c] {
            rows.extend((matrix[i].len() as u32).to_le_bytes());
            for (c, j) in &matrix[i] {
                rows.extend((*j as u32).to_le_bytes());
                rows.extend(bytes(&[*c])[0]);
            }
        }
    }
    sectioned(b"r1cs", 1, &[(1, header), (2, rows)])
}
pub fn wtns_bytes(z: &[Fr]) -> Vec<u8> {
    use ark_ff::{BigInteger, PrimeField};
    let mut h = 32u32.to_le_bytes().to_vec();
    h.extend(Fr::MODULUS.to_bytes_le());
    h.extend((z.len() as u32).to_le_bytes());
    sectioned(
        b"wtns",
        2,
        &[(1, h), (2, bytes(z).into_iter().flatten().collect())],
    )
}
pub fn sectioned(tag: &[u8; 4], version: u32, sections: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut out = tag.to_vec();
    out.extend(version.to_le_bytes());
    out.extend((sections.len() as u32).to_le_bytes());
    for (kind, data) in sections {
        out.extend(kind.to_le_bytes());
        out.extend((data.len() as u64).to_le_bytes());
        out.extend(data);
    }
    out
}
pub fn tempdir() -> std::path::PathBuf {
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("dynark-t2-{}-{suffix}", std::process::id()));
    std::fs::create_dir(&p).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    p
}
