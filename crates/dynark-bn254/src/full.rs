use crate::{randomness, Error, PackageIdentity, PublicPackage, ValidatedAssignment};
use ark_bn254::{Bn254, Fr};
use ark_ff::Zero;
use ark_poly::GeneralEvaluationDomain;
use dynark::r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};
use rand::{CryptoRng, RngCore};

/// A complete ordinary proof bound to an exact statement/package and caller-assigned generation.
/// This stateless T1 generation is not an authenticated persistence commitment.
#[derive(Debug)]
pub struct ProofStatement {
    pub proof: ordinary::Proof<Bn254>,
    pub public_values: Vec<Fr>,
    pub package: PackageIdentity,
    pub generation: u64,
}

/// Validated no-cache full proof, retaining coordinate one in the instance assignment.
/// Both fallible randomizers are sampled before proof arithmetic; failure returns no proof.
pub fn prove<R: RngCore + CryptoRng + ?Sized>(
    package: &PublicPackage,
    assignment: &ValidatedAssignment,
    generation: u64,
    rng: &mut R,
) -> Result<ProofStatement, Error> {
    let p = &package.0;
    if assignment.package != p.identity {
        return Err(Error::AssignmentPackage);
    }
    let (r, s) = randomness::blinders(rng)?;
    let (a, b, c) = dynark::utils::lagrange_of_dense_vec(&p.matrices, &assignment.values)
        .map_err(Error::Arithmetic)?;
    let quotient =
        LibsnarkReduction::compute_quotient::<Fr, GeneralEvaluationDomain<Fr>>(&p.domain, a, b, c)
            .map_err(Error::Arithmetic)?;
    if quotient.len() != p.shape.domain_size || !quotient[p.shape.domain_size - 1].is_zero() {
        return Err(Error::QuotientDegree);
    }
    let proof = dynark::Groth16::<Bn254>::create_proof_with_assignment(
        &p.pk,
        r,
        s,
        &quotient[..p.shape.domain_size - 1],
        &assignment.values[..p.shape.instance_len],
        &assignment.values[p.shape.instance_len..],
    )
    .map_err(Error::Arithmetic)?;
    Ok(ProofStatement {
        proof: ordinary::Proof {
            a: proof.a_g1,
            b: proof.b_g2,
            c: proof.c_g1,
        },
        public_values: assignment.values[1..p.shape.instance_len].to_vec(),
        package: p.identity,
        generation,
    })
}
