//! Complete ordinary Groth16 verification; never confuses checks with proofs.
use crate::artifacts::*;
use ark_bn254::{Bn254, Fr};
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use dynark_bn254::{ProofStatement, PublicPackage};
use serde_json::{json, Value};
use std::{io::Write, path::Path};

#[derive(Default, Clone, Copy)]
pub(crate) struct Counts {
    pub proofs: u64,
    pub positives: u64,
    pub altered: u64,
    pub cross_root: u64,
}
impl Counts {
    pub fn checks(self) -> u64 {
        self.positives + self.altered + self.cross_root
    }
    pub fn json(self) -> Value {
        json!({"proofs":self.proofs,"positive_checks":self.positives,"altered_public_checks":self.altered,"cross_root_checks":self.cross_root,"ordinary_checks":self.checks()})
    }
    pub fn full(n: u64) -> Self {
        Self {
            proofs: 3 * n,
            positives: 3 * n,
            altered: 18 * n,
            cross_root: 2 * n,
        }
    }
    pub fn anchor(n: u64) -> Self {
        Self {
            proofs: n,
            positives: n,
            altered: 6 * n,
            cross_root: n,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn training_proof_and_check_counts_are_distinct() {
        let full = Counts::full(9);
        let anchor = Counts::anchor(9);
        assert_eq!(full.proofs, 27);
        assert_eq!(full.checks(), 207);
        assert_eq!(anchor.proofs, 9);
        assert_eq!(anchor.checks(), 72);
        assert_eq!(Counts::anchor(1).checks(), 8);
        assert_eq!(Counts::full(4).proofs, 12);
    }
}
pub(crate) fn verify_save(
    package: &PublicPackage,
    statement: &ProofStatement,
    expected: &[Fr],
    generation: u64,
    out: &Path,
    name: &str,
    counts: &mut Counts,
) -> Result<Vec<u8>> {
    required(
        statement.package == package.identity()
            && statement.public_values == expected
            && expected.len() == 6
            && statement.generation == generation,
        "exact proof statement context",
    )?;
    let vk = ordinary::prepare_verifying_key(&package.ordinary_verifying_key());
    let mut bytes = Vec::new();
    statement.proof.serialize_compressed(&mut bytes)?;
    required(bytes.len() == 128, "ordinary compressed proof size")?;
    let decoded = ordinary::Proof::<Bn254>::deserialize_compressed(&bytes[..])?;
    required(
        ordinary::Groth16::<Bn254>::verify_proof(&vk, &decoded, expected)?,
        "ordinary positive rejected",
    )?;
    counts.proofs += 1;
    counts.positives += 1;
    for i in 0..6 {
        let mut wrong = expected.to_vec();
        wrong[i] += Fr::ONE;
        required(
            !ordinary::Groth16::<Bn254>::verify_proof(&vk, &decoded, &wrong)?,
            "altered public accepted",
        )?;
        counts.altered += 1;
    }
    let mut proof_file = private_file(&out.join(format!("{name}.proof")))?;
    proof_file.write_all(&bytes)?;
    proof_file.sync_all()?;
    save(&out.join(format!("{name}-public.bin")), &expected.to_vec())?;
    Ok(bytes)
}
pub(crate) fn reject_cross_root(
    package: &PublicPackage,
    statement: &ProofStatement,
    wrong: &[Fr],
    counts: &mut Counts,
) -> Result<()> {
    let vk = ordinary::prepare_verifying_key(&package.ordinary_verifying_key());
    required(
        !ordinary::Groth16::<Bn254>::verify_proof(&vk, &statement.proof, wrong)?,
        "cross-root proof accepted",
    )?;
    counts.cross_root += 1;
    Ok(())
}
