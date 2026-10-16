//! Non-authorizing complete v3 relation boundary.
//!
//! Input candidate values must originate in the pinned native input worker.
//! Candidate JSON and WTNS are untrusted outputs, never expected-value sources.
//! Structural/cryptographic relation acceptance authenticates no chain account,
//! enrollment, allocation, clock, request, signer capability or application right.
//! V3BoundWitness::open_full remains closed until concrete live authorities and
//! exact admitted credential/action/state bindings are integrated separately.
use crate::{
    ClientError, OperationControl, V3CompilerInputMap, V3InputCandidate, V3SharedSetup, WitnessMode,
    V3_COORDINATES, V3_INPUT_KEYS, V3_INPUT_SCALARS, V3_WITNESS_BYTES,
};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::CanonicalDeserialize;
use dynark_bn254::ValidatedAssignment;
use std::fmt::Write;

// Exact worker scalar groups in the independent reference.FIELDS order. Neither
// supplied JSON nor a caller-selected coordinate can redefine this layout.
const INPUT_LENGTHS: [usize; 14] = [1, 1, 1, 1, 1, 1, 1, 1, 672, 17, 17, 17, 10, 10];
const INPUT_JSON_CAP: usize = 65_536;

/// Private complete-assignment result, not a chain or application capability.
/// No public constructor, deserializer, Debug, or proof interface is supplied.
pub struct V3CheckedRelation {
    assignment: ValidatedAssignment,
}
impl V3CheckedRelation {
    /// Test-only mathematical qualification; establishes no current authority.
    #[cfg(test)]
    fn prove_qualification_full(
        &self,
        setup: &V3SharedSetup,
        control: &OperationControl,
    ) -> Result<dynark_bn254::ProofStatement, ClientError> {
        control.check()?;
        let statement = dynark_bn254::prove(
            setup.package(),
            &self.assignment,
            0,
            &mut rand::rngs::OsRng,
        )
        .map_err(|error| match error {
            dynark_bn254::Error::Entropy { .. }
            | dynark_bn254::Error::RejectionLimit { .. } => ClientError::Entropy,
            _ => ClientError::Proof,
        });
        control.check()?;
        let statement = statement?;
        let verification = verify_qualification_full(
            &setup.package().ordinary_verifying_key(),
            &statement.proof,
            &statement.public_values,
        );
        control.check()?;
        verification?;
        Ok(statement)
    }

    /// Derive exact 14-key canonical JSON from the 751 checked input scalars;
    /// compare the supplied serialization byte-for-byte. Require Full mode,
    /// canonical 25,113,548-byte WTNS with 784,796 coordinates, constant one and
    /// the exact six public values. Compare all 751 input coordinates using the
    /// independently authenticated compiler map before relation evaluation.
    /// Validate every field and the entire R1CS using the admitted shared
    /// PublicPackage::validate_assignment before constructing this object.
    /// Check OperationControl at each bounded stage. No proof is created.
    pub fn check(
        setup: &V3SharedSetup,
        input_map: &V3CompilerInputMap,
        candidate: &V3InputCandidate,
        input_json: &[u8],
        wtns: &[u8],
        mode: WitnessMode,
        control: &OperationControl,
    ) -> Result<Self, ClientError> {
        control.check()?;
        if mode != WitnessMode::Full {
            return Err(ClientError::Unsupported);
        }
        let package = setup.package();
        let shape = package.shape();
        if shape.assignment_len != V3_COORDINATES
            || shape.instance_len != 7
            || shape.constraint_rows != 793_681
            || shape.reduction_rows != 793_681
        {
            return Err(ClientError::Identity);
        }
        if input_json.is_empty() || input_json.len() > INPUT_JSON_CAP {
            return Err(ClientError::Bound);
        }

        let scalars = candidate.scalars();
        let mut expected_json = String::new();
        expected_json
            .try_reserve_exact(INPUT_JSON_CAP)
            .map_err(|_| ClientError::Bound)?;
        let mut expected_public = [Fr::from(0u64); 6];
        let mut scalar = 0;
        expected_json.push('{');
        for (field, length) in INPUT_LENGTHS.iter().copied().enumerate() {
            control.check()?;
            if field != 0 {
                expected_json.push(',');
            }
            write!(expected_json, "\"{}\":", V3_INPUT_KEYS[field])
                .map_err(|_| ClientError::Encoding)?;
            if length > 1 {
                expected_json.push('[');
            }
            for index in 0..length {
                if index != 0 {
                    expected_json.push(',');
                }
                let value = Fr::deserialize_compressed(&scalars[scalar][..])
                    .map_err(|_| ClientError::Encoding)?;
                if scalar < expected_public.len() {
                    expected_public[scalar] = value;
                }
                // Canonical decimal strings, including zero, with no whitespace
                // or newline. actionHash is already LE in the worker candidate.
                write!(expected_json, "\"{}\"", value.into_bigint())
                    .map_err(|_| ClientError::Encoding)?;
                scalar += 1;
            }
            if length > 1 {
                expected_json.push(']');
            }
        }
        expected_json.push('}');
        if scalar != V3_INPUT_SCALARS || expected_json.as_bytes() != input_json {
            return Err(ClientError::Identity);
        }
        drop(expected_json);
        control.check()?;

        let words = parse_wtns(wtns, control)?;
        let mut scalar = 0;
        for (field, length) in INPUT_LENGTHS.iter().copied().enumerate() {
            control.check()?;
            for index in 0..length {
                let key = V3_INPUT_KEYS[field];
                let name = if length == 1 {
                    format!("main.{key}")
                } else {
                    format!("main.{key}[{index}]")
                };
                let coordinate = input_map.coordinate(&name).ok_or(ClientError::Identity)?;
                if coordinate == 0
                    || (field < 6 && coordinate != field + 1)
                    || words.get(coordinate) != Some(&scalars[scalar])
                {
                    return Err(ClientError::Identity);
                }
                scalar += 1;
            }
        }
        // The admitted package scans every relation row. Its API has no
        // cancellation callback, so retain even an error until control is
        // checked again after the finite, nonpreemptible scan.
        control.check()?;
        let assignment = package.validate_assignment(&words, &expected_public);
        control.check()?;
        Ok(Self {
            assignment: assignment.map_err(|_| ClientError::Relation)?,
        })
    }
}

#[cfg(test)]
fn verify_qualification_full(
    vk: &ordinary::VerifyingKey<ark_bn254::Bn254>,
    proof: &ordinary::Proof<ark_bn254::Bn254>,
    public: &[Fr],
) -> Result<(), ClientError> {
    if public.len() != 6 || vk.gamma_abc_g1.len() != 7 {
        return Err(ClientError::Identity);
    }
    match ordinary::Groth16::<ark_bn254::Bn254>::verify_proof(
        &ordinary::prepare_verifying_key(vk),
        proof,
        public,
    ) {
        Ok(true) => Ok(()),
        _ => Err(ClientError::Proof),
    }
}

fn parse_wtns(
    bytes: &[u8],
    control: &OperationControl,
) -> Result<Vec<[u8; 32]>, ClientError> {
    control.check()?;
    if bytes.len() != V3_WITNESS_BYTES
        || &bytes[..4] != b"wtns"
        || bytes[4..12] != [2, 0, 0, 0, 2, 0, 0, 0]
        || bytes[12..28] != [1, 0, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0]
        || bytes[28..60] != Fr::MODULUS.to_bytes_le()
        || bytes[60..64] != (V3_COORDINATES as u32).to_le_bytes()
        || bytes[64..68] != 2u32.to_le_bytes()
        || bytes[68..76] != (32u64 * V3_COORDINATES as u64).to_le_bytes()
    {
        return Err(ClientError::Encoding);
    }
    let mut one = [0; 32];
    one[0] = 1;
    if bytes[76..108] != one {
        return Err(ClientError::Encoding);
    }
    let mut words = Vec::new();
    words
        .try_reserve_exact(V3_COORDINATES)
        .map_err(|_| ClientError::Bound)?;
    for (coordinate, bytes) in bytes[76..].chunks_exact(32).enumerate() {
        if coordinate % 1024 == 0 {
            control.check()?;
        }
        let word: [u8; 32] = bytes.try_into().map_err(|_| ClientError::Encoding)?;
        Fr::deserialize_compressed(&word[..]).map_err(|_| ClientError::Encoding)?;
        words.push(word);
    }
    control.check()?;
    Ok(words)
}

#[cfg(test)]
#[path = "../tests/support/v3_full_qualification.rs"]
mod qualification;
