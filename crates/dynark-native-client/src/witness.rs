use crate::{
    AuthenticatedTarget, ClientError, Digest, InvalidationReason, NativePackageManifest,
    OperationControl, WitnessBinding,
};
use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use dynark_bn254::{PublicPackage, ValidatedAssignment};
use rand::{CryptoRng, RngCore};

pub const V1_COORDINATES: usize = 643_563;
pub const V1_WITNESS_BYTES: usize = 76 + 32 * V1_COORDINATES;

pub fn parse_canonical_wtns(bytes: &[u8]) -> Result<Vec<[u8; 32]>, ClientError> {
    parse_wtns(bytes, V1_COORDINATES)
}

pub fn parse_canonical_v2_wtns(bytes: &[u8]) -> Result<Vec<[u8; 32]>, ClientError> {
    parse_wtns(bytes, crate::V2_COORDINATES)
}

fn parse_wtns(bytes: &[u8], coordinates: usize) -> Result<Vec<[u8; 32]>, ClientError> {
    if bytes.len() != 76 + 32 * coordinates
        || &bytes[..4] != b"wtns"
        || bytes[4..12] != [2, 0, 0, 0, 2, 0, 0, 0]
        || bytes[12..28] != [1, 0, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0]
        || bytes[60..64] != (coordinates as u32).to_le_bytes()
        || bytes[64..68] != 2u32.to_le_bytes()
        || bytes[68..76] != (32u64 * coordinates as u64).to_le_bytes()
    {
        return Err(ClientError::Encoding);
    }
    let modulus = Fr::MODULUS.to_bytes_le();
    if bytes[28..60] != modulus {
        return Err(ClientError::Encoding);
    }
    let mut words = Vec::with_capacity(coordinates);
    for word in bytes[76..].chunks_exact(32) {
        let value: [u8; 32] = word.try_into().map_err(|_| ClientError::Encoding)?;
        Fr::deserialize_compressed(&value[..]).map_err(|_| ClientError::Encoding)?;
        words.push(value);
    }
    let mut one = [0; 32];
    one[0] = 1;
    if words[0] != one {
        return Err(ClientError::Encoding);
    }
    Ok(words)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessMode {
    IncrementalV1,
    Full,
}

/// Implementations return untrusted candidate bytes; the native boundary always
/// validates the entire relation before constructing an installed generation.
pub trait WitnessGenerator {
    fn generate(
        &mut self,
        before_input: &[u8],
        before_witness: &[u8],
        target_input: &[u8],
        allow_incremental: bool,
        control: &OperationControl,
    ) -> Result<(Vec<u8>, WitnessMode), ClientError>;
}

pub struct WitnessContext {
    package: PublicPackage,
    manifest: NativePackageManifest,
    v2: Option<crate::V2FullManifest>,
    binding: WitnessBinding,
    input: Vec<u8>,
    wtns: Vec<u8>,
    assignment: Option<ValidatedAssignment>,
    invalid: Option<InvalidationReason>,
}

pub struct PreparedWitness {
    base_generation: u64,
    base_binding: WitnessBinding,
    binding: WitnessBinding,
    input: Vec<u8>,
    wtns: Vec<u8>,
    assignment: ValidatedAssignment,
    deltas: Vec<(usize, [u8; 32])>,
    public_deltas: Vec<(usize, [u8; 32])>,
    mode: WitnessMode,
}
impl PreparedWitness {
    pub fn binding(&self) -> &WitnessBinding {
        &self.binding
    }
    pub fn deltas(&self) -> &[(usize, [u8; 32])] {
        &self.deltas
    }
    pub fn public_deltas(&self) -> &[(usize, [u8; 32])] {
        &self.public_deltas
    }
    pub fn mode(&self) -> WitnessMode {
        self.mode
    }
}

fn public_fields(target: &impl AuthenticatedTarget) -> Result<Vec<Fr>, ClientError> {
    let values = target.public_values();
    if values.len() != 5 || values[0] != target.binding().target.root {
        return Err(ClientError::Identity);
    }
    let mut action = target.binding().action;
    action.reverse();
    if values[4] != action {
        return Err(ClientError::Identity);
    }
    values
        .iter()
        .map(|value| Fr::deserialize_compressed(&value[..]).map_err(|_| ClientError::Encoding))
        .collect()
}
fn validate(
    package: &PublicPackage,
    target: &impl AuthenticatedTarget,
    wtns: &[u8],
    v2: Option<crate::V2FullManifest>,
) -> Result<ValidatedAssignment, ClientError> {
    if let Some(manifest) = v2 {
        manifest.check_package(package)?;
        manifest.check_binding(target.binding())?;
        let words = parse_canonical_v2_wtns(wtns)?;
        return package
            .validate_assignment(&words, &public_fields(target)?)
            .map_err(|_| ClientError::Relation);
    }
    target.binding().check_v1()?;
    if target.binding().package != package.identity()
        || package.shape().assignment_len != V1_COORDINATES
        || package.shape().instance_len != 6
    {
        return Err(ClientError::Identity);
    }
    let words = parse_canonical_wtns(wtns)?;
    package
        .validate_assignment(&words, &public_fields(target)?)
        .map_err(|_| ClientError::Relation)
}

impl WitnessContext {
    pub fn open(
        package: PublicPackage,
        manifest: NativePackageManifest,
        target: &impl AuthenticatedTarget,
        generator: &mut impl WitnessGenerator,
        now_unix: u64,
        control: &OperationControl,
    ) -> Result<Self, ClientError> {
        control.check()?;
        target.authorize(now_unix)?;
        manifest.check(&package)?;
        target.binding().check_v1()?;
        if target.input().len() > 65_536 {
            return Err(ClientError::Bound);
        }
        let (witness, mode) = generator.generate(&[], &[], target.input(), false, control)?;
        if mode != WitnessMode::Full {
            return Err(ClientError::Identity);
        }
        let assignment = validate(&package, target, &witness, None)?;
        control.check()?;
        Ok(Self {
            package,
            manifest,
            v2: None,
            binding: target.binding().clone(),
            input: target.input().to_vec(),
            wtns: witness,
            assignment: Some(assignment),
            invalid: None,
        })
    }
    /// Imports an exact v2 Full candidate. Authentication adapters must admit
    /// the credential and finalize/sign the action before producing the target.
    pub fn open_v2(
        package: PublicPackage,
        manifest: crate::V2FullManifest,
        target: &impl AuthenticatedTarget,
        generator: &mut impl WitnessGenerator,
        now_unix: u64,
        control: &OperationControl,
    ) -> Result<Self, ClientError> {
        control.check()?;
        target.authorize(now_unix)?;
        manifest.check_package(&package)?;
        manifest.check_binding(target.binding())?;
        if target.input().is_empty() || target.input().len() > 65_536 {
            return Err(ClientError::Bound);
        }
        let (witness, mode) = generator.generate(&[], &[], target.input(), false, control)?;
        if mode != WitnessMode::Full {
            return Err(ClientError::Unsupported);
        }
        control.check()?;
        let assignment = validate(&package, target, &witness, Some(manifest))?;
        control.check()?;
        Ok(Self {
            package,
            manifest: manifest.native,
            v2: Some(manifest),
            binding: target.binding().clone(),
            input: target.input().to_vec(),
            wtns: witness,
            assignment: Some(assignment),
            invalid: None,
        })
    }
    pub fn binding(&self) -> &WitnessBinding {
        &self.binding
    }
    pub fn invalidate(&mut self, reason: InvalidationReason) {
        self.invalid = Some(reason);
        self.input.fill(0);
        self.wtns.fill(0);
        self.assignment = None;
    }
    fn check(&self) -> Result<(), ClientError> {
        if let Some(reason) = self.invalid {
            return Err(ClientError::Invalidated(reason));
        }
        Ok(())
    }
    pub fn prepare(
        &self,
        target: &impl AuthenticatedTarget,
        generator: &mut impl WitnessGenerator,
        now_unix: u64,
        control: &OperationControl,
    ) -> Result<PreparedWitness, ClientError> {
        self.check()?;
        control.check()?;
        target.authorize(now_unix)?;
        if target.binding().generation <= self.binding.generation {
            return Err(ClientError::Generation);
        }
        if target.binding().package != self.package.identity() {
            return Err(ClientError::Unsupported);
        }
        if target.input().len() > 65_536 {
            return Err(ClientError::Bound);
        }
        if target.binding().target.version < self.binding.target.version
            || (target.binding().target.version == self.binding.target.version
                && target.binding().target.root != self.binding.target.root)
        {
            return Err(ClientError::Version);
        }
        if let Some(manifest) = self.v2 {
            manifest.check_binding(target.binding())?;
        }
        let reusable = self.v2.is_none() && self.binding.same_reusable_context(target.binding());
        let (wtns, mode) =
            generator.generate(&self.input, &self.wtns, target.input(), reusable, control)?;
        if self.v2.is_some() && mode != WitnessMode::Full {
            return Err(ClientError::Unsupported);
        }
        if mode == WitnessMode::IncrementalV1 && !reusable {
            return Err(ClientError::Identity);
        }
        control.check()?;
        let assignment = validate(&self.package, target, &wtns, self.v2)?;
        control.check()?;
        let parser = if self.v2.is_some() {
            parse_canonical_v2_wtns
        } else {
            parse_canonical_wtns
        };
        let before = parser(&self.wtns)?;
        let after = parser(&wtns)?;
        let mut deltas = Vec::new();
        for (coordinate, (a, b)) in before.iter().zip(&after).enumerate() {
            if a == b {
                continue;
            }
            if coordinate == 0 {
                return Err(ClientError::Encoding);
            }
            let a = Fr::deserialize_compressed(&a[..]).map_err(|_| ClientError::Encoding)?;
            let b = Fr::deserialize_compressed(&b[..]).map_err(|_| ClientError::Encoding)?;
            let mut bytes = [0; 32];
            (b - a)
                .serialize_compressed(&mut bytes[..])
                .map_err(|_| ClientError::Encoding)?;
            deltas.push((coordinate, bytes));
        }
        let public_deltas = deltas.iter().filter(|(i, _)| *i < 6).copied().collect();
        control.check()?;
        Ok(PreparedWitness {
            base_generation: self.binding.generation,
            base_binding: self.binding.clone(),
            binding: target.binding().clone(),
            input: target.input().to_vec(),
            wtns,
            assignment,
            deltas,
            public_deltas,
            mode,
        })
    }
    pub fn commit(
        &mut self,
        prepared: PreparedWitness,
        expected_generation: u64,
        current: &impl AuthenticatedTarget,
        now_unix: u64,
        control: &OperationControl,
    ) -> Result<(), ClientError> {
        self.check()?;
        control.check()?;
        current.authorize(now_unix)?;
        if self.binding.generation != expected_generation
            || prepared.base_generation != expected_generation
            || prepared.base_binding != self.binding
            || current.binding() != &prepared.binding
        {
            return Err(ClientError::Superseded);
        }
        self.binding = prepared.binding;
        self.input = prepared.input;
        self.wtns = prepared.wtns;
        self.assignment = Some(prepared.assignment);
        Ok(())
    }
    /// Full is the only exposed native proof mode until the other modes have
    /// matching native-path verification evidence. Randomness is caller supplied.
    pub fn prove_full<R: RngCore + CryptoRng>(
        &self,
        target: &impl AuthenticatedTarget,
        rng: &mut R,
        now_unix: u64,
        control: &OperationControl,
    ) -> Result<ProofResult, ClientError> {
        self.check()?;
        control.check()?;
        target.authorize(now_unix)?;
        if target.binding() != &self.binding {
            return Err(ClientError::Superseded);
        }
        let assignment = self
            .assignment
            .as_ref()
            .ok_or(ClientError::RebuildRequired)?;
        let statement =
            dynark_bn254::prove(&self.package, assignment, self.binding.generation, rng).map_err(
                |e| match e {
                    dynark_bn254::Error::Entropy { .. }
                    | dynark_bn254::Error::RejectionLimit { .. } => ClientError::Entropy,
                    _ => ClientError::Proof,
                },
            )?;
        control.check()?;
        let pvk = ordinary::prepare_verifying_key(&self.package.ordinary_verifying_key());
        if !ordinary::Groth16::<Bn254>::verify_proof(
            &pvk,
            &statement.proof,
            &statement.public_values,
        )
        .map_err(|_| ClientError::Proof)?
        {
            return Err(ClientError::Proof);
        }
        control.check()?;
        Ok(ProofResult {
            statement,
            binding: self.binding.clone(),
            manifest: self.manifest,
            v2: self.v2,
        })
    }
}

pub struct ProofResult {
    statement: dynark_bn254::ProofStatement,
    binding: WitnessBinding,
    manifest: NativePackageManifest,
    v2: Option<crate::V2FullManifest>,
}
impl ProofResult {
    pub fn binding(&self) -> &WitnessBinding {
        &self.binding
    }
    pub fn proof(&self) -> &ordinary::Proof<Bn254> {
        &self.statement.proof
    }
    pub fn public_values(&self) -> &[Fr] {
        &self.statement.public_values
    }
    pub fn action(&self) -> Digest {
        self.binding.action
    }
    pub fn ordinary_vk_digest(&self) -> Digest {
        self.manifest.ordinary_vk_digest
    }
    pub fn package_manifest(&self) -> NativePackageManifest {
        self.manifest
    }
    pub fn v2_manifest(&self) -> Option<crate::V2FullManifest> {
        self.v2
    }
    pub fn ensure_submission_current(
        &self,
        target: &impl AuthenticatedTarget,
        now_unix: u64,
        control: &OperationControl,
    ) -> Result<(), ClientError> {
        control.check()?;
        target.authorize(now_unix)?;
        if target.binding() != &self.binding {
            return Err(ClientError::Superseded);
        }
        Ok(())
    }
}

#[cfg(test)]
mod v2_contract_tests {
    #[test]
    fn rejects_truncated_v2_witness() {
        assert!(matches!(
            super::parse_canonical_v2_wtns(&[]),
            Err(crate::ClientError::Encoding)
        ));
    }
}
