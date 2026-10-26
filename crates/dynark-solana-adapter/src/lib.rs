//! Matching-key ordinary Groth16 to the existing Solana verifier ABI.
//! Expected identities must come from a trusted deployment/package manifest.
#![forbid(unsafe_code)]
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub circuit: [u8; 32],
    pub package: [u8; 32],
    pub schema: [u8; 32],
    pub ordinary_vk_digest: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error { Length, Field, Point, Identity, Key, Schema, Proof, Solana }
#[derive(Debug, PartialEq, Eq)]
pub struct Encoded {
    pub proof: [u8; 256],
    pub inputs: [[u8; 32]; 5],
}
pub struct Verifier {
    vk: ordinary::VerifyingKey<Bn254>,
    prepared: ordinary::PreparedVerifyingKey<Bn254>,
    identity: Identity,
}
pub const ORDINARY_VK_TAG: &[u8] = b"dynark-solana-adapter/ordinary-vk/v1";

fn be<F: PrimeField>(value: F) -> [u8; 32] {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}
fn field<F: PrimeField>(bytes: &[u8]) -> Result<F, Error> {
    if bytes.len() != 32 { return Err(Error::Length); }
    let value = F::from_be_bytes_mod_order(bytes);
    if be(value).as_slice() != bytes { return Err(Error::Field); }
    Ok(value)
}
fn check_g1(point: &G1Affine) -> Result<(), Error> {
    if point.is_zero() || !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(Error::Point);
    }
    Ok(())
}
fn check_g2(point: &G2Affine) -> Result<(), Error> {
    if point.is_zero() || !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(Error::Point);
    }
    Ok(())
}
fn g1(point: &G1Affine) -> [u8; 64] {
    if point.is_zero() { return [0; 64]; }
    let mut out = [0; 64];
    out[..32].copy_from_slice(&be(point.x));
    out[32..].copy_from_slice(&be(point.y));
    out
}
fn g2(point: &G2Affine) -> [u8; 128] {
    let mut out = [0; 128];
    for (chunk, value) in out.chunks_exact_mut(32).zip([point.x.c1, point.x.c0, point.y.c1, point.y.c0]) {
        chunk.copy_from_slice(&be(value));
    }
    out
}
fn parse_g1(bytes: &[u8]) -> Result<G1Affine, Error> {
    if bytes.len() != 64 { return Err(Error::Length); }
    let point = G1Affine::new_unchecked(field::<Fq>(&bytes[..32])?, field::<Fq>(&bytes[32..])?);
    check_g1(&point)?;
    Ok(point)
}
fn parse_g2(bytes: &[u8]) -> Result<G2Affine, Error> {
    if bytes.len() != 128 { return Err(Error::Length); }
    let xc1 = field::<Fq>(&bytes[..32])?;
    let xc0 = field::<Fq>(&bytes[32..64])?;
    let yc1 = field::<Fq>(&bytes[64..96])?;
    let yc0 = field::<Fq>(&bytes[96..])?;
    let point = G2Affine::new_unchecked(Fq2::new(xc0, xc1), Fq2::new(yc0, yc1));
    check_g2(&point)?;
    Ok(point)
}
fn public_values(bytes: &[u8]) -> Result<[Fr; 5], Error> {
    if bytes.len() != 160 { return Err(Error::Length); }
    let mut out = [Fr::from(0u64); 5];
    for (value, chunk) in out.iter_mut().zip(bytes.chunks_exact(32)) { *value = field(chunk)?; }
    Ok(out)
}

/// SHA256(tag || u32_be(5) || u32_be(6) || alpha || beta || gamma || delta || IC[0..6]).
/// G1 is x||y; G2 is x.c1||x.c0||y.c1||y.c0; Fq components are 32-byte BE.
/// Alpha is not negated. Only IC[0] may be infinity, encoded as 64 zero bytes.
/// Reject non-six IC, other infinity, off-curve and non-subgroup points.
/// This ordinary VK commitment is distinct from the engine's extended VK commitment.
pub fn ordinary_vk_digest(vk: &ordinary::VerifyingKey<Bn254>) -> Result<[u8; 32], Error> {
    if vk.gamma_abc_g1.len() != 6 { return Err(Error::Schema); }
    check_g1(&vk.alpha_g1)?;
    for point in [&vk.beta_g2, &vk.gamma_g2, &vk.delta_g2] { check_g2(point)?; }
    for (index, point) in vk.gamma_abc_g1.iter().enumerate() {
        if index == 0 && point.is_zero() { continue; }
        check_g1(point)?;
    }
    let mut digest = Sha256::new();
    digest.update(ORDINARY_VK_TAG);
    digest.update(5u32.to_be_bytes());
    digest.update(6u32.to_be_bytes());
    digest.update(g1(&vk.alpha_g1));
    for point in [&vk.beta_g2, &vk.gamma_g2, &vk.delta_g2] { digest.update(g2(point)); }
    for point in &vk.gamma_abc_g1 { digest.update(g1(point)); }
    Ok(digest.finalize().into())
}
impl Verifier {
    /// The caller authenticates the manifest association between VK and all expected identities.
    pub fn new(vk: ordinary::VerifyingKey<Bn254>, expected: Identity) -> Result<Self, Error> {
        if ordinary_vk_digest(&vk)? != expected.ordinary_vk_digest { return Err(Error::Key); }
        let prepared = ordinary::prepare_verifying_key(&vk);
        Ok(Self { vk, prepared, identity: expected })
    }
    fn identity(&self, actual: Identity) -> Result<(), Error> {
        if actual != self.identity { return Err(Error::Identity); }
        Ok(())
    }
    fn verify(&self, proof: &ordinary::Proof<Bn254>, public: &[Fr]) -> Result<(), Error> {
        if public.len() != 5 { return Err(Error::Schema); }
        check_g1(&proof.a)?;
        check_g2(&proof.b)?;
        check_g1(&proof.c)?;
        match ordinary::Groth16::<Bn254>::verify_proof(&self.prepared, proof, public) {
            Ok(true) => Ok(()),
            _ => Err(Error::Proof),
        }
    }
    pub fn encode(&self, proof: &ordinary::Proof<Bn254>, public: &[Fr], actual: Identity) -> Result<Encoded, Error> {
        self.identity(actual)?;
        self.verify(proof, public)?;
        let mut out = Encoded { proof: [0; 256], inputs: [[0; 32]; 5] };
        out.proof[..64].copy_from_slice(&g1(&-proof.a));
        out.proof[64..192].copy_from_slice(&g2(&proof.b));
        out.proof[192..].copy_from_slice(&g1(&proof.c));
        for (encoded, value) in out.inputs.iter_mut().zip(public) { *encoded = be(*value); }
        Ok(out)
    }
    pub fn decode(&self, proof: &[u8], inputs: &[u8], actual: Identity) -> Result<ordinary::Proof<Bn254>, Error> {
        self.identity(actual)?;
        if proof.len() != 256 || inputs.len() != 160 { return Err(Error::Length); }
        let public = public_values(inputs)?;
        let decoded = ordinary::Proof { a: -parse_g1(&proof[..64])?, b: parse_g2(&proof[64..192])?, c: parse_g1(&proof[192..])? };
        self.verify(&decoded, &public)?;
        Ok(decoded)
    }
    /// Runs the installed groth16-solana verifier. Native results are not SBF/CU measurements.
    pub fn verify_solana(&self, proof: &[u8], inputs: &[u8], actual: Identity) -> Result<(), Error> {
        self.decode(proof, inputs, actual)?;
        let mut public = [[0; 32]; 5];
        for (encoded, bytes) in public.iter_mut().zip(inputs.chunks_exact(32)) { encoded.copy_from_slice(bytes); }
        let ic: Vec<_> = self.vk.gamma_abc_g1.iter().map(g1).collect();
        let vk = Groth16Verifyingkey {
            nr_pubinputs: 5, vk_alpha_g1: g1(&self.vk.alpha_g1), vk_beta_g2: g2(&self.vk.beta_g2),
            vk_gamme_g2: g2(&self.vk.gamma_g2), vk_delta_g2: g2(&self.vk.delta_g2), vk_ic: &ic,
        };
        let a: &[u8; 64] = proof[..64].try_into().map_err(|_| Error::Length)?;
        let b: &[u8; 128] = proof[64..192].try_into().map_err(|_| Error::Length)?;
        let c: &[u8; 64] = proof[192..].try_into().map_err(|_| Error::Length)?;
        let mut verifier = Groth16Verifier::new(a, b, c, &public, &vk).map_err(|_| Error::Solana)?;
        verifier.verify().map_err(|_| Error::Solana)
    }
}

/// Separately typed six-field successor; the existing five-field API is unchanged.
pub mod v3;
