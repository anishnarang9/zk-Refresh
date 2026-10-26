//! Separately typed six-public-field ordinary Groth16 / Solana ABI.
//!
//! Ordered fields are root, issuerHash, notBefore, notAfter, actionHash,
//! policyHash. A trusted manifest must bind circuit, package, semantic schema,
//! profile and tagged ordinary VK digest. This module embeds no trusted key,
//! admits no credential profile by itself and changes no five-field API.
use crate::{be, check_g1, check_g2, field, g1, g2, parse_g1, parse_g2, Error};
use ark_bn254::{Bn254, Fr};
use ark_ec::AffineRepr;
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use sha2::{Digest, Sha256};

pub const PUBLIC_INPUTS: usize = 6;
pub const PUBLIC_BYTES: usize = PUBLIC_INPUTS * 32;
/// Public scalars first (192 bytes), then the existing 256-byte proof ABI.
pub const WIRE_BYTES: usize = PUBLIC_BYTES + 256;
pub const PUBLIC_NAMES: [&str; PUBLIC_INPUTS] = [
    "root",
    "issuerHash",
    "notBefore",
    "notAfter",
    "actionHash",
    "policyHash",
];
/// Separate from the unchanged five-field `ordinary-vk/v1` domain.
pub const ORDINARY_VK_TAG: &[u8] = b"dynark-solana-adapter/ordinary-vk/v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    pub circuit: [u8; 32],
    pub package: [u8; 32],
    /// Semantic six-field schema digest; not the raw WTNS or public file hash.
    pub schema: [u8; 32],
    pub profile: [u8; 32],
    /// Tagged ordinary VK digest; not extended engine VK or raw VK file SHA256.
    pub ordinary_vk_digest: [u8; 32],
}

#[derive(Debug, PartialEq, Eq)]
pub struct Encoded {
    /// G1 -A, G2 B in c1/c0 order, G1 C; canonical 32-byte BE Fq components.
    pub proof: [u8; 256],
    pub inputs: [[u8; 32]; PUBLIC_INPUTS],
}

pub struct Verifier {
    vk: ordinary::VerifyingKey<Bn254>,
    prepared: ordinary::PreparedVerifyingKey<Bn254>,
    identity: Identity,
}

/// Parse six canonical BE Fr values without reduction. Parsing is not proof verification.
pub fn canonical_public_values(bytes: &[u8]) -> Result<[Fr; PUBLIC_INPUTS], Error> {
    if bytes.len() != PUBLIC_BYTES {
        return Err(Error::Length);
    }
    let mut values = [Fr::from(0u64); PUBLIC_INPUTS];
    for (value, chunk) in values.iter_mut().zip(bytes.chunks_exact(32)) {
        *value = field(chunk)?;
    }
    Ok(values)
}

/// SHA256(tag || u32_be(6) || u32_be(7) || alpha || beta || gamma || delta || IC[0..7]).
///
/// Alpha is not negated. G1 is x||y; G2 is x.c1||x.c0||y.c1||y.c0.
/// Each Fq is canonical 32-byte BE. Exactly seven ICs are required; only IC[0]
/// may be infinity (64 zero bytes). Other infinity, off-curve and non-subgroup
/// points are rejected. No engine dimensions/reduction data enter this digest.
pub fn ordinary_vk_digest(vk: &ordinary::VerifyingKey<Bn254>) -> Result<[u8; 32], Error> {
    if vk.gamma_abc_g1.len() != PUBLIC_INPUTS + 1 {
        return Err(Error::Schema);
    }
    check_g1(&vk.alpha_g1)?;
    for point in [&vk.beta_g2, &vk.gamma_g2, &vk.delta_g2] {
        check_g2(point)?;
    }
    for (index, point) in vk.gamma_abc_g1.iter().enumerate() {
        if index == 0 && point.is_zero() {
            continue;
        }
        check_g1(point)?;
    }
    let mut digest = Sha256::new();
    digest.update(ORDINARY_VK_TAG);
    digest.update((PUBLIC_INPUTS as u32).to_be_bytes());
    digest.update(((PUBLIC_INPUTS + 1) as u32).to_be_bytes());
    digest.update(g1(&vk.alpha_g1));
    for point in [&vk.beta_g2, &vk.gamma_g2, &vk.delta_g2] {
        digest.update(g2(point));
    }
    for point in &vk.gamma_abc_g1 {
        digest.update(g1(point));
    }
    Ok(digest.finalize().into())
}

impl Verifier {
    /// The caller authenticates the complete expected manifest association.
    pub fn new(vk: ordinary::VerifyingKey<Bn254>, expected: Identity) -> Result<Self, Error> {
        if ordinary_vk_digest(&vk)? != expected.ordinary_vk_digest {
            return Err(Error::Key);
        }
        let prepared = ordinary::prepare_verifying_key(&vk);
        Ok(Self {
            vk,
            prepared,
            identity: expected,
        })
    }
    fn identity(&self, actual: Identity) -> Result<(), Error> {
        if actual != self.identity {
            return Err(Error::Identity);
        }
        Ok(())
    }
    fn verify(&self, proof: &ordinary::Proof<Bn254>, public: &[Fr]) -> Result<(), Error> {
        if public.len() != PUBLIC_INPUTS {
            return Err(Error::Schema);
        }
        check_g1(&proof.a)?;
        check_g2(&proof.b)?;
        check_g1(&proof.c)?;
        match ordinary::Groth16::<Bn254>::verify_proof(&self.prepared, proof, public) {
            Ok(true) => Ok(()),
            _ => Err(Error::Proof),
        }
    }
    pub fn encode(
        &self,
        proof: &ordinary::Proof<Bn254>,
        public: &[Fr],
        actual: Identity,
    ) -> Result<Encoded, Error> {
        self.identity(actual)?;
        self.verify(proof, public)?;
        let mut encoded = Encoded {
            proof: [0; 256],
            inputs: [[0; 32]; PUBLIC_INPUTS],
        };
        encoded.proof[..64].copy_from_slice(&g1(&-proof.a));
        encoded.proof[64..192].copy_from_slice(&g2(&proof.b));
        encoded.proof[192..].copy_from_slice(&g1(&proof.c));
        for (bytes, value) in encoded.inputs.iter_mut().zip(public) {
            *bytes = be(*value);
        }
        Ok(encoded)
    }
    pub fn decode(
        &self,
        proof: &[u8],
        inputs: &[u8],
        actual: Identity,
    ) -> Result<ordinary::Proof<Bn254>, Error> {
        self.identity(actual)?;
        if proof.len() != 256 || inputs.len() != PUBLIC_BYTES {
            return Err(Error::Length);
        }
        let public = canonical_public_values(inputs)?;
        let decoded = ordinary::Proof {
            a: -parse_g1(&proof[..64])?,
            b: parse_g2(&proof[64..192])?,
            c: parse_g1(&proof[192..])?,
        };
        self.verify(&decoded, &public)?;
        Ok(decoded)
    }
    /// Independently invokes installed groth16-solana after ordinary verification.
    /// Native verification does not establish SBF, compute units or application effects.
    pub fn verify_solana(
        &self,
        proof: &[u8],
        inputs: &[u8],
        actual: Identity,
    ) -> Result<(), Error> {
        self.decode(proof, inputs, actual)?;
        let mut public = [[0; 32]; PUBLIC_INPUTS];
        for (field, bytes) in public.iter_mut().zip(inputs.chunks_exact(32)) {
            field.copy_from_slice(bytes);
        }
        let ic: Vec<_> = self.vk.gamma_abc_g1.iter().map(g1).collect();
        let vk = Groth16Verifyingkey {
            nr_pubinputs: PUBLIC_INPUTS,
            vk_alpha_g1: g1(&self.vk.alpha_g1),
            vk_beta_g2: g2(&self.vk.beta_g2),
            vk_gamme_g2: g2(&self.vk.gamma_g2),
            vk_delta_g2: g2(&self.vk.delta_g2),
            vk_ic: &ic,
        };
        let a: &[u8; 64] = proof[..64].try_into().map_err(|_| Error::Length)?;
        let b: &[u8; 128] = proof[64..192].try_into().map_err(|_| Error::Length)?;
        let c: &[u8; 64] = proof[192..].try_into().map_err(|_| Error::Length)?;
        let mut verifier =
            Groth16Verifier::new(a, b, c, &public, &vk).map_err(|_| Error::Solana)?;
        verifier.verify().map_err(|_| Error::Solana)
    }
}
