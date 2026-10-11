use crate::Error;
use ark_bn254::Fr;
use ark_ff::{BigInt, PrimeField};
use rand::{CryptoRng, RngCore};

// A masked uniform 256-bit draw is uniform over [0, 2^254). Rejection at the
// modulus preserves exact uniformity in Fr; no modulo reduction is performed.
// A bounded rejection failure prevents pathological caller RNGs from hanging.
fn scalar<R: RngCore + CryptoRng + ?Sized>(rng: &mut R, draw: usize) -> Result<Fr, Error> {
    for _ in 0..128 {
        let mut bytes = [0u8; 32];
        rng.try_fill_bytes(&mut bytes)
            .map_err(|source| Error::Entropy { draw, source })?;
        bytes[31] &= 0x3f;
        let mut limbs = [0u64; 4];
        for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
            let mut word = [0u8; 8];
            word.copy_from_slice(chunk);
            *limb = u64::from_le_bytes(word);
        }
        if let Some(value) = Fr::from_bigint(BigInt(limbs)) {
            return Ok(value);
        }
    }
    Err(Error::RejectionLimit { draw })
}

pub(crate) fn blinders<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> Result<(Fr, Fr), Error> {
    let r = scalar(rng, 0)?;
    let s = scalar(rng, 1)?;
    Ok((r, s))
}
