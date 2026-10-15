//! Bounded-v3 membership math. This module authenticates no issuer, policy,
//! source, publication, clock or application state; those are separate gates.
use super::{Error, Field, CAPACITY, DEPTH, LEAF_DOMAIN};
use ark_bn254::Fr;
use light_poseidon::{Poseidon, PoseidonBytesHasher};

// BN254 Fr modulus in canonical big-endian bytes. Do not reduce received words.
const FR_MODULUS: Field = [
    48, 100, 78, 114, 225, 49, 160, 41, 184, 80, 69, 182, 129, 129, 88, 93, 40, 51, 232, 72, 121,
    185, 112, 145, 67, 225, 245, 147, 240, 0, 0, 1,
];

fn canonical(value: &Field) -> Result<(), Error> {
    if value >= &FR_MODULUS {
        return Err(Error::Invalid);
    }
    Ok(())
}

fn number(value: u64) -> Field {
    let mut out = [0; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

fn hash(values: &[Field]) -> Result<Field, Error> {
    for value in values {
        canonical(value)?;
    }
    Poseidon::<Fr>::new_circom(values.len())
        .map_err(|_| Error::Invalid)?
        .hash_bytes_be(
            &values
                .iter()
                .map(|value| value.as_slice())
                .collect::<Vec<_>>(),
        )
        .map_err(|_| Error::Invalid)
}

/// Raw SHA256 digest is split into two unsigned BE128 values, never reduced as
/// a single field. Output is canonical BE32; slot must be below1024.
pub fn leaf_hash(digest: [u8; 32], slot: usize, active: bool) -> Result<Field, Error> {
    if slot >= CAPACITY {
        return Err(Error::Invalid);
    }
    let mut high = [0; 32];
    let mut low = [0; 32];
    high[16..].copy_from_slice(&digest[..16]);
    low[16..].copy_from_slice(&digest[16..]);
    hash(&[
        number(LEAF_DOMAIN),
        high,
        low,
        number(slot as u64),
        number(u64::from(active)),
    ])
}

/// Fixed depth10 tree. Empty unallocated leaves are zero; inactive allocated
/// leaves retain the TBS digest with active=0. Issuance/revocation authority and
/// allocation history must be enforced by the separately versioned protocol.
#[derive(Clone)]
pub struct Tree {
    levels: Vec<Vec<Field>>,
}

impl Tree {
    pub fn new() -> Result<Self, Error> {
        let mut empty = [0; 32];
        let mut width = CAPACITY;
        let mut levels = vec![vec![empty; width]];
        for _ in 0..DEPTH {
            // Every node in an empty level is identical; hash it once.
            empty = hash(&[empty, empty])?;
            width >>= 1;
            levels.push(vec![empty; width]);
        }
        Ok(Self { levels })
    }
    pub fn set(&mut self, slot: usize, digest: [u8; 32], active: bool) -> Result<(), Error> {
        let mut node = leaf_hash(digest, slot, active)?;
        let mut index = slot;
        let mut updates = Vec::with_capacity(DEPTH + 1);
        updates.push((0, index, node));
        for level in 0..DEPTH {
            let sibling = self.levels[level][index ^ 1];
            node = if index & 1 == 0 {
                hash(&[node, sibling])?
            } else {
                hash(&[sibling, node])?
            };
            index >>= 1;
            updates.push((level + 1, index, node));
        }
        // Every fallible hash finishes before the first mutation.
        for (level, index, value) in updates {
            self.levels[level][index] = value;
        }
        Ok(())
    }
    pub fn root(&self) -> Field {
        self.levels[DEPTH][0]
    }
    /// Leaf upward, with least-significant slot bit first, exactly matching
    /// pathIndices[level] in the frozen circuit.
    pub fn path(&self, slot: usize) -> Result<Vec<Field>, Error> {
        if slot >= CAPACITY {
            return Err(Error::Invalid);
        }
        Ok((0..DEPTH)
            .map(|level| self.levels[level][(slot >> level) ^ 1])
            .collect())
    }
    pub fn verify(
        digest: [u8; 32],
        slot: usize,
        active: bool,
        siblings: &[Field],
        root: Field,
    ) -> Result<(), Error> {
        if slot >= CAPACITY || siblings.len() != DEPTH {
            return Err(Error::Invalid);
        }
        canonical(&root)?;
        for sibling in siblings {
            canonical(sibling)?;
        }
        let mut node = leaf_hash(digest, slot, active)?;
        for (level, sibling) in siblings.iter().enumerate() {
            node = if (slot >> level) & 1 == 0 {
                hash(&[node, *sibling])?
            } else {
                hash(&[*sibling, node])?
            };
        }
        if node != root {
            return Err(Error::Authentication);
        }
        Ok(())
    }
}
