//! Isolated v2 development registry. Authority keys and fresh heads are caller trust.
use ark_bn254::Fr;
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    RebuildRequired,
    Invalid,
    Authentication,
    Replay,
    GapRequiresSnapshot,
    Stale,
    Disabled,
    Revoked,
    Bound,
    Io,
}
pub fn private_cache_after_restart() -> Result<(), Error> {
    Err(Error::RebuildRequired)
}
pub type Field = [u8; 32];
pub mod v3;
mod protocol;
mod storage;
pub use protocol::*;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub issuer: [u8; 32],
    pub issuer_version: u64,
    pub tbs_digest: [u8; 32],
}
fn number(n: u64) -> Field {
    let mut b = [0; 32];
    b[24..].copy_from_slice(&n.to_be_bytes());
    b
}
fn hash(values: &[Field]) -> Result<Field, Error> {
    Poseidon::<Fr>::new_circom(values.len())
        .map_err(|_| Error::Invalid)?
        .hash_bytes_be(&values.iter().map(|v| v.as_slice()).collect::<Vec<_>>())
        .map_err(|_| Error::Invalid)
}
fn leaf(digest: Field, slot: usize, active: bool) -> Result<Field, Error> {
    if slot >= 1024 {
        return Err(Error::Invalid);
    }
    let mut high = [0; 32];
    let mut low = [0; 32];
    high[16..].copy_from_slice(&digest[..16]);
    low[16..].copy_from_slice(&digest[16..]);
    hash(&[
        number(20261015),
        high,
        low,
        number(slot as u64),
        number(active as u64),
    ])
}
#[derive(Clone)]
pub struct Tree {
    levels: Vec<Vec<Field>>,
}
impl Tree {
    pub fn new() -> Result<Self, Error> {
        let mut levels = vec![vec![[0; 32]; 1024]];
        for n in 0..10 {
            let next = levels[n]
                .chunks_exact(2)
                .map(hash)
                .collect::<Result<Vec<_>, _>>()?;
            levels.push(next);
        }
        Ok(Self { levels })
    }
    pub fn set(&mut self, slot: usize, digest: Field, active: bool) -> Result<(), Error> {
        let value = leaf(digest, slot, active)?;
        // Compute the complete path first so a rejected hash cannot partially mutate the tree.
        let mut updates = vec![(0, slot, value)];
        let mut index = slot;
        let mut current = value;
        for level in 0..10 {
            let other = self.levels[level][index ^ 1];
            current = if index & 1 == 0 {
                hash(&[current, other])?
            } else {
                hash(&[other, current])?
            };
            index >>= 1;
            updates.push((level + 1, index, current));
        }
        for (level, index, value) in updates {
            self.levels[level][index] = value;
        }
        Ok(())
    }
    pub fn root(&self) -> Field {
        self.levels[10][0]
    }
    pub fn path(&self, slot: usize) -> Result<Vec<Field>, Error> {
        if slot >= 1024 {
            return Err(Error::Invalid);
        }
        let mut index = slot;
        let mut path = Vec::with_capacity(10);
        for level in 0..10 {
            path.push(self.levels[level][index ^ 1]);
            index >>= 1;
        }
        Ok(path)
    }
    pub fn verify(
        digest: Field,
        slot: usize,
        active: bool,
        path: &[Field],
        root: Field,
    ) -> Result<(), Error> {
        if path.len() != 10 {
            return Err(Error::Invalid);
        }
        let mut current = leaf(digest, slot, active)?;
        let mut index = slot;
        for other in path {
            current = if index & 1 == 0 {
                hash(&[current, *other])?
            } else {
                hash(&[*other, current])?
            };
            index >>= 1;
        }
        if current != root {
            return Err(Error::Authentication);
        }
        Ok(())
    }
}
