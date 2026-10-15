//! Deliberately failing RED scaffold. Positive hashing/tree code follows only
//! after ROOT reviews one executed independent-vector assertion failure.
use super::{Error, Field};

/// Raw SHA256 digest is split into two unsigned BE128 values, never reduced as
/// a single field. Output is canonical BE32; slot must be below1024.
pub fn leaf_hash(_digest: [u8; 32], _slot: usize, _active: bool) -> Result<Field, Error> {
    Err(Error::Invalid)
}

/// No v3 tree can be constructed by this scaffold. Inactive leaves will retain
/// their TBS digest with active=0; empty unallocated leaves will be field zero.
#[derive(Clone)]
pub struct Tree {
    _not_implemented: (),
}

impl Tree {
    pub fn new() -> Result<Self, Error> {
        Err(Error::Invalid)
    }
    pub fn set(&mut self, _slot: usize, _digest: [u8; 32], _active: bool) -> Result<(), Error> {
        Err(Error::Invalid)
    }
    pub fn root(&self) -> Field {
        unimplemented!("v3 tree RED scaffold is not constructible")
    }
    pub fn path(&self, _slot: usize) -> Result<Vec<Field>, Error> {
        Err(Error::Invalid)
    }
    pub fn verify(
        _digest: [u8; 32],
        _slot: usize,
        _active: bool,
        _siblings: &[Field],
        _root: Field,
    ) -> Result<(), Error> {
        Err(Error::Invalid)
    }
}
