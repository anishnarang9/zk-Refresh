use crate::fixtures::{
    digest, field_decimal, field_from_biguint, field_from_decimal, limbs, ownership_signature,
    validate_profile, Credential, Field, Fixtures,
};
use anyhow::{ensure, Context, Result};
use ark_bn254::Fr;
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
pub const DEPTH: usize = 10;
pub struct Registry {
    pub fixtures: Fixtures,
    pub issuer: Field,
    pub version: u64,
    pub history: Vec<Snapshot>,
    active: Vec<bool>,
    levels: Vec<Vec<Field>>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub root: Field,
    pub version: u64,
    pub published_at: i64,
}
pub fn hash(values: &[Field]) -> Result<Field> {
    Ok(Poseidon::<Fr>::new_circom(values.len())?.hash_bytes_be(
        &values
            .iter()
            .map(|field| field.as_slice())
            .collect::<Vec<_>>(),
    )?)
}
pub fn credential_leaf(credential: &Credential, slot: usize, active: bool) -> Result<Field> {
    let bytes = digest(&credential.tbs);
    hash(&[
        field_from_decimal("20261009")?,
        field_from_biguint(&BigUint::from_bytes_be(&bytes[..16]))?,
        field_from_biguint(&BigUint::from_bytes_be(&bytes[16..]))?,
        field_from_biguint(&BigUint::from(slot))?,
        field_from_decimal(if active { "1" } else { "0" })?,
    ])
}
impl Registry {
    pub fn new(fixtures: Fixtures) -> Result<Self> {
        ensure!(
            (1..=1024).contains(&fixtures.credentials.len()),
            "Invalid credential count"
        );
        let issuer_limbs = limbs(&fixtures.issuer.modulus)?
            .iter()
            .map(|value| field_from_decimal(value))
            .collect::<Result<Vec<_>>>()?;
        let issuer = hash(&[hash(&issuer_limbs[..8])?, hash(&issuer_limbs[8..])?])?;
        for credential in &fixtures.credentials {
            validate_profile(&credential.tbs)?;
        }
        let mut registry = Self {
            active: vec![true; fixtures.credentials.len()],
            fixtures,
            issuer,
            version: 0,
            history: vec![],
            levels: vec![],
        };
        registry.levels = registry.build_levels(&registry.active)?;
        Ok(registry)
    }
    fn build_levels(&self, active: &[bool]) -> Result<Vec<Vec<Field>>> {
        let mut leaves = vec![[0; 32]; 1 << DEPTH];
        for (slot, credential) in self.fixtures.credentials.iter().enumerate() {
            leaves[slot] = credential_leaf(credential, slot, active[slot])?;
        }
        let mut levels = vec![leaves];
        for level in 0..DEPTH {
            let next = levels[level]
                .chunks_exact(2)
                .map(hash)
                .collect::<Result<Vec<_>>>()?;
            levels.push(next);
        }
        Ok(levels)
    }
    pub fn root(&self) -> Field {
        self.levels[DEPTH][0]
    }
    pub fn snapshot(&mut self, published_at: i64) -> Result<Snapshot> {
        if let Some(last) = self.history.last() {
            if last.version == self.version {
                return Ok(last.clone());
            }
            ensure!(
                published_at >= last.published_at,
                "Publication time must increase"
            );
        }
        let snapshot = Snapshot {
            root: self.root(),
            version: self.version,
            published_at,
        };
        self.history.push(snapshot.clone());
        if self.history.len() > 256 {
            self.history.remove(0);
        }
        Ok(snapshot)
    }
    pub fn revoke(&mut self, slot: usize, published_at: i64) -> Result<Snapshot> {
        ensure!(
            self.active.get(slot) == Some(&true),
            "Credential missing or already revoked"
        );
        let last = self
            .history
            .last()
            .context("Publish initial snapshot before revoking")?;
        ensure!(
            published_at >= last.published_at,
            "Publication time must increase"
        );
        let version = self
            .version
            .checked_add(1)
            .context("Registry version overflow")?;
        let mut active = self.active.clone();
        active[slot] = false;
        let levels = self.build_levels(&active)?;
        self.active = active;
        self.levels = levels;
        self.version = version;
        self.snapshot(published_at)
    }
    pub fn input(&self, slot: usize, action: Field) -> Result<Value> {
        let credential = self
            .fixtures
            .credentials
            .get(slot)
            .context("Invalid credential slot")?;
        let mut index = slot;
        let mut siblings = vec![];
        let mut path_indices = vec![];
        for level in 0..DEPTH {
            siblings.push(field_decimal(&self.levels[level][index ^ 1]));
            path_indices.push(index & 1);
            index >>= 1;
        }
        Ok(
            json!({ "root":field_decimal(&self.root()), "issuerHash":field_decimal(&self.issuer),
            "notBefore":credential.not_before.to_string(), "notAfter":credential.not_after.to_string(), "actionHash":field_decimal(&action),
            "tbs":credential.tbs, "issuerModulus":limbs(&self.fixtures.issuer.modulus)?, "issuerSignature":limbs(&credential.signature)?,
            "holderSignature":limbs(&ownership_signature(credential,&action)?)?, "slot":slot,"siblings":siblings,"pathIndices":path_indices }),
        )
    }
}
