//! Concrete v3 account-byte and action checks for a future local state adapter.
//!
//! All observations and keys here are caller data. A successful check supplies
//! no RPC provenance, PDA authentication, deployment admission, detached source
//! signature verification or registry authorization. This type deliberately does
//! not implement AuthenticatedV3State and cannot open V3BoundWitness.
use crate::{
    decode_digest, v3_prepare_action, ClientError, Digest, OperationControl, V3ActionConfig,
    V3ActionMeta, V3ActionRequest, V3CredentialSummary, V3FullManifest,
};
use ark_bn254::Fr;
use ark_serialize::CanonicalDeserialize;

/// Untrusted observed account bytes, including actual owner/executable metadata.
pub struct V3LocalAccount<'a> {
    pub key: Digest,
    pub owner: Digest,
    pub executable: bool,
    pub data: &'a [u8],
}
/// One coherent observation candidate. No constructor authenticates its origin.
pub struct V3LocalAccountSet<'a> {
    pub program: Digest,
    pub genesis: Digest,
    pub config: V3LocalAccount<'a>,
    pub issuer: V3LocalAccount<'a>,
    pub request: V3LocalAccount<'a>,
    pub queue: V3LocalAccount<'a>,
    pub publisher_head: V3LocalAccount<'a>,
    pub actual_metas: &'a [V3ActionMeta],
}
/// Checked bytes only; deliberately no state capability, serialization or Debug.
pub struct V3CheckedLocalAccounts {
    action_be: Digest,
    publics: [Digest; 6],
}
impl V3CheckedLocalAccounts {
    pub fn action_be(&self) -> Digest {
        self.action_be
    }
    pub fn public_values(&self) -> &[Digest; 6] {
        &self.publics
    }
}
impl V3LocalAccountSet<'_> {
    /// Decode exact current v3 layouts and bind their complete canonical action
    /// to the imported credential's six public fields. `now` is caller data.
    /// Account ownership, associations, current head/epoch tuple and padding are
    /// checked; independently authenticating these observations remains required.
    pub fn check(
        &self,
        credential: &V3CredentialSummary,
        manifest: &V3FullManifest,
        expected_action_be: Digest,
        now: u64,
        control: &OperationControl,
    ) -> Result<V3CheckedLocalAccounts, ClientError> {
        control.check()?;
        manifest.check()?;
        let now = i64::try_from(now).map_err(|_| ClientError::Bound)?;
        let accounts = [
            &self.config,
            &self.issuer,
            &self.request,
            &self.queue,
            &self.publisher_head,
        ];
        for (index, account) in accounts.iter().enumerate() {
            if account.owner != self.program
                || account.executable
                || account.key == [0; 32]
                || accounts[..index]
                    .iter()
                    .any(|prior| prior.key == account.key)
            {
                return Err(ClientError::Identity);
            }
        }
        let c = account(&self.config, 381, b"DYNCONF3")?;
        let i = account(&self.issuer, 374, b"DYNISS03")?;
        let r = account(&self.request, 2249, b"DYNREQ03")?;
        let q = account(&self.queue, 2090, b"DYNQUE03")?;
        let h = account(&self.publisher_head, 280, b"DYNHEAD3")?;
        let policy = field(c, 136)?;
        let root = field(c, 332)?;
        let issuer = field(i, 40)?;
        let vk = decode_digest("2f9b770ff51ac399619a3127ddb32efad67697402f10c4549441a3578e4f9a4e")?;
        if word(c, 104) != self.genesis
            || word(c, 172) != manifest.package.circuit_digest
            || word(c, 204) != manifest.package.package_digest
            || word(c, 236) != manifest.admission.semantic_schema
            || word(c, 268) != manifest.admission.profile
            || word(c, 300) != vk
            || u32::from_be_bytes(c[168..172].try_into().unwrap()) == 0
            || c[380] != 1
            || policy != credential.policy_hash
            || issuer != credential.issuer_hash
            || word(i, 8) != self.config.key
            || word(i, 72) != manifest.admission.profile
            || i[104..108] != 3u32.to_be_bytes()
            || i[108..128] != credential.signed_aki
            || i[128..140].iter().any(|b| *b != 0)
            || i[172] != 1
            || word(i, 140) == [0; 32]
            || word(i, 140) == word(c, 8)
            || word(i, 140) == word(c, 72)
            || u64be(i, 309) == 0
            || word(i, 317) == [0; 32]
            || u64be(i, 349) != u64be(c, 372)
            || u64be(i, 366) != u64be(i, 358)
        {
            return Err(ClientError::Identity);
        }
        control.check()?;
        let observed = i64be(i, 213);
        let expires = i64be(i, 221);
        if i[357] != 1
            || u64be(i, 173) == 0
            || word(i, 181) == [0; 32]
            || observed < 0
            || observed > now
            || expires <= now
            || expires
                .checked_sub(observed)
                .filter(|age| (0..=300).contains(age))
                .is_none()
            || now
                .checked_sub(observed)
                .filter(|age| *age <= 300)
                .is_none()
        {
            return Err(ClientError::StaleIssuer);
        }
        // Require both the issuer's bound tuple and current publisher head.
        if word(i, 229) != word(c, 332)
            || u64be(i, 261) != u64be(c, 364)
            || u64be(i, 269) != u64be(i, 173)
            || word(i, 277) != word(i, 181)
            || word(h, 8) != self.config.key
            || word(h, 40) != self.issuer.key
            || word(h, 72) != word(c, 72)
            || u64be(h, 104) == 0
            || word(h, 112) == [0; 32]
            || (u64be(h, 104) == 1) != (word(h, 144) == [0; 32])
            || word(h, 112) == word(h, 144)
            || word(h, 176) != word(c, 332)
            || u64be(h, 208) != u64be(c, 364)
            || u64be(h, 216) != u64be(i, 173)
            || word(h, 224) != word(i, 181)
            || u64be(h, 256) != u64be(c, 372)
            || u64be(h, 264) != u64be(i, 358)
            || i64be(h, 272) < observed
            || i64be(h, 272) > now
        {
            return Err(ClientError::Superseded);
        }
        if word(r, 8) != self.config.key
            || field(r, 104)? != issuer
            || word(q, 8) != self.config.key
        {
            return Err(ClientError::Identity);
        }
        let payload_len = u16be(r, 178) as usize;
        let count = r[184] as usize;
        if r[183] != 1
            || !(2..=16).contains(&count)
            || payload_len > 1024
            || u16be(r, 180) as usize != payload_len
            || r[182] as usize != count
            || r[185 + count * 65..1225].iter().any(|b| *b != 0)
            || r[1225 + payload_len..].iter().any(|b| *b != 0)
        {
            return Err(ClientError::Encoding);
        }
        let metas: Vec<_> = (0..count)
            .map(|index| {
                let start = 185 + 65 * index;
                V3ActionMeta {
                    key: word(r, start),
                    flags: r[start + 32],
                    owner: word(r, start + 33),
                }
            })
            .collect();
        let request = V3ActionRequest {
            config: self.config.key,
            creator: word(r, 40),
            nonce: word(r, 72),
            issuer_hash_be: word(r, 104),
            recipient: word(r, 136),
            request_type: u16be(r, 168),
            deadline: i64be(r, 170),
            payload: r[1225..1225 + payload_len].to_vec(),
            metas,
        };
        let config = V3ActionConfig {
            genesis: self.genesis,
            program: self.program,
            config: self.config.key,
            policy_id_be: word(c, 136),
            policy_version: u32::from_be_bytes(c[168..172].try_into().unwrap()),
            circuit_id: manifest.package.circuit_digest,
            request_key: self.request.key,
            queue_key: self.queue.key,
            issuer_account: self.issuer.key,
        };
        // This pure preparation verifies account order/owners and action equality;
        // it grants no signer capability and performs no holder RSA verification.
        v3_prepare_action(
            &config,
            &request,
            self.actual_metas,
            expected_action_be,
            &credential.holder_modulus_be,
            &credential.holder_modulus_be,
            now,
        )?;
        let queue_len = u16be(q, 40) as usize;
        if queue_len > 64 || q[42 + 32 * queue_len..].iter().any(|b| *b != 0) {
            return Err(ClientError::Encoding);
        }
        let entries = &q[42..42 + 32 * queue_len];
        for (index, key) in entries.chunks_exact(32).enumerate() {
            if key == self.request.key
                || entries[..index * 32]
                    .chunks_exact(32)
                    .any(|prior| prior == key)
            {
                return Err(ClientError::Completed);
            }
        }
        if queue_len == 64 {
            return Err(ClientError::Bound);
        }
        if credential.not_before >= credential.not_after
            || (now as u64) < credential.not_before
            || (now as u64) >= credential.not_after
        {
            return Err(ClientError::Expired);
        }
        let mut action = expected_action_be;
        action.reverse();
        control.check()?;
        Ok(V3CheckedLocalAccounts {
            action_be: expected_action_be,
            publics: [
                root,
                issuer,
                small(credential.not_before),
                small(credential.not_after),
                action,
                policy,
            ],
        })
    }
}
fn account<'a>(
    a: &'a V3LocalAccount<'_>,
    len: usize,
    magic: &[u8; 8],
) -> Result<&'a [u8], ClientError> {
    if a.data.len() != len || a.data.get(..8) != Some(magic.as_slice()) {
        return Err(ClientError::Encoding);
    }
    Ok(a.data)
}
fn word(b: &[u8], offset: usize) -> Digest {
    b[offset..offset + 32].try_into().unwrap()
}
fn u16be(b: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(b[offset..offset + 2].try_into().unwrap())
}
fn u64be(b: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(b[offset..offset + 8].try_into().unwrap())
}
fn i64be(b: &[u8], offset: usize) -> i64 {
    i64::from_be_bytes(b[offset..offset + 8].try_into().unwrap())
}
fn field(b: &[u8], offset: usize) -> Result<Digest, ClientError> {
    let mut value = word(b, offset);
    value.reverse();
    Fr::deserialize_compressed(&value[..]).map_err(|_| ClientError::Encoding)?;
    Ok(value)
}
fn small(value: u64) -> Digest {
    let mut b = [0; 32];
    b[..8].copy_from_slice(&value.to_le_bytes());
    b
}
#[cfg(test)]
#[path = "../tests/support/v3_local_accounts.rs"]
mod tests;
