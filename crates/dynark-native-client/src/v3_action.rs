//! Canonical action-v2 records for the six-field client. Constructing records or
//! passing these pure checks does not authenticate finalized accounts or owners.
//! A trusted chain adapter must supply the immutable request and actual accounts.
use crate::{ClientError, Digest};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::CanonicalDeserialize;
use sha2::{Digest as _, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V3ActionConfig {
    pub genesis: Digest,
    pub program: Digest,
    pub config: Digest,
    pub policy_id_be: Digest,
    pub policy_version: u32,
    pub circuit_id: Digest,
    pub request_key: Digest,
    pub queue_key: Digest,
    pub issuer_account: Digest,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V3ActionMeta {
    pub key: Digest,
    pub flags: u8,
    pub owner: Digest,
}
/// The chain adapter must require the actual request state to be Finalized,
/// decode all lengths/upload counters, and bind these fields to those bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct V3ActionRequest {
    pub config: Digest,
    pub creator: Digest,
    pub nonce: Digest,
    pub issuer_hash_be: Digest,
    pub recipient: Digest,
    pub request_type: u16,
    pub deadline: i64,
    pub payload: Vec<u8>,
    pub metas: Vec<V3ActionMeta>,
}
/// Private-constructor preparation result. It authorizes no signature by itself.
pub struct V3PreparedAction {
    action_be: Digest,
}
impl V3PreparedAction {
    pub(crate) fn action_be(&self) -> Digest { self.action_be }
}

pub fn v3_action_preimage(
    config: &V3ActionConfig,
    request: &V3ActionRequest,
) -> Result<Vec<u8>, ClientError> {
    if request.payload.len() > 1024
        || !(2..=16).contains(&request.metas.len())
        || request.deadline <= 0
        || request.request_type != 1
    {
        return Err(ClientError::Bound);
    }
    if request.config != config.config {
        return Err(ClientError::Identity);
    }
    if config.policy_version == 0 {
        return Err(ClientError::Version);
    }
    for word in [config.policy_id_be, request.issuer_hash_be] {
        let mut little_endian = word;
        little_endian.reverse();
        Fr::deserialize_compressed(&little_endian[..]).map_err(|_| ClientError::Encoding)?;
    }
    if request.metas.iter().any(|meta| meta.flags > 3) {
        return Err(ClientError::Identity);
    }
    let mut bytes = Vec::with_capacity(295 + 33 * request.metas.len());
    bytes.extend_from_slice(b"DYNARK-WORK-REQUEST");
    bytes.push(2);
    bytes.extend(config.genesis);
    bytes.extend(config.program);
    bytes.extend(request.config);
    bytes.extend(config.policy_id_be);
    bytes.extend(config.policy_version.to_be_bytes());
    bytes.extend(config.circuit_id);
    bytes.extend(request.nonce);
    bytes.extend(request.recipient);
    bytes.extend(request.request_type.to_be_bytes());
    bytes.extend((request.payload.len() as u32).to_be_bytes());
    bytes.extend(Sha256::digest(&request.payload));
    bytes.push(request.metas.len() as u8);
    for meta in &request.metas {
        bytes.extend(meta.key);
        bytes.push(meta.flags);
    }
    bytes.extend(request.deadline.to_be_bytes());
    Ok(bytes)
}
pub fn v3_action_hash(
    config: &V3ActionConfig,
    request: &V3ActionRequest,
) -> Result<Digest, ClientError> {
    let preimage = v3_action_preimage(config, request)?;
    // Reduction applies only to the SHA256 digest prescribed by action-v2.
    // Caller-provided field encodings above are checked without reduction.
    let scalar = Fr::from_be_bytes_mod_order(&Sha256::digest(&preimage));
    let encoded = scalar.into_bigint().to_bytes_be();
    let mut action_be = [0; 32];
    action_be[32 - encoded.len()..].copy_from_slice(&encoded);
    Ok(action_be)
}
pub fn v3_match_holder_modulus(
    credential_holder: &[u8; 256],
    signer_holder: &[u8; 256],
) -> Result<(), ClientError> {
    if credential_holder != signer_holder {
        return Err(ClientError::Identity);
    }
    if credential_holder[0] & 0x80 == 0 || credential_holder[255] & 1 == 0 {
        return Err(ClientError::Encoding);
    }
    Ok(())
}
/// Validate ordered actual metas, deadline, holder-key match and exact expected
/// canonical action before a signer is invoked. Actual signature verification is
/// required separately under the imported credential's holder modulus.
pub fn v3_prepare_action(
    config: &V3ActionConfig,
    request: &V3ActionRequest,
    actual: &[V3ActionMeta],
    expected_action_be: Digest,
    credential_holder: &[u8; 256],
    signer_holder: &[u8; 256],
    now: i64,
) -> Result<V3PreparedAction, ClientError> {
    v3_match_holder_modulus(credential_holder, signer_holder)?;
    let action_be = v3_action_hash(config, request)?;
    if actual != request.metas.as_slice()
        || request.metas[0].key != config.request_key
        || request.metas[1].key != config.queue_key
        || request.metas[..2]
            .iter()
            .any(|meta| meta.flags != 2 || meta.owner != config.program)
        || action_be != expected_action_be
    {
        return Err(ClientError::Identity);
    }
    for (index, meta) in request.metas.iter().enumerate() {
        if meta.key == config.config
            || meta.key == config.issuer_account
            || request.metas[..index]
                .iter()
                .any(|prior| prior.key == meta.key)
        {
            return Err(ClientError::Identity);
        }
    }
    if now < 0 || now > request.deadline {
        return Err(ClientError::Expired);
    }
    Ok(V3PreparedAction { action_be })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dynark_native_client::decode_digest;

    fn fixture() -> (V3ActionConfig, V3ActionRequest) {
        let mut policy = [0; 32];
        policy[31] = 4;
        let mut issuer = [0; 32];
        issuer[31] = 15;
        let config = V3ActionConfig {
            genesis: [1; 32],
            program: [2; 32],
            config: [3; 32],
            policy_id_be: policy,
            policy_version: 7,
            circuit_id: decode_digest(
                "eae99530daf7331037f2d1c6dc93ccc582603bd448f38d06e6469c734e8252fe",
            )
            .unwrap(),
            request_key: [10; 32],
            queue_key: [11; 32],
            issuer_account: [16; 32],
        };
        let request = V3ActionRequest {
            config: config.config,
            creator: [14; 32],
            nonce: [8; 32],
            issuer_hash_be: issuer,
            recipient: [9; 32],
            request_type: 1,
            deadline: 1_800_000_000,
            payload: b"bounded-v3-action".to_vec(),
            metas: vec![
                V3ActionMeta {
                    key: [10; 32],
                    flags: 2,
                    owner: config.program,
                },
                V3ActionMeta {
                    key: [11; 32],
                    flags: 2,
                    owner: config.program,
                },
                V3ActionMeta {
                    key: [12; 32],
                    flags: 1,
                    owner: [13; 32],
                },
            ],
        };
        (config, request)
    }
    fn expected_action() -> Digest {
        decode_digest("09b1b947699a3927e6654b5b37caf74211edde16b887afba5da2796b56411cc2").unwrap()
    }
    fn from_hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
    #[test]
    fn canonical_action_v2_bytes_and_reduced_hash_match_fixed_vector() {
        let (config, request) = fixture();
        // Independent stdlib SHA256/integer reference over the published action-v2
        // preimage. No holder key or certificate participates in this public vector.
        let expected = from_hex(concat!(
            "44594e41524b2d574f524b2d5245515545535402010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303000000000000000000000000000000000000000000000000000000000000000400000007",
            "eae99530daf7331037f2d1c6dc93ccc582603bd448f38d06e6469c734e8252fe08080808080808080808080808080808080808080808080808080808080808080909090909090909090909090909090909090909090909090909090909090909000100000011908d2fcbf46c2fc1265669fccb2c40f0fb29b5cc7c64335314e7f228ee49717b03",
            "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a020b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b020c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c01000000006b49d200"
        ));
        assert_eq!(expected.len(), 394);
        assert_eq!(
            v3_action_preimage(&config, &request)
                .expect("canonical action-v2 preimage is implemented"),
            expected
        );
        assert_eq!(v3_action_hash(&config, &request), Ok(expected_action()));
    }
    #[test]
    fn every_hashed_request_field_and_order_is_bound_to_the_action() {
        let (config, request) = fixture();
        let base = expected_action();
        for field in 0..14 {
            let mut c = config.clone();
            let mut r = request.clone();
            match field {
                0 => c.genesis[0] ^= 1,
                1 => c.program[0] ^= 1,
                2 => c.policy_version += 1,
                3 => c.circuit_id[0] ^= 1,
                4 => c.policy_id_be[31] += 1,
                5 => {
                    r.config[0] ^= 1;
                    c.config = r.config;
                }
                6 => r.nonce[0] ^= 1,
                7 => r.recipient[0] ^= 1,
                8 => r.request_type += 1,
                9 => r.payload.push(1),
                10 => r.deadline += 1,
                11 => r.metas.swap(0, 1),
                12 => r.metas[2].flags ^= 1,
                _ => r.metas.push(V3ActionMeta {
                    key: [17; 32],
                    flags: 0,
                    owner: [18; 32],
                }),
            }
            assert_ne!(v3_action_hash(&c, &r), Ok(base));
        }
    }
    #[test]
    fn preparation_accepts_exact_accounts_action_and_matching_holder() {
        let (config, request) = fixture();
        let holder = [0x81; 256]; // Public shape-only test modulus, no private key.
        assert_eq!(v3_match_holder_modulus(&holder, &holder), Ok(()));
        let prepared = v3_prepare_action(
            &config,
            &request,
            &request.metas,
            expected_action(),
            &holder,
            &holder,
            1_799_999_999,
        )
        .expect("exact action preparation is implemented");
        assert_eq!(prepared.action_be, expected_action());
    }
    #[test]
    fn wrong_holder_account_owner_order_privileges_and_action_are_rejected() {
        let (config, request) = fixture();
        let holder = [0x81; 256];
        let other = [0x83; 256];
        assert_eq!(
            v3_match_holder_modulus(&holder, &other),
            Err(ClientError::Identity)
        );
        for field in 0..5 {
            let mut actual = request.metas.clone();
            let mut action = expected_action();
            match field {
                0 => actual[0].key[0] ^= 1,
                1 => actual[2].owner[0] ^= 1,
                2 => actual.swap(0, 1),
                3 => actual[2].flags ^= 1,
                _ => action[31] ^= 1,
            }
            assert!(matches!(
                v3_prepare_action(
                    &config,
                    &request,
                    &actual,
                    action,
                    &holder,
                    &holder,
                    1_799_999_999
                ),
                Err(ClientError::Identity)
            ));
        }
        assert!(matches!(
            v3_prepare_action(
                &config,
                &request,
                &request.metas,
                expected_action(),
                &holder,
                &other,
                1_799_999_999
            ),
            Err(ClientError::Identity)
        ));
    }
    #[test]
    fn owners_are_validated_separately_from_the_action_v2_preimage() {
        let (config, mut request) = fixture();
        let original = request.clone();
        request.metas[2].owner[0] ^= 1;
        assert_eq!(
            v3_action_preimage(&config, &request).unwrap(),
            v3_action_preimage(&config, &original).unwrap()
        );
        let holder = [0x81; 256];
        assert!(matches!(
            v3_prepare_action(
                &config,
                &request,
                &original.metas,
                expected_action(),
                &holder,
                &holder,
                1_799_999_999
            ),
            Err(ClientError::Identity)
        ));
    }
}
