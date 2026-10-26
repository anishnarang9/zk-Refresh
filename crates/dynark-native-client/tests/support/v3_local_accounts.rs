use super::*;
use crate::{decode_digest, V3ActionMeta};
use std::time::{Duration, Instant};

struct Fixture {
    config: Vec<u8>,
    issuer: Vec<u8>,
    request: Vec<u8>,
    queue: Vec<u8>,
    head: Vec<u8>,
    summary: V3CredentialSummary,
    manifest: V3FullManifest,
    metas: Vec<V3ActionMeta>,
}
fn put(bytes: &mut [u8], offset: usize, value: &[u8]) {
    bytes[offset..offset + value.len()].copy_from_slice(value);
}
fn be(value: u64) -> Digest {
    let mut b = [0; 32];
    b[24..].copy_from_slice(&value.to_be_bytes());
    b
}
fn le(value: u64) -> Digest {
    let mut b = be(value);
    b.reverse();
    b
}
impl Fixture {
    fn new() -> Self {
        let manifest = V3FullManifest::frozen_development().unwrap();
        let mut config = vec![0; 381];
        put(&mut config, 0, b"DYNCONF3");
        for (offset, value) in [
            (8, [1; 32]),
            (40, [2; 32]),
            (72, [3; 32]),
            (104, [4; 32]),
            (136, be(5)),
            (172, manifest.package.circuit_digest),
            (204, manifest.package.package_digest),
            (236, manifest.admission.semantic_schema),
            (268, manifest.admission.profile),
            (
                300,
                decode_digest("2f9b770ff51ac399619a3127ddb32efad67697402f10c4549441a3578e4f9a4e")
                    .unwrap(),
            ),
            (332, be(6)),
        ] {
            put(&mut config, offset, &value);
        }
        put(&mut config, 168, &7u32.to_be_bytes());
        put(&mut config, 364, &8u64.to_be_bytes());
        put(&mut config, 372, &9u64.to_be_bytes());
        config[380] = 1;
        let mut issuer = vec![0; 374];
        put(&mut issuer, 0, b"DYNISS03");
        for (offset, value) in [
            (8, [10; 32]),
            (40, be(11)),
            (72, manifest.admission.profile),
            (140, [12; 32]),
            (181, [13; 32]),
            (229, be(6)),
            (277, [13; 32]),
            (317, [14; 32]),
        ] {
            put(&mut issuer, offset, &value);
        }
        put(&mut issuer, 104, &3u32.to_be_bytes());
        issuer[108..128].fill(15);
        issuer[172] = 1;
        for (offset, value) in [
            (173, 16u64),
            (213, 1000),
            (221, 1200),
            (261, 8),
            (269, 16),
            (309, 17),
            (349, 9),
            (358, 18),
            (366, 18),
        ] {
            put(&mut issuer, offset, &value.to_be_bytes());
        }
        issuer[357] = 1;
        let metas = vec![
            V3ActionMeta {
                key: [19; 32],
                owner: [20; 32],
                flags: 2,
            },
            V3ActionMeta {
                key: [21; 32],
                owner: [20; 32],
                flags: 2,
            },
        ];
        let mut request = vec![0; 2249];
        put(&mut request, 0, b"DYNREQ03");
        for (offset, value) in [
            (8, [10; 32]),
            (40, [22; 32]),
            (72, [23; 32]),
            (104, be(11)),
            (136, [24; 32]),
        ] {
            put(&mut request, offset, &value);
        }
        put(&mut request, 168, &1u16.to_be_bytes());
        put(&mut request, 170, &1150i64.to_be_bytes());
        put(&mut request, 178, &3u16.to_be_bytes());
        put(&mut request, 180, &3u16.to_be_bytes());
        request[182] = 2;
        request[183] = 1;
        request[184] = 2;
        for (index, m) in metas.iter().enumerate() {
            let start = 185 + 65 * index;
            put(&mut request, start, &m.key);
            request[start + 32] = m.flags;
            put(&mut request, start + 33, &m.owner);
        }
        put(&mut request, 1225, b"abc");
        let mut queue = vec![0; 2090];
        put(&mut queue, 0, b"DYNQUE03");
        put(&mut queue, 8, &[10; 32]);
        let mut head = vec![0; 280];
        put(&mut head, 0, b"DYNHEAD3");
        for (offset, value) in [
            (8, [10; 32]),
            (40, [25; 32]),
            (72, [3; 32]),
            (112, [26; 32]),
            (176, be(6)),
            (224, [13; 32]),
        ] {
            put(&mut head, offset, &value);
        }
        for (offset, value) in [
            (104, 1u64),
            (208, 8),
            (216, 16),
            (256, 9),
            (264, 18),
            (272, 1020),
        ] {
            put(&mut head, offset, &value.to_be_bytes());
        }
        let mut holder = [0x81; 256];
        holder[255] |= 1;
        let summary = V3CredentialSummary {
            layout: 0,
            tbs_digest: [27; 32],
            holder_modulus_be: holder,
            issuer_hash: le(11),
            policy_hash: le(5),
            not_before: 900,
            not_after: 1300,
            signed_aki: [15; 20],
            signed_organization: [0; 16],
            signed_group: [0; 32],
            structural_offsets: [0; 9],
        };
        Self {
            config,
            issuer,
            request,
            queue,
            head,
            summary,
            manifest,
            metas,
        }
    }
    fn accounts(&self) -> V3LocalAccountSet<'_> {
        let account = |key, data| V3LocalAccount {
            key,
            owner: [20; 32],
            executable: false,
            data,
        };
        V3LocalAccountSet {
            program: [20; 32],
            genesis: [4; 32],
            config: account([10; 32], &self.config),
            issuer: account([25; 32], &self.issuer),
            request: account([19; 32], &self.request),
            queue: account([21; 32], &self.queue),
            publisher_head: account([28; 32], &self.head),
            actual_metas: &self.metas,
        }
    }
    fn action(&self) -> Digest {
        let config = V3ActionConfig {
            genesis: [4; 32],
            program: [20; 32],
            config: [10; 32],
            policy_id_be: be(5),
            policy_version: 7,
            circuit_id: self.manifest.package.circuit_digest,
            request_key: [19; 32],
            queue_key: [21; 32],
            issuer_account: [25; 32],
        };
        let request = V3ActionRequest {
            config: [10; 32],
            creator: [22; 32],
            nonce: [23; 32],
            issuer_hash_be: be(11),
            recipient: [24; 32],
            request_type: 1,
            deadline: 1150,
            payload: b"abc".to_vec(),
            metas: self.metas.clone(),
        };
        crate::v3_action_hash(&config, &request).unwrap()
    }
    fn check(&self) -> Result<V3CheckedLocalAccounts, ClientError> {
        self.accounts().check(
            &self.summary,
            &self.manifest,
            self.action(),
            1100,
            &OperationControl::new(Instant::now() + Duration::from_secs(5)),
        )
    }
}
#[test]
fn exact_current_accounts_recompute_canonical_action_and_six_publics() {
    let f = Fixture::new();
    let checked = f
        .check()
        .expect("exact current v3 accounts admitted as nonauthoritative data");
    assert_eq!(checked.action_be(), f.action());
    let mut action = f.action();
    action.reverse();
    assert_eq!(
        checked.public_values(),
        &[le(6), le(11), le(900), le(1300), action, le(5)]
    );
}
#[test]
fn account_owner_executable_length_and_association_substitutions_fail() {
    let f = Fixture::new();
    for n in 0..5 {
        let mut accounts = f.accounts();
        let account = match n {
            0 => &mut accounts.config,
            1 => &mut accounts.issuer,
            2 => &mut accounts.request,
            3 => &mut accounts.queue,
            _ => &mut accounts.publisher_head,
        };
        account.owner = [99; 32];
        assert!(accounts
            .check(
                &f.summary,
                &f.manifest,
                f.action(),
                1100,
                &OperationControl::new(Instant::now() + Duration::from_secs(5))
            )
            .is_err());
    }
    let mut a = f.accounts();
    a.config.executable = true;
    assert!(a
        .check(
            &f.summary,
            &f.manifest,
            f.action(),
            1100,
            &OperationControl::new(Instant::now() + Duration::from_secs(5))
        )
        .is_err());
    let mut a = f.accounts();
    a.queue.key = a.request.key;
    assert!(a
        .check(
            &f.summary,
            &f.manifest,
            f.action(),
            1100,
            &OperationControl::new(Instant::now() + Duration::from_secs(5))
        )
        .is_err());
    let mut f = Fixture::new();
    f.request.pop();
    assert!(f.check().is_err());
}
#[test]
fn disabled_stale_changed_epochs_heads_and_credential_context_fail() {
    for (which, offset) in [
        (0, 104),
        (0, 136),
        (0, 172),
        (0, 204),
        (0, 236),
        (0, 268),
        (0, 300),
        (0, 380),
        (1, 8),
        (1, 40),
        (1, 72),
        (1, 108),
        (1, 128),
        (1, 172),
        (1, 173),
        (1, 181),
        (1, 221),
        (1, 229),
        (1, 261),
        (1, 269),
        (1, 277),
        (1, 349),
        (1, 357),
        (1, 358),
        (1, 366),
        (2, 8),
        (2, 104),
        (3, 8),
        (4, 8),
        (4, 40),
        (4, 72),
        (4, 104),
        (4, 144),
        (4, 176),
        (4, 208),
        (4, 216),
        (4, 224),
        (4, 256),
        (4, 264),
        (4, 272),
    ] {
        let mut f = Fixture::new();
        let b = match which {
            0 => &mut f.config,
            1 => &mut f.issuer,
            2 => &mut f.request,
            3 => &mut f.queue,
            _ => &mut f.head,
        };
        b[offset] ^= 128;
        assert!(
            f.check().is_err(),
            "account {which} offset {offset} must reject"
        );
    }
}
#[test]
fn finalized_counters_padding_queue_replay_and_capacity_are_checked() {
    for (which, start, length) in [(0, 309, 8), (0, 317, 32), (1, 112, 32)] {
        let mut f = Fixture::new();
        let b = if which == 0 {
            &mut f.issuer
        } else {
            &mut f.head
        };
        b[start..start + length].fill(0);
        assert!(f.check().is_err());
    }
    for offset in [178, 180, 182, 183, 184, 185, 217, 218, 315, 1228, 2248] {
        let mut f = Fixture::new();
        f.request[offset] ^= 128;
        assert!(f.check().is_err(), "request offset {offset}");
    }
    let mut f = Fixture::new();
    put(&mut f.queue, 40, &1u16.to_be_bytes());
    put(&mut f.queue, 42, &[19; 32]);
    assert!(f.check().is_err());
    let mut f = Fixture::new();
    put(&mut f.queue, 40, &64u16.to_be_bytes());
    for n in 0..64 {
        put(&mut f.queue, 42 + n * 32, &[40 + n as u8; 32]);
    }
    assert!(f.check().is_err());
    let mut f = Fixture::new();
    f.queue[2090 - 1] = 1;
    assert!(f.check().is_err());
}
#[test]
fn action_payload_nonce_and_actual_meta_substitutions_fail() {
    let f = Fixture::new();
    let expected = f.action();
    for offset in [72, 136, 170, 1225] {
        let mut f = Fixture::new();
        f.request[offset] ^= 1;
        assert!(f
            .accounts()
            .check(
                &f.summary,
                &f.manifest,
                expected,
                1100,
                &OperationControl::new(Instant::now() + Duration::from_secs(5))
            )
            .is_err());
    }
    let mut f = Fixture::new();
    f.metas.swap(0, 1);
    assert!(f.check().is_err());
    let mut f = Fixture::new();
    f.metas[0].owner = [99; 32];
    assert!(f.check().is_err());
}
#[test]
fn cancellation_and_expiry_fail() {
    let f = Fixture::new();
    let c = OperationControl::new(Instant::now() + Duration::from_secs(5));
    c.cancel();
    assert!(matches!(
        f.accounts()
            .check(&f.summary, &f.manifest, f.action(), 1100, &c),
        Err(ClientError::Cancelled)
    ));
    let c = OperationControl::new(Instant::now() + Duration::from_secs(5));
    assert!(f
        .accounts()
        .check(&f.summary, &f.manifest, f.action(), 1200, &c)
        .is_err());
    let mut f = Fixture::new();
    f.summary.not_after = 1100;
    assert!(matches!(
        f.accounts()
            .check(&f.summary, &f.manifest, f.action(), 1100, &c),
        Err(ClientError::Expired)
    ));
}

#[test]
fn every_account_rejects_wrong_magic_truncation_and_extensions() {
    for which in 0..5 {
        for mutation in 0..3 {
            let mut f = Fixture::new();
            let bytes = match which {
                0 => &mut f.config,
                1 => &mut f.issuer,
                2 => &mut f.request,
                3 => &mut f.queue,
                _ => &mut f.head,
            };
            match mutation {
                0 => bytes[0] ^= 1,
                1 => {
                    bytes.pop();
                }
                _ => bytes.push(0),
            }
            assert!(f.check().is_err(), "account {which} mutation {mutation}");
        }
    }
}

#[test]
fn staging_consumed_cancelled_and_noncanonical_fields_fail() {
    for state in [0, 2, 3] {
        let mut f = Fixture::new();
        f.request[183] = state;
        assert!(f.check().is_err());
    }
    let modulus =
        decode_digest("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001").unwrap();
    for (which, offset) in [(0, 136), (0, 332), (1, 40), (2, 104)] {
        let mut f = Fixture::new();
        let bytes = match which {
            0 => &mut f.config,
            1 => &mut f.issuer,
            _ => &mut f.request,
        };
        put(bytes, offset, &modulus);
        assert!(f.check().is_err());
    }
}
