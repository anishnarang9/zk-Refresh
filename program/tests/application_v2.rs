use solana_program::pubkey::Pubkey;
use zk_fresh_program::application_v2::*;

fn field(n: u8) -> [u8; 32] {
    let mut x = [0; 32];
    x[31] = n;
    x
}
fn config() -> Config {
    Config {
        admin: Pubkey::new_unique(),
        seed: [7; 32],
        publisher: Pubkey::new_unique(),
        genesis: [1; 32],
        policy_id: [2; 32],
        policy_version: 1,
        circuit_id: [3; 32],
        package_id: [4; 32],
        schema_id: [5; 32],
        root: field(6),
        root_version: 0,
        enabled: true,
    }
}
fn issuer() -> Issuer {
    Issuer {
        config: Pubkey::new_unique(),
        issuer_hash: field(8),
        profile_id: [9; 32],
        profile_version: 1,
        aki: [10; 32],
        source: Pubkey::new_unique(),
        enabled: true,
        sequence: 0,
        digest: [0; 32],
        observed_at: 0,
        expires_at: 0,
    }
}
fn request() -> Request {
    Request {
        config: Pubkey::new_unique(),
        creator: Pubkey::new_unique(),
        nonce: [11; 32],
        issuer_hash: field(8),
        recipient: Pubkey::new_unique(),
        request_type: 1,
        deadline: 500,
        payload_len: 3,
        uploaded: 0,
        metas_uploaded: 2,
        state: RequestState::Staging,
        metas: vec![
            RelevantMeta {
                key: Pubkey::new_unique(),
                flags: 2,
                owner: Pubkey::new_unique(),
            },
            RelevantMeta {
                key: Pubkey::new_unique(),
                flags: 2,
                owner: Pubkey::new_unique(),
            },
        ],
        payload: vec![0; 3],
    }
}
#[test]
fn bounded_parser_rejects_empty_unknown_trailing_and_oversized() {
    assert!(AppInstruction::parse(&[]).is_err());
    assert!(AppInstruction::parse(&[0x50, 255]).is_err());
    assert!(AppInstruction::parse(&[0x50, 5, 0]).is_err());
    assert!(AppInstruction::parse(&vec![0; 2048]).is_err());
    assert!(matches!(
        AppInstruction::parse(&[0x50, 5]),
        Ok(AppInstruction::Finalize)
    ));
}
#[test]
fn account_codecs_reject_truncation_versions_and_trailing() {
    let c = config();
    let bytes = c.encode();
    assert_eq!(Config::decode(&bytes).unwrap(), c);
    assert!(Config::decode(&bytes[..bytes.len() - 1]).is_err());
    let mut wrong = bytes.clone();
    wrong[7] = 3;
    assert!(Config::decode(&wrong).is_err());
    wrong = bytes;
    wrong.push(0);
    assert!(Config::decode(&wrong).is_err());
    let i = issuer();
    assert_eq!(Issuer::decode(&i.encode()).unwrap(), i);
    let r = request();
    assert_eq!(Request::decode(&r.encode()).unwrap(), r);
    let q = Queue::new(r.config);
    assert_eq!(Queue::decode(&q.encode()).unwrap(), q);
}
#[test]
fn staging_is_contiguous_bounded_and_finalization_immutable() {
    let mut r = request();
    assert!(r.finalize(100).is_err());
    assert!(r.upload(1, b"a").is_err());
    r.upload(0, b"a").unwrap();
    assert!(r.upload(1, b"bcd").is_err());
    r.upload(1, b"bc").unwrap();
    r.finalize(100).unwrap();
    assert_eq!(r.state, RequestState::Finalized);
    assert!(r.upload(0, b"abc").is_err());
    assert!(r.finalize(100).is_err());
    assert_eq!(r.payload, b"abc");
}
#[test]
fn source_sequence_does_not_retime_replayed_evidence() {
    let mut i = issuer();
    i.observe(0, 1, [1; 32], 100, 400, 100).unwrap();
    let saved = i.clone();
    assert!(i.observe(1, 2, [1; 32], 101, 401, 101).is_err());
    assert_eq!(i, saved);
    assert!(i.observe(1, 2, [2; 32], 100, 400, 101).is_err());
    assert!(i.observe(0, 2, [2; 32], 101, 401, 101).is_err());
    assert!(i.observe(1, 2, [2; 32], 102, 402, 101).is_err());
    i.observe(1, 2, [2; 32], 101, 401, 101).unwrap();
    assert!(i.fresh(402).is_err());
    assert!(i.fresh(100).is_err());
    assert!(i.fresh(401).is_ok());
}
#[test]
fn root_updates_require_exact_predecessor() {
    let mut c = config();
    let saved = c.clone();
    assert!(c.publish(1, field(9)).is_err());
    assert_eq!(c, saved);
    c.publish(0, field(9)).unwrap();
    assert_eq!(c.root_version, 1);
    assert!(c.publish(0, field(10)).is_err());
}
#[test]
fn queue_capacity_replay_and_failed_effect_preserve_request() {
    let mut r = request();
    r.upload(0, b"abc").unwrap();
    r.finalize(100).unwrap();
    let key = Pubkey::new_unique();
    let mut q = Queue::new(r.config);
    append(&mut q, &mut r, key, 100).unwrap();
    assert_eq!(q.entries, vec![key]);
    assert_eq!(r.state, RequestState::Consumed);
    assert!(append(&mut q, &mut r, key, 100).is_err());
    let mut other = request();
    other.upload(0, b"abc").unwrap();
    other.finalize(100).unwrap();
    q.entries = vec![Pubkey::new_unique(); QUEUE_CAPACITY];
    let old = other.clone();
    let oldq = q.clone();
    assert!(append(&mut q, &mut other, Pubkey::new_unique(), 100).is_err());
    assert_eq!(other, old);
    assert_eq!(q, oldq);
}
#[test]
fn action_hash_binds_every_canonical_component() {
    let c = config();
    let mut r = request();
    r.upload(0, b"abc").unwrap();
    r.finalize(100).unwrap();
    let program = Pubkey::new_unique();
    let h = action_hash(&program, &c, &r).unwrap();
    assert!(h < zk_fresh_program::FIELD_MODULUS);
    let mut changed = r.clone();
    changed.payload[0] ^= 1;
    assert_ne!(action_hash(&program, &c, &changed).unwrap(), h);
    changed = r.clone();
    changed.metas.swap(0, 1);
    assert_ne!(action_hash(&program, &c, &changed).unwrap(), h);
    changed = r.clone();
    changed.metas[0].flags ^= 1;
    assert_ne!(action_hash(&program, &c, &changed).unwrap(), h);
    changed = r.clone();
    changed.deadline += 1;
    assert_ne!(action_hash(&program, &c, &changed).unwrap(), h);
    let mut changedc = c.clone();
    changedc.genesis[0] ^= 1;
    assert_ne!(action_hash(&program, &changedc, &r).unwrap(), h);
    changedc = c.clone();
    changedc.policy_version += 1;
    assert_ne!(action_hash(&program, &changedc, &r).unwrap(), h);
    changedc = c;
    changedc.circuit_id[0] ^= 1;
    assert_ne!(action_hash(&program, &changedc, &r).unwrap(), h);
}

#[test]
fn metadata_upload_is_contiguous_bounded_and_immutable() {
    let mut r = request();
    let metas = r.metas.clone();
    r.metas_uploaded = 0;
    assert!(r.upload_metas(1, &metas[..1]).is_err());
    r.upload_metas(0, &metas[..1]).unwrap();
    r.upload_metas(1, &metas[1..]).unwrap();
    r.upload(0, b"abc").unwrap();
    r.finalize(100).unwrap();
    assert!(r.upload_metas(0, &metas).is_err());
}

#[test]
fn action_matches_independent_python_sha256_big_endian_vector() {
    let c = config();
    let mut r = request();
    r.config = Pubkey::new_from_array([13; 32]);
    r.recipient = Pubkey::new_from_array([14; 32]);
    r.metas[0].key = Pubkey::new_from_array([15; 32]);
    r.metas[1].key = Pubkey::new_from_array([16; 32]);
    r.upload(0, b"abc").unwrap();
    r.finalize(100).unwrap();
    let expected = [
        0, 218, 125, 179, 114, 137, 3, 25, 76, 202, 210, 255, 126, 159, 237, 151, 172, 84, 105,
        255, 206, 31, 226, 4, 176, 35, 203, 173, 31, 233, 133, 148,
    ];
    assert_eq!(
        action_hash(&Pubkey::new_from_array([12; 32]), &c, &r).unwrap(),
        expected
    );
}

#[test]
fn cancelled_partial_staging_retains_decodable_immutable_tombstone() {
    let mut r = request();
    r.upload(0, b"a").unwrap();
    r.state = RequestState::Cancelled;
    assert_eq!(Request::decode(&r.encode()).unwrap(), r);
    assert!(r.upload(1, b"bc").is_err());
    assert!(r.finalize(100).is_err());
}

#[test]
fn request_and_queue_reject_nonzero_unused_allocation_padding() {
    let r = request();
    let mut b = r.encode();
    b[REQUEST_LEN - 1] = 1;
    assert!(Request::decode(&b).is_err());
    b = r.encode();
    b[185 + r.metas.len() * 65] = 1;
    assert!(Request::decode(&b).is_err());
    let q = Queue::new(r.config);
    let mut b = q.encode();
    b[QUEUE_LEN - 1] = 1;
    assert!(Queue::decode(&b).is_err());
}
