//! Tests-first v3 contract slice. No setup, verifier, proof, validator or v2 mutations.
use solana_program::pubkey::Pubkey;
use zk_fresh_program::{
    application_runtime_v3 as runtime, application_v3::*, generated_vk_v3 as identity,
};
fn field(n: u8) -> [u8; 32] {
    let mut b = [0; 32];
    b[31] = n;
    b
}
fn actor(key: Pubkey) -> Authority {
    Authority {
        key,
        is_signer: true,
    }
}
fn config() -> Config {
    Config {
        admin: Pubkey::new_from_array([18; 32]),
        seed: [7; 32],
        publisher: Pubkey::new_from_array([19; 32]),
        genesis: [1; 32],
        policy_id: [2; 32],
        policy_version: 1,
        circuit_id: identity::CIRCUIT_ID,
        package_id: identity::PACKAGE_ID,
        schema_id: identity::SEMANTIC_SCHEMA_ID,
        profile_id: identity::PROFILE_ID,
        ordinary_vk_digest: identity::ORDINARY_VK_DIGEST,
        root: field(6),
        root_version: 0,
        eligibility_epoch: 0,
        enabled: true,
    }
}
fn issuer(c: &Config, n: u8) -> Issuer {
    Issuer {
        config: Pubkey::new_from_array([13; 32]),
        issuer_hash: field(n),
        profile_id: c.profile_id,
        profile_version: 3,
        aki: {
            let mut b = [0; 32];
            b[..20].fill(n);
            b
        },
        source: Pubkey::new_from_array([n; 32]),
        enabled: true,
        sequence: 0,
        digest: [0; 32],
        observed_at: 0,
        expires_at: 0,
        bound_root: [0; 32],
        bound_root_version: 0,
        bound_source_sequence: 0,
        bound_source_digest: [0; 32],
        enrollment_version: 1,
        evidence_digest: [n; 32],
        observed_config_epoch: 0,
        status_valid: false,
        eligibility_epoch: 0,
        observed_issuer_epoch: 0,
    }
}
fn request() -> Request {
    Request {
        config: Pubkey::new_from_array([13; 32]),
        creator: Pubkey::new_from_array([18; 32]),
        nonce: [11; 32],
        issuer_hash: field(8),
        recipient: Pubkey::new_from_array([14; 32]),
        request_type: 1,
        deadline: 500,
        payload_len: 3,
        uploaded: 3,
        metas_uploaded: 2,
        state: RequestState::Finalized,
        metas: vec![
            RelevantMeta {
                key: Pubkey::new_from_array([15; 32]),
                flags: 2,
                owner: Pubkey::new_from_array([12; 32]),
            },
            RelevantMeta {
                key: Pubkey::new_from_array([16; 32]),
                flags: 2,
                owner: Pubkey::new_from_array([12; 32]),
            },
        ],
        payload: b"abc".to_vec(),
    }
}
fn observe_and_bind(c: &Config, i: &mut Issuer, now: i64, digest: u8) {
    i.observe(
        c,
        actor(i.source),
        c.eligibility_epoch,
        i.eligibility_epoch,
        i.sequence,
        i.sequence + 1,
        [digest; 32],
        now,
        now + 300,
        now,
    )
    .unwrap();
    i.bind_current(
        c,
        actor(c.publisher),
        c.eligibility_epoch,
        i.eligibility_epoch,
        c.root_version,
        i.sequence,
        now,
    )
    .unwrap();
}
#[test]
fn v3_parser_is_six_fields_exact_and_cannot_accept_v2_transport() {
    let mut wire = vec![0x51, 7];
    for n in 1..=6 {
        wire.extend(field(n));
    }
    wire.extend([1; 256]);
    assert_eq!(wire.len(), 450);
    assert_eq!(
        AppInstruction::parse(&wire),
        Ok(AppInstruction::Execute {
            inputs: std::array::from_fn(|i| field(i as u8 + 1)),
            proof: [1; 256]
        })
    );
    assert_eq!(
        AppInstruction::parse(&[0x51, 5]),
        Ok(AppInstruction::Finalize)
    );
    assert!(AppInstruction::parse(&[0x50, 5]).is_err());
    wire[0] = 0x50;
    assert!(AppInstruction::parse(&wire).is_err());
    wire[0] = 0x51;
    wire.push(0);
    assert!(AppInstruction::parse(&wire).is_err());
    assert!(AppInstruction::parse(&vec![0; 2048]).is_err());
    let mut five = vec![0x51, 7];
    five.extend([0; 416]);
    assert!(AppInstruction::parse(&five).is_err());
    assert!(zk_fresh_program::application_v2::AppInstruction::parse(&[0x51, 5]).is_err());
}
#[test]
fn config_codec_has_exact_epoch_and_identity_offsets() {
    let c = config();
    let bytes = c.encode();
    assert_eq!(bytes.len(), 381);
    assert_eq!(&bytes[..8], b"DYNCONF3");
    assert_eq!(&bytes[268..300], &c.profile_id);
    assert_eq!(&bytes[300..332], &c.ordinary_vk_digest);
    assert_eq!(&bytes[332..364], &c.root);
    assert_eq!(&bytes[364..372], &c.root_version.to_be_bytes());
    assert_eq!(&bytes[372..380], &0u64.to_be_bytes());
    assert_eq!(bytes[380], 1);
    assert_eq!(Config::decode(&bytes), Ok(c.clone()));
    for old in [b"DYNCONF2", b"DYNISS03"] {
        let mut bad = bytes.clone();
        bad[..8].copy_from_slice(old);
        assert!(Config::decode(&bad).is_err());
    }
    assert!(Config::decode(&bytes[..380]).is_err());
    let mut bad = bytes;
    bad.push(0);
    assert!(Config::decode(&bad).is_err());
    let mut bad = c.clone();
    bad.policy_id = zk_fresh_program::FIELD_MODULUS;
    assert!(Config::decode(&bad.encode()).is_err());
}
#[test]
fn issuer_codec_records_enrollment_and_observation_epoch_without_fixture_aki() {
    let c = config();
    for n in [8, 9] {
        let i = issuer(&c, n);
        let bytes = i.encode();
        assert_eq!(bytes.len(), 374);
        assert_eq!(&bytes[..8], b"DYNISS03");
        assert_eq!(&bytes[309..317], &1u64.to_be_bytes());
        assert_eq!(&bytes[317..349], &i.evidence_digest);
        assert_eq!(&bytes[349..357], &0u64.to_be_bytes());
        assert_eq!(bytes[357], 0);
        assert_eq!(&bytes[358..366], &0u64.to_be_bytes());
        assert_eq!(&bytes[366..374], &0u64.to_be_bytes());
        let mut legacy_prefix = bytes.clone();
        legacy_prefix.truncate(358);
        assert!(Issuer::decode(&legacy_prefix).is_err());
        assert_eq!(Issuer::decode(&bytes), Ok(i.clone()));
        let mut old = bytes.clone();
        old[..8].copy_from_slice(b"DYNIS2B1");
        assert!(Issuer::decode(&old).is_err());
        let mut bad = i.clone();
        bad.aki[31] = 1;
        assert!(Issuer::decode(&bad.encode()).is_err());
    }
}
#[test]
fn request_queue_codecs_have_v3_magic_and_canonical_unused_padding() {
    let r = request();
    let rb = r.encode();
    assert_eq!(rb.len(), 2249);
    assert_eq!(&rb[..8], b"DYNREQ03");
    assert_eq!(Request::decode(&rb), Ok(r.clone()));
    let q = Queue::new(r.config);
    let qb = q.encode();
    assert_eq!(qb.len(), 2090);
    assert_eq!(&qb[..8], b"DYNQUE03");
    assert_eq!(Queue::decode(&qb), Ok(q));
    let mut bad = rb.clone();
    bad[2248] = 1;
    assert!(Request::decode(&bad).is_err());
    let mut bad = rb.clone();
    bad[315] = 1;
    assert!(Request::decode(&bad).is_err());
    let mut bad = qb.clone();
    bad[2089] = 1;
    assert!(Queue::decode(&bad).is_err());
    let mut old = rb;
    old[..8].copy_from_slice(b"DYNREQ02");
    assert!(Request::decode(&old).is_err());
    let mut old = qb;
    old[..8].copy_from_slice(b"DYNQUE02");
    assert!(Queue::decode(&old).is_err());
}
#[test]
fn action_v2_preimage_is_verbatim_despite_account_version_and_authority_epochs() {
    use zk_fresh_program::application_v2 as old;
    let c = config();
    let r = request();
    let program = Pubkey::new_from_array([12; 32]);
    let oldc = old::Config {
        admin: c.admin,
        seed: c.seed,
        publisher: c.publisher,
        genesis: c.genesis,
        policy_id: c.policy_id,
        policy_version: c.policy_version,
        circuit_id: c.circuit_id,
        package_id: c.package_id,
        schema_id: c.schema_id,
        root: c.root,
        root_version: c.root_version,
        enabled: c.enabled,
    };
    let oldr = old::Request {
        config: r.config,
        creator: r.creator,
        nonce: r.nonce,
        issuer_hash: r.issuer_hash,
        recipient: r.recipient,
        request_type: r.request_type,
        deadline: r.deadline,
        payload_len: r.payload_len,
        uploaded: r.uploaded,
        metas_uploaded: r.metas_uploaded,
        state: old::RequestState::Finalized,
        metas: r
            .metas
            .iter()
            .map(|m| old::RelevantMeta {
                key: m.key,
                flags: m.flags,
                owner: m.owner,
            })
            .collect(),
        payload: r.payload.clone(),
    };
    let expected = old::action_preimage(&program, &oldc, &oldr).unwrap();
    assert_eq!(expected.len(), 361);
    assert_eq!(action_preimage(&program, &c, &r), Ok(expected.clone()));
    assert_eq!(
        action_hash(&program, &c, &r),
        old::action_hash(&program, &oldc, &oldr)
    );
    let mut changed = c.clone();
    changed.eligibility_epoch += 1;
    changed.root = field(20);
    changed.root_version += 1;
    assert_eq!(action_preimage(&program, &changed, &r), Ok(expected));
}
#[test]
fn v3_pda_domains_isolate_versions_issuers_and_policies() {
    let c = config();
    let program = Pubkey::new_from_array([12; 32]);
    let ca = runtime::config_address(&program, &c.admin, &c.seed).0;
    assert_ne!(
        ca,
        zk_fresh_program::application_runtime_v2::config_address(&program, &c.admin, &c.seed).0
    );
    assert_ne!(
        runtime::issuer_address(&program, &ca, &field(8)),
        runtime::issuer_address(&program, &ca, &field(9))
    );
    let second = runtime::config_address(&program, &c.admin, &[8; 32]).0;
    assert_ne!(ca, second);
    assert_ne!(
        runtime::queue_address(&program, &ca),
        runtime::queue_address(&program, &second)
    );
}
#[test]
fn one_policy_enrolls_two_distinct_issuer_associations_without_new_key() {
    let c = config();
    let key = Pubkey::new_from_array([13; 32]);
    for n in [8, 9] {
        let i = issuer(&c, n);
        let enrolled = Issuer::enroll(
            key,
            &c,
            actor(c.admin),
            i.issuer_hash,
            i.aki,
            i.source,
            1,
            i.evidence_digest,
        );
        assert_eq!(enrolled, Ok(i));
    }
    let i = issuer(&c, 8);
    assert!(Issuer::enroll(
        key,
        &c,
        actor(c.publisher),
        i.issuer_hash,
        i.aki,
        i.source,
        1,
        i.evidence_digest
    )
    .is_err());
    assert!(Issuer::enroll(
        key,
        &c,
        Authority {
            key: c.admin,
            is_signer: false
        },
        i.issuer_hash,
        i.aki,
        i.source,
        1,
        i.evidence_digest
    )
    .is_err());
}
#[test]
fn unobserved_source_sequence_zero_cannot_bind_even_with_matching_zero_fields() {
    let c = config();
    let mut i = issuer(&c, 8);
    i.status_valid = true;
    i.observed_at = 100;
    i.expires_at = 400;
    i.bound_root = c.root;
    assert_eq!(i.fresh(&c, 100), Err(AppError::Status));
    assert_eq!(i.binding_current(&c), Err(AppError::Binding));
    assert!(i
        .bind_current(
            &c,
            actor(c.publisher),
            c.eligibility_epoch,
            i.eligibility_epoch,
            0,
            0,
            100
        )
        .is_err());
}
#[test]
fn status_and_publication_require_their_own_signed_authorities_and_exact_predecessors() {
    let mut c = config();
    let mut i = issuer(&c, 8);
    let initial = i.clone();
    assert!(i
        .observe(
            &c,
            actor(c.admin),
            c.eligibility_epoch,
            i.eligibility_epoch,
            0,
            1,
            [1; 32],
            100,
            400,
            100
        )
        .is_err());
    assert_eq!(i, initial);
    assert!(i
        .observe(
            &c,
            Authority {
                key: i.source,
                is_signer: false
            },
            c.eligibility_epoch,
            i.eligibility_epoch,
            0,
            1,
            [1; 32],
            100,
            400,
            100
        )
        .is_err());
    assert_eq!(i, initial);
    i.observe(
        &c,
        actor(i.source),
        c.eligibility_epoch,
        i.eligibility_epoch,
        0,
        1,
        [1; 32],
        100,
        400,
        100,
    )
    .unwrap();
    assert_eq!(i.sequence, 1);
    assert!(i.status_valid);
    let saved = i.clone();
    assert!(i
        .bind_current(
            &c,
            actor(c.admin),
            c.eligibility_epoch,
            i.eligibility_epoch,
            0,
            1,
            100
        )
        .is_err());
    assert_eq!(i, saved);
    assert!(i
        .bind_current(
            &c,
            actor(c.publisher),
            c.eligibility_epoch,
            i.eligibility_epoch,
            1,
            1,
            100
        )
        .is_err());
    assert_eq!(i, saved);
    i.bind_current(
        &c,
        actor(c.publisher),
        c.eligibility_epoch,
        i.eligibility_epoch,
        0,
        1,
        100,
    )
    .unwrap();
    assert_eq!(i.binding_current(&c), Ok(()));
    let savedc = c.clone();
    assert!(c.publish(actor(c.admin), 0, field(10)).is_err());
    assert_eq!(c, savedc);
    c.publish(actor(c.publisher), 0, field(10)).unwrap();
    assert_eq!(c.root_version, 1);
    assert!(i.binding_current(&c).is_err());
}
#[test]
fn source_updates_only_its_issuer_and_never_retime_identical_evidence() {
    let c = config();
    let mut a = issuer(&c, 8);
    let mut b = issuer(&c, 9);
    observe_and_bind(&c, &mut a, 100, 1);
    observe_and_bind(&c, &mut b, 100, 2);
    let oldb = b.clone();
    assert!(a
        .observe(
            &c,
            actor(a.source),
            c.eligibility_epoch,
            a.eligibility_epoch,
            1,
            2,
            [1; 32],
            101,
            401,
            101
        )
        .is_err());
    a.observe(
        &c,
        actor(a.source),
        c.eligibility_epoch,
        a.eligibility_epoch,
        1,
        2,
        [3; 32],
        101,
        401,
        101,
    )
    .unwrap();
    assert!(a.binding_current(&c).is_err());
    assert_eq!(b, oldb);
    assert_eq!(b.binding_current(&c), Ok(()));
}
#[test]
fn config_disable_reenable_fences_all_issuers_until_each_observes_and_binds_again() {
    let mut c = config();
    let mut a = issuer(&c, 8);
    let mut b = issuer(&c, 9);
    observe_and_bind(&c, &mut a, 100, 1);
    observe_and_bind(&c, &mut b, 100, 2);
    let olda = a.clone();
    let oldb = b.clone();
    let before = c.clone();
    assert!(c.set_enabled(actor(c.publisher), false).is_err());
    assert_eq!(c, before);
    c.set_enabled(actor(c.admin), false).unwrap();
    assert_eq!(c.eligibility_epoch, 1);
    assert_eq!(a, olda);
    assert_eq!(b, oldb);
    assert!(a.fresh(&c, 100).is_err());
    assert!(a.binding_current(&c).is_err());
    c.set_enabled(actor(c.admin), false).unwrap();
    assert_eq!(c.eligibility_epoch, 1);
    c.set_enabled(actor(c.admin), true).unwrap();
    assert_eq!(c.eligibility_epoch, 2);
    assert!(a
        .bind_current(
            &c,
            actor(c.publisher),
            c.eligibility_epoch,
            a.eligibility_epoch,
            0,
            1,
            101
        )
        .is_err());
    assert!(b
        .bind_current(
            &c,
            actor(c.publisher),
            c.eligibility_epoch,
            b.eligibility_epoch,
            0,
            1,
            101
        )
        .is_err());
    observe_and_bind(&c, &mut a, 101, 3);
    assert_eq!(a.observed_config_epoch, 2);
    assert_eq!(a.binding_current(&c), Ok(()));
    assert!(b.binding_current(&c).is_err());
}
#[test]
fn issuer_disable_reenable_retains_source_predecessor_and_does_not_disable_other_issuers() {
    let c = config();
    let mut a = issuer(&c, 8);
    let mut b = issuer(&c, 9);
    observe_and_bind(&c, &mut a, 100, 1);
    observe_and_bind(&c, &mut b, 100, 2);
    let saved = b.clone();
    a.set_enabled(&c, actor(c.admin), false).unwrap();
    assert!(!a.status_valid);
    assert_eq!((a.sequence, a.digest, a.observed_at), (1, [1; 32], 100));
    a.set_enabled(&c, actor(c.admin), true).unwrap();
    assert!(!a.status_valid);
    assert!(a
        .bind_current(
            &c,
            actor(c.publisher),
            c.eligibility_epoch,
            a.eligibility_epoch,
            0,
            1,
            101
        )
        .is_err());
    assert!(a
        .observe(
            &c,
            actor(a.source),
            c.eligibility_epoch,
            a.eligibility_epoch,
            0,
            1,
            [3; 32],
            101,
            401,
            101
        )
        .is_err());
    observe_and_bind(&c, &mut a, 101, 3);
    assert_eq!(a.sequence, 2);
    assert_eq!(b, saved);
    assert_eq!(b.binding_current(&c), Ok(()));
}
#[test]
fn epoch_overflow_and_profile_substitution_fail_without_mutation() {
    let mut c = config();
    c.eligibility_epoch = u64::MAX;
    let before = c.clone();
    assert!(c.set_enabled(actor(c.admin), false).is_err());
    assert_eq!(c, before);
    let c = config();
    let i = issuer(&c, 8);
    let mut wrong = c.clone();
    wrong.profile_id[0] ^= 1;
    assert!(i.admitted(&wrong).is_err());
    let mut bad = i.clone();
    bad.profile_id[0] ^= 1;
    assert!(bad.admitted(&c).is_err());
    assert_eq!(i.admitted(&c), Ok(()));
}

#[test]
fn sixth_public_policy_is_canonical_exact_config_policy_not_a_caller_choice() {
    let c = config();
    assert_eq!(c.require_policy(&c.policy_id), Ok(()));
    assert!(c.require_policy(&field(9)).is_err());
    assert!(c.require_policy(&zk_fresh_program::FIELD_MODULUS).is_err());
}
#[test]
fn independent_enable_controls_and_bounded_variable_instruction_parser() {
    assert_eq!(
        AppInstruction::parse(&[0x51, 10, 0]),
        Ok(AppInstruction::SetConfigEnabled { enabled: false })
    );
    assert_eq!(
        AppInstruction::parse(&[0x51, 12, 1]),
        Ok(AppInstruction::SetIssuerEnabled { enabled: true })
    );
    for wire in [
        vec![0x51, 10, 2],
        vec![0x51, 12, 1, 0],
        vec![0x51, 6, 0, 0, 0xff, 0xff],
        vec![0x51, 8, 0, 255],
    ] {
        assert!(AppInstruction::parse(&wire).is_err());
    }
    assert_eq!(
        AppInstruction::parse(&[0x51, 6, 0, 0, 0, 1, 42]),
        Ok(AppInstruction::Upload {
            offset: 0,
            bytes: vec![42]
        })
    );
}

#[test]
fn presigned_observe_before_config_toggle_cannot_be_relabeled_to_current_epoch() {
    let mut c = config();
    let mut i = issuer(&c, 8);
    observe_and_bind(&c, &mut i, 100, 1);
    let signed_config_epoch = c.eligibility_epoch;
    let signed_issuer_epoch = i.eligibility_epoch;
    c.set_enabled(actor(c.admin), false).unwrap();
    c.set_enabled(actor(c.admin), true).unwrap();
    let unchanged = i.clone();
    assert!(i
        .observe(
            &c,
            actor(i.source),
            signed_config_epoch,
            signed_issuer_epoch,
            1,
            2,
            [2; 32],
            101,
            401,
            101
        )
        .is_err());
    assert_eq!(i, unchanged);
    assert!(i
        .bind_current(
            &c,
            actor(c.publisher),
            signed_config_epoch,
            signed_issuer_epoch,
            c.root_version,
            1,
            101
        )
        .is_err());
    assert_eq!(i, unchanged);
    assert!(i.admitted(&c).is_err());
    assert!(i.fresh(&c, 101).is_err());
    i.observe(
        &c,
        actor(i.source),
        c.eligibility_epoch,
        i.eligibility_epoch,
        1,
        2,
        [2; 32],
        101,
        401,
        101,
    )
    .unwrap();
    assert_eq!(i.observed_config_epoch, 2);
    assert_eq!(i.observed_issuer_epoch, 0);
    assert!(i.binding_current(&c).is_err());
    assert!(i
        .bind_current(
            &c,
            actor(c.publisher),
            signed_config_epoch,
            signed_issuer_epoch,
            c.root_version,
            2,
            101
        )
        .is_err());
    i.bind_current(
        &c,
        actor(c.publisher),
        c.eligibility_epoch,
        i.eligibility_epoch,
        c.root_version,
        2,
        101,
    )
    .unwrap();
    assert_eq!(i.binding_current(&c), Ok(()));
}
#[test]
fn presigned_observe_before_issuer_toggle_cannot_be_relabeled_to_current_epoch() {
    let c = config();
    let mut i = issuer(&c, 8);
    observe_and_bind(&c, &mut i, 100, 1);
    let signed_config_epoch = c.eligibility_epoch;
    let signed_issuer_epoch = i.eligibility_epoch;
    i.set_enabled(&c, actor(c.admin), false).unwrap();
    i.set_enabled(&c, actor(c.admin), true).unwrap();
    assert_eq!(i.eligibility_epoch, 2);
    assert_eq!((i.sequence, i.digest, i.observed_at), (1, [1; 32], 100));
    let unchanged = i.clone();
    assert!(i
        .observe(
            &c,
            actor(i.source),
            signed_config_epoch,
            signed_issuer_epoch,
            1,
            2,
            [2; 32],
            101,
            401,
            101
        )
        .is_err());
    assert_eq!(i, unchanged);
    assert!(i
        .bind_current(
            &c,
            actor(c.publisher),
            signed_config_epoch,
            signed_issuer_epoch,
            c.root_version,
            1,
            101
        )
        .is_err());
    assert_eq!(i, unchanged);
    assert!(i.admitted(&c).is_err());
    assert!(i.fresh(&c, 101).is_err());
    i.observe(
        &c,
        actor(i.source),
        c.eligibility_epoch,
        i.eligibility_epoch,
        1,
        2,
        [2; 32],
        101,
        401,
        101,
    )
    .unwrap();
    assert_eq!(i.observed_config_epoch, 0);
    assert_eq!(i.observed_issuer_epoch, 2);
    assert!(i.binding_current(&c).is_err());
    assert!(i
        .bind_current(
            &c,
            actor(c.publisher),
            signed_config_epoch,
            signed_issuer_epoch,
            c.root_version,
            2,
            101
        )
        .is_err());
    i.bind_current(
        &c,
        actor(c.publisher),
        c.eligibility_epoch,
        i.eligibility_epoch,
        c.root_version,
        2,
        101,
    )
    .unwrap();
    assert_eq!(i.binding_current(&c), Ok(()));
}
#[test]
fn issuer_epoch_changes_only_on_real_flips_and_checked_overflow_never_mutates() {
    let c = config();
    let mut i = issuer(&c, 8);
    i.set_enabled(&c, actor(c.admin), true).unwrap();
    assert_eq!(i.eligibility_epoch, 0);
    i.set_enabled(&c, actor(c.admin), false).unwrap();
    assert_eq!(i.eligibility_epoch, 1);
    i.set_enabled(&c, actor(c.admin), false).unwrap();
    assert_eq!(i.eligibility_epoch, 1);
    i.eligibility_epoch = u64::MAX;
    let unchanged = i.clone();
    assert!(i.set_enabled(&c, actor(c.admin), true).is_err());
    assert_eq!(i, unchanged);
}
#[test]
fn observe_and_bind_wire_include_both_signed_epoch_predecessors() {
    let mut observe = vec![0x51, 3];
    for value in [2u64, 3, 4, 5] {
        observe.extend(value.to_be_bytes());
    }
    observe.extend([9; 32]);
    observe.extend(100i64.to_be_bytes());
    observe.extend(400i64.to_be_bytes());
    assert_eq!(observe.len(), 82);
    assert_eq!(
        AppInstruction::parse(&observe),
        Ok(AppInstruction::Observe {
            expected_config_epoch: 2,
            expected_issuer_epoch: 3,
            expected: 4,
            sequence: 5,
            digest: [9; 32],
            observed: 100,
            expires: 400
        })
    );
    let mut bind = vec![0x51, 11];
    for value in [2u64, 3, 4, 5] {
        bind.extend(value.to_be_bytes());
    }
    assert_eq!(bind.len(), 34);
    assert_eq!(
        AppInstruction::parse(&bind),
        Ok(AppInstruction::BindCurrent {
            expected_config_epoch: 2,
            expected_issuer_epoch: 3,
            root_version: 4,
            source_sequence: 5
        })
    );
    let mut old_observe = observe.clone();
    old_observe.drain(2..18);
    assert!(AppInstruction::parse(&old_observe).is_err());
    let mut old_bind = bind.clone();
    old_bind.drain(2..18);
    assert!(AppInstruction::parse(&old_bind).is_err());
}

#[test]
fn admission_and_freshness_never_accept_mismatched_recorded_epochs() {
    let c = config();
    let mut i = issuer(&c, 8);
    observe_and_bind(&c, &mut i, 100, 1);
    for issuer_epoch in [false, true] {
        let mut changed = i.clone();
        if issuer_epoch {
            changed.observed_issuer_epoch = 1;
        } else {
            changed.observed_config_epoch = 1;
        }
        let original = changed.clone();
        assert!(changed.admitted(&c).is_err());
        assert!(changed.fresh(&c, 100).is_err());
        assert!(changed.binding_current(&c).is_err());
        assert!(changed
            .bind_current(
                &c,
                actor(c.publisher),
                c.eligibility_epoch,
                changed.eligibility_epoch,
                c.root_version,
                changed.sequence,
                100
            )
            .is_err());
        assert_eq!(changed, original);
    }
}
