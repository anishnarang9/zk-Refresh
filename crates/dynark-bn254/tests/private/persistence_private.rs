use super::*;
use crate::persistence::*;
#[path = "../dynamic_fixture.rs"]
mod fixture;
use rand::{CryptoRng, RngCore, SeedableRng};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    time::{SystemTime, UNIX_EPOCH},
};
fn descriptor(reduction: crate::Reduction, five: bool) -> crate::CircuitDescriptor {
    let names = if five {
        ["root", "issuerHash", "notBefore", "notAfter", "actionHash"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    } else {
        vec!["x".to_owned()]
    };
    crate::CircuitDescriptor {
        r1cs_artifact_digest: [if five { 41 } else { 21 }; 32],
        witness_executable_digest: [if five { 42 } else { 22 }; 32],
        profile_digest: [if five { 43 } else { 23 }; 32],
        public_schema_digest: crate::public_schema_digest(&names),
        public_schema: names,
        reduction,
    }
}
fn make(
    p: PublicPackage,
    z: &[Fr],
    b: u64,
    d: crate::CircuitDescriptor,
) -> (DynamicState, ExpectedContext) {
    let uk = crate::UpdatingMaterial::prepare(&p, Limits::small()).unwrap();
    let tables = ReconstructionMaterial::prepare(&p, &uk, Limits::small()).unwrap();
    let va = p
        .validate_assignment(&fixture::encode(z), &z[1..p.shape().instance_len])
        .unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(94231);
    let anchor = Anchor::create(
        &p,
        &uk,
        va,
        AnchorBinding::new(&p, [1; 32], [2; 32], 1),
        Limits::small(),
        &mut rng,
    )
    .unwrap();
    let mut cfg = DynamicConfig::small();
    cfg.threshold = b;
    let mut prep = DynamicPreparation::adopt(&p, &tables, anchor, cfg).unwrap();
    prep.advance_preparation(usize::MAX);
    let s = prep.finish().unwrap();
    let c =
        ExpectedContext::new(&p, &tables, &d, [3; 32], [1; 32], [2; 32], [4; 32], [5; 32]).unwrap();
    (s, c)
}
fn state(n: usize, b: u64) -> (DynamicState, ExpectedContext, Vec<Fr>) {
    let z = fixture::assignment(5, 3, 2);
    let (s, c) = make(
        fixture::package(n, 5, false),
        &z,
        b,
        descriptor(crate::Reduction::Original, false),
    );
    (s, c, z)
}
fn snap(c: &ExpectedContext) -> ProviderSnapshot {
    ProviderSnapshot {
        context: c.digest(),
        session: c.session_id(),
        session_epoch: 1,
        key_id: [7; 32],
        key_epoch: 1,
        status: SessionStatus::Active,
        capability: ProviderCapability::ProcessLifetime,
        enrollment_authorized: true,
        receipt: None,
        unresolved: None,
    }
}
fn encoded(s: &DynamicState, c: &ExpectedContext) -> (Zeroizing<Vec<u8>>, [u8; 1024]) {
    let p = LoadPolicy::small(s.config);
    let b = encode(s, c, &p, &mut AdmissionMetrics::default()).unwrap();
    let (h, _) = crate::persistence::wire::header(
        s,
        c,
        &snap(c),
        Reservation {
            nonce: [8; 12],
            commit_id: [9; 32],
        },
        b.len(),
        SyncTier::FileAndDirectory,
    )
    .unwrap();
    (b, h)
}
fn restored(s: &DynamicState, c: &ExpectedContext) -> DynamicState {
    let (b, h) = encoded(s, c);
    let mut m = AdmissionMetrics::default();
    m.buffer_capacity = b.capacity();
    let r = decode(
        &b,
        &h,
        &s.package,
        &s.tables,
        c,
        &LoadPolicy::small(s.config),
        &s.root.current.assignment.values[1..s.package.shape().instance_len],
        &mut m,
    )
    .unwrap();
    assert_eq!(*encoded(&r, c).0, *b);
    r
}
fn update(s: &mut DynamicState, z: &[Fr], target: &[Fr], rng: &mut rand::rngs::StdRng) {
    let t = Transition::new(
        &s.package,
        s.binding().unwrap(),
        s.binding().unwrap().generation + 1,
        &fixture::delta(z, target),
        &target[1..s.package.shape().instance_len],
        Limits::small(),
    )
    .unwrap();
    let out = s.update(&t, rng).unwrap();
    assert!(ordinary::Groth16::<Bn254>::verify_proof(
        &ordinary::prepare_verifying_key(&s.package.ordinary_verifying_key()),
        &out.proof,
        &out.public_values
    )
    .unwrap());
    let va = s
        .package
        .validate_assignment(&fixture::encode(target), &out.public_values)
        .unwrap();
    let full = capture(&s.package, va, s.root.current.r, s.root.current.s).unwrap();
    assert_eq!(
        (
            s.root.current.a,
            s.root.current.b1,
            s.root.current.b2,
            s.root.current.c
        ),
        (full.a_g1, full.b_g1, full.b_g2, full.c_g1)
    );
}
#[test]
fn golden_offsets_pool_aliases_and_all_phase_fft_stream_roundtrips() {
    let mut checkpoints = 0;
    for n in [2, 8, 16, 32, 64, 128, 256] {
        let (mut s, c, z) = state(n, 4);
        let (b, h) = encoded(&s, &c);
        assert_eq!(&h[..8], b"DYNARKP1");
        assert_eq!(u16_at(&h, 10).unwrap(), 1024);
        assert_eq!(b.len(), 1216 + 32 * 5 + 16 + 320 * n);
        assert_eq!(sections(&b).unwrap()[0].offset, 320);
        assert_eq!(sections(&b).unwrap()[8].len, 96);
        assert_eq!(b[320 + 144], 1);
        let r = restored(&s, &c);
        let (_, objs, k) = map_ids(&r);
        assert_eq!(k, 1);
        assert!(Arc::ptr_eq(
            r.root.active.as_ref().unwrap().maps.first().unwrap(),
            r.root.builder.as_ref().unwrap().pending.first().unwrap()
        ));
        drop(r);
        let target = fixture::assignment(5, 4, 3);
        update(
            &mut s,
            &z,
            &target,
            &mut rand::rngs::StdRng::seed_from_u64(99),
        );
        let mut last = None;
        loop {
            let cur = &s.root.builder.as_ref().unwrap().cursor;
            let parts = cur.persistence_parts();
            let key = (cur.phase, parts[0], parts[2]);
            if last != Some(key) || cur.phase == ReconstructionPhase::Materialize {
                let _r = restored(&s, &c);
                checkpoints += 1;
                last = Some(key);
            }
            if cur.ready() {
                break;
            }
            s.advance(1).unwrap();
        }
        println!("T6_PHASE n={n} checkpoints={checkpoints}");
    }
    assert!(checkpoints > 100);
}
#[test]
fn resumed_distinct_swaps_common_randomness_and_raw_proofs() {
    for n in [2, 8, 16, 32, 64, 128, 256] {
        let (mut s, c, mut z) = state(n, 5);
        let mut resumed = restored(&s, &c);
        let mut rng = rand::rngs::StdRng::seed_from_u64(1200);
        for i in 0..10 {
            let target = fixture::assignment(5, 4 + i % 5, 1 + i % 3);
            let mut other = rng.clone();
            update(&mut s, &z, &target, &mut rng);
            update(&mut resumed, &z, &target, &mut other);
            assert_eq!(*encoded(&s, &c).0, *encoded(&resumed, &c).0);
            resumed = restored(&resumed, &c);
            z = target;
        }
        assert!(s.ledger.completed_distinct_snapshots >= 2);
        println!(
            "T6_RESUME n={n} proofs=20 swaps={}",
            s.ledger.completed_distinct_snapshots
        );
    }
}
#[test]
fn full_only_nondefault_roles_distance_telemetry_and_zero_delta() {
    let (mut s, c, z) = state(8, 5);
    let mut rng = rand::rngs::StdRng::seed_from_u64(3);
    let mut current = z;
    for i in 0..3 {
        let target = fixture::assignment(5, 4 + i, 3 + i);
        update(&mut s, &current, &target, &mut rng);
        current = target;
    }
    assert_ne!(s.root.roles, Roles::default());
    let va = s
        .package
        .validate_assignment(&fixture::encode(&current), &current[1..2])
        .unwrap();
    s.full_for_binding(va, [1; 32], [2; 32], 50, &mut rng)
        .unwrap();
    assert_eq!(s.status(), crate::DynamicStatus::FullOnly);
    s.ledger.saturated = true;
    s.ledger.attempted_reconstruction_actions = u64::MAX;
    let r = restored(&s, &c);
    assert_eq!(r.root.roles, s.root.roles);
    assert_eq!(r.root.distance, s.root.distance);
    let mut r = r;
    update(&mut r, &current, &current, &mut rng);
    assert_eq!(r.accepted_distance(), s.accepted_distance());
    let _ = restored(&r, &c);
}
fn reject(s: &DynamicState, c: &ExpectedContext, b: &[u8], h: &[u8; 1024], before_groups: bool) {
    let mut m = AdmissionMetrics::default();
    let r = decode(
        b,
        h,
        &s.package,
        &s.tables,
        c,
        &LoadPolicy::small(s.config),
        &s.root.current.assignment.values[1..s.package.shape().instance_len],
        &mut m,
    );
    assert!(r.is_err());
    if before_groups {
        assert_eq!(m.group_checks, 0);
        assert_eq!(m.field_checks, 0);
        assert_eq!(m.decoded_allocations, 0);
    }
}
#[test]
fn authenticated_framing_counts_roles_reserved_cursor_adversaries_predecode() {
    let (mut s, c, z) = state(8, 4);
    let target = fixture::assignment(5, 4, 3);
    update(
        &mut s,
        &z,
        &target,
        &mut rand::rngs::StdRng::seed_from_u64(5),
    );
    let (b, h) = encoded(&s, &c);
    let sec = sections(&b).unwrap();
    for pos in [
        8,
        10,
        12,
        14,
        24,
        32,
        34,
        36,
        48,
        56,
        sec[0].offset + 6,
        sec[0].offset + 128,
        sec[0].offset + 136,
        sec[0].offset + 138,
        sec[0].offset + 145,
        sec[0].offset + 168,
        sec[1].offset + 112,
        sec[2].offset + 6,
        sec[2].offset + 176,
        sec[8].offset + 5,
        sec[8].offset + 40,
        sec[8].offset + 72,
    ] {
        let mut bad = b.to_vec();
        bad[pos] ^= 0x80;
        reject(&s, &c, &bad, &h, true);
    }
    for pos in [
        16,
        40,
        sec[0].offset + 160,
        sec[8].offset + 8,
        sec[8].offset + 16,
        sec[8].offset + 48,
        sec[8].offset + 56,
    ] {
        let mut bad = b.to_vec();
        put64(&mut bad, pos, u64::MAX);
        reject(&s, &c, &bad, &h, true);
    }
    for end in [0, 31, 319, 320, b.len() - 1] {
        reject(&s, &c, &b[..end], &h, true);
    }
    let mut extra = b.to_vec();
    extra.push(0);
    reject(&s, &c, &extra, &h, true);
}
#[test]
fn invalid_canonical_fields_points_raw_rows_and_alias_maps_rejected() {
    let (s, c, _) = state(8, 4);
    let (b, h) = encoded(&s, &c);
    let sec = sections(&b).unwrap();
    for pos in [
        sec[3].offset,
        sec[4].offset,
        sec[4].offset + 64,
        sec[4].offset + 160,
        sec[6].offset,
        sec[7].offset,
    ] {
        let mut bad = b.to_vec();
        bad[pos..pos + 32].fill(255);
        reject(&s, &c, &bad, &h, false);
    }
    let mut bad = b.to_vec();
    write_value(&Fr::from(2u64), &mut bad[sec[3].offset..sec[3].offset + 32]).unwrap();
    reject(&s, &c, &bad, &h, false);
    let mut bad = b.to_vec();
    write_value(&Fr::from(7u64), &mut bad[sec[7].offset..sec[7].offset + 32]).unwrap();
    reject(&s, &c, &bad, &h, false);
    let mut bad = b.to_vec();
    write_value(&G1::zero(), &mut bad[sec[4].offset..sec[4].offset + 32]).unwrap();
    reject(&s, &c, &bad, &h, false);
}
#[test]
fn same_n_reduction_descriptor_material_and_all_five_public_negatives() {
    let mut original: Option<(
        PublicPackage,
        ReconstructionMaterial,
        ExpectedContext,
        Zeroizing<Vec<u8>>,
        [u8; 1024],
    )> = None;
    for reduction in [
        crate::Reduction::Original,
        crate::Reduction::InstanceAugmentedA,
    ] {
        let p = fixture::five_public_package(reduction);
        let z = fixture::five_public_assignment(3, 2);
        let (s, c) = make(p, &z, 12, descriptor(reduction, true));
        let (b, h) = encoded(&s, &c);
        let _ = restored(&s, &c);
        for i in 0..5 {
            let mut wrong = z[1..6].to_vec();
            wrong[i] += Fr::ONE;
            let mut metrics = AdmissionMetrics::default();
            assert!(decode(
                &b,
                &h,
                &s.package,
                &s.tables,
                &c,
                &LoadPolicy::small(s.config),
                &wrong,
                &mut metrics
            )
            .is_err());
            assert_eq!(metrics.decoded_allocations, 0);
            assert_eq!(metrics.group_checks, 0);
        }
        if let Some((op, ot, oc, ob, oh)) = original.take() {
            assert!(decode(
                &ob,
                &oh,
                &s.package,
                &s.tables,
                &c,
                &LoadPolicy::small(s.config),
                &z[1..6],
                &mut AdmissionMetrics::default()
            )
            .is_err());
            assert!(decode(
                &b,
                &h,
                &op,
                &ot,
                &oc,
                &LoadPolicy::small(s.config),
                &z[1..6],
                &mut AdmissionMetrics::default()
            )
            .is_err());
        } else {
            original = Some((s.package.clone(), s.tables.clone(), c.clone(), b, h));
        }
        let different =
            ReconstructionMaterial::prepare(&s.package, &s.tables.0.uk, Limits::small()).unwrap();
        assert!(c.check(&s.package, &different).is_err());
    }
}
fn rootdir() -> std::path::PathBuf {
    let root =
        std::env::var_os("DYNARK_PRIVATE_ROOT").expect("protected DYNARK_PRIVATE_ROOT required");
    let dir = std::path::PathBuf::from(root).join(format!(
        "t6-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
fn store(dir: &std::path::Path, limits: StoreLimits) -> ProtectedStore {
    let fd = rustix::fs::open(
        dir,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    ProtectedStore::open_private_leaf(fd, &["session"], dir.metadata().unwrap().uid(), limits)
        .unwrap()
}
fn enrolled(c: &ExpectedContext) -> SyntheticProvider {
    let p = SyntheticProvider::new(8, 512).unwrap();
    p.enroll_validated(c, KeyLease::protected([6; 32]), [7; 32], 1, 1)
        .unwrap();
    p
}
#[test]
fn encrypted_files_exact_recovery_resave_and_whole_store_rollback() {
    let (mut s, c, z) = state(8, 4);
    let dir = rootdir();
    let provider = enrolled(&c);
    let mut session =
        CheckpointSession::open(&provider, store(&dir, StoreLimits::small()), c.clone()).unwrap();
    let policy = LoadPolicy::small(s.config);
    let mut rng = rand::rngs::StdRng::seed_from_u64(291);
    let mut m = AdmissionMetrics::default();
    assert!(matches!(
        session
            .save(&mut s, policy, SyncTier::FileAndDirectory, &mut rng, &mut m)
            .unwrap(),
        SaveOutcome::Committed { .. }
    ));
    let old = session.receipt().unwrap();
    let mut loaded = session
        .recover(&s.package, &s.tables, &z[1..2], policy, &mut m)
        .unwrap();
    let target = fixture::assignment(5, 4, 3);
    loaded
        .with_state(&provider, |state| update(state, &z, &target, &mut rng))
        .unwrap();
    assert!(matches!(
        loaded
            .checkpoint(
                &mut session,
                policy,
                SyncTier::FileAndDirectory,
                &mut rng,
                &mut m
            )
            .unwrap(),
        SaveOutcome::Committed { .. }
    ));
    let newer = session.receipt().unwrap();
    assert_eq!(newer.revision, 2);
    let again = session
        .recover(&s.package, &s.tables, &target[1..2], policy, &mut m)
        .unwrap();
    drop(again);
    let filename = |id: [u8; 32]| {
        format!(
            "commit-{}.dync",
            id.iter().map(|x| format!("{x:02x}")).collect::<String>()
        )
    };
    let leaf = dir.join("session");
    fs::copy(
        leaf.join(filename(old.commit_id)),
        leaf.join(filename(newer.commit_id)),
    )
    .unwrap();
    assert!(session
        .recover(&s.package, &s.tables, &target[1..2], policy, &mut m)
        .is_err());
    for entry in fs::read_dir(&leaf).unwrap() {
        let path = entry.unwrap().path();
        assert_eq!(path.metadata().unwrap().mode() & 0o777, 0o600);
    }
    let restarted = SyntheticProvider::new(1, 8).unwrap();
    assert!(restarted.read(c.session_id()).is_err());
    fs::remove_dir_all(dir).unwrap();
}
#[test]
fn unknown_late_cas_resolution_fences_and_invalidation() {
    for fault in [
        SyntheticCasFault::DelayThenUnknown,
        SyntheticCasFault::CommitThenUnknown,
        SyntheticCasFault::MalformedAfterCommit,
    ] {
        let (mut s, c, z) = state(2, 4);
        let dir = rootdir();
        let provider = enrolled(&c);
        let mut session =
            CheckpointSession::open(&provider, store(&dir, StoreLimits::small()), c.clone())
                .unwrap();
        let policy = LoadPolicy::small(s.config);
        let mut rng = rand::rngs::StdRng::seed_from_u64(303);
        let mut m = AdmissionMetrics::default();
        provider.set_next_cas_fault(fault).unwrap();
        assert!(matches!(
            session
                .save(&mut s, policy, SyncTier::FileAndDirectory, &mut rng, &mut m)
                .unwrap(),
            SaveOutcome::Unknown { .. }
        ));
        assert!(matches!(
            session.save(&mut s, policy, SyncTier::FileAndDirectory, &mut rng, &mut m),
            Err(PersistenceError::Fenced)
        ));
        assert!(session
            .recover(&s.package, &s.tables, &z[1..2], policy, &mut m)
            .is_err());
        if fault == SyntheticCasFault::DelayThenUnknown {
            assert!(matches!(
                session.resolve().unwrap(),
                SaveOutcome::Unknown { .. }
            ));
            assert!(provider.read(c.session_id()).unwrap().receipt.is_none());
            provider
                .set_resolution(SyntheticResolution::Execute)
                .unwrap();
        }
        assert!(matches!(
            session.resolve().unwrap(),
            SaveOutcome::Committed { .. }
        ));
        let _ = session
            .recover(&s.package, &s.tables, &z[1..2], policy, &mut m)
            .unwrap();
        provider
            .invalidate(c.session_id(), 1, InvalidationReason::OwnRevocation)
            .unwrap();
        assert!(session
            .recover(&s.package, &s.tables, &z[1..2], policy, &mut m)
            .is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
struct FailingEntropy {
    draw: usize,
    fail: usize,
}
impl CryptoRng for FailingEntropy {}
impl RngCore for FailingEntropy {
    fn next_u32(&mut self) -> u32 {
        0
    }
    fn next_u64(&mut self) -> u64 {
        0
    }
    fn fill_bytes(&mut self, b: &mut [u8]) {
        self.try_fill_bytes(b).unwrap()
    }
    fn try_fill_bytes(&mut self, b: &mut [u8]) -> std::result::Result<(), rand::Error> {
        let n = self.draw;
        self.draw += 1;
        if n == self.fail {
            return Err(rand::Error::new("synthetic entropy failure"));
        }
        b.fill(3);
        Ok(())
    }
}
#[test]
fn entropy_second_draw_duplicates_shared_key_namespace_and_exhaustion() {
    let (mut s, c, _) = state(2, 4);
    let dir = rootdir();
    let provider = enrolled(&c);
    let mut session =
        CheckpointSession::open(&provider, store(&dir, StoreLimits::small()), c.clone()).unwrap();
    let policy = LoadPolicy::small(s.config);
    for fail in [0, 1] {
        assert!(
            matches!(session.save(&mut s,policy,SyncTier::FileAndDirectory,&mut FailingEntropy{draw:0,fail},&mut AdmissionMetrics::default()),Err(PersistenceError::Entropy{draw,..})if draw==fail)
        );
    }
    let expected = provider.read(c.session_id()).unwrap();
    let r = Reservation {
        nonce: [3; 12],
        commit_id: [3; 32],
    };
    assert_eq!(
        provider.reserve(&expected, r).unwrap(),
        ReserveOutcome::Reserved
    );
    assert!(matches!(
        session.save(
            &mut s,
            policy,
            SyncTier::FileAndDirectory,
            &mut FailingEntropy {
                draw: 0,
                fail: usize::MAX
            },
            &mut AdmissionMetrics::default()
        ),
        Err(PersistenceError::ReservationExhausted)
    ));
    let mut other = c.clone();
    other.session = [30; 32];
    other.digest = [31; 32];
    provider
        .enroll_validated(&other, KeyLease::protected([6; 32]), [7; 32], 1, 2)
        .unwrap();
    let snapshot = provider.read(other.session_id()).unwrap();
    assert_eq!(
        provider
            .reserve(
                &snapshot,
                Reservation {
                    nonce: [3; 12],
                    commit_id: [33; 32]
                }
            )
            .unwrap(),
        ReserveOutcome::Duplicate
    );
    let small = SyntheticProvider::new(1, 1).unwrap();
    small
        .enroll_validated(&c, KeyLease::protected([6; 32]), [7; 32], 1, 1)
        .unwrap();
    let ss = small.read(c.session_id()).unwrap();
    small.reserve(&ss, r).unwrap();
    assert!(matches!(
        small.reserve(
            &ss,
            Reservation {
                nonce: [4; 12],
                commit_id: [4; 32]
            }
        ),
        Err(PersistenceError::ReservationExhausted)
    ));
    fs::remove_dir_all(dir).unwrap();
}
#[test]
fn unsupported_media_busy_and_admission_caps_before_decode() {
    let (mut s, c, z) = state(8, 4);
    let (b, h) = encoded(&s, &c);
    for kind in 0..5 {
        let mut policy = LoadPolicy::small(s.config);
        match kind {
            0 => policy.max_group_checks = 0,
            1 => policy.max_private_peak = 0,
            2 => policy.max_field_checks = 0,
            3 => policy.old_live_bytes = usize::MAX,
            _ => policy.max_group_scalar_calls = 0,
        };
        let mut m = AdmissionMetrics::default();
        assert!(decode(&b, &h, &s.package, &s.tables, &c, &policy, &z[1..2], &mut m).is_err());
        assert_eq!(m.decoded_allocations, 0);
    }
    let target = fixture::assignment(5, 4, 3);
    let tr = Transition::new(
        &s.package,
        s.binding().unwrap(),
        2,
        &fixture::delta(&z, &target),
        &target[1..2],
        Limits::small(),
    )
    .unwrap();
    s.begin_update(&tr, &mut rand::rngs::StdRng::seed_from_u64(3))
        .unwrap();
    assert!(encode(
        &s,
        &c,
        &LoadPolicy::small(s.config),
        &mut AdmissionMetrics::default()
    )
    .is_err());
    s.cancel_update().unwrap();
}
#[test]
fn every_storage_boundary_interruption_preserves_exact_old_receipt() {
    use crate::persistence::storage::{inject, FaultPoint};
    let (mut s, c, z) = state(2, 4);
    for point in [
        FaultPoint::Create,
        FaultPoint::Header,
        FaultPoint::Payload,
        FaultPoint::Tag,
        FaultPoint::FileSync,
        FaultPoint::Close,
        FaultPoint::Publish,
        FaultPoint::Reopen,
        FaultPoint::DirectorySync,
        FaultPoint::BeforeCas,
    ] {
        let dir = rootdir();
        let provider = enrolled(&c);
        let mut session =
            CheckpointSession::open(&provider, store(&dir, StoreLimits::small()), c.clone())
                .unwrap();
        let policy = LoadPolicy::small(s.config);
        let mut rng = rand::rngs::StdRng::seed_from_u64(19);
        let mut m = AdmissionMetrics::default();
        session
            .save(&mut s, policy, SyncTier::FileAndDirectory, &mut rng, &mut m)
            .unwrap();
        let old = provider.read(c.session_id()).unwrap();
        inject(Some(point));
        assert!(session
            .save(&mut s, policy, SyncTier::FileAndDirectory, &mut rng, &mut m)
            .is_err());
        inject(None);
        assert_eq!(provider.read(c.session_id()).unwrap(), old);
        let _ = session
            .recover(&s.package, &s.tables, &z[1..2], policy, &mut m)
            .unwrap();
        fs::remove_dir_all(dir).unwrap();
    }
}
#[test]
fn unknown_cancel_and_invalidation_prevent_late_cas_resurrection() {
    for invalidation in [
        None,
        Some(InvalidationReason::OwnRevocation),
        Some(InvalidationReason::IssuerDisabled),
        Some(InvalidationReason::ActionComplete),
    ] {
        let (mut s, c, _) = state(2, 4);
        let dir = rootdir();
        let provider = enrolled(&c);
        let mut session =
            CheckpointSession::open(&provider, store(&dir, StoreLimits::small()), c.clone())
                .unwrap();
        provider
            .set_next_cas_fault(SyntheticCasFault::DelayThenUnknown)
            .unwrap();
        let mut rng = rand::rngs::StdRng::seed_from_u64(551);
        let policy = LoadPolicy::small(s.config);
        session
            .save(
                &mut s,
                policy,
                SyncTier::FileAndDirectory,
                &mut rng,
                &mut AdmissionMetrics::default(),
            )
            .unwrap();
        if let Some(reason) = invalidation {
            provider.invalidate(c.session_id(), 1, reason).unwrap();
            provider
                .set_resolution(SyntheticResolution::Execute)
                .unwrap();
            assert!(matches!(
                session.resolve().unwrap(),
                SaveOutcome::Conflict(_)
            ));
            assert_eq!(
                provider.read(c.session_id()).unwrap().status,
                SessionStatus::Invalidated
            );
        } else {
            provider
                .set_resolution(SyntheticResolution::Cancel)
                .unwrap();
            assert_eq!(session.resolve().unwrap(), SaveOutcome::KnownNotAttempted);
            assert!(provider.read(c.session_id()).unwrap().receipt.is_none());
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
#[test]
fn nofollow_noreplace_fifo_and_hard_store_budget() {
    let (mut s, c, z) = state(2, 4);
    let dir = rootdir();
    let provider = enrolled(&c);
    let mut session =
        CheckpointSession::open(&provider, store(&dir, StoreLimits::small()), c.clone()).unwrap();
    let policy = LoadPolicy::small(s.config);
    let mut rng = rand::rngs::StdRng::seed_from_u64(104);
    let mut m = AdmissionMetrics::default();
    session
        .save(&mut s, policy, SyncTier::FileAndDirectory, &mut rng, &mut m)
        .unwrap();
    let receipt = session.receipt().unwrap();
    let filename = format!(
        "commit-{}.dync",
        receipt
            .commit_id
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<String>()
    );
    let leaf = dir.join("session");
    let path = leaf.join(&filename);
    let original = fs::read(&path).unwrap();
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink("/dev/null", &path).unwrap();
    assert!(session
        .recover(&s.package, &s.tables, &z[1..2], policy, &mut m)
        .is_err());
    fs::remove_file(&path).unwrap();
    assert!(std::process::Command::new("/usr/bin/mkfifo")
        .args(["-m", "600"])
        .arg(&path)
        .status()
        .unwrap()
        .success());
    assert!(session
        .recover(&s.package, &s.tables, &z[1..2], policy, &mut m)
        .is_err());
    fs::remove_file(&path).unwrap();
    fs::write(&path, &original).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let st = store(&dir, StoreLimits::small());
    let (payload, h) = encoded(&s, &c);
    let tag =
        crate::persistence::wire::seal(&KeyLease::protected([6; 32]), &h, &mut payload.to_vec())
            .unwrap();
    let mut hash = Sha256::new();
    hash.update(h);
    hash.update(&payload);
    hash.update(tag);
    assert!(st
        .publish(
            receipt.commit_id,
            &h,
            &payload,
            &tag,
            hash.finalize().into(),
            policy.max_record_bytes
        )
        .is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
    let bounded = store(
        &dir,
        StoreLimits {
            max_bytes: original.len() as u64,
            max_entries: 512,
        },
    );
    assert!(bounded
        .publish(
            [66; 32],
            &h,
            &payload,
            &tag,
            [0; 32],
            policy.max_record_bytes
        )
        .is_err());
    fs::remove_dir_all(dir).unwrap();
}
#[test]
fn exact_header_caps_identities_aead_tamper_and_subgroup_quarantine() {
    let (s, c, z) = state(8, 4);
    let (b, h) = encoded(&s, &c);
    let mut snapshot = snap(&c);
    let (_, mut receipt) = crate::persistence::wire::header(
        &s,
        &c,
        &snapshot,
        Reservation {
            nonce: [8; 12],
            commit_id: [9; 32],
        },
        b.len(),
        SyncTier::FileAndDirectory,
    )
    .unwrap();
    let key = KeyLease::protected([6; 32]);
    let mut ciphertext = b.to_vec();
    let tag = crate::persistence::wire::seal(&key, &h, &mut ciphertext).unwrap();
    let mut hash = Sha256::new();
    hash.update(h);
    hash.update(&ciphertext);
    hash.update(tag);
    receipt.envelope_digest = hash.finalize().into();
    snapshot.receipt = Some(receipt);
    snapshot.enrollment_authorized = false;
    let policy = LoadPolicy::small(s.config);
    assert_eq!(
        crate::persistence::wire::preflight(&h, (b.len() + 1040) as u64, &c, &snapshot, &policy)
            .unwrap(),
        b.len()
    );
    for offset in [
        0, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 33, 36, 37, 38, 39, 40, 48, 56, 64,
        72, 104, 112, 120, 144, 152, 172, 176, 208, 240, 272, 304, 336, 368, 400, 432, 464, 496,
        528, 560, 592, 624, 656, 688, 720, 752, 784, 816, 848, 880, 912, 920, 1023,
    ] {
        let mut bad = h;
        bad[offset] ^= 0x80;
        assert!(
            crate::persistence::wire::preflight(
                &bad,
                (b.len() + 1040) as u64,
                &c,
                &snapshot,
                &policy
            )
            .is_err(),
            "header offset {offset}"
        );
    }
    for offset in [80, 88, 96] {
        let mut bad = h;
        put64(&mut bad, offset, u64::MAX);
        assert!(
            crate::persistence::wire::preflight(&bad, u64::MAX, &c, &snapshot, &policy).is_err()
        );
    }
    for target in 0..3 {
        let mut bad = ciphertext.clone();
        let mut head = h;
        let mut badtag = tag;
        match target {
            0 => head[160] ^= 1,
            1 => bad[0] ^= 1,
            _ => badtag[0] ^= 1,
        };
        assert!(crate::persistence::wire::open(&key, &head, &mut bad, &badtag).is_err());
    }
    let sec = sections(&b).unwrap();
    let mut malformed = b.to_vec();
    let mut invalid = None;
    for i in 1..100 {
        let x = ark_bn254::Fq2::new(ark_bn254::Fq::from(i as u64), ark_bn254::Fq::from(3u64));
        if let Some(point) = G2Affine::get_point_from_x_unchecked(x, false) {
            if !point.is_in_correct_subgroup_assuming_on_curve() {
                invalid = Some(point);
                break;
            }
        }
    }
    let point = invalid.expect("on-curve non-subgroup synthetic fixture");
    write_value(
        &point,
        &mut malformed[sec[4].offset + 64..sec[4].offset + 128],
    )
    .unwrap();
    let sealed_tag = crate::persistence::wire::seal(&key, &h, &mut malformed).unwrap();
    crate::persistence::wire::open(&key, &h, &mut malformed, &sealed_tag).unwrap();
    let mut m = AdmissionMetrics::default();
    assert!(decode(
        &malformed,
        &h,
        &s.package,
        &s.tables,
        &c,
        &policy,
        &z[1..2],
        &mut m
    )
    .is_err());
    assert_eq!(m.group_checks, 3);
}
#[test]
fn concurrent_exact_base_cas_has_one_winner_and_lease_blocks_invalidation() {
    let (s, c, _) = state(2, 4);
    let provider = enrolled(&c);
    let old = provider.read(c.session_id()).unwrap();
    let mut proposals = Vec::new();
    for i in 0..2 {
        let r = Reservation {
            nonce: [10 + i; 12],
            commit_id: [10 + i; 32],
        };
        provider.reserve(&old, r).unwrap();
        let b = encoded(&s, &c).0;
        let (_, mut receipt) =
            crate::persistence::wire::header(&s, &c, &old, r, b.len(), SyncTier::FileAndDirectory)
                .unwrap();
        receipt.envelope_digest = [40 + i; 32];
        proposals.push((r, receipt));
    }
    let barrier = std::sync::Barrier::new(2);
    let results = std::thread::scope(|scope| {
        let a = scope.spawn(|| {
            barrier.wait();
            provider.compare_and_set(&old, proposals[0].0, proposals[0].1)
        });
        let b = scope.spawn(|| {
            barrier.wait();
            provider.compare_and_set(&old, proposals[1].0, proposals[1].1)
        });
        [a.join().unwrap(), b.join().unwrap()]
    });
    assert_eq!(
        results
            .iter()
            .filter(|x| matches!(x, CasOutcome::Committed(_)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|x| matches!(x, CasOutcome::Conflict(_)))
            .count(),
        1
    );
    let current = provider.read(c.session_id()).unwrap();
    let lease = provider.use_lease(&current).unwrap();
    let barrier = std::sync::Barrier::new(2);
    let done = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|scope| {
        let child = scope.spawn(|| {
            barrier.wait();
            provider
                .invalidate(c.session_id(), 1, InvalidationReason::ActionComplete)
                .unwrap();
            done.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        barrier.wait();
        assert!(!done.load(std::sync::atomic::Ordering::SeqCst));
        drop(lease);
        child.join().unwrap();
    });
    assert!(done.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        provider.read(c.session_id()).unwrap().status,
        SessionStatus::Invalidated
    );
}
#[test]
fn save_scope_half_root_map_budget_and_validation_counts_regressions() {
    let (mut s, c, z) = state(8, 4);
    let policy = LoadPolicy::small(s.config);
    let binding = s.root.current.binding;
    s.root.current.binding.action = [90; 32];
    assert!(encode(&s, &c, &policy, &mut AdmissionMetrics::default()).is_err());
    s.root.current.binding = binding;
    let builder = s.root.builder.take();
    assert!(encode(&s, &c, &policy, &mut AdmissionMetrics::default()).is_err());
    s.root.builder = builder;
    let target = fixture::assignment(5, 4, 3);
    update(
        &mut s,
        &z,
        &target,
        &mut rand::rngs::StdRng::seed_from_u64(410),
    );
    let (b, h) = encoded(&s, &c);
    let mut limited = policy;
    limited.max_map_scan = 0;
    let mut m = AdmissionMetrics::default();
    assert!(decode(
        &b,
        &h,
        &s.package,
        &s.tables,
        &c,
        &limited,
        &target[1..2],
        &mut m
    )
    .is_err());
    assert_eq!(m.map_scan_entries, 0);
    assert_eq!(m.decoded_allocations, 0);
    let mut m = AdmissionMetrics::default();
    let _r = decode(
        &b,
        &h,
        &s.package,
        &s.tables,
        &c,
        &policy,
        &target[1..2],
        &mut m,
    )
    .unwrap();
    let mat = &s.package.0.matrices;
    assert_eq!(
        m.row_entries,
        3 * (mat.a_num_non_zero + mat.b_num_non_zero + mat.c_num_non_zero)
            + mat.a_num_non_zero
            + mat.b_num_non_zero
    );
}

// A transport adapter can return a typed but incoherent conflict after the
// underlying provider accepted dispatch. Neither that reply nor rereading the
// old receipt is definitive operation resolution.
struct MalformedConflictProvider<'a> {
    inner: &'a SyntheticProvider,
    mutation: usize,
    reply: std::cell::Cell<Option<ProviderSnapshot>>,
}
impl TrustedProvider for MalformedConflictProvider<'_> {
    type UseLease<'a>
        = <SyntheticProvider as TrustedProvider>::UseLease<'a>
    where
        Self: 'a;
    fn read(&self, s: [u8; 32]) -> crate::persistence::Result<ProviderSnapshot> {
        self.inner.read(s)
    }
    fn key(&self, s: &ProviderSnapshot) -> crate::persistence::Result<KeyLease> {
        self.inner.key(s)
    }
    fn reserve(
        &self,
        s: &ProviderSnapshot,
        r: Reservation,
    ) -> crate::persistence::Result<ReserveOutcome> {
        self.inner.reserve(s, r)
    }
    fn compare_and_set(
        &self,
        old: &ProviderSnapshot,
        r: Reservation,
        proposed: Receipt,
    ) -> CasOutcome {
        assert_eq!(
            self.inner.compare_and_set(old, r, proposed),
            CasOutcome::Unknown
        );
        let mut s = *old;
        match self.mutation {
            0 => {} // unchanged old snapshot
            1 => s.context[0] ^= 1,
            2 => s.session[0] ^= 1,
            3 => s.session_epoch = 0,
            4 => s.key_id = [0; 32],
            5 => s.key_epoch = 0,
            6 => s.unresolved = Some(proposed.commit_id),
            7 => {
                s.receipt = Some(proposed);
                s.enrollment_authorized = false;
            }
            8 => {
                let mut receipt = proposed;
                receipt.commit_id[0] ^= 1;
                receipt.session[0] ^= 1;
                s.receipt = Some(receipt);
                s.enrollment_authorized = false;
            }
            9 => {
                s.status = SessionStatus::Invalidated;
                s.enrollment_authorized = false;
            }
            10 => s.capability = ProviderCapability::Durable,
            11..=14 => {
                let mut receipt = proposed;
                receipt.commit_id[0] ^= 1;
                match self.mutation {
                    11 => receipt.key_id[0] ^= 1,
                    12 => receipt.revision = 0,
                    13 => receipt.base_id = [0; 32],
                    14 => receipt.session_epoch = 0,
                    _ => unreachable!(),
                }
                s.receipt = Some(receipt);
                s.enrollment_authorized = false;
            }
            _ => unreachable!(),
        }
        self.reply.set(Some(s));
        CasOutcome::Conflict(s)
    }
    fn resolve(&self, s: [u8; 32], op: [u8; 32]) -> CasOutcome {
        match self.reply.get() {
            Some(reply) => CasOutcome::Conflict(reply),
            None => self.inner.resolve(s, op),
        }
    }
    fn use_lease<'a>(
        &'a self,
        s: &ProviderSnapshot,
    ) -> crate::persistence::Result<Self::UseLease<'a>> {
        self.inner.use_lease(s)
    }
    fn invalidate(
        &self,
        s: [u8; 32],
        epoch: u64,
        reason: InvalidationReason,
    ) -> crate::persistence::Result<()> {
        self.inner.invalidate(s, epoch, reason)
    }
}
#[test]
fn malformed_conflict_after_dispatch_retains_unknown_fence_and_files() {
    for mutation in 0..15 {
        let (mut s, c, z) = state(2, 4);
        let dir = rootdir();
        let provider = enrolled(&c);
        let mut rng = rand::rngs::StdRng::seed_from_u64(781 + mutation as u64);
        let policy = LoadPolicy::small(s.config);
        let mut first =
            CheckpointSession::open(&provider, store(&dir, StoreLimits::small()), c.clone())
                .unwrap();
        let old = match first
            .save(
                &mut s,
                policy,
                SyncTier::FileAndDirectory,
                &mut rng,
                &mut AdmissionMetrics::default(),
            )
            .unwrap()
        {
            SaveOutcome::Committed { receipt, .. } => receipt,
            _ => panic!("initial checkpoint"),
        };
        drop(first);
        let adapter = MalformedConflictProvider {
            inner: &provider,
            mutation,
            reply: std::cell::Cell::new(None),
        };
        let mut session =
            CheckpointSession::open(&adapter, store(&dir, StoreLimits::small()), c.clone())
                .unwrap();
        provider
            .set_next_cas_fault(SyntheticCasFault::DelayThenUnknown)
            .unwrap();
        let proposed = match session
            .save(
                &mut s,
                policy,
                SyncTier::FileAndDirectory,
                &mut rng,
                &mut AdmissionMetrics::default(),
            )
            .unwrap()
        {
            SaveOutcome::Unknown { proposed } => proposed,
            _ => panic!("malformed conflict was treated as definitive"),
        };
        assert_eq!(provider.read(c.session_id()).unwrap().receipt, Some(old));
        assert!(
            matches!(session.resolve().unwrap(), SaveOutcome::Unknown { proposed: p } if p == proposed)
        );
        assert!(matches!(
            session.save(
                &mut s,
                policy,
                SyncTier::FileAndDirectory,
                &mut rng,
                &mut AdmissionMetrics::default()
            ),
            Err(PersistenceError::Fenced)
        ));
        assert!(matches!(
            session.recover(
                &s.package,
                &s.tables,
                &z[1..2],
                policy,
                &mut AdmissionMetrics::default()
            ),
            Err(PersistenceError::Fenced)
        ));
        // Lock file plus both retained old and new publications.
        assert_eq!(fs::read_dir(dir.join("session")).unwrap().count(), 3);
        adapter.reply.set(None);
        provider
            .set_resolution(SyntheticResolution::Execute)
            .unwrap();
        assert!(
            matches!(session.resolve().unwrap(), SaveOutcome::Committed { receipt, .. } if receipt == proposed)
        );
        session
            .recover(
                &s.package,
                &s.tables,
                &z[1..2],
                policy,
                &mut AdmissionMetrics::default(),
            )
            .unwrap();
        fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn physical_key_aliases_cannot_reset_nonce_namespace() {
    let (_, c, _) = state(2, 4);
    let provider = SyntheticProvider::new(8, 32).unwrap();
    provider
        .enroll_validated(&c, KeyLease::protected([6; 32]), [7; 32], 1, 1)
        .unwrap();
    let first = provider.read(c.session_id()).unwrap();
    let nonce = [9; 12];
    provider
        .reserve(
            &first,
            Reservation {
                nonce,
                commit_id: [10; 32],
            },
        )
        .unwrap();
    for (j, (id, epoch)) in [([8; 32], 1), ([7; 32], 2), ([8; 32], 2)]
        .into_iter()
        .enumerate()
    {
        let mut other = c.clone();
        other.session = [40 + j as u8; 32];
        other.digest = [50 + j as u8; 32];
        assert!(matches!(
            provider.enroll_validated(&other, KeyLease::protected([6; 32]), id, epoch, 2),
            Err(PersistenceError::Trust("physical key namespace alias"))
        ));
        assert!(provider.read(other.session_id()).is_err());
        // A failed alias enrollment consumes neither session capacity nor trust.
        provider
            .enroll_validated(&other, KeyLease::protected([6; 32]), [7; 32], 1, 2)
            .unwrap();
        let shared = provider.read(other.session_id()).unwrap();
        assert_eq!(
            provider
                .reserve(
                    &shared,
                    Reservation {
                        nonce,
                        commit_id: [60 + j as u8; 32]
                    }
                )
                .unwrap(),
            ReserveOutcome::Duplicate
        );
    }
    let mut rotated = c.clone();
    rotated.session = [70; 32];
    rotated.digest = [71; 32];
    provider
        .enroll_validated(&rotated, KeyLease::protected([11; 32]), [7; 32], 2, 3)
        .unwrap();
    let new_key = provider.read(rotated.session_id()).unwrap();
    assert_eq!(
        provider
            .reserve(
                &new_key,
                Reservation {
                    nonce,
                    commit_id: [72; 32]
                }
            )
            .unwrap(),
        ReserveOutcome::Reserved
    );
}

#[test]
fn save_work_caps_precede_payload_allocation_normalization_and_validation() {
    let (mut s, c, z) = state(8, 4);
    let target = fixture::assignment(5, 4, 3);
    update(
        &mut s,
        &z,
        &target,
        &mut rand::rngs::StdRng::seed_from_u64(901),
    );
    let (_, objects, k) = map_ids(&s);
    let distinct: usize = objects.into_iter().take(k).map(|x| x.unwrap().len()).sum();
    assert!(distinct > 0);
    let dir = rootdir();
    let provider = enrolled(&c);
    let old = provider.read(c.session_id()).unwrap();
    let mut session =
        CheckpointSession::open(&provider, store(&dir, StoreLimits::small()), c.clone()).unwrap();
    for cap in 0..5 {
        let mut policy = LoadPolicy::small(s.config);
        match cap {
            0 => policy.max_group_checks = 0,
            1 => policy.max_field_checks = 0,
            2 => policy.max_map_scan = 0,
            3 => policy.max_group_scalar_calls = 0,
            4 => policy.max_matrix_entries = 0,
            _ => unreachable!(),
        }
        let mut metrics = AdmissionMetrics::default();
        let mut entropy = FailingEntropy { draw: 0, fail: 0 };
        assert!(matches!(
            session.save(
                &mut s,
                policy,
                SyncTier::FileAndDirectory,
                &mut entropy,
                &mut metrics
            ),
            Err(PersistenceError::Bound(_))
        ));
        assert_eq!(metrics.buffer_capacity, 0);
        assert_eq!(metrics.canonical_bytes, 0);
        assert_eq!(metrics.decoded_allocations, 0);
        assert_eq!(metrics.group_checks, 0);
        assert_eq!(metrics.field_checks, 0);
        assert_eq!(metrics.group_scalar_calls, 0);
        assert_eq!(metrics.row_entries, 0);
        assert_eq!(entropy.draw, 0);
        assert_eq!(provider.read(c.session_id()).unwrap(), old);
    }
    // All six logical references alias one object. Logical work, independently
    // of distinct storage, still rejects before canonicalizing this state.
    let map = Arc::new(vec![(0, Fr::ONE)]);
    s.root.active.as_mut().unwrap().maps = [map.clone(), map.clone()];
    let builder = s.root.builder.as_mut().unwrap();
    builder.overlays = [map.clone(), map.clone()];
    builder.pending = [map.clone(), map];
    let mut policy = LoadPolicy::small(s.config);
    policy.max_map_scan = 5;
    let mut metrics = AdmissionMetrics::default();
    assert!(matches!(
        encode(&s, &c, &policy, &mut metrics),
        Err(PersistenceError::Bound("distinct/logical map scan"))
    ));
    assert_eq!(metrics.buffer_capacity, 0);
    assert_eq!(metrics.canonical_bytes, 0);
    assert_eq!(metrics.group_scalar_calls, 0);
    assert_eq!(metrics.row_entries, 0);
    fs::remove_dir_all(dir).unwrap();
}
