use super::*;
#[path = "../dynamic_fixture.rs"]
mod fixture;
use rand::SeedableRng;

fn state(n: usize, v: usize, b: u64) -> (DynamicState, Vec<Fr>) {
    let p = fixture::package(n, v, false);
    let z = fixture::assignment(v, 3, 2);
    let uk = crate::UpdatingMaterial::prepare(&p, Limits::small()).unwrap();
    let tables = ReconstructionMaterial::prepare(&p, &uk, Limits::small()).unwrap();
    let va = p
        .validate_assignment(&fixture::encode(&z), &z[1..2])
        .unwrap();
    let anchor = Anchor::create(
        &p,
        &uk,
        va,
        AnchorBinding::new(&p, [1; 32], [2; 32], 1),
        Limits::small(),
        &mut rand::rngs::OsRng,
    )
    .unwrap();
    let mut c = DynamicConfig::small();
    c.threshold = b;
    let mut prep = DynamicPreparation::adopt(&p, &tables, anchor, c).unwrap();
    prep.advance_preparation(usize::MAX);
    (prep.finish().unwrap(), z)
}
fn transition(s: &DynamicState, z: &[Fr], target: &[Fr], generation: u64) -> Transition {
    Transition::new(
        &s.package,
        s.binding().unwrap(),
        generation,
        &fixture::delta(z, target),
        &target[1..2],
        Limits::small(),
    )
    .unwrap()
}
fn snapshot(s: &DynamicState) -> (Vec<u8>, Vec<u8>) {
    let mut physical = Vec::new();
    if let Some(pool) = &s.pool {
        for slot in &pool.g {
            for g in slot {
                for coordinate in [g.x, g.y, g.z] {
                    coordinate.serialize_compressed(&mut physical).unwrap();
                }
            }
        }
        for slot in &pool.f {
            slot.serialize_compressed(&mut physical).unwrap();
        }
    }
    let mut meta = Vec::new();
    let r = &s.root;
    let mut h = HashWriter(Sha256::new());
    hash_binding(&mut h, &r.current.binding);
    let bindingdigest: [u8; 32] = h.0.finalize().into();
    meta.extend(bindingdigest);
    for x in [r.distance, r.t] {
        meta.extend(x.to_le_bytes());
    }
    for slot in r
        .roles
        .active_g
        .into_iter()
        .chain(r.roles.build_g)
        .chain(r.roles.active_f)
        .chain(r.roles.build_f)
    {
        meta.extend((slot as u64).to_le_bytes());
    }
    r.current
        .assignment
        .values
        .serialize_compressed(&mut meta)
        .unwrap();
    for g in [&r.current.a, &r.current.b1, &r.current.c] {
        for x in [g.x, g.y, g.z] {
            x.serialize_compressed(&mut meta).unwrap();
        }
    }
    for x in [r.current.r, r.current.s] {
        x.serialize_compressed(&mut meta).unwrap();
    }
    for coordinate in [r.current.b2.x, r.current.b2.y, r.current.b2.z] {
        coordinate.serialize_compressed(&mut meta).unwrap();
    }
    if let Some(active) = &r.active {
        meta.extend(active.generation.to_le_bytes());
        meta.extend(active.distance.to_le_bytes());
        meta.extend(active.token);
        for map in &active.maps {
            map.as_ref().serialize_compressed(&mut meta).unwrap();
        }
    }
    if let Some(builder) = &r.builder {
        meta.extend(builder.generation.to_le_bytes());
        meta.extend(builder.distance.to_le_bytes());
        meta.extend(builder.token);
        meta.extend(format!("{:?}", builder.cursor).as_bytes());
        for slot in builder.source {
            meta.extend((slot as u64).to_le_bytes());
        }
        for map in builder.overlays.iter().chain(&builder.pending) {
            map.as_ref().serialize_compressed(&mut meta).unwrap();
        }
    }
    (physical, meta)
}
#[test]
fn cancellation_every_phase_tuple_write_promotion_header_and_complete_physical_restore() {
    let (mut s, z) = state(8, 5, 4);
    let target = fixture::assignment(5, 4, 3);
    let t = transition(&s, &z, &target, 2);
    s.update(&t, &mut rand::rngs::OsRng).unwrap();
    s.advance(5).unwrap();
    let reverse = transition(&s, &target, &z, 3);
    let before = snapshot(&s);
    for phase in [
        ReconstructionPhase::Materialize,
        ReconstructionPhase::Prepare,
        ReconstructionPhase::Forward,
        ReconstructionPhase::Pointwise,
        ReconstructionPhase::Inverse,
        ReconstructionPhase::Scale,
        ReconstructionPhase::Integrate,
    ] {
        for nth in 0..2 {
            s.begin_update(&reverse, &mut rand::rngs::OsRng).unwrap();
            let mut hit = false;
            let mut writes = 0;
            let result = s.advance_update_with(usize::MAX, |event| {
                if let WorkEvent::Write { phase: p, .. } = event {
                    if p == phase {
                        let cancel = writes == nth;
                        writes += 1;
                        if cancel {
                            hit = true;
                            return true;
                        }
                    }
                }
                false
            });
            assert!(hit, "unreached phase {phase:?}, write {nth}");
            assert!(matches!(result, Err(Error::Cancelled)));
            assert_eq!(snapshot(&s), before);
            assert!(s.journal.marks.iter().all(|x| *x == 0));
        }
    }
    for event in [WorkEvent::Promotion, WorkEvent::Header] {
        s.begin_update(&reverse, &mut rand::rngs::OsRng).unwrap();
        let mut hit = false;
        assert!(matches!(
            s.advance_update_with(usize::MAX, |e| {
                if e == event {
                    hit = true;
                    true
                } else {
                    false
                }
            }),
            Err(Error::Cancelled)
        ));
        assert!(hit);
        assert_eq!(snapshot(&s), before);
    }
    s.begin_update(&reverse, &mut rand::rngs::OsRng).unwrap();
    for _ in 0..8 {
        assert!(matches!(
            s.advance_update(7).unwrap(),
            UpdateProgress::Pending { .. }
        ));
    }
    assert!(s.journal.lengths().0 > 0);
    s.cancel_update().unwrap();
    assert_eq!(snapshot(&s), before);
    s.update(&reverse, &mut rand::rngs::OsRng).unwrap();
    assert_eq!(s.ledger().completed_distinct_snapshots, 1);
}
#[test]
fn overshoot_recycling_restores_retired_active_row_and_group_cells_after_promotion() {
    let (mut s, z) = state(8, 5, 5);
    let first = fixture::assignment(5, 4, 3);
    let t = transition(&s, &z, &first, 2);
    s.update(&t, &mut rand::rngs::OsRng).unwrap();
    let second = fixture::assignment(5, 5, 4);
    let t = transition(&s, &first, &second, 3);
    s.update(&t, &mut rand::rngs::OsRng).unwrap();
    assert_eq!(s.cycle_credit(), 3);
    let third = fixture::assignment(5, 6, 2);
    let t = transition(&s, &second, &third, 4);
    let before = snapshot(&s);
    for phase in [
        ReconstructionPhase::Materialize,
        ReconstructionPhase::Prepare,
        ReconstructionPhase::Forward,
    ] {
        s.begin_update(&t, &mut rand::rngs::OsRng).unwrap();
        let mut promoted = false;
        let mut hit = false;
        assert!(matches!(
            s.advance_update_with(usize::MAX, |event| {
                if event == WorkEvent::Promotion {
                    promoted = true;
                }
                if let WorkEvent::Write { phase: p, .. } = event {
                    if promoted && p == phase {
                        hit = true;
                        return true;
                    }
                }
                false
            }),
            Err(Error::Cancelled)
        ));
        assert!(promoted && hit);
        assert_eq!(snapshot(&s), before);
    }
    s.update(&t, &mut rand::rngs::OsRng).unwrap();
    assert_eq!(s.cycle_credit(), 2);
    assert_eq!(s.ledger().completed_distinct_snapshots, 1);
}
#[test]
fn full_raw_checkpoints_and_rebuilt_frozen_projections_match_eager_oracle() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(63882);
    for (n, v) in [
        (2, 5),
        (8, 5),
        (16, 21),
        (32, 5),
        (64, 5),
        (128, 5),
        (256, 5),
    ] {
        let (mut s, mut z) = state(n, v, (v + 3) as u64);
        for i in 0..14 {
            let target = fixture::assignment(v, 2 + (i % 5) as u64, 1 + (i % 3) as u64);
            let t = transition(&s, &z, &target, (i + 2) as u64);
            let out = s.update(&t, &mut rng).unwrap();
            assert!(ordinary::Groth16::<ark_bn254::Bn254>::verify_proof(
                &ordinary::prepare_verifying_key(&s.package.ordinary_verifying_key()),
                &out.proof,
                &target[1..2]
            )
            .unwrap());
            let va = s
                .package
                .validate_assignment(&fixture::encode(&target), &target[1..2])
                .unwrap();
            let fresh = capture(&s.package, va, s.root.current.r, s.root.current.s).unwrap();
            assert_eq!(s.root.current.a, fresh.a_g1);
            assert_eq!(s.root.current.b1, fresh.b_g1);
            assert_eq!(s.root.current.b2, fresh.b_g2);
            assert_eq!(s.root.current.c, fresh.c_g1);
            let pool = s.pool.as_ref().unwrap();
            let uk = &s.tables.0.uk;
            assert_eq!(
                pool.g[s.root.roles.active_g[0]],
                uk.project(&s.package, &pool.f[s.root.roles.active_f[0]])
            );
            assert_eq!(
                pool.g[s.root.roles.active_g[1]],
                uk.project(&s.package, &pool.f[s.root.roles.active_f[1]])
            );
            z = target;
        }
        assert!(s.ledger().completed_distinct_snapshots >= 2);
    }
}
#[test]
fn explicit_preflight_caps_adoption_and_whole_journal_fail_before_any_pool_write() {
    let (mut s, z) = state(8, 5, 4);
    let target = fixture::assignment(5, 4, 3);
    let t = transition(&s, &z, &target, 2);
    s.update(&t, &mut rand::rngs::OsRng).unwrap();
    let reverse = transition(&s, &target, &z, 3);
    let before = snapshot(&s);
    let beforecap = s.journal.bytes();
    s.config.max_journal_bytes = beforecap;
    assert!(matches!(
        s.begin_update(&reverse, &mut rand::rngs::OsRng),
        Err(Error::Bound(_))
    ));
    assert_eq!(snapshot(&s), before);
    assert_eq!(s.journal.bytes(), beforecap);
    s.config.max_journal_bytes = 16 * 1024 * 1024;
    s.config.max_row_support = 0;
    s.config.cap_policy = CapPolicy::FullOnly;
    let out = s.update(&reverse, &mut rand::rngs::OsRng).unwrap();
    assert!(ordinary::Groth16::<ark_bn254::Bn254>::verify_proof(
        &ordinary::prepare_verifying_key(&s.package.ordinary_verifying_key()),
        &out.proof,
        &z[1..2]
    )
    .unwrap());
    assert_eq!(s.status(), DynamicStatus::FullOnly);
    assert!(s.pool.is_none());
    assert!(s.private_structural_bytes().unwrap() < 4096);
}

#[test]
fn residual_caps_refuse_before_target_validation_and_before_any_map_merge() {
    let (mut s, z) = state(128, 133, 200);
    let target = fixture::assignment(133, 4, 3);
    let t = transition(&s, &z, &target, 2);
    let old = snapshot(&s);
    let before = s.ledger();
    let private = s.private_structural_bytes().unwrap();
    let public = s.shared_public_structural_bytes().unwrap();
    s.config.max_private_bytes = private;
    assert!(matches!(
        s.begin_update(&t, &mut rand::rngs::OsRng),
        Err(Error::Bound(_))
    ));
    assert_eq!(
        s.ledger().assignment_copied_elements,
        before.assignment_copied_elements
    );
    assert_eq!(s.ledger().validation_entries, before.validation_entries);
    assert_eq!(snapshot(&s), old);
    s.config.max_private_bytes = 32 * 1024 * 1024;
    s.config.max_global_bytes = private + public;
    assert!(matches!(
        s.begin_update(&t, &mut rand::rngs::OsRng),
        Err(Error::Bound(_))
    ));
    assert_eq!(
        s.ledger().assignment_copied_elements,
        before.assignment_copied_elements
    );
    s.config.max_global_bytes = 64 * 1024 * 1024;
    s.update(&t, &mut rand::rngs::OsRng).unwrap();
    let mut next = target.clone();
    next[5] += Fr::from(1u64);
    let tiny = transition(&s, &target, &next, 3);
    let old = snapshot(&s);
    let before = s.ledger();
    let allowance = validation_allocation_bound(&s.package, &tiny).unwrap();
    s.config.max_private_bytes = s.private_structural_bytes().unwrap() + allowance;
    assert!(matches!(
        s.begin_update(&tiny, &mut rand::rngs::OsRng),
        Err(Error::Bound(_))
    ));
    assert!(s.ledger().assignment_copied_elements > before.assignment_copied_elements);
    assert_eq!(s.ledger().map_merge_elements, before.map_merge_elements);
    assert_eq!(snapshot(&s), old);
}

#[test]
fn lifetime_telemetry_saturates_without_changing_scheduler_or_rollback() {
    let (mut s, z) = state(8, 5, 4);
    let target = fixture::assignment(5, 4, 3);
    let t = transition(&s, &z, &target, 2);
    s.update(&t, &mut rand::rngs::OsRng).unwrap();
    let binding = s.binding().unwrap();
    let distance = s.accepted_distance();
    let credit = s.cycle_credit();
    s.ledger.attempted_reconstruction_actions = u64::MAX;
    s.ledger.committed_reconstruction_actions = u64::MAX;
    s.ledger.attempted_group_scalar_calls = u64::MAX;
    s.ledger.attempted_field_mul_calls = u64::MAX;
    s.ledger.committed_group_scalar_calls = u64::MAX;
    s.ledger.mark_clear_visits = u64::MAX;
    s.journal.group_logs = usize::MAX;
    s.journal.field_logs = usize::MAX;
    s.advance(12).unwrap();
    assert!(s.ledger.saturated && s.journal.saturated);
    assert_eq!(s.ledger.attempted_reconstruction_actions, u64::MAX);
    assert_eq!(s.binding().unwrap(), binding);
    assert_eq!(s.accepted_distance(), distance);
    assert_eq!(s.cycle_credit(), credit);
    let before = snapshot(&s);
    let reverse = transition(&s, &target, &z, 3);
    s.ledger.rollback_cells = u64::MAX;
    s.begin_update(&reverse, &mut rand::rngs::OsRng).unwrap();
    s.advance_update(8).unwrap();
    s.cancel_update().unwrap();
    assert_eq!(snapshot(&s), before);
    assert_eq!(s.ledger.rollback_cells, u64::MAX);
}

#[test]
fn five_public_inputs_original_and_augmented_dynamic_checkpoints() {
    for reduction in [
        crate::Reduction::Original,
        crate::Reduction::InstanceAugmentedA,
    ] {
        let p = fixture::five_public_package(reduction);
        assert_eq!(p.shape().domain_size, 16);
        let uk = crate::UpdatingMaterial::prepare(&p, Limits::small()).unwrap();
        let tables = ReconstructionMaterial::prepare(&p, &uk, Limits::small()).unwrap();
        let mut z = fixture::five_public_assignment(3, 2);
        let va = p
            .validate_assignment(&fixture::encode(&z), &z[1..6])
            .unwrap();
        let anchor = Anchor::create(
            &p,
            &uk,
            va,
            AnchorBinding::new(&p, [1; 32], [2; 32], 1),
            Limits::small(),
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        let mut config = DynamicConfig::small();
        config.threshold = 12;
        let mut prep = DynamicPreparation::adopt(&p, &tables, anchor, config).unwrap();
        prep.advance_preparation(usize::MAX);
        let mut s = prep.finish().unwrap();
        for i in 0..12 {
            let target = fixture::five_public_assignment(4 + i, 3 + i);
            let t = Transition::new(
                &p,
                s.binding().unwrap(),
                2 + i,
                &fixture::delta(&z, &target),
                &target[1..6],
                Limits::small(),
            )
            .unwrap();
            let before = snapshot(&s);
            for j in 0..5 {
                let mut wrong = target[1..6].to_vec();
                wrong[j] += Fr::from(1u64);
                let bad = Transition::new(
                    &p,
                    s.binding().unwrap(),
                    2 + i,
                    &fixture::delta(&z, &target),
                    &wrong,
                    Limits::small(),
                )
                .unwrap();
                assert!(s.begin_update(&bad, &mut rand::rngs::OsRng).is_err());
                assert_eq!(snapshot(&s), before);
            }
            let out = s.update(&t, &mut rand::rngs::OsRng).unwrap();
            assert_eq!(out.public_values, target[1..6]);
            assert!(ordinary::Groth16::<ark_bn254::Bn254>::verify_proof(
                &ordinary::prepare_verifying_key(&p.ordinary_verifying_key()),
                &out.proof,
                &target[1..6]
            )
            .unwrap());
            let va = p
                .validate_assignment(&fixture::encode(&target), &target[1..6])
                .unwrap();
            let raw = capture(&p, va, s.root.current.r, s.root.current.s).unwrap();
            assert_eq!(
                (
                    s.root.current.a,
                    s.root.current.b1,
                    s.root.current.b2,
                    s.root.current.c
                ),
                (raw.a_g1, raw.b_g1, raw.b_g2, raw.c_g1)
            );
            let active = s.root.active.as_ref().unwrap();
            let active_z = s.pool.as_ref().unwrap();
            assert_eq!(
                active_z.g[s.root.roles.active_g[0]],
                uk.project(&p, &active_z.f[s.root.roles.active_f[0]])
            );
            assert_eq!(
                active_z.g[s.root.roles.active_g[1]],
                uk.project(&p, &active_z.f[s.root.roles.active_f[1]])
            );
            assert!(active.distance <= s.root.distance);
            z = target;
        }
        assert!(s.ledger.completed_distinct_snapshots >= 2);
        println!("five_public reduction={reduction:?} transitions=12 distinct_snapshots={} private_bytes={}",s.ledger.completed_distinct_snapshots,s.private_structural_bytes().unwrap());
    }
}

#[test]
fn engine_normalized_delta_cap_rejects_broad_transition_before_validation() {
    let (mut s, z) = state(8, 5, 8);
    let target = fixture::assignment(5, 4, 3);
    let t = transition(&s, &z, &target, 2);
    assert_eq!(t.normalized_count(), 4);
    s.config.operation.max_delta_entries = 1;
    let before = snapshot(&s);
    let ledger = s.ledger();
    assert!(matches!(
        s.begin_update(&t, &mut rand::rngs::OsRng),
        Err(Error::Bound(_))
    ));
    assert_eq!(s.ledger(), ledger);
    assert_eq!(snapshot(&s), before);
}
