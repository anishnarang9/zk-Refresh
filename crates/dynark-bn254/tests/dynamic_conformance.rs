mod dynamic_fixture;
use ark_bn254::Fr;
use dynamic_fixture as f;
use dynark_bn254::{
    Anchor, AnchorBinding, CapPolicy, DynamicConfig, DynamicPreparation, DynamicState,
    DynamicStatus, Error, Limits, ReconstructionMaterial, Transition, UpdateProgress,
    UpdatingMaterial,
};
use rand::{CryptoRng, RngCore, SeedableRng};

fn state(p: &dynark_bn254::PublicPackage, z: &[Fr], b: u64, policy: CapPolicy) -> DynamicState {
    let uk = UpdatingMaterial::prepare(p, Limits::small()).unwrap();
    let tables = ReconstructionMaterial::prepare(p, &uk, Limits::small()).unwrap();
    assert!(tables.shares_storage_with(&tables.clone()));
    let va = p
        .validate_assignment(&f::encode(z), &z[1..p.shape().instance_len])
        .unwrap();
    let a = Anchor::create(
        p,
        &uk,
        va,
        AnchorBinding::new(p, [1; 32], [2; 32], 1),
        Limits::small(),
        &mut rand::rngs::OsRng,
    )
    .unwrap();
    let mut config = DynamicConfig::small();
    config.threshold = b;
    config.cap_policy = policy;
    let mut prep = DynamicPreparation::adopt(p, &tables, a, config).unwrap();
    let before = prep.advance_preparation(0);
    assert_eq!(before.completed, 0);
    let mut total = 0;
    loop {
        let progress = prep.advance_preparation(3);
        assert!(progress.completed > total);
        total = progress.completed;
        if progress.ready {
            break;
        }
    }
    prep.finish().unwrap()
}
fn verify(p: &dynark_bn254::PublicPackage, out: &dynark_bn254::ProofStatement, z: &[Fr]) {
    assert_eq!(out.public_values, z[1..p.shape().instance_len]);
    assert!(ordinary::Groth16::<ark_bn254::Bn254>::verify_proof(
        &ordinary::prepare_verifying_key(&p.ordinary_verifying_key()),
        &out.proof,
        &z[1..p.shape().instance_len]
    )
    .unwrap());
}
#[test]
fn thousand_valid_transitions_multiple_distinct_reconstructions_and_independent_verification() {
    let mut emitted = 0;
    let mut rng = rand::rngs::StdRng::seed_from_u64(8147);
    for (n, v, dense, count) in [(2, 5, false, 360), (8, 5, false, 360), (16, 21, true, 280)] {
        let p = f::package(n, v, dense);
        let mut z = f::assignment(v, 3, 2);
        let mut s = state(&p, &z, (v + 3) as u64, CapPolicy::Reject);
        let prepared = ordinary::prepare_verifying_key(&p.ordinary_verifying_key());
        for i in 0..count {
            let target = if i % 11 == 0 {
                z.clone()
            } else {
                f::assignment(v, 2 + (i % 7) as u64, 1 + (i % 5) as u64)
            };
            let raw = f::delta(&z, &target);
            let old_distance = s.accepted_distance();
            let old_credit = s.cycle_credit();
            let old_work = s.reconstruction_completed().unwrap();
            let t = Transition::new(
                &p,
                s.binding().unwrap(),
                (i + 2) as u64,
                &raw,
                &target[1..2],
                Limits::small(),
            )
            .unwrap();
            let out = s.update(&t, &mut rng).unwrap();
            assert!(ordinary::Groth16::<ark_bn254::Bn254>::verify_proof(
                &prepared,
                &out.proof,
                &target[1..2]
            )
            .unwrap());
            assert_eq!(s.accepted_distance(), old_distance + raw.len() as u64);
            if raw.is_empty() {
                assert_eq!(s.cycle_credit(), old_credit);
                assert_eq!(s.reconstruction_completed().unwrap(), old_work);
            }
            if i % 31 == 0 {
                assert_eq!(s.advance(0).unwrap(), 0);
            }
            if i % 79 == 0 {
                let full = dynark_bn254::prove(
                    &p,
                    &p.validate_assignment(&f::encode(&target), &target[1..2])
                        .unwrap(),
                    out.generation,
                    &mut rng,
                )
                .unwrap();
                verify(&p, &full, &target);
            }
            z = target;
            emitted += 1;
        }
        assert!(s.ledger().completed_distinct_snapshots >= 2);
        assert!(s.private_structural_bytes().unwrap() < DynamicConfig::small().max_private_bytes);
        println!("dynamic_aggregate N={n} v={v} dense={dense} transitions={count} private_bytes={} shared_public_bytes={} ledger={:?}",s.private_structural_bytes().unwrap(),s.shared_public_structural_bytes().unwrap(),s.ledger());
    }
    assert_eq!(emitted, 1000);
}
#[test]
fn exact_threshold_overshoot_reverse_zero_and_whole_call_cancellation() {
    let p = f::package(8, 5, false);
    let z = f::assignment(5, 3, 2);
    let target = f::assignment(5, 4, 3);
    let raw = f::delta(&z, &target);
    let mut s = state(&p, &z, raw.len() as u64, CapPolicy::Reject);
    let initial = s.binding().unwrap();
    let t = Transition::new(&p, initial, 2, &raw, &target[1..2], Limits::small()).unwrap();
    verify(&p, &s.update(&t, &mut rand::rngs::OsRng).unwrap(), &target);
    assert_eq!(s.cycle_credit(), 0);
    assert_eq!(s.reconstruction_completed().unwrap(), 1);
    assert_eq!(s.ledger().completed_distinct_snapshots, 0);
    let reverse = Transition::new(
        &p,
        s.binding().unwrap(),
        3,
        &f::delta(&target, &z),
        &z[1..2],
        Limits::small(),
    )
    .unwrap();
    let before = s.binding().unwrap();
    s.begin_update(&reverse, &mut rand::rngs::OsRng).unwrap();
    assert!(matches!(
        s.advance_update(0).unwrap(),
        UpdateProgress::Pending { .. }
    ));
    assert!(matches!(s.binding(), Err(Error::Busy)));
    assert!(matches!(
        s.advance_update(7).unwrap(),
        UpdateProgress::Pending { .. }
    ));
    s.cancel_update().unwrap();
    assert_eq!(s.binding().unwrap(), before);
    verify(&p, &s.update(&reverse, &mut rand::rngs::OsRng).unwrap(), &z);
    assert_eq!(s.accepted_distance(), 2 * raw.len() as u64);
    assert_eq!(s.ledger().completed_distinct_snapshots, 1);
    let noop =
        Transition::new(&p, s.binding().unwrap(), 4, &[], &z[1..2], Limits::small()).unwrap();
    let work = s.reconstruction_completed().unwrap();
    verify(&p, &s.update(&noop, &mut rand::rngs::OsRng).unwrap(), &z);
    assert_eq!(s.reconstruction_completed().unwrap(), work);
}
#[test]
fn oversized_full_only_action_invalidation_and_replay_rejection() {
    let p = f::package(8, 5, false);
    let z = f::assignment(5, 3, 2);
    let target = f::assignment(5, 4, 3);
    let mut s = state(&p, &z, 1, CapPolicy::FullOnly);
    let old = s.binding().unwrap();
    let t = Transition::new(
        &p,
        old,
        2,
        &f::delta(&z, &target),
        &target[1..2],
        Limits::small(),
    )
    .unwrap();
    verify(&p, &s.update(&t, &mut rand::rngs::OsRng).unwrap(), &target);
    assert_eq!(s.status(), DynamicStatus::FullOnly);
    assert!(matches!(s.phase(), Err(Error::NotReady)));
    assert_eq!(s.accepted_distance(), t.normalized_count() as u64);
    assert!(matches!(
        s.update(&t, &mut rand::rngs::OsRng),
        Err(Error::AnchorBinding)
    ));
    let distance = s.accepted_distance();
    let va = p.validate_assignment(&f::encode(&z), &z[1..2]).unwrap();
    verify(
        &p,
        &s.full_for_binding(va, [7; 32], [8; 32], 3, &mut rand::rngs::OsRng)
            .unwrap(),
        &z,
    );
    assert_eq!(s.binding().unwrap().action, [8; 32]);
    assert_eq!(s.accepted_distance(), distance);
    assert_eq!(s.cycle_credit(), 0);
}
struct EntropyFailure {
    draw: usize,
    fail: usize,
}
impl CryptoRng for EntropyFailure {}
impl RngCore for EntropyFailure {
    fn next_u32(&mut self) -> u32 {
        panic!("infallible RNG")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("infallible RNG")
    }
    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("infallible RNG")
    }
    fn try_fill_bytes(&mut self, b: &mut [u8]) -> Result<(), rand::Error> {
        let draw = self.draw;
        self.draw += 1;
        if draw == self.fail {
            return Err(rand::Error::new(std::io::Error::other("synthetic entropy")));
        }
        b.fill(0);
        b[0] = 3;
        Ok(())
    }
}
#[test]
fn both_entropy_failures_preserve_committed_generation_and_progress() {
    let p = f::package(8, 5, false);
    let z = f::assignment(5, 3, 2);
    let target = f::assignment(5, 4, 3);
    let mut s = state(&p, &z, 8, CapPolicy::Reject);
    let t = Transition::new(
        &p,
        s.binding().unwrap(),
        2,
        &f::delta(&z, &target),
        &target[1..2],
        Limits::small(),
    )
    .unwrap();
    for fail in 0..2 {
        let binding = s.binding().unwrap();
        let work = s.reconstruction_completed().unwrap();
        assert!(matches!(
            s.begin_update(&t, &mut EntropyFailure { draw: 0, fail }),
            Err(Error::Entropy { .. })
        ));
        assert_eq!(s.binding().unwrap(), binding);
        assert_eq!(s.reconstruction_completed().unwrap(), work);
        assert_eq!(s.status(), DynamicStatus::DynamicReady);
    }
}

#[test]
fn full_only_from_explicit_binding_remains_full_proving_even_with_reject_cap_policy() {
    let p = f::package(8, 5, false);
    let z = f::assignment(5, 3, 2);
    let target = f::assignment(5, 4, 3);
    let mut s = state(&p, &z, 8, CapPolicy::Reject);
    let va = p.validate_assignment(&f::encode(&z), &z[1..2]).unwrap();
    verify(
        &p,
        &s.full_for_binding(va, [4; 32], [5; 32], 2, &mut rand::rngs::OsRng)
            .unwrap(),
        &z,
    );
    assert_eq!(s.status(), DynamicStatus::FullOnly);
    let t = Transition::new(
        &p,
        s.binding().unwrap(),
        3,
        &f::delta(&z, &target),
        &target[1..2],
        Limits::small(),
    )
    .unwrap();
    verify(&p, &s.update(&t, &mut rand::rngs::OsRng).unwrap(), &target);
    assert_eq!(s.status(), DynamicStatus::FullOnly);
    assert_eq!(s.binding().unwrap().action, [5; 32]);
    assert_eq!(s.accepted_distance(), t.normalized_count() as u64);
}
