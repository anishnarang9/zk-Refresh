use super::*;
use ark_ec::PrimeGroup;
use ark_ff::Zero;
#[path = "../dynamic_fixture.rs"]
mod fixture;

fn fixture(
    n: usize,
) -> (
    PublicPackage,
    ReconstructionMaterial,
    Pool,
    Builder,
    Roles,
    Journal,
) {
    let p = fixture::package(n, if n == 2 { 5 } else { n + 5 }, false);
    let uk = UpdatingMaterial::prepare(&p, Limits::small()).unwrap();
    let tables = ReconstructionMaterial::prepare(&p, &uk, Limits::small()).unwrap();
    let a = (0..n)
        .map(|i| Fr::from((i * i + 3) as u64))
        .collect::<Vec<_>>();
    let b = (0..n)
        .map(|i| Fr::from((i * 7 + 1) as u64))
        .collect::<Vec<_>>();
    let empty = Arc::new(Vec::new());
    let pool = Pool {
        n,
        g: [
            vec![G1::generator(); n],
            vec![G1::generator(); n],
            vec![G1::zero(); n],
            vec![G1::zero(); n],
        ],
        f: [
            a,
            b,
            vec![Fr::ZERO; n],
            vec![Fr::ZERO; n],
            vec![Fr::ZERO; n],
            vec![Fr::ZERO; n],
        ],
    };
    let builder = Builder {
        generation: 1,
        distance: 0,
        token: [7; 32],
        source: [0, 1],
        overlays: [
            Arc::new(vec![(0, Fr::from(5u64)), (n - 1, Fr::from(2u64))]),
            empty.clone(),
        ],
        pending: [empty.clone(), empty],
        cursor: Cursor::frozen(),
    };
    let journal = Journal::empty(vec![0; (10 * n + 63) / 64]);
    (p, tables, pool, builder, Roles::default(), journal)
}
#[test]
fn exact_arkworks_fft_inverse_projection_and_phase_units_all_odd_even_domains() {
    for n in [2, 8, 16, 32, 64, 128, 256] {
        let (p, t, mut pool, mut b, r, mut j) = fixture(n);
        let w = work(n).unwrap();
        j.reserve(n, w, usize::MAX).unwrap();
        let mut expected_a = pool.f[0].clone();
        for &(i, x) in b.overlays[0].iter() {
            expected_a[i] += x;
        }
        let expected_b = pool.f[1].clone();
        let mut counts = [0usize; 8];
        let mut group_writes_count = 0;
        let mut observe = |event| {
            if let WorkEvent::Action(phase) = event {
                let index = match phase {
                    ReconstructionPhase::Materialize => 0,
                    ReconstructionPhase::Prepare => 1,
                    ReconstructionPhase::Forward => 2,
                    ReconstructionPhase::Pointwise => 3,
                    ReconstructionPhase::Inverse => 4,
                    ReconstructionPhase::Scale => 5,
                    ReconstructionPhase::Integrate => 6,
                    _ => 7,
                };
                counts[index] += 1;
            }
            if let WorkEvent::Write {
                phase: ReconstructionPhase::Prepare,
                ..
            } = event
            {
                group_writes_count += 1;
            }
            false
        };
        // Partition lengths include tiny positive budgets and non-dividing tails.
        let budgets = [1, 3, 17, 2, 63, 9];
        let mut chunk = 0;
        let mut checked_forward = false;
        let mut checked_inverse = false;
        let mut inverse_expected = None;
        let mut inverse_candidate_stages = Vec::new();
        let mut inverse_captures = 0;
        while !b.cursor.ready() {
            let begin = b.cursor.done;
            let end = w.min(begin + budgets[chunk % budgets.len()]);
            chunk += 1;
            while b.cursor.done < end && !b.cursor.ready() {
                step(&mut pool, &mut j, &r, &mut b, &t.0, &mut observe).unwrap();
                if b.cursor.phase == ReconstructionPhase::Pointwise
                    && b.cursor.stream == 0
                    && b.cursor.index == 0
                {
                    let ga = expected_a
                        .iter()
                        .zip(&t.0.uk.0.lagrange)
                        .map(|(a, l)| *l * *a)
                        .collect::<Vec<_>>();
                    let gb = expected_b
                        .iter()
                        .zip(&t.0.uk.0.lagrange)
                        .map(|(a, l)| *l * *a)
                        .collect::<Vec<_>>();
                    assert_eq!(pool.g[2], p.0.domain.fft(&ga));
                    assert_eq!(pool.g[3], p.0.domain.fft(&gb));
                    assert_eq!(pool.f[4], p.0.domain.fft(&expected_a));
                    assert_eq!(pool.f[5], p.0.domain.fft(&expected_b));
                    checked_forward = true;
                }
                if b.cursor.phase == ReconstructionPhase::Inverse
                    && b.cursor.stream == 0
                    && b.cursor.index == 0
                {
                    inverse_candidate_stages.push(b.cursor.stage);
                    if b.cursor.stage == 0 {
                        let gf = p.0.domain.ifft(&pool.g[2]);
                        let ff = p.0.domain.ifft(&pool.f[4]);
                        inverse_expected = Some((gf, ff));
                        inverse_captures += 1;
                    }
                }
                if b.cursor.phase == ReconstructionPhase::Integrate && b.cursor.index == 0 {
                    let (gf, ff) = inverse_expected.take().unwrap();
                    assert_eq!(pool.g[2], gf);
                    assert_eq!(pool.f[4], ff);
                    checked_inverse = true;
                }
            }
            assert!(b.cursor.done > begin || b.cursor.ready());
        }
        drop(observe);
        assert!(checked_forward && checked_inverse);
        assert_eq!(b.cursor.done, w);
        let k = n.ilog2() as usize;
        assert_eq!(inverse_captures, 1);
        assert_eq!(inverse_candidate_stages, (0..=k).collect::<Vec<_>>());
        println!("T5_FFT_CAPTURE n={n} candidate_stages={inverse_candidate_stages:?} actual_capture_count={inverse_captures}");
        assert_eq!(
            counts,
            [
                n,
                n,
                4 * n + 2 * n * k,
                4 * n,
                4 * n + 2 * n * k,
                4 * n,
                n,
                0
            ]
        );
        assert_eq!(group_writes_count, 4 * n);
        assert_eq!(pool.g[2], t.0.uk.project(&p, &expected_a));
        assert_eq!(pool.g[3], t.0.uk.project(&p, &expected_b));
        assert_eq!(j.lengths(), (2 * n, 4 * n));
        assert_eq!(j.group_logs, 2 * n);
        assert_eq!(j.field_logs, 4 * n);
        assert_eq!(b.cursor.group_scalar_calls as usize, 2 * n * k + 10 * n);
        assert_eq!(b.cursor.field_mul_calls as usize, 2 * n * k + 4 * n);
        let old_done = b.cursor.done;
        step(&mut pool, &mut j, &r, &mut b, &t.0, &mut |_| false).unwrap();
        assert_eq!(b.cursor.done, old_done);
        j.finish(&mut pool, false);
        assert!(j.marks.iter().all(|x| *x == 0));
    }
}
#[test]
fn first_touch_physical_preimages_and_typed_cursor_slot_capacity_failures() {
    let (_, t, mut p, mut b, r, mut j) = fixture(8);
    let old = p.g[2][0];
    j.reserve(8, 4, usize::MAX).unwrap();
    j.group(&p, 2, 0).unwrap();
    p.g[2][0] = G1::generator();
    for _ in 0..20 {
        j.group(&p, 2, 0).unwrap();
        p.g[2][0] += G1::generator();
    }
    assert_eq!(j.lengths(), (1, 0));
    assert_eq!(j.group_logs, 1);
    j.finish(&mut p, true);
    assert_eq!(p.g[2][0].x, old.x);
    assert_eq!(p.g[2][0].y, old.y);
    assert_eq!(p.g[2][0].z, old.z);
    let before = j.bytes();
    assert!(matches!(j.reserve(8, usize::MAX, 64), Err(Error::Bound(_))));
    assert_eq!(j.bytes(), before);
    let mut bad = r.clone();
    bad.build_g = [9, 3];
    assert!(matches!(
        step(&mut p, &mut j, &bad, &mut b, &t.0, &mut |_| false),
        Err(Error::Bound(_))
    ));
    b.cursor.phase = ReconstructionPhase::Forward;
    b.cursor.stage = usize::MAX;
    assert!(matches!(
        step(&mut p, &mut j, &r, &mut b, &t.0, &mut |_| false),
        Err(Error::Bound(_))
    ));
    let (_, t, mut p, mut b, r, mut j) = fixture(8);
    assert!(matches!(
        step(&mut p, &mut j, &r, &mut b, &t.0, &mut |_| false),
        Err(Error::Bound("field journal capacity"))
    ));
    j.finish(&mut p, true);
    assert_eq!(size_of::<G1>(), 96);
    assert_eq!(size_of::<Fr>(), 32);
    assert_eq!(size_of::<usize>(), 8);
}

#[test]
fn invalid_scalar_counts_and_overlay_prefix_fail_before_any_write() {
    let (_, t, mut pool, mut b, r, mut j) = fixture(8);
    j.reserve(8, work(8).unwrap(), usize::MAX).unwrap();
    let original_g = pool.g.clone();
    let original_f = pool.f.clone();
    b.cursor.group_scalar_calls = u64::MAX;
    assert!(matches!(
        step(&mut pool, &mut j, &r, &mut b, &t.0, &mut |_| false),
        Err(Error::Bound(_))
    ));
    b.cursor.group_scalar_calls = 0;
    b.cursor.field_mul_calls = u64::MAX;
    assert!(matches!(
        step(&mut pool, &mut j, &r, &mut b, &t.0, &mut |_| false),
        Err(Error::Bound(_))
    ));
    b.cursor.field_mul_calls = 0;
    b.cursor.overlay[0] = 1; // row zero falsely claimed consumed before materializing it
    assert!(matches!(
        step(&mut pool, &mut j, &r, &mut b, &t.0, &mut |_| false),
        Err(Error::Bound(_))
    ));
    b.cursor.overlay[0] = 0;
    b.cursor.index = 1;
    b.cursor.done = 2;
    assert!(matches!(
        step(&mut pool, &mut j, &r, &mut b, &t.0, &mut |_| false),
        Err(Error::Bound(_))
    ));
    assert_eq!(pool.g, original_g);
    assert_eq!(pool.f, original_f);
    assert_eq!(j.lengths(), (0, 0));
}
