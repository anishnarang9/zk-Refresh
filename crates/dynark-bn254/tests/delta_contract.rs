mod support;
use ark_bn254::Fr;
use ark_ff::{Field, Zero};
use dynark_bn254::{AnchorBinding, Error, Limits, Reduction, Transition};

#[test]
fn duplicates_cancel_and_counts_distinguish_touched_from_nonzero_rows() {
    let p = support::package(5, Reduction::Original);
    let z = support::assignment(5, 3, 2);
    let base = p
        .validate_assignment(&support::bytes(&z), &z[1..2])
        .unwrap();
    let binding = AnchorBinding::new(&p, [1; 32], [2; 32], 7);
    let delta = support::bytes(&[Fr::ONE, -Fr::ONE, Fr::from(2), -Fr::from(2), Fr::ONE]);
    let raw = vec![
        (2, delta[0]),
        (3, delta[1]),
        (4, delta[2]),
        (4, delta[3]),
        (4, delta[4]),
    ];
    // A row 1 cancels after both changed columns have been visited.
    let mut target = z.clone();
    target[2] += Fr::ONE;
    target[3] -= Fr::ONE;
    target[1] = target[2] * target[2];
    target[4] = (target[2] + target[3]) * target[3];
    let mut raw = raw;
    raw.pop();
    raw.push((1, support::bytes(&[target[1] - z[1]])[0]));
    raw.push((4, support::bytes(&[target[4] - z[4]])[0]));
    let t = Transition::new(&p, binding, 8, &raw, &target[1..2], Limits::small()).unwrap();
    let prepared = t.validate_target(&p, &base).unwrap();
    assert_eq!(t.normalized_count(), 4);
    let s = prepared.stats();
    assert_eq!(s.a.touched_entries, 4);
    assert_eq!(s.a.touched_rows, 3);
    assert_eq!(s.a.nonzero_rows, 2);
    assert!(prepared.row_deltas().a.iter().all(|(_, x)| !x.is_zero()));
}
#[test]
fn malformed_coordinates_fields_public_and_generations_fail() {
    let p = support::package(5, Reduction::Original);
    let b = AnchorBinding::new(&p, [1; 32], [2; 32], 7);
    let one = support::bytes(&[Fr::ONE])[0];
    assert!(matches!(
        Transition::new(
            &p,
            b,
            8,
            &[(0, one), (0, support::bytes(&[-Fr::ONE])[0])],
            &[Fr::from(9)],
            Limits::small()
        ),
        Err(Error::ConstantMutation)
    ));
    assert!(matches!(
        Transition::new(&p, b, 8, &[(5, one)], &[Fr::from(9)], Limits::small()),
        Err(Error::DeltaCoordinate)
    ));
    assert!(matches!(
        Transition::new(&p, b, 8, &[(2, [255; 32])], &[Fr::from(9)], Limits::small()),
        Err(Error::NonCanonicalField { .. })
    ));
    assert!(matches!(
        Transition::new(&p, b, 7, &[], &[Fr::from(9)], Limits::small()),
        Err(Error::Generation)
    ));
    let z = support::assignment(5, 3, 2);
    let base = p
        .validate_assignment(&support::bytes(&z), &z[1..2])
        .unwrap();
    let t = Transition::new(&p, b, 8, &[], &[Fr::from(10)], Limits::small()).unwrap();
    assert!(matches!(
        t.validate_target(&p, &base),
        Err(Error::PublicStatement)
    ));
    let t = Transition::new(&p, b, 8, &[(2, one)], &[Fr::from(9)], Limits::small()).unwrap();
    assert!(matches!(
        t.validate_target(&p, &base),
        Err(Error::Unsatisfied { .. })
    ));
}

#[test]
fn canonical_r1cs_wtns_and_malicious_counts_are_bounded() {
    use dynark_bn254::import::{read_r1cs, read_wtns, ImportLimits};
    let dir = support::tempdir();
    let rpath = dir.join("circuit.r1cs");
    let wpath = dir.join("assignment.wtns");
    let m = support::relation(5);
    let rb = support::r1cs_bytes(&m);
    std::fs::write(&rpath, &rb).unwrap();
    let imported = read_r1cs(&rpath, ImportLimits::small()).unwrap();
    assert_eq!(imported.a, m.a);
    assert_eq!(imported.b, m.b);
    assert_eq!(imported.c, m.c);
    let p = support::package(5, Reduction::Original);
    let z = support::assignment(5, 3, 2);
    let wb = support::wtns_bytes(&z);
    std::fs::write(&wpath, &wb).unwrap();
    assert!(read_wtns(&wpath, &p, &z[1..2], ImportLimits::small()).is_ok());
    let mut cap = ImportLimits::small();
    cap.max_file_bytes = wb.len() as u64 - 1;
    assert!(matches!(
        read_wtns(&wpath, &p, &z[1..2], cap),
        Err(Error::Bound(_))
    ));
    cap = ImportLimits::small();
    cap.max_section_bytes = 39;
    assert!(matches!(
        read_wtns(&wpath, &p, &z[1..2], cap),
        Err(Error::Bound(_))
    ));
    cap = ImportLimits::small();
    cap.max_sections = 1;
    assert!(matches!(
        read_wtns(&wpath, &p, &z[1..2], cap),
        Err(Error::Bound(_))
    ));
    let mut invalid = wb.clone();
    invalid[80..112].fill(255);
    std::fs::write(&wpath, &invalid).unwrap();
    assert!(matches!(
        read_wtns(&wpath, &p, &z[1..2], ImportLimits::small()),
        Err(Error::NonCanonicalField { .. })
    ));
    let mut invalid = wb.clone();
    invalid.push(0);
    std::fs::write(&wpath, &invalid).unwrap();
    assert!(matches!(
        read_wtns(&wpath, &p, &z[1..2], ImportLimits::small()),
        Err(Error::Import(_))
    ));
    let mut invalid = rb.clone();
    invalid[100..104].copy_from_slice(&u32::MAX.to_le_bytes());
    std::fs::write(&rpath, &invalid).unwrap();
    assert!(matches!(
        read_r1cs(&rpath, ImportLimits::small()),
        Err(Error::Bound(_))
    ));
    let mut invalid = rb.clone();
    invalid[104..108].copy_from_slice(&5u32.to_le_bytes());
    std::fs::write(&rpath, &invalid).unwrap();
    assert!(matches!(
        read_r1cs(&rpath, ImportLimits::small()),
        Err(Error::Matrix(_))
    ));
    let mut invalid = rb;
    invalid[108..140].fill(255);
    std::fs::write(&rpath, &invalid).unwrap();
    assert!(matches!(
        read_r1cs(&rpath, ImportLimits::small()),
        Err(Error::NonCanonicalField { .. })
    ));
    std::fs::remove_dir_all(dir).unwrap();
}
