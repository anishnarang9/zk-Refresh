use zk_fresh_benchmark::{
    fixtures::{create_fixtures, field_decimal},
    policy::{accept, Policy},
    registry::Registry,
};
#[test]
fn current_root_and_historical_roots_follow_different_age_rules() {
    let mut registry =
        Registry::new(create_fixtures(2, 1_791_000_000, 1_791_086_400).unwrap()).unwrap();
    registry.snapshot(1000).unwrap();
    let signals = vec![
        field_decimal(&registry.root()),
        field_decimal(&registry.issuer),
        "900".into(),
        "2000".into(),
        "1".into(),
    ];
    assert!(
        accept(&signals, &registry, Policy::Strict, 1301)
            .unwrap()
            .accepted
    );
    assert!(
        accept(&signals, &registry, Policy::Historical, 1300)
            .unwrap()
            .accepted
    );
    assert!(
        !accept(&signals, &registry, Policy::Historical, 1301)
            .unwrap()
            .accepted
    );
    assert!(
        !accept(&signals, &registry, Policy::Strict, 999)
            .unwrap()
            .accepted
    );
    registry.revoke(1, 1010).unwrap();
    assert!(
        !accept(&signals, &registry, Policy::Strict, 1011)
            .unwrap()
            .accepted
    );
    assert!(
        accept(&signals, &registry, Policy::Historical, 1011)
            .unwrap()
            .accepted
    );
    assert_eq!(
        accept(&signals, &registry, Policy::Historical, 2001)
            .unwrap()
            .reason,
        "expired"
    );
    assert_eq!(
        accept(&signals, &registry, Policy::Historical, 899)
            .unwrap()
            .reason,
        "not-yet-valid"
    );
}
