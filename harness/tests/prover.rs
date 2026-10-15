use zk_fresh_benchmark::prover::{acquire_prover, parse_peak_rss};
#[test]
fn a_second_job_cannot_run_until_the_first_permit_is_dropped() {
    let first = acquire_prover().unwrap();
    assert!(acquire_prover().is_err());
    drop(first);
    assert!(acquire_prover().is_ok());
}
#[test]
fn peak_memory_units_are_explicit() {
    assert_eq!(
        parse_peak_rss("  123456 maximum resident set size", true).unwrap(),
        123456
    );
    assert_eq!(
        parse_peak_rss("Maximum resident set size (kbytes): 123", false).unwrap(),
        123 * 1024
    );
    assert!(parse_peak_rss("no measurements", true).is_err());
}
