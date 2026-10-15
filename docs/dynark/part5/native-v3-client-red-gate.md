# Bounded v3 native client: tests-first red gate

The first native-client slice separates the frozen public package record,
private credential import, and already authenticated application-state record.
Constructing a record does not authenticate the issuer, current root, or
ordinary adapter key. The adapter-key admission method remains closed until a
separately measured tagged digest and ROOT-reviewed receipt are pinned.

The exact test `v3::tests::frozen_shared_package_accepts_exact_six_field_shape`
compiled and failed at the intended `Unsupported` scaffold assertion. One
test ran, with 16 filtered out. This is a tests-first result, not a passing
client or proof gate. The bounded command used `cargo test --offline --locked`
with one Cargo job, four Rayon workers and one test thread. It exited 101 in
2.320 seconds; sampled peak workload RSS was 192,528,384 bytes and sampled
positive storage growth was 424,152 bytes. The monitor recorded no limit stop
or residual owned process.

The source scaffold is commit `1c57373`. The public monitor receipt is
`results/dynark/part5/native-v3-slice1-red-bounded-001.json`; private command
logs remain under protected ignored artifacts. Rust importer, package, state
coherence, actual proof, and onchain qualification are still pending.
