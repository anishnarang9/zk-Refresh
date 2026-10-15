# V2 finalized effect host rebuild

The patched v2 queue host runner rebuilt under the October 15, 2026 bounded
offline gate. Four host tests passed; the two tests that require a ROOT-pinned
validator were ignored. The bounded build exited 0 in 5.776 seconds with no
cap stop or residual owned process. Sampled peak owned-tree RSS was
356,155,392 bytes and sampled target growth was 19,597,139 bytes.

The rebuilt 19,014,056-byte runner is
`harness/target/debug/build/zk-fresh-benchmark/3147fa1ba77ddb84/out/queue_v2-3147fa1ba77ddb84`,
SHA-256 `7564930d60b0e82c9084d17e7bccbca40fa622e0d10de560e3c460527cb6f7aa`.
The external receipt is
`results/dynark/part5/v2-finalized-reconciliation-host-bounded-001.json`,
SHA-256 `488e1bacce17bd45327e46caf69e3ccfb0bd4030552df029d38c44f031f9c557`.

This rebuild includes exact finalized request/queue byte verification and the
consumed-only restart report. It has not yet restarted the saved validator
ledger or observed the historical application effect at finalized commitment.
