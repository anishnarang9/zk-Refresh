# Credential dynamic runtime003: functional gate accepted

ROOT accepted the completed source007 credential-scale sequence on October 14, 2026. All ten supplied-witness transitions completed, with real reconstruction promotions at targets05 and09, authenticated save/drop/recovery at target05, and continued updates through target10. This closes the required credential-scale T5 reconstruction and T6 recovery exercise. It does not close T7 economics or establish durable trusted-provider restart.

The [scrubbed aggregate](../../../../results/dynark/phase-2/credential/dynamic-runtime-003-scrubbed-aggregate-acceptance-001.json) has SHA256 `b9e8b7ee5072f90997744eb220affc6934a5dbd111e9c24bf7b3b2368026115f`. Source007 is `90acae63c4bd8a09df5c744ecc494e425eccc71e9397a7b334bb5d9fd6c70fad`; the frozen executable is `c1ce520ac6aed4a922af3da249933bbcd1727e9e7fc5834588276d134cc28b5a`. Product arithmetic remains the accepted `54523c1` implementation with isolated harness instrumentation. [Preconditions, schedule and unchanged limits](credential-rebind-oct14.md).

ROOT executed the frozen workload, inspected its final output and host completion, independently summed all 26,686 maintenance records, checked matching primary/duplicate reports (`c4b2a5627536a3715a0dc8d13e2e96d8b3467a17a5d92510394a9dcb7e9042e4`), confirmed all recorded owned processes absent and matched all 93 external hashes. The worker's separate postflight matched sizes, owners, modes and regular-file identities. CORE authenticated all 36 fixture files before and after the child, with no mismatch. Independent review also reconciled raw chunks, target totals, phase accounting and checkpoint intervals, finding no functional acceptance blocker. Earlier failed or interrupted runs remain preserved.

## Correctness and paid work

The 154 ordinary Groth16 checks comprise 22 decoded/output positives, 110 altered-public negatives, 20 cross-generation wrong-public negatives and two internal save/recover positives. Final current/active/frozen generations are 10/5/9. The final reconstruction remains deliberately partial at Forward cursor `[0,471858,15,1204,1194]`, after 10,957,619 actions in that reconstruction; the test does not claim a third completed promotion.

The exact maintenance ledger contains 53,060,793 cross pairs, 218,575,669 actions, 114,766,642 G1 scalar calls and 92,274,688 field multiplications. There were 53,372 process-clock reads. Instrumented maintenance totaled 1,528.299896501 monotonic seconds and 4,501.536053 all-thread process CPU seconds. The largest observed maintenance-call pause was 1.080713833 seconds. These are one forced schedule's observations, not a client latency distribution or an optimization comparison.

Checkpoint save took 18.885418625 monotonic seconds, old-state wipe/drop 0.123396542, and recovery 31.405834708; the full instrumented block took 50.433405500 seconds. The old engine was absent during recovery. Canonical equality covered 11,133,149 installed values and the same number of placement checks, with 1,068,968,704 observer hash bytes. The synthetic trusted provider survived within the same process. No whole-store rollback protection, external provider restart or independent full-domain quotient oracle follows from this result.

Cold strict package import cost 102.972636625 monotonic seconds; fresh anchor capture/projection/commit cost 785.677091333. Ten full-proof comparators cost 24.824679292 seconds in total. Setup, instrumentation, validation, promotion, persistence and cleanup remain paid. Witness generation was excluded because this run consumed already generated fixtures.

## Resource and timing boundaries

The child exited zero with no limit stop or runner error and no remaining/unknown owned processes. Sampled peak workload-tree RSS was 1,646,690,304 bytes, output growth 365,821,936 bytes, over 11,050 samples. The fixed four-worker, 4-GiB RSS, 4-GiB growth and 14,400-second runtime caps were unchanged. Structural capacity accounting and the monitor's planning reserve are separate from sampled RSS.

Elapsed clocks disagree: the runner reports 2,510.551905625 monotonic seconds and Rust reports 2,508.366431209, whereas `/usr/bin/time` reports 4,300.99 real seconds and UTC endpoints span 4,301.174892 seconds. The approximately 1,790-second discrepancy has no established cause. Preserve all originals; do not infer sleep, repair timestamps, call 41.8 minutes calendar elapsed time, or use this run for a clean latency/speedup claim. Functional verification and exact work accounting are accepted with this timing limitation unresolved.

The remaining evaluation must select defaults using complete paid session workloads. Real X.509 qualification, network catch-up, combined witness/proof refresh, original `.zkey` compatibility and Solana execution remain separate gates.
