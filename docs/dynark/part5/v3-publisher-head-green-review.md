# V3 publisher-head host gate

Opcode 13 now accepts the exact revision-1 179-byte bind wire and commits a
280-byte `DYNHEAD3` account at the per-config, per-issuer, per-publisher PDA.
The publisher-signed transaction advances an exact onchain predecessor
sequence/digest and binds root/version, source head and both eligibility
epochs while updating the issuer record. It accepts an empty prefunded
System-owned PDA, rejects malformed or wrong-stream existing heads, and
requires an active source with `now < expires_at`. The detached envelope is
still verified offchain; the program stores its opaque raw digest.

The focused bounded suite passed all 13 publisher-head host tests in 3.077
seconds. The [focused receipt](../../../results/dynark/part5/v3-publisher-head-green-bounded-001.json)
records exit 0, no cap or runner error, no residual owned process, 211,664,896
bytes sampled peak owned-tree RSS and 8,246,017 bytes sampled logical target
growth. A fresh [regression receipt](../../../results/dynark/part5/v3-publisher-head-regression-bounded-001.json)
records 61 passing v3 program host tests across state, runtime, status,
staging and publisher-head targets, in 3.809 seconds with 205,668,352 bytes
sampled peak RSS. Both used one Cargo job, four Rayon workers and one test
thread. Private stdout/stderr remain under the corresponding
`artifacts/dynark/part5/v3-publisher-head-*-monitor-001` directories.

The host CPI model is not loaded SBF evidence. Actual allocation, prefunded
transfer/allocate/assign, borrow lifetime and transaction rollback require a
loaded-ELF local-validator check. V3 Execute still returns `Unavailable` and
does not yet require this head or verify a proof or append to the queue.
