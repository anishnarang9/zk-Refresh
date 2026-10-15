# V3 Execute fail-closed preflight and proof gate

Execute now reads the execution Clock, checks the actual ordered application
accounts and current state, and verifies the six-public ordinary proof. It
still returns `Unavailable` after a valid proof, with no writes or authorized
queue effect. This preserves a closed application boundary while the exact
request-bound Full proof and atomic effect tests are prepared.

The [focused bounded receipt](../../../results/dynark/part5/v3-execute-negative-green-bounded-001.json)
records both new tests passed, including 15 typed rejection and nonmutation
cases. The first [full regression receipt](../../../results/dynark/part5/v3-execute-negative-regression-bounded-001.json)
found a prior placeholder assertion expecting `Unavailable` without a Clock
stub. Five existing v3 host tests were updated to supply Clock where needed
and assert the new specific failure while preserving unchanged-state checks.
The [final bounded regression](../../../results/dynark/part5/v3-execute-negative-regression-bounded-002.json)
records 111 passed program tests, exit 0, 11.644 seconds, 178,012,160 bytes
sampled peak owned-tree RSS, 6,910,128 bytes sampled storage growth, no cap
and no residual owned process.

This is host rejection behavior. A successful request-bound v3 proof, loaded
ELF, compute/packet limits, queue append and request consumption remain open.
