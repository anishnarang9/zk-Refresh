# Confirmed-bank readiness after local validator restart

The first local v2 Execute attempt failed at its first confirmed-commitment
request-account read. A separate bounded diagnostic copied the stopped ledger
byte for byte into a fresh private directory, started the pinned validator on
that copy, and made only `getGenesisHash`, `getSlot` and `getMultipleAccounts`
calls for config, issuer, request and queue. It submitted no application
transaction, did not reset or reload the program, and left the original ledger
unchanged.

At 0.298 seconds after validator spawn, processed and finalized both exposed
slot 8 with all four accounts under the expected owner and with exact prepared
data hashes. The same sample's confirmed view reported slot 0 and no app
accounts. This difference persisted through 1.061 seconds. At 1.316 seconds,
confirmed first exposed all four exact account hashes at context slot 41. By
the final sample at 19.824 seconds, every account matched at all three
commitments. The harness's ordinary `Rpc.account` requests confirmed state, so
checking only `getGenesisHash` before launching Execute was an insufficient
startup condition. The copied ledger demonstrated persistence; the failing
attempt observed the confirmed bank before it caught up.

The monitor recorded exit zero in 20.454 seconds, 569,049,088 bytes sampled
peak workload RSS, 66,056,178 bytes positive storage growth against a
67,108,864-byte cap, no cap stop and no residual owned process. The validator
was reaped after the observation; the source file inventory matched before
and after. Source and exact proposal are in
`harness/tests/queue_v2_replay_diagnostic.py` and
`harness/tests/queue_v2_replay_diagnostic_proposal.json`; scrubbed receipts are
`results/dynark/part5/v2-replay-diagnostic-bounded-001.json` and
`results/dynark/part5/v2-replay-diagnostic-summary-001.json`.

The Execute supervisor must wait for confirmed and finalized account views to
reach at least the finalized preparation slot and match one exact allowed
request/queue state before it starts the transaction runner. It must fail
closed on persistent absence or mismatch within a finite deadline. A consumed
request with the exact one-entry queue is a separate reconciliation state. No
Execute transaction or protected effect was demonstrated by this diagnostic.

## Readiness repair

Commit `7a47fcb` adds a finite, exact account-state barrier before the Execute
runner starts. At both confirmed and finalized commitments, the account query
must cover at least the finalized preparation slot and return identical config,
issuer, request and queue bytes with the expected owner, length and executable
flag. The prepared state's four SHA-256 hashes were independently reconstructed
from the pinned plan and private prepared bytes and matched the diagnostic.

An already consumed request with exactly one queue entry is accepted only as a
reconciliation state. The issuer's immutable enrollment prefix and its complete
source observation/current-root publisher binding are checked against the
pinned synthetic context; the runner receives an explicit reconciliation-only
guard that prevents a new Execute if state changes after the barrier. The
repair's 19 focused Python tests passed, and `rustfmt --check` passed for the
small Rust guard. The host runner must be rebuilt and repinned before a single
reviewed local Execute retry. No retry or application effect is claimed here.
