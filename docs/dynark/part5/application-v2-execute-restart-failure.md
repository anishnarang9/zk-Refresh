# Local v2 Execute restart gate: first attempt

The first Execute phase against the prepared persistent local validator ledger
failed before source observation, proof verification or any protected queue
transaction. The restarted validator reported the expected genesis and loaded
program, but the runner's first `getAccountInfo` for the prepared request
returned no account. The runner raised `program state missing` in
`harness/src/solana.rs` before it read the queue/config/issuer accounts.

The exact Execute proposal is
`harness/tests/queue_v2_execute_proposal.json`, SHA-256
`e8b89aa9a35394342dee2b9c409f91d4aef76c5aba4fde6bef701df3cc18ad71`.
It pins the previously prepared genesis, actual v2 ELF, finalized request plan
and exact 416-byte Full proof wire. The preparation report had reached finalized
slot 8. The supervisor's readiness probe checked genesis, then started the
runner shortly after validator startup. The restart log reported no snapshot
package; the account visibility state at later slots was not measured in this
attempt.

The external bounded receipt
`results/dynark/part5/v2-execute-bounded-001.json` records exit 1 in 0.577
seconds, no cap stop, 267,157,504 bytes sampled peak workload RSS, 3,293 bytes
positive storage growth and zero residual owned processes. The supervisor
reaped both direct children and set `ledger_reuse_requires_review=true`. There
is no completed Execute effect to reconcile from this attempt. The persistent
ledger and protected proof artifacts are preserved for a read-only restart
diagnostic before any retry or source change.
