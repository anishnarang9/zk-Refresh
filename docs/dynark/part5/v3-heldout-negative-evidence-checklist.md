# Post-Training-012 loaded negative evidence checklist

This checklist covers the two acceptance-plan cases that still need loaded-validator evidence: an issuer status whose signed expiry has passed, and an Execute attempt against a full request queue. The acceptance plan explicitly names stale status and queue capacity at lines 44–50 of `v3-heldout-acceptance-plan.md`.

## Gate before loaded execution and heldout freeze

- Wait until the Training-012 matrix has a final sequence receipt and its registered report gate, including the clock-drift audit, economics, reconciliation, and total summary, has completed. Training-011 stopped at its storage limit and has no final sequence. A running driver, a partial receipt stream, or an interrupted matrix is not the gate.
- Keep every Training-012-pinned file and artifact unchanged through that gate. Source-only work on separate heldout files may proceed, but do not build or run a competing proof, validator, or loaded-negative job. Freeze tooling, the accepted runner-002 binary, and the active campaign identities must not be overwritten.
- After the gate, work from the accepted Training-012 identities. Add a new heldout tooling freeze/cohort and a new isolated Rust runner artifact; do not overwrite runner-002 or the canonical Training-009 proof binary. The new tooling freeze must pin the additions below and continue to pin the same accepted application ELF hash.
- First run the new Python and Rust source-level tests. Then run one bounded loaded-validator stale-status pilot. Queue capacity has a much larger setup cost; qualify its setup and finite owner limit before scheduling it. No result is claimed by this checklist.

## Expected program behavior

The application defines `STATUS_MAX_AGE = 300` and `QUEUE_CAPACITY = 64`. The Execute preflight returns `AppError::Capacity` (708) when the queue already has 64 entries, before issuer-status and proof checks. Issuer freshness returns `AppError::Status` (705) when `now >= expires_at` or the observation is too old. For the clean negative, still provide a complete, valid Full wire and arrange all the other preconditions to pass, so the intended condition is the only failing condition.

Both transactions should be finalized with the Execute instruction at index 1, as in the existing disabled-config supervisor. Expected RPC error JSON is exactly `{"InstructionError":[1,{"Custom":705}]}` for expired status and `{"InstructionError":[1,{"Custom":708}]}` for full queue. The application-level config, issuer, head, request, and queue account bytes must match their immediate pre-submit snapshots after either rejection. The slot and fee payer may advance because a failed transaction is still submitted; report this as no application effect, not as no ledger activity.

The local unit tests already check the two error ordinals and atomic account snapshots (`program/tests/application_v3_execute.rs:255–355,681–692`). They are useful source-level regression checks but do not replace a loaded-validator run.

## Stale-status negative: one per heldout A case

Add `harness/tests/queue_v3_local_expired_status_negative.py`, its Rust entry point/module in `harness/tests/queue_v3.rs` and `harness/src/solana/queue_v3.rs`, and focused Python/Rust tests. Follow the ownership, clone, bounded-process, pinned-input, ordered-transaction, five-account snapshot, cleanup, and report-validation structure in `queue_v3_local_disabled_config_negative.py`.

Setup and run order:

1. Start from that case's independently cloned A-stage ledger and verify its initial account bytes are identical to the finalized stage. Pin the accepted program ID, genesis, loaded ELF, stage report/plan, source receipt, Full proof receipt, Full wire, clone receipt, and new supervisor/config hashes.
2. On the clone, publish an active authenticated issuer observation with `observed_at` equal to the observed current clock and `expires_at` shortly afterward (for example, 15–30 seconds later, while `expires_at - observed_at <= 300`). Bind the current publisher head. Capture the finalized transactions and issuer/head bytes that establish the active, correctly bound status.
3. Wait with a finite deadline until finalized RPC block time is at or beyond `expires_at`, while confirming `now - observed_at <= 300`. If the clock does not reach the window before the owner deadline, fail closed and rerun from a fresh clone; do not mutate issuer bytes directly or claim expiry from wall-clock sleep alone.
4. Snapshot the exact five ordered application accounts. Submit the case's valid Full Execute once. Require finalized custom error 705 at instruction index 1. Fetch the five accounts again at finalized commitment and require byte-for-byte equality with the pre-submit snapshots.
5. Emit a versioned report and status with exact loaded identity, observed/bound/expiry/current times, transaction signature/slot/error/finalization, snapshot paths and hashes, `application_effect: false`, and cleanup status. Keep keys, DER, witnesses, proof bytes, and raw transaction wire out of JSON; refer to already-pinned proof/wire artifacts only by their protected path and hash.

Limit each owner to one validator and one Rust runner, with finite wall-time, RSS, storage-growth, and clock-wait bounds. Use a separate clone and output/control directory for every variant. Record the total wall time as an explicit journal step so the acceptance cost report can verify it.

## Full-queue negative: one shared cohort-level loaded fixture

Register this once against the heldout cohort and accepted loaded ELF. Queue capacity is application state independent of DER layout, so a single shared loaded negative is the smallest useful evidence unit; eight repeated 64-entry fills would multiply work without testing a different capacity rule. If the acceptance owner instead requires one per certificate, make that cardinality explicit in the manifest/verifier and budget the extra fills before execution.

Add `harness/tests/queue_v3_local_queue_capacity_negative.py`, its Rust entry point/module, and focused tests. Use a dedicated fresh ledger/clone and output root, separate from every accepted Full/Anchor branch and the stale-status clone.

Setup and run order:

1. Keep the same accepted program ID, genesis, ELF, current config/issuer/head identities, and a still-fresh active status. Finalize 65 distinct requests with valid action bindings and sufficient deadlines. Each of the first 64 requests needs its own valid proof because the action hash binds the nonce; do not reuse a proof across different actions.
2. Submit valid Full Execute transactions for the first 64 requests, one at a time, waiting for finalization and checking after each that exactly that request became consumed and exactly its request address was appended once. Before proceeding, independently decode the final queue and require exactly 64 distinct entries, all corresponding to those successful fill transactions.
3. Keep the 65th request finalized, unconsumed, and absent from the queue. Prepare its complete valid Full proof/wire and independently verify the wire against that request's action. Confirm fresh status, a current head, a live request deadline, correct account owners/order/privileges, and the same loaded program/genesis/ELF.
4. Snapshot config, issuer, head, request-65, and queue bytes at finalized commitment. Submit Execute once. Require finalized custom error 708 at instruction index 1. Fetch those five accounts again and require exact byte equality. Also require the decoded queue still has 64 entries and does not contain request-65.
5. Write a report that accounts for all 64 successful fill signatures/slots and links each fill to its request address and before/after request/queue hashes. The sidecar may store bounded summaries and hashes; it must not embed proof bytes, wires, witnesses, keys, or credential data. Pin the 65th request's proof/wire receipt by path and hash.

There is no zero-cost state-seeding shortcut established in the current harness. The loaded program's `Initialize` creates both config and queue PDAs, while the normal queue mutation is successful Execute. The existing clone runner resumes an already-created ledger. Do not edit a ledger database, call an unsupported RPC mutation, or use an account override as proof of runtime behavior. If a supported local fixture mechanism that preserves the accepted genesis and ELF is later demonstrated, document and independently verify it before replacing the 64-successful-Execute fill. Otherwise treat the measured 64-fill setup as the cost of this negative and enforce a finite owner limit; timeout is an incomplete case, not a pass.

## Evidence integration and independent checks

After the new Rust/Python sources exist, update `freeze_v3_heldout_cohort.py`'s registry/client source lists so the freeze covers the new supervisors, imported helpers, Rust modules, tests, heldout runner, assembler, verifier, and cost analyzer. Build and pin a separate runner binary. Freeze the updated source bundle and create a fresh cohort/manifest only after Training-012 is final; old receipts remain valid evidence for their old source hashes but cannot certify the new negative-evidence implementation.

Extend the case runner and journal as follows:

- Add `expired_status_negative` to each case sidecar, with a separate cost field equal to its clone/setup/wait/execute journal steps. Require a new sidecar hash and schema; do not allow old fragments to omit it.
- Add one cohort-level `queue_capacity_negative` reference and finite wall-time accounting to the acceptance manifest. Its runner report must bind the common freeze/ELF/genesis and the exact case's 65th request/proof/wire.
- Update `assemble_v3_heldout_acceptance.py` exact key sets and reference caps, then update the heldout verifier and cost analyzer. Keep explicit counts (proposed: eight loaded expired-status negatives and one loaded queue-capacity negative) so omission cannot be mistaken for success.

The independent verifier must reopen and hash every report, sidecar, snapshot, and referenced wire/proof receipt. For each stale-status case, independently assert the current clock is at/after signed expiry but within the 300-second observation-age bound, the issuer/head remain active and bound, the transaction error is exactly 705 at instruction 1, and all five application-account bytes are unchanged. For capacity, independently verify all 64 successful fill entries are distinct and finalized, queue length is exactly 64 immediately before rejection, request-65 is finalized and absent, status/head/deadline and the valid wire are current, the error is exactly 708 at instruction 1, and all five bytes are unchanged afterward. Reject missing reports, wrong cardinality, nonfinalized transactions, identity drift, duplicate fills, unexpected queue entries, changed bytes, unknown schema fields, and any cleanup/owner-limit failure.

The acceptance result should report the added evidence counts and their measured setup costs separately from matched Full-versus-Anchor branch costs. A loaded negative pass supports only the tested local application behavior; it does not establish upstream revocation freshness or production signer security.

## Source pointers checked

- `program/src/application_v3.rs:10,15,24–47,535–545,978–999`
- `program/src/application_preflight_v3.rs:104–142`
- `program/src/application_runtime_v3.rs:224–259,315–350`
- `program/tests/application_v3_execute.rs:255–355,681–692`
- `harness/tests/queue_v3_local_disabled_config_negative.py:24–49,68–124,127–224,269–440`
- `tools/part5/freeze_v3_heldout_cohort.py:37–109`
- `tools/part5/run_v3_heldout_case.py:830–831,1198–1345,2337–2403,2506–2542`
- `tools/part5/assemble_v3_heldout_acceptance.py:32–43,115–135,194–228`
- `tools/part5/verify_v3_heldout_acceptance.py:2376–2405,2702–2845,3740–3793`
- `tools/part5/analyze_v3_heldout_costs.py:213–223,278–278,1058–1105`
