# Credential dynamic successor prerequisites

This is a read-only dependency audit following the accepted reconstruction arithmetic pilot. It is not a grant to execute or author a successor. ROOT and the independent reviewer inspected the existing harness and original grant. The batch product correctness and integrated timing gates come first.

## Source binding

Start a new immutable snapshot from the accepted current engine. Preserve the harness and checkpoint observer from `artifacts/dynark/phase-2/credential/dynamic-source-005/crates/dynark-bn254/tests/private/credential_dynamic_harness.rs` and `credential_checkpoint_trace.rs`. Reapply only their existing test-only capacity hooks in `src/dynamic.rs`, checkpoint observer hooks in `src/dynamic/persistence_codec.rs`, and required registrations. Do not replace current product files with the old snapshot; its library omitted selective registration, which must not be carried forward as an unrelated change.

The existing generic helper `results/dynark/phase-2/credential/launch_credential_dynamic.py` accepts explicit source, binary and output arguments. It may remain unchanged if those assumptions and its pins still match. The old host wrapper `artifacts/dynark/phase-2/fixed-budget/dynamic-launch-source-002/launch_dynamic_host.py` requires a new immutable successor bound to supervisor006, its runner and guardian, new source/binary identities and fresh evidence paths. Its old local supervisor/runner cannot remain active. Rebind the constructor parity test `test_dynamic_launcher_source005.py` in that same old wrapper directory into a fresh source, then review its exact command and helper parity.

Preserve the current pinned Rayon dependency and lockfile lineage. The old harness's process-clock instrumentation additionally requires the existing `rustix` dependency's `time` feature. Add that feature narrowly; copying the old Cargo files would incorrectly remove the accepted Rayon change.

Historical identity records remain untouched:

- `results/dynark/phase-2/credential/dynamic-source-freeze-005.json`
- `results/dynark/phase-2/credential/dynamic-launch-source-freeze-002.json`
- `results/dynark/phase-2/credential/fixture-identities.json`
- `results/dynark/phase-2/credential/fixed-dynamic-001-replay004-parent-granted.json`
- `results/dynark/phase-2/credential/fixed-dynamic-001-queue-granted-receipt.json`

## Initial state and required outcome

The old interrupted run has four committed targets but no committed target05 checkpoint. It provides no recoverable target04 starting artifact. A successor starts at serial00 using the existing exact R1CS, UK and eleven received witnesses. The harness prepares reconstruction public tables and performs **one fresh serial00 `Anchor::create`**, then adopts it into the dynamic state. It does not load the retained near-E2 private cache. Reusing that unrelated cache would violate the existing initial-state contract. Charge this once-per-trial preparation, along with all previously spent interrupted work in the historical ledger; do not silently erase either cost or add a second preparation.

Retain all ten transitions, two real promotions at targets05/09, one save/cold recovery at05 and resumed promotion at09. The successful schedule checks 218,575,669 committed maintenance actions, 114,766,642 committed requested G1 scalar calls, 92,274,688 committed field multiplications and 26,686 positive maintenance calls. External ordinary checks total 152, with two internal save/load checks for 154 overall. There are 53,060,793 cross pairs, below 11 million per target and 60 million total. The final partial builder remains intentionally incomplete after the two required completed cycles.

The harness logs attempted work separately; it does not assert attempted counts equal cursor advancement on a failed chunk. New speculative batch work must stay in those attempted counters. Successful committed totals and cursor checkpoints remain exact. Existing process-clock instrumentation uses two reads per maintenance call and measures all process threads; parallel kernel wall improvements are not substitutes for those CPU observations.

## Budgets and admission

Preserve the original 14,400-second / 4-GiB sampled workload RSS / 4-GiB output-growth limits, four Rayon workers, one test thread and one heavyweight owner. Preserve internal 10-second chunk, 9,000-second maintenance and 14,040-second whole-stage headroom checks. The existing private/global structural limits are 4/6 GiB and the journal ceiling is 768 MiB; these are structural accounting limits, distinct from the 4-GiB sampled RSS ceiling. They are not new allowances.

Batch scratch must fit the current state and caller's external assignment/context accounting. Preserve existing external-peak guards, failure evidence, cap handling, proof checks and resource measurements. A fresh source freeze, offline single-job build, exact emitted-binary binding, finite harness/parity tests and reviewed concrete runtime grant are prerequisites. No automatic retry, changed cap, omitted checkpoint or source-only performance extrapolation closes this gate.

## Caller memory reservation during maintenance

The old harness retains an external target vector through maintenance but has no external-live-byte argument to `advance_update`. Its pre-begin guard does not by itself establish a bound on the allocator's actual batch-buffer capacity. Requested capacity must not be treated as guaranteed actual capacity.

ROOT and the independent reviewer accepted a harness-only design: let `E` be the actual retained target capacity plus a conservative declared allowance for remaining driver/context storage, `B` the complete post-begin private structural bytes, and `P` shared public bytes. Check `B + E <= C.private` and `P + B + E <= C.global` under the original configuration `C`. During maintenance only, checked-subtract `E` from both internal private/global limits. Existing engine admission then enforces the actual scratch allocation against the remaining space, so combined caller and engine storage stays within the original limits. Journal limits, scheduler, operation limits and quotas stay unchanged. Pending pool/journal capacities are fixed before these calls; promotion exchanges or retires existing structures.

Run maintenance inside a closure that returns its result, restore the original configuration unconditionally, then propagate any typed error. Restore before the full comparator and before any persistence header, encode, save or recovery: persistence authenticates configuration. Current transition/proof tokens do not include configuration, and commit/cancel do not derive configuration bindings. This does not promise restoration after a process crash or panic and does not introduce a product API or persistence-format change.

Log original limits, reserved limits and `E`, and verify restoration. Finite tests must cover subtraction/admission refusal and restoration on success and typed failure before any long-run grant. The fixed 4-GiB RSS ceiling remains unchanged. This design acceptance does not itself authorize successor authoring or execution.
