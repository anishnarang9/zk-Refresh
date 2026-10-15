# Pre-Part 5 status and ownership

October 15, 2026. Authoritative checkout: `/Users/anishnarang/Zk-refresh` at `c2a558f` when this phase began. The existing untracked and ignored artifact baseline is preserved. This record controls work started by the current Phase 3–4 task; it does not change the historical evidence.

## Current gates

- Phase 2 functional engine and credential-scale reconstruction/recovery qualification are accepted under the limits in `../phase-2/SOL-HANDOFF-2026-10-14.md`. Session audit groups 000–005 passed; group 006 failed its original work reservation; groups 007–008 and the later campaign have not run.
- The accounting successor in `artifacts/dynark/phase-2/fixed-budget/session-source-004/` and `artifacts/dynark/phase-2/sessions/tooling-source-003/` contains authored but unexecuted tests. It is not yet an accepted binary or campaign source.
- The Phase 3 witness evaluator has exact-output pilot evidence for the unchanged synthetic circuit, with its documented limited transition shape. Native packaging and application integration remain open.
- The older chat's `dynark-engine-progress` two-hour heartbeat was paused with user authorization on October 15. Its most recent observed chat status was idle, and no matching build/proof process was active at this phase's start. ROOT now owns the single heavy queue for this task.

## File ownership and queue

| Owner | Initial exclusive scope | Current action |
| --- | --- | --- |
| ROOT | `docs/dynark/pre-part5/`, architecture/contracts, security and evidence review, serialized heavy execution queue | Read sources, freeze contracts, review worker diffs and grants |
| M1 engine | `artifacts/dynark/phase-2/fixed-budget/session-source-004/crates/dynark-bn254/` and `artifacts/dynark/phase-2/sessions/tooling-source-003/`; new M1 session evidence only after review | Complete the exact accounting repair; no execution yet |
| M2 witness/client | Read-only discovery of Phase 3 witness sources; new M2 component paths require contract transfer | Map verified evaluator, API and lifecycle gaps |
| M3 credential/profile | Read-only discovery of `circuits/`, `harness/` and fixtures; new M3 component paths require contract transfer | Define versioned narrow development profile and circuit gaps |
| M4 registry/durable state | Not dispatched; proposed new registry/state component paths | Await available slot and frozen interface |
| M5 interoperability/readiness | Read-only discovery complete; proposed `crates/dynark-solana-adapter/` and isolated interoperability paths | Matching development-key strategy and local verifier plan recorded; implementation awaits contract transfer |

Only ROOT grants heavy runs. Phase 2 uses `dynark-fixed-budget-v1`: one heavy job, four Rayon workers, one test thread, 4 GiB sampled owned-workload-tree RSS, offline/locked one-job builds, and the original per-job caps. Each run requires a fresh reviewed question, exact sources/binary, limits, stop condition and evidence path. No worker may change a shared manifest, lockfile, schema or circuit interface without explicit ownership transfer. No worker may delegate. Local source review and bounded discovery may proceed while heavy execution is held.

The first Phase 2 continuation must preserve all 234 original envelopes, original audit groups 000–005 and their source labels, the aborted paid ledger in full, and the failed group 006 record. New groups 006–008 require a separately reviewed successor and grant. TRAIN, HOLDOUT and allocation diagnostics follow only after audit acceptance.
