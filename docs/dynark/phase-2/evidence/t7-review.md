# T7 frozen source-001 independent review

October 10, 2026. GPT-6.1 Sol/high; read-only source/spec/security review. Parent owns acceptance.

## 1. Scope and deviations

Read the complete accepted dependency and worker briefs, P2-D13, implementation plan, freeze manifest, all selective source/tests/fixture, narrow lib diff, and relevant accepted anchor/delta/assignment boundaries. Spec review preceded code/security review. No source/helper edits, delegation, build, test body, benchmark, credential access, private runtime-vector read or heavy queue use. The only authored file is this report.

This gate covers the bounded selective engine, not the subsequent medium-worker full session economics, admission selector, real credential distribution or production durability.

## 2. Files and ownership

Reviewed `crates/dynark-bn254/src/selective.rs`, `tests/private/selective_private.rs`, `tests/private/selective_fixture.rs`, and the two added module/export lines in `src/lib.rs`. Supporting reads: `src/anchored.rs`, `src/delta.rs`, `src/artifact.rs`. Existing package, full, dynamic, reconstruction, persistence, lock and vendor ownership is unchanged. No unrelated dirty/untracked file was modified.

## 3. Exact identities

Baseline accepted T6 HEAD: `df0b3a780074e44d85884643183cd26ccfa8d2be` (freeze manifest). Independently hashed current reviewed bytes:

| File | SHA256 |
|---|---|
| `results/dynark/phase-2/selective/source-before-build-001.json` | `794cba307114b6454e21fbc536e21b5a83dfe7bdc1bdc068da02d029c5d49a8c` |
| `src/selective.rs` | `061f2d1c5f5312ba7adcf05d30d2dd070caa9817d71714eb1a6be770024d7dc3` |
| `tests/private/selective_private.rs` | `be5c42c11eb4165095f770b53678cdc423c573161db26ea7ee1043a6e3d70bb8` |
| `tests/private/selective_fixture.rs` | `f59f9c9398659ea2da7d25d7950fbb32451cd19553e275afccb606de4a73d560` |
| `src/lib.rs` | `7e50dceb1312dc8b254ab314dbf8f13f6e9892b0e7a30d4ee3b81a8d36c2924d` |

These agree with the frozen manifest. Lock SHA256 recorded there is `50a18e4e57bad47cf266089dc5da60f901b34332646117092f5f7084567a4a6b`; no dependency change is proposed. Worker copied-executable identity, not independently executed by this reviewer: `56d7547da458d1d0c63abf946a959cc083be085cab5d1933266f63264c0787a9`.

## 4. Read commands and actions

Used bounded `cat`, `nl -ba ... | sed -n`, `rg -n`, `rg --files`, `wc -l`, scoped `git diff`/`git status --short`, and `shasum -a 256`; added only this report with `apply_patch`. Aggregate build/proposal/identity records were read. No command listed or executed test bodies. No new runtime identity or measurement was produced.

## 5. Findings and disposition

**P2 — Preflight the initial full allowance before copies and entropy.** `selective.rs:271–297`: `create` allocates current/public copies and samples r/s at line 291 before `full_ticket` rejects `max_full_calls=0` at line 297. A valid package/assignment with `SelectiveConfig::small()` except zero full allowance is already unsupported; a failing caller RNG instead produces `Entropy`, and a working RNG consumes both draws before the eventual full-bound rejection. This does not launch a full proof or publish partial state, but violates the required unsupported-work preflight order. Narrow repair: check the initial full allowance against a fresh zero-stat ledger before owned copies/randomness; retain the paid ticket immediately before capture. A cheap zero-allowance/zero-RNG-call regression distinguishes the order. Subsequent fallback and explicit full/restart paths already call `full_preflight` before entropy.

**P2 for the session-economics gate — Account attempted validation, both assignment scans and both gather stages.** These are observable ledger gaps, not proof or eight-attempt-cap exploits. Parent requires checked reservations/actual counters before session economics:

- `selective.rs:466–469` charges one `assignment_len` to `anchor_delta_scanned_elements`; admissible calls scan every element once to count support at 470–477 and again to build it at 491–505. The present field undercounts actual scanned elements. Charge the second traversal with checked arithmetic before it starts. Alternatively, preserve an explicitly named logical-pass count and add a separate checked second-traversal counter.
- `selective.rs:439–444` adds `validation_entries` only after `validate_target` succeeds. An unsatisfied target can execute matrix arithmetic and then return with no such charge; the authored invalid-assignment case at `selective_private.rs:877–883` exercises that path. Explicit full/restart validation counters similarly follow dispatch at 997/1020 and 1095/1113. The worker's `source-001-review.md` expressly describes successful-only validation stages and disclaims failed-call CPU coverage, so this is a documented limitation rather than a concealed complete-work claim. Narrow repair: conservatively reserve matrix-entry validation attempts with checked arithmetic before dispatch, including failed calls, and label that counter as reservation rather than exact visited work. Do not call the present successful-only counter a complete attempted-work total.
- Current-to-target A/B/C gather stats are available from `PreparedTransition` but are dropped at `selective.rs:449–451`; `anchor_touched_entries` at 521 counts only the later anchor-relative A/B gather. Retain checked distinct current-to-target A/B/C touched-work counters (or a conservative pre-dispatch reservation), alongside the anchor-relative A/B stage. The economics owner must additionally charge input normalization/admission validation and canceled work. These counters do not replace measured whole-session wall/CPU.

No additional confirmed correctness/security defect was found. Accounting limitations are nonblocking for the algebra alone, but required repairs for complete session economics. Parent has directed narrow source-002 fixes and owns their acceptance.

## 6. Static outcomes and measurement limits

The direct kernel at 1153–1191 implements both modular weight orientations and the separate diagonal exactly: `sum(a_j*w_(i-j)*L_j) + sum(a_j*w_(j-i))*L_i + a_i*p_i`. Bounds precede indexing. It streams constant accumulators and performs N row visits, N+1 logical G1 calls and 2(N-1) Fr multiplications per complete entry; these are source-derived counts, not timing or backend curve-operation measurements.

Demand at 465–595 compares the entire frozen assignment with the validated target; B differences request A entries and A differences request B entries. C participates in full satisfaction while contributing no projection quotient. `correct` at 1192–1275 matches the accepted complete A/B1/B2/C correction, private query split and fresh-randomizer formula. The accepted direct weighted Quadratic cross is retained.

Fixed arrays enforce four committed/two staged entries. Admission checks attempts/work before a missing-entry scan. Tickets start on the first positive entry action; cancellation and late faults discard staged state without refunding consumed entry counters. Requested hits remain pinned; replacement chooses unrequested LRU slots. Proof/public output, generation, cache and LRU install together after fallible work. Zero advance returns without changing a selective or full-result cursor. Successful full fallback retires anchor/cache and latches FullOnly; later invalidation/reload routes do not reopen selective mode.

Preallocation estimates cover retained assignments/rows, target and full copies, current/output publics, tree and result storage, cross vectors, old plus staged entries and conservative full scratch. Actual Vec capacities are checked. Shared package/UK capacities are counted once; initialization calls capture without eager `project`, T5 reconstruction or N-group private outputs. Structural ceilings are not allocator bookkeeping, RSS or recoverable OOM guarantees. Caller-retained independent engines/returned outputs remain outside the engine's private count and require harness accounting.

The primary synthetic tests use both reductions and N8–256, v>N plus compact v<N, five public inputs and all five alterations, C-only/public differences, dense/zero/full-width endpoint entries, accumulated support/fanout, common-r/s four raw components, entropy/fault/cancel prefixes, LRU/recomputation, eight/ninth attempts, typed demand/fallback, FullOnly, invalidation and ledger-preserving restart. The schoolbook quotient oracle is independent of the weight formula; the fresh full capture is independent of selective entries. The eager comparator deliberately shares accepted cross/proof correction, so its pass alone would not establish independence. Exact component comparison and ordinary verification provide distinct checks.

Source-derived schoolbook pair counts agree with the proposal: 1,048,320 main-shape plus 6,144 endpoint visits = 1,054,464; at most 393,216 per shape case. The separately conservative sparse comparator allowance is <512 pairs. Eager projection/setup/capture work is additional, explicitly inventoried by the worker, and is not schoolbook-pair work or measured entry cost. No runtime pass, speedup, crossover or session footprint is established by this review.

## 7. Evidence paths

Requirements: `docs/dynark/phase-2/evidence/t7-dependency.md`, `t7-worker-brief.md`, and `phase-2/decisions.md` P2-D13. Authoring/identities: `results/dynark/phase-2/selective/implementation-plan.md`, `source-before-build-001.json`, `source-001-review.md`. The later-created aggregate `build-001.json` records exit 0 without a stop/runner error; `executables-build-001.json` explicitly marks the executable untested. `command-small-001.json` remains a proposed bounded 600s/1GiB/2GiB runtime invocation. Build success and a 16-name inventory establish no test-body pass. Protected credential/runtime scalar data was not read.

## 8. Security and trust limits

The caller-held ledger is opaque/non-Clone and paired by Arc identity plus exact current binding; cancellation/reload retain spent entry attempts. Restart deliberately rebuilds a valid full state and loses private selective reuse. It neither authenticates a persisted selective witness nor establishes durable process-restart resource accounting. Loss of the ledger requires a distinctly labeled new cold evaluation. Caller-supplied holder/action labels still need application policy linking them to the validated statement; content tokens are not authorization or antirollback. Fresh `CryptoRng` behavior remains the caller contract behind the existing fallible sampler.

No cross-action projection reuse, timing privacy, forward security, sensitive-buffer erasure, original-zkey interoperability, production persistence or credential workload benefit is claimed. Sparse synthetic sign flips exercise algebra and lifecycle, not real action/root authorization.

## 9. Gate verdict and next gate

Frozen001 mathematical/state design has no confirmed critical defect, but initial zero-full-budget preflight needs the narrow repair above; attempted validation/scan/gather accounting must be repaired before complete session economics. This is conditional source review, not runtime acceptance. Parent will request source-002 fixes, review the narrow diff, freeze new identities and grant the bounded small correctness run, then independently review/rerun consequential results. Only afterward transfer the separately authorized full-session economics to the medium worker. No reviewer queue is held.
