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

## Source-002 scoped static re-review addendum

Read the complete `results/dynark/phase-2/selective/source-001-to-002.diff`, `source-002-review.md`, `source-before-build-002.json`, the changed live source contexts and all three added focused tests. Used only bounded read/hash commands and this document append; no build, test, helper, runtime measurement or new feature. The source-001 findings and evidence above remain historical.

Independently hashed live source-002:

| File | SHA256 |
|---|---|
| `src/selective.rs` | `e7de63d79de22c955379e6f8a4f698b8e642fae39d6010a7e4b55289ebd743b5` |
| `tests/private/selective_private.rs` | `3e77c54e7c912e57099b9ed227d5c56e96093d8f9fe02b153f8a8ce7246fc628` |
| `results/dynark/phase-2/selective/source-before-build-002.json` | `6d2bcebec930fa8f9defdc1728e14f1bdb412877409e41dc42cd6043a01fc422` |

Both changed source hashes agree with the freeze. Its manifest records documentation HEAD `83f51e73baa4da1b6d457ee1640c98513d4e4c92` separately from accepted implementation base `df0b3a780074e44d85884643183cd26ccfa8d2be`; the other 52 pins, including lock, fixture and narrow lib registration, are unchanged in the manifests. Parent independently matched all 54 live pins. This reviewer did not rerun all 54 file hashes in this narrow addendum.

**Both reported finding categories are resolved statically:**

- Initial full allowance is checked against fresh zero stats at `selective.rs:251–256`, before public-capacity scanning, assignment/public copies, entropy or capture. The paid ticket remains before capture. The added zero-allowance case at `selective_private.rs:987–1010` distinguishes the bound error from entropy failure and asserts zero RNG draws; absence of assignment-copy/capture dispatch follows from the source order, not a runtime allocation assertion.
- `validation_ticket` at `selective.rs:1362–1377` stages all counter changes on a copied aggregate and installs them only after checked additions succeed. It reserves complete matrix validation, its assignment copy and separate current A/B/C column-touch sums before `validate_target` at 445–446. Explicit full validation at 1001–1005 and restart validation at 1092–1095 similarly reserve before dispatch, with zero gather reservations where no gather occurs. Names/comments now identify conservative reservations, including failed validation, rather than exact executed CPU or terms.
- The immutable assignment count/build traversals each charge v before their scan at 464–467 and 489–492. Calls rejected before the second traversal charge only work actually reached. Anchor-relative A/B touch reservation precedes both gathers at 521–523. Reload's separate assignment clone is reserved at 952–958, and its later full-validation copy is independently reserved. None of these charges is refunded by cancellation.

The focused failed-validation test at `selective_private.rs:1012–1106` covers current/full/restart rejection, retained reservations, zero entropy and unchanged committed state; malformed opaque assignments occur only inside private test fault injection. The C-only cancel/success case at 1108–1150 checks both scans, all current gather reservations including nonzero C touches, repeated dispatch charges and cancellation retention. These are discriminating authored checks inspected in source; no pass or compilation is asserted. Some expected touch values reuse the counting helper, so independent confidence in all three matrix orientations comes from reviewing its complete loop at `selective.rs:1348–1359`, rather than treating those assertions alone as an independent oracle.

The exact diff changes preflight/accounting and three tests only. Direct-entry/proof arithmetic, typed demand, cache/LRU atomic commit, fixed 4/2/8 limits, FullOnly policy, reload trust boundary and dependencies remain unchanged. No additional confirmed defect was introduced by this diff. Reservations can exceed work executed before an early error; they remain distinct from actual entry counters and measured whole-session CPU. Initial caller validation/input normalization, outside retained state and whole-session costs still require the later economics harness.

**Current verdict:** reported source findings resolved; source-002 is statically ready for the parent's next bounded build/correctness gate. All 19 proposed tests are unbuilt/unexecuted in this review. No runtime acceptance, performance result or queue grant follows from this addendum, and no reviewer queue is held.
