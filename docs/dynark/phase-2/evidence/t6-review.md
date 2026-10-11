# T6 independent frozen004 source review

October 10, 2026 (America/New_York). Reviewer `t1_review`, GPT-6.1 Sol high. **Changes required before source acceptance: two P2 findings, both confirmed by the parent.** No critical authentication, exact-receipt recovery, state-reconstruction or CAS defect was identified in the reviewed scope. This is a read-only source/evidence review, not a persistence runtime/security proof.

## 1. Scope and gate verdict

Reviewed accepted `persistence-design.md` / `evidence/t6-wire-review.md`, frozen `src/persistence.rs`, `persistence/{provider,storage,wire}.rs`, `dynamic/persistence_codec.rs`, reconstruction adapter diff and discriminating synthetic test source. Checked the fixed header/nine sections, canonical full retained graph, bounded loader admission, independent statement/raw verification, immutable publication/provider transaction and explicit unsupported capabilities. Parent owns acceptance; worker owns implementation and the serial runtime queue.

Recommend a narrow combined repair after the running unit001 completes: physical AES-key alias rejection and save-side metadata/work preflight. Then inspect the changed source/freeze and fresh targeted/full small-gate evidence; parent independently reruns. Build004 success and in-progress test progress do not close this gate.

## 2. Specification coverage and deviations

The implementation follows the accepted 1024-byte header and strict nine-section format, DirectQuad-only exact DynamicConfig, distinct persistence revision/witness generation, complete independently supplied descriptor/context and exact shared ReconstructionMaterial Arc. Root/mode/role/source/map-reference/count/cursor checks occur without scalar/group decoding on load. It preserves one assignment, up to six shared map objects, all 4N G1/6N Fr physical cells and exact cursor/telemetry; FullOnly preserves C/nondefault roles with t=0 and absent pool/builder/maps. Canonical compressed round-trip preserves points rather than projective X/Y/Z or retained Vec capacities.

Busy/undo/dirty-mark state is rejected; initial preparation/media/durable capability are explicitly unsupported. No arbitrary older/newest/orphan file is chosen for recovery. Immutable old/orphan files are deliberately retained under hard store bounds, rather than implementing cleanup now. These are stated implementation limits, not omitted production guarantees.

## 3. P2: identical physical AES keys can acquire separate nonce ledgers

**Locations:** `src/persistence/provider.rs:96–115`, `:224–236`.

`enroll_validated` searches KeyNamespace only by key ID+epoch. A matching tuple requires identical bytes and shares its nonce vector correctly. A distinct tuple creates a new namespace without rejecting the same 32-byte AES key already registered elsewhere. `reserve` checks only that new namespace's nonce vector. Consequently, changing ID or epoch while retaining the physical AES key permits a previously consumed nonce under that same key to be reserved again. Different commit IDs avoid the independent global commit-ID collision check. The existing shared-key test (`tests/private/persistence_private.rs:600–670`) exercises the same ID+epoch across sessions, and therefore does not distinguish this alias path.

**Required repair accepted by parent:** reject identical AES-key bytes under any distinct key ID/epoch during synthetic enrollment, before installing another namespace/session. Keep same tuple+same key sharing the existing ledger. A key-epoch/ID transition must not accidentally reset uniqueness for unchanged physical key material. This is a violation of the fresh-nonce enrollment contract; it is not a claim that AES-GCM-SIV automatically loses authenticity upon one repeated nonce.

**Discriminating validation:** changed ID and changed epoch with identical key must reject; existing same-tuple sharing remains allowed and rejects reused nonces. Distinct fresh keys may obtain their own namespaces. No test was executed by this reviewer.

## 4. P2: save work ceilings are enforced after full canonical encoding

**Locations:** `src/dynamic/persistence_codec.rs:758–827`, `:861–904`, `:913`; count/work checks at `:449–472`, `:586–602`.

Save checks record length and live-byte estimates before allocating its payload. It then serializes the complete assignment, raw proof/blinders, maps and pool, including canonical compression/normalization of all 4N projective pool points. Only afterward does `scan` enforce distinct/logical map scan, group/field checks, raw scalar and matrix work ceilings. A caller's stricter save LoadPolicy can therefore produce a typed bound error only after the very allocation/whole-state encoding work that its work preflight should prevent. Loader `scan` precedes decoded allocations/group operations and does not have this ordering defect.

**Required repair accepted by parent:** factor a narrow metadata-only save count preflight using known lengths/IDs/k, distinct and logical referenced-map entries, N/v and package matrix counts; enforce the shared work ceilings before payload allocation and whole assignment/map/pool canonical encoding. Keep final encoded framing scan and available mathematical validation. Check products/sums and actual capacities; do not hide encoding point-normalization work by labeling it decoder `group_checks`.

**Discriminating validation:** restrictive save work/map caps reject with no payload allocation or whole-state point encoding; sufficient limits preserve the existing exact bytes/round trips. Reuse already-covered positive cases rather than adding unrelated fixtures. No test was executed by this reviewer.

## 5. Authentication, admission and retained-state checks

`persistence.rs:598–620` checks external provider/context and expected public digest before receive/allocation, receives one bounded same-handle snapshot, compares its exact whole-file digest and performs detached AEAD before payload decode. `wire.rs:176–262` checks known versions/reserved bytes/full expected public identity/receipt/length and live-byte caps; header preflight is correctly separate from AEAD authentication. `storage.rs:154–177` uses NOFOLLOW+NONBLOCK and verifies regular file/owner/mode/link count; receive detects exact EOF/growth/size changes. No wire-selected key/trust context or secret payload callback precedes authentication.

`codec::scan:341–635` bounds section arithmetic, modes, map declarations before entry scans, alias graph, cursor prefixes/exact per-build action/scalar counts, generation/distance namespace and requested decoded/private/global capacities. Canonical per-cell decode verifies curve/subgroup/field encoding and canonical re-encoding without an unbounded pool batch. `decode:971–997` checks coordinate one/expected publics/full satisfaction before moving values through the existing opaque validator. `validate_current:660–755` checks full satisfaction, exact A/B1/B2 from assignment+r/s, ordinary A/B2/C proof/public values and active/frozen/materialized-prefix/map relations. The independent polynomial quotient `capture` is used by synthetic test update oracles, rather than reused as the persisted validator.

The reconstruction change factors the existing cursor metadata guard and exposes crate-private adapters; it does not change the approved FFT schedule/arithmetic. Aliased maps are rebuilt once and shared; all initialized physical slots are decoded, including stale/recycled scratch. Tokens and q/partial FFT provenance remain authenticated trusted-producer claims: current proof/row relations cannot prove arbitrary projection cells were honestly computed. No historical assignment or token history is fabricated.

## 6. Provider, races, publication and failure outcomes

`ExpectedContext::new` validates descriptor/schema against circuit commitment and streams exact public material commitments; save checks holder/action and assignment package. SyntheticProvider is explicitly process-lifetime. Exact snapshots/CAS/reservations/invalidation linearize under one mutex. Unknown attempts are retained/fenced and resolved by operation ID; delayed CAS resolution rechecks epoch/status/exact base, while malformed or contradictory post-dispatch outcomes stay Unknown (`persistence.rs:268–330,541–584`). An old receipt read alone does not cancel a dispatched operation. Existing synthetic tests discriminate commit-then-unknown, delayed execution/cancellation, invalidation, malformed conflict and competing exact-base CAS.

Recover rechecks authoritative state after validation. `FencedState::with_state` holds the provider use lease through its callback; the application must supply the same authoritative trust service and honor the documented no-reentrancy/no-borrowed-state-escape contract. Rust permits replacing/moving state through this caller callback, so the interface does not enforce a malicious caller's authorization policy. Current-root/issuer/action checks remain external. Invalidation scopes are caller-selected and issuer invalidation linearizes separately per session, not atomically across all issuers/sessions.

Publication uses held component/directory descriptors, private exclusive temp creation, safe file sync/close, no-replace rename, exact inode/length/hash reopen, then held-directory sync before CAS (`storage.rs:179–263`). Cooperative publications hold the validated lock through store-budget checking/publication. Old/orphans remain on pre-CAS failure, conflicts and unknown outcomes. Acknowledged exact CAS installs fixed-size receipt metadata without a new fallible step; no post-CAS verifier/entropy/fsync can relabel committed success as ordinary failure. Store substitution/corruption still may cause denial/explicit rebuild; availability against a co-UID/privileged attacker is not claimed.

## 7. Zeroization, close, cost and security limits

Zeroizing byte/key/assignment/map guards and `FencedState::Drop -> wipe_borrowed` provide best-effort cleanup of owned initialized pool/current/map values. **No blanket secret-erasure claim is justified:** pending target/root and journal preimage/backing storage are not comprehensively wiped by that function; failed raw point/scalar temporaries, backend/compiler copies, allocator capacity/pages, swap/crash dumps and historical ciphertext may remain. Normal scope drops are not physical erasure. The current accepted contract explicitly permits this limit; do not silently strengthen it in product/evidence prose.

Safe File Drop closes before publication but cannot report kernel close errors (`storage.rs:213–215`). Reopen/digest/size checks and file/directory sync are present; this is an explicit safe-Rust limitation, not a universal durability proof. Media sync/durable provider are rejected; no restart antirollback or unqualified power-loss guarantee follows from process-only filesystem tests.

Costs need exact labels and the requested supplemental budget: ExpectedContext construction canonicalizes 2N public projectives and 4N public fields (weights/roots/forward/reverse), plus fixed domain/inverse; save encodes 4N pool points+four raw points and all fields/maps. Current raw recomputation performs 3v+3 direct scalar multiplications **on each save and load**. Ordinary verification additionally prepares public input contributions (ell-1 scalar multiplications in pinned `ordinary` verifier) and pairing/preparation work; those are not the raw scalar counter. Three satisfaction passes plus available A/B row scans on load are conservatively bounded by four matrix-entry traversals and charged in metrics. Structural scratch/capacity ceilings do not establish actual heap/RSS or recovery from dependency allocator abort. Compression/subgroup/normalization, public binding, encoding, verification, wipe and abandoned attempts all count in subsequent measured costs.

## 8. Identities, actions and available evidence

Only this review document was written. Read-only `rg`, `sed`/`nl`, `cat`, `wc`, `git diff`, `shasum` inspection; no code/helper/build/test/benchmark/commit/delegation or sensitive credential/vector-log read. No execution queue was held. Read aggregate build004 report (exit0, no stop); fresh 17-test unit001 remained in progress at report finalization. Test lists/source are planned discriminating coverage, not an observed pass count. Parent independently reviewed source; fixes below require a new freeze.

| Frozen input | SHA-256 |
|---|---|
| source-before-build-004.json | `4dfcb98f0a2baa5e1b32b30dbc358aca54ce3e050d05973b03a5c83697f3ff70` |
| src/persistence.rs | `c6a97ea84a645a084345c4f7400e8bb849079ac393bbdfd6767f133af9214d44` |
| persistence/provider.rs | `3c6b23958ad208a9ef343264baceaa0823754293d89a54ccea884930255bc58d` |
| persistence/storage.rs | `6907941f61697a321978332141b9ec13c3baea785f22f787bb0b252dad0f5bc7` |
| persistence/wire.rs | `408491c5a5d3c4a774a2f301240053477fa1f1e432824b738fdaffd9a0b29448` |
| dynamic/persistence_codec.rs | `32cc91851ca87f9ddc84866dbb72b4b5c4e5f471360d6d69ece7b6ad2b2c3b37` |
| src/reconstruction.rs | `b90910376efd609a9ed3a55fdddf45a68f1e9df60f564f8607a40250394fa326` |
| tests/private/persistence_private.rs | `0f030b2b9e1e0d1cf24fc90a675ee0797f66a584e5d0ff696eadc03ad77fb0da` |

Observed source hashes match frozen004. Its manifest records HEAD `eb5295d46e7a13e33e0dbb5a40c8bdf3d297af89`. Executable metadata records `96751027b5e0192f6e047a91f0373f3acd33997ac1fb223abd6e668388489b19`; this reviewer did not execute it. No measurement or performance/security gain is produced by the source review.

## 9. Required next gate / nine-part return

Parent accepted both findings and requests one combined worker repair after unit001, preserving the failed/superseded source/evidence. Add only the discriminating key-alias and early-save-cap checks, freeze new source/test/executable identities, review dependency/source drift and obtain fresh bounded small correctness plus independent parent rerun. Supplement large-operation budgets before any credential checkpoint work; no new heavy run is authorized here.

Return: **scope** frozen004 T6 spec/code/security review; **deviations** two required repairs, accepted process/close/wipe limits; **files** this report only; **identities** exact freeze above; **commands/outcomes** read-only inspection/build aggregate/no reviewer execution; **measurements versus claims** structural/counted costs only; **evidence** accepted wire/source and synthetic test inspection, runtime pending; **security limits** trusted producer/context/provider and conditional backend/application obligations; **next gate** combined repair, re-review/freeze/fresh gate and parent acceptance.

## Parent source005 acceptance addendum

October 10–11, 2026. The historical frozen004 findings above remain intact. Both required repairs are now accepted after source inspection and fresh execution. The physical-key check rejects a matching AES key under any different ID/epoch before creating a namespace/session; same-ID/epoch enrollment shares the existing ledger. The save path now calls the same checked map/group/field/raw-scalar/matrix count admission before header-public encoding, payload allocation or whole-state normalization. Final framing and mathematical validation remain. New tests discriminate both defects; no unrelated production refactor was included.

The parent independently matched all 11 files to [source005](../../../../results/dynark/phase-2/persistence/source-before-build-005.json), SHA `d19ac18c3848b500b1189b97c1d71a7d532bc5573756caeeed65a31838337afe`; lock SHA `50a18e4e57bad47cf266089dc5da60f901b34332646117092f5f7084567a4a6b`. Build005 passed. Immutable test executable `4e48fb2d454c26163fbbd3ce03c78ceef6902711b6b50df7ed3a8e745ee1df02` passed all 19 worker tests, including 911 total reconstruction-stage checkpoints and 20 resumed proofs/seven distinct swaps for each of seven domains. Worker wall was 281.69 seconds; runner 282.060, 1,250 samples, sampled RSS 10,354,688 bytes, no stop or remaining process.

The parent then independently ran the same protected executable with filter `dynamic::persistence_codec::tests::`, skipping only `golden_offsets_pool_aliases_and_all_phase_fft_stream_roundtrips`, after inspecting its complete passing worker output. Existing bounded runner owner `parent-t6-unit-001`, 900 seconds/2 GiB RSS/128 MiB aggregate growth, four Rayon threads, serial tests and a fresh private data root. All 18 tests passed in 117.47 seconds (runner 117.558765; 522 samples; sampled RSS 9,633,792 bytes; 7,810-byte growth; no stop, runner error or survivor). The executable hash was unchanged and the test-data root empty. Exact argv and primary outputs are protected under `artifacts/dynark/phase-2/persistence/parent-unit-001`; [scrubbed report](../../../../results/dynark/phase-2/persistence/parent-unit-001.json).

This closes the small persistence implementation/security-review gate. It does not close the separately budgeted actual credential checkpoint/reload gate, establish a durable provider, strengthen application freshness or erase the explicit provenance, caller-contract, safe-close and memory-erasure limits above. Snapshot measurement hooks still need source review/parity and their own execution grant.
