# T6 precise envelope and retained-state proposal

October 10, 2026. Reviewer `t1_review`, GPT-6.1 Sol high. **Document proposal for parent acceptance; no serializer, dependency change or persistence gate is approved by this report.** Offsets below are zero-based; intervals exclude their end. This proposal implements the accepted [persistence boundary](../persistence-design.md) and [security design](t6-security-design.md) against T5 commit `04b01b023311e1869d89381bcc20fe15a43201a2`.

## 1. Scope, disposition and deviations

Recommend a full partial-builder checkpoint with one fixed 1024-byte public authenticated header and nine fixed ordered encrypted sections. Supported modes are committed `DynamicReady` and `FullOnly`. `Busy`, a staged target, nonempty undo journal/nonzero first-touch marks, and unfinished `DynamicPreparation` return typed unsupported/busy errors. There is no pending-target journal, history log, fabricated historical assignment or implicit rebuild-as-resume mode.

Preserve every initialized physical pool cell as a mathematical point/Fr, every applicable role, cursor, map alias, token, generation, distance and telemetry value. Canonical compression changes projective coordinates. Empty journal capacities, allocator capacities and Arc addresses are reconstructed rather than preserved; their new allocations are charged. Current T5 retains exactly one assignment and at most six distinct sparse map objects. FullOnly retains its existing role permutation and lifetime C, requires t=0, and has no pool/active/builder/maps/cursor.

Parent has approved the following interpretation during this review: complete descriptors/reduction/schema/issuer/application scope come from independent ExpectedContext; clean journal persistence contains telemetry only; FullOnly is exempt from C modulo b. Wire v1 encodes exactly existing DynamicConfig/Limits and a fixed directQuadratic algorithm version, with no CrossConfig or algorithm selector. An alternative requires an explicitly reviewed new schema/version.

## 2. External expected context and trusted provider

ExpectedContext is independently supplied alongside the already accepted immutable PublicPackage and ReconstructionMaterial. It binds all five package digests, Shape, the trusted descriptor/manifest's R1CS/executable/profile/public-schema commitments and exact reduction, domain convention, registered session ID, holder/credential, action, issuer scope and application-policy commitment. PublicPackage currently retains only PackageIdentity/Shape, so the other claims must never be recovered from this envelope. Check the descriptor/manifest binding against the trusted package/context before save or load. Opaque scope digests commit to caller-defined policy; they do not implement its meaning, issuer freshness or authorization.

The provider supplies an authenticated authoritative Active/Invalidated status, session epoch, protected key epoch/key ID, capability, and either an explicitly authorized enrollment marker or exact ExpectedCommit. A receipt contains session/context identity, revision, commit ID, base-present/base ID/revision/generation, exact whole-envelope SHA-256, key epoch/ID, witness generation, current state token, config/public-statement digests, schema/unit and agreed sync tier. These fixed base fields do not require retaining a history of old assignments/receipts. A missing provider/receipt is not bootstrap authorization. Header values only cross-check these expectations; they select neither a key nor a trust context. The caller's load policy independently caps bytes/work/allocations and allows the exact stored configuration; wire limits cannot increase it.

Each encryption attempt reserves a **fresh 12-byte nonce and a separately drawn fresh nonzero 32-byte commit ID** through fallible caller cryptographic entropy. Provider reservations are bounded and consumed on success/error/orphan/conflict. Nonce uniqueness covers the entire **(key ID, key epoch) namespace**, including every session sharing that key; a session-epoch change does not reset this reservation history while the key ID/epoch remains in use. Commit-ID uniqueness is separately enforced across at least the publication and provider-operation namespaces in which the ID is used; it is not the nonce namespace. Retry exhaustion is typed. Do not derive either value from the other, proof r/s, witness, filename generation or persisted RNG state. The commit ID, together with session/epoch, can identify the idempotent provider operation; an additional random operation ID is unnecessary. Process-only reservations/receipts protect only this provider lifetime. Durable uniqueness, rollback-resistant trust and key service are later integrations.

Revision is checked old revision+1 (first revision=1); witness generation may remain equal for maintenance and cannot move backwards. CAS checks the **full exact old receipt**, context, Active status and one session epoch shared with leases/reservations/invalidation. Outcomes distinguish acknowledged committed exact proposed receipt, definitive conflict, definitely undispatched unavailability and dispatched/unknown outcome. A contradictory/malformed reply after dispatch cannot establish definite failure. Unknown keeps both files and fences further saves; resolve or fence that exact operation before retrying. An old receipt read alone does not prove an outstanding CAS cannot later execute. Invalidation for own revocation, issuer disablement or action completion advances/fences the same epoch; re-enrollment requires separate authorized validated rebuilding. Recovery must re-read the exact receipt/epoch/status before release, and resident use remains subject to provider lease/application checks.

## 3. Fixed public header: exactly 1024 bytes

File = header || ciphertext[L] || detached tag[16]; total=1040+L. All integers are fixed-width unsigned little-endian; byte strings have exactly the listed width. AAD is the exact ASCII bytes `dynark-bn254/persistence-envelope/v1` followed immediately by all 1024 header bytes. AES-256-GCM-SIV is algorithm tag 1. Canonical encodings are pinned arkworks 0.5 compressed BN254 Fr/G1/G2: widths 32/32/64 bytes respectively. No raw memory, Montgomery limbs, compression, alternate encoding or trailing bytes.

| Offset | Width | Field / v1 rule |
|---:|---:|---|
| 0 | 8 | Magic ASCII `DYNARKP1` |
| 8 | 2 | Envelope version=1 |
| 10 | 2 | Header bytes=1024 |
| 12 | 2 | Payload schema=1 |
| 14 | 2 | AEAD=1 |
| 16,18,20 | 2 each | Fr/G1/G2 encoding IDs=1 each |
| 22,24 | 2 each | Curve BN254=1; proof system Groth16=1 |
| 26 | 2 | Reduction: Original=0; InstanceAugmentedA=1; exact ExpectedContext match |
| 28,30 | 2 each | Domain convention=1 (`radix2`, roots omega^i); reconstruction units=1 |
| 32 | 4 | Flags: bit0 BASE_PRESENT; every other bit zero |
| 36 | 1 | Mode: DynamicReady=1; FullOnly=2 |
| 37 | 1 | Requested/fulfilled sync tier: file+directory process-interruption baseline=1; separately approved supported stronger tier=2 |
| 38 | 1 | Provider capability: process-lifetime=1; durable=2; must match external provider, durable unsupported by the initial synthetic implementation |
| 39 | 1 | Reserved zero |
| 40,48,56,64,72 | 8 each | constraint_rows, reduction_rows, assignment_len=v, instance_len=ell, domain_size=N |
| 80,88,96 | 8 each | Plaintext L, ciphertext L, total file bytes=1040+L |
| 104,112 | 8 each | Base persistence revision, new persistence revision |
| 120,128,136 | 8 each | Current witness generation, active generation, builder generation; last two zero in FullOnly |
| 144,152 | 8 each | Session epoch, key epoch |
| 160 | 12 | Reserved fresh nonce |
| 172 | 4 | Reserved zero |
| 176,208 | 32 each | Key ID, provider session ID |
| 240,272 | 32 each | Credential/holder binding, action binding |
| 304,336 | 32 each | Issuer-scope commitment, application-policy commitment |
| 368,400 | 32 each | Base commit ID, new commit ID |
| 432 | 32 | Current AnchorBinding.anchor_state token |
| 464,496,528,560,592 | 32 each | Complete PackageIdentity: matrix, circuit, proving key, verifying key, package digests |
| 624,656,688,720 | 32 each | Trusted R1CS artifact, witness executable, profile, public-schema digests |
| 752,784,816 | 32 each | Exact domain, UpdatingMaterial, ReconstructionMaterial digests defined below |
| 848,880 | 32 each | Exact config-block digest, current public-statement digest |
| 912 | 8 | Base witness generation |
| 920 | 104 | Reserved zero |

BASE_PRESENT=0 is allowed only against explicit external enrollment: base ID/revision/generation all zero, new revision=1. BASE_PRESENT=1 requires a nonzero exact base ID, revision>=1 and exact expected base generation; new revision is checked base+1. New IDs are always nonzero. Generation zero remains a valid witness generation, distinct from absent enrollment. FullOnly active/builder generation zeros are absence fields, not an invented snapshot. Every duplicate in the payload must match the header. Public AAD leaks session linkage, shape, size and snapshot generations; no sparse coordinates, private counter, blinder or private witness digest is placed there.

Use SHA-256 with these exact ASCII prefixes and concatenations (no terminator): `dynark-bn254/persistence-domain/v1` || canonical compressed GeneralEvaluationDomain; `dynark-bn254/persistence-uk/v1` || PackageIdentity digests in header order || N[u64] || N canonical lagrange G1 || N diagonal G1 || N weights Fr; `dynark-bn254/persistence-tables/v1` || the same identity || UK digest || units[u16] || N[u64] || N roots Fr || N forward Fr || N reverse Fr || inverse_n Fr. These are shared-public preparation commitments, computed/checked once with charged canonicalization/hash costs, never accepted by self-hashing untrusted tables. Config digest=`dynark-bn254/persistence-config/v1` || exact section-2 bytes. Statement digest=`dynark-bn254/persistence-public/v1` || package_digest || current generation[u64] || (ell-1)[u64] || ordered canonical public Fr. No whole-envelope digest is embedded in its own header: the exact final-file digest belongs in the external receipt.

## 4. Encrypted payload schema and exact retained graph

Payload prefix is 32 bytes: magic `DYNARKS1` at0[8], schema=1 at8[u16], directory entry size=32 at10[u16], section count=9 at12[u16], reserved zero at14[u16], L at16[u64], reserved zero at24[u64]. Nine entries occupy bytes32..320. Entry is tag[u16], version=1[u16], flags=0[u32], element_count[u64], offset[u64], byte_length[u64]. Tags below occur exactly once in ascending order. First offset=320; subsequent offsets equal preceding offset+length, with no padding/overlap/holes; final end=L. Empty sections still have their exact descriptor and next contiguous offset. No unknown extension/trailing data.

| Tag | Section | Element count / exact bytes |
|---:|---|---|
| 1 | Root metadata | 1 / 256 |
| 2 | Configuration | 1 / 128 |
| 3 | Lifetime accounting | 1 / 192 |
| 4 | Current assignment | v / 32v; exactly one retained assignment object, reconstructed once as Arc |
| 5 | Current raw proof/blinders | 1 / 224: A[32], B1[32], B2[64], C[32], r[32], s[32] in that order |
| 6 | Map objects | K / sum(16+40*entry_count), DynamicReady 1<=K<=6; FullOnly K=0/length0 |
| 7 | Physical G1 pool | DynamicReady 4N /128N, vectors slot0..3 then index0..N-1; FullOnly 0/0 |
| 8 | Physical Fr pool | DynamicReady 6N /192N, vectors slot0..5 then index0..N-1; FullOnly 0/0 |
| 9 | Builder cursor | DynamicReady 1/96; FullOnly 0/0 |

Root section: version=1[u16] at0, length=256[u16] at2; mode[u8] at4; presence bits at5 (active=1,builder=2: DynamicReady=3, FullOnly=0); reserved0 at6[2]. C[u64] at8; t[u64] at16; derived W[u64] at24. Active generation/distance at32/40[u64], token at48[32]; builder generation/distance at80/88[u64], token at96[32]. Roles at128[8] ordered active_g[2],build_g[2],active_f[2],build_f[2], each u8. Builder source slots at136[2]. Map references at138[6] ordered active A/B, overlay A/B, pending A/B. K[u8] at144, reserved zero145..152. Physical pool N[u64] at152 and mark-word count[u64] at160; reserved zero168..256. FullOnly absent generation/distance/token fields and pool N/marks are zero, source/ref bytes are 0xff, while roles and C are preserved. W is always derived from trusted N, not a scheduling assertion for FullOnly.

Each map object is ID[u8], seven reserved zero bytes, entry_count[u64], followed by entry_count pairs index[u64] + canonical Fr[32]. Entries are sorted, unique, nonzero, index<N and individually support-bounded. K equals directory/root counts. IDs are 0..K-1 in deterministic first-reference order through the six root references; every object is referenced. Encode identical Arc references once, including shared empties; equal-content distinct Arcs remain distinct IDs. Decode each object once, then clone its immutable Arc for all references. Active/current/frozen row aliases are physical slot references, not duplicated vectors. Field work slots4/5 have their existing fixed meaning. No raw pointer/address/capacity appears on wire.

Configuration section: version=1[u16] at0, length=128[u16] at2; cap policy[u8] at4 (Reject=0,FullOnly=1); reserved zero[u8] at5; fixed cross-algorithm version=1[u16] at6, meaning the accepted directQuadratic weighted loop. Threshold b[u64] at8. Six Limits fields at16..64, every8 bytes, in declaration order: max_domain,max_assignment,max_matrix_entries,max_delta_entries,max_pair_work,max_allocation_bytes. Six dynamic limits at64..112, every8 bytes: max_row_support,max_total_pair_visits,max_private_bytes,max_global_bytes,max_journal_bytes,max_transaction_actions. Bytes112..128 reserved zero. There is no CrossConfig, Fast selector, dormant limit block or inferred crossover threshold. Any other algorithm/config version returns typed unsupported; an alternative requires an explicitly reviewed new schema/version and exact limit/fallback/accounting policy. Stored b/cap policy/config are exact, and independently allowed by reload policy; do not silently clamp b or change units/algorithm after load.

Accounting section: version=1[u16] at0, length=192[u16] at2; WorkLedger.saturated[u8] at4, clean Journal.saturated[u8] at5 (booleans0/1), reserved zero at6[2]. Nineteen u64 counters start at8 in current declaration order: initialization_actions,adopted_cells,header_actions,attempted_reconstruction_actions,committed_reconstruction_actions,attempted_group_scalar_calls,attempted_field_mul_calls,committed_group_scalar_calls,committed_field_mul_calls,validation_entries,assignment_copied_elements,map_merge_elements,quadratic_pair_visits,group_preimages,field_preimages,mark_clear_visits,rollback_cells,full_fallbacks,completed_distinct_snapshots. Journal lifetime group_logs/field_logs[u64] at160/168; reserved zero176..192. These counters are authenticated producer telemetry, not verified history or scheduling credit. Preserve saturation flags; near-max lifetime counts must use the accepted saturation behavior. Journal usize values require checked host conversion. FullOnly clean journal counts/flag are zero under current T5, while historical WorkLedger remains intact.

Cursor section: version=1[u16] at0, length=96[u16] at2; phase[u8] at4; reserved zero5..8. u64 at8,16,24,32,40,48,56,64 are done,group_scalar_calls,field_mul_calls,stream,index,stage,overlay_A,overlay_B. Reserved zero72..96. Phase tags0..8: InitialReadyAlias,Materialize,Prepare,Forward,Pointwise,Inverse,Scale,Integrate,Ready. These tags are explicit wire values, not Rust enum discriminants. Exact counters/cursor and initialized cell contents survive reload; no phase is rerun to reconstruct missing buffers.

## 5. Admission ordering and available mathematical invariants

1. Before any payload allocation: use independent provider/context/key expectations and same held file handle; inspect only the fixed header, exact regular-file metadata, version/reserved values, dimensions and checked total length. Require exact package/reduction/session/epoch/commit/revision/generation/statement expectations and caller size bound. N>=2 radix-two, Shape/reduction rows and canonical domain must match trusted package, with v/ell checked independently of N. Authenticate the header **together with the full ciphertext/tag**, not by pretending header preflight authenticates it.
2. Allocate only one bounded quarantined byte buffer; read exactly L and tag with a bounded exact-EOF/growth check. Check the received whole-file digest against the trusted receipt, then detached AEAD. No payload parsing, scalar/group operation, object, secret log or callback before AEAD success; failed buffer cleanup is best effort. Reading/hash/decrypt have explicit byte/work caps. Whole-file digest is not a replacement for authentication.
3. Scan authenticated framing and all scalar-free metadata without state vectors/groups: exact sections/count products/EOF, modes, host conversions, map record counts/indices/order, references/aliases, role permutations, config, cursor integer ranges/counts, generation/distance rules and strict reserved zeros. Bound logical referenced-map scan work as well as distinct-object allocations. Determine all requested decoded capacities, mark initialization, row-validation scratch, public material/verifier scratch and group/field validation work before any decoded vector/group allocation. Check aggregate private/global/admission ceilings, including live old state if replacement recovery retains it, byte buffer, shared public allocation and decoder state. Check actual reserved capacities before filling them. A structural pre-scan cannot establish point validity.
4. Canonical-decode Fr/points into quarantined ownership with subgroup/curve checks and exact canonical re-encoding comparison where necessary; bounded per-cell checks avoid hidden all-pool batch allocations. Validate exactly one assignment through internal complete coordinate-one, canonical, expected-public and full-satisfaction validation; compare its statement digest with the external receipt/caller expectation. Independently verify current ordinary A/B2/C proof. Check A/B1/B2 against assignment and retained r/s using the exact matching PK, with separately bounded/charged MSM scratch/work; do not run the full quotient/projection initializer to load.
5. Check available row/map relations and exact cursor below. Current reduced A/B row evaluations must equal active stored rows plus active maps. For each side, normalized overlay+pending must equal active map. During Materialize, only destination rows index<cursor.index must equal source active rows+overlay; later phases require that equality for all N frozen rows, and current rows=frozen rows+pending. InitialReadyAlias instead requires active/builder generation,distance,token equality, empty overlays and numerical pending=active maps; unused build slots are preserved without pretending they contain frozen rows. FullOnly has no such rows/maps.
6. Recheck exact provider receipt/status/epoch; install only a fully validated fenced state and preallocated receipt. Dynamic token chains cannot be recomputed without discarded history: AEAD/exact trusted commit binds stored tokens. q and partial FFT correctness still relies on the authenticated validated producer. Ordinary verification, row relations and subgroup checks do not prove arbitrary stored projections were computed honestly. Legacy enrollment requires T2's separately trusted exact-cache/package/witness/public/blinder/session context; the legacy digest alone does not authenticate absent labels.

DynamicReady: b>0, checked4b, 0<=t<b, C>=active.distance, C>=builder.distance>=active.distance, active.gen<=builder.gen<=current.gen, C-active.distance<=4b, and t=C mod b. For a real builder, builder.distance>=C-t (actual whole-target freeze including overshoot). InitialReadyAlias has C<b and active/builder distance=0. If a stored snapshot generation equals current generation its token matches the current token and its through-current correction is empty. FullOnly requires t=0 and absent active/builder/pool/maps/cursor; retain C and valid roles without a modulo rule. Roles separately permute group0..3 and field-row0..3; builder.source=active_f; marks are rebuilt as ceil(10N/64) zero words. No telemetry counter substitutes for any checked scheduler quantity.

For cursor validation, let k=log2N, T=N+Nk/2, W=1+19N+4Nk. Phase bases are Materialize=1,Prepare=1+N,Forward=1+2N,Pointwise=Forward+4T,Inverse=Pointwise+4N,Scale=Inverse+4T,Integrate=Scale+4N. Row phases require stream=stage=0,index<N and done=base+index. Pointwise/Scale require stage=0,stream<4,index<N,done=base+stream*N+index. FFT phases require stream<4,stage<=k and index<N if stage0 else index<N/2; done=base+stream*T+(stage0 ? index : N+(stage-1)*N/2+index). Ready/Alias require index=stream=stage=0,done=W. All intermediates/conversions are checked before indexing/shift/resume.

Materialize overlay cursors count exactly entries with row<index; later phases consume the entire overlay. Alias overlays/cursors are empty/zero. Reuse/factor the accepted `reconstruction::validate_cursor` guard through a checked wire-cursor adapter, rather than independently weakening it. Its exact call counts use B=Nk/2 and p=0 at stage0, otherwise (stage-1)*N/2+index. Define fg=min(stream,2)*B+(stream<2 ? p : 0), ff=max(stream-2,0)*B+(stream>=2 ? p : 0), eg=min(stream,2)*N+(stream<2 ? index : 0), ef=max(stream-2,0)*N+(stream>=2 ? index : 0). Required group/field counts are:

| Phase | group_scalar_calls | field_mul_calls |
|---|---|---|
| Alias / Materialize | 0 | 0 |
| Prepare | 2index | 0 |
| Forward | 2N+fg | ff |
| Pointwise | 2N+Nk+eg | Nk+ef |
| Inverse | 4N+Nk+fg | 2N+Nk+ff |
| Scale | 4N+2Nk+eg | 2N+2Nk+ef |
| Integrate | 6N+2Nk+4index | 4N+2Nk |
| Ready | 10N+2Nk | 4N+2Nk |

Scalar-free pre-scan enforces cursor equations and overlay prefixes using bounded borrowed wire indices, before decoded vectors/group operations. After admission retain the same accepted engine guard. All products/conversions are checked. There is no fake initialized-prefix mask: all pool vectors are fully initialized; the cursor defines which recycled cells have their new semantic meaning.

## 6. Immutable files, CAS, faults and sync strength

Hold the serial state owner throughout validation/encoding; no N-scale private clone is implicit. Preflight/allocate all buffers, result receipts and fallible entropy/serialization before CAS. Write header+ciphertext+tag to a fresh fd-relative private exclusive no-follow temp file, synchronize and close, publish a unique `commit-<trusted-id-lowercase-hex>.dync` basename without replacement, reopen/check the exact published inode/bytes under bounded reads, then synchronize the held directory **before** external CAS. Keep old trusted file until definite success. Use only approved safe rustix operations; no overwrite rename/path-following fallback. A co-UID/privileged store attacker can still cause denial/missing-file rebuild; held directory descriptors do not promise availability.

Before CAS failures leave the old exact receipt/file authoritative; reservation remains consumed. Directory-synced new files are still orphans. Known conflict uses the authoritative winner. Dispatched unknown outcome retains old/new files and blocks saves until that exact operation resolves/is definitively fenced; late CAS execution must be tested. After acknowledged CAS, receipt/state installation is infallible/prepared: no verifier, RNG, allocation, fallible sync or injected cancellation converts success to ordinary failure. Cleanup failures are separate committed status, with bounded orphan retention and provider-fenced deletion. Do not delete another winner or the last trusted file to make space. New missing/corrupt trusted storage returns explicit rebuild, never an older valid file.

Load only the exact trusted filename/digest; no newest/max-generation scan. Re-read provider after decode and before use. Missing trust/key/file and authentication failure require explicit rebuild; transient provider outage/conflict/unresolved CAS remain distinct fenced outcomes, not guessed rollback. A failed checkpoint does not undo an already committed live T5 witness update; return live generation and durable receipt separately. Maintenance at unchanged generation gets a fresh revision/commit ID.

Baseline sync tier records actual successful file+directory sync and tested process-interruption semantics on the host. Stronger macOS media sync is accepted only with a separately frozen supported/tested operation sequence; requested unsupported strength fails before CAS. No unqualified power-loss, durable synthetic-provider, secure-erasure or instantaneous distributed-revocation claim follows. Key rotation/re-enrollment for this initial contract changes/fences session epoch and requires explicit validated rebuild; transparent historical-key rotation is unresolved future integration.

## 7. Minimal private-access handoff and outstanding decisions

Transfer only explicit T6 ownership of new encoding/cache/provider modules and narrow **crate-private** adapters in frozen `dynamic.rs`/`reconstruction.rs`, plus necessary module/error registrations. Do not make Current/Active/Root/Current.assignment/raw fields public or introduce a general public deserializer/raw accessor. Required borrowed save access: DynamicState package/tables/config/root/pool/ledger, clean-journal predicate and telemetry; Current assignment/binding/A/B1/B2/C/r/s; Active metadata/maps; Builder metadata/source/overlays/pending/cursor; all physical buffers/roles. Required restore access: validated private assignment constructor, checked Cursor construction/export of private stream/index/stage/overlay, fresh empty zero-mark Journal with restored lifetime counters, and checked DynamicState installation with pending=None. Tables' private forward/reverse/inverse_n need only a crate-private trusted public commitment method. Existing `Pool::validate`, `validate_cursor` and accepted package/material checks stay authoritative.

Prefer owner-module borrowed snapshot/admission methods or a narrowly scoped crate-private view/restore DTO. They must not clone dense vectors or bypass validation, and must restore shared map references once. Read/encode callbacks are internal only and never receive public logging hooks. Parent must grant exact shared-source edits and enforce no concurrent T5 edits; T5 owner confirms these adapters preserve its in-memory physical rollback contract. Freeze source/dependency manifests before the medium worker builds.

**Outstanding, not accepted behavior:** parent must approve these exact offsets/tags/digest prefixes, receipt/provider API and adapter ownership; the worker must propose exact error/outcome types, preflight work/budget interfaces and golden fixtures. Precise dependency features/transitives/version preservation remain a separate pre-build review. Parent's completed T4 primary timings did not establish a reliable Fast crossover, so accepted production directQuadratic remains unchanged; alternative algorithm/schema integration requires explicit future acceptance. A durable provider, transparent key rotation and stronger media tier require their own capability/rollback/fault evidence. These do not block a clearly labeled process-only synthetic P2-E6a implementation after the wire proposal is accepted.

## 8. Exact identities, actions, evidence and limits

Read-only inspection: `rg`, `sed`/`cat`, `git status --short`, `git rev-parse HEAD`, `shasum -a 256`; report-only `apply_patch`. No code/helper/build/test/benchmark/delegation/commit or real/private credential/vector-log read; no execution slot. Unrelated baseline/live edits remain untouched. Parent's accepted T5 17-unit+5-integration/1000-transition gate is context, not evidence for unimplemented persistence.

Initial observed HEAD was accepted T5 `04b01b023311e1869d89381bcc20fe15a43201a2`; later parent documentation work advanced HEAD to `258475eb021570a1ce60349da26c073b4ca609a9`. Final live reconstruction hash is `f3e6b22e8ddd6afda50f5d6cbb89ac3e8db441172dd6b6fda42ea2b38d6b74f0`: read-only `git diff 04b01b0 -- src/reconstruction.rs` confirmed only four appended lines registering `#[cfg(test)] reconstruction_pilot.rs`, with the retained representation/cursor implementation unchanged. Dynamic hash still matches below. This proposal uses the accepted T5 body; it grants no pilot execution or persistence runtime acceptance.

| Input at inspection | SHA-256 |
|---|---|
| persistence-design.md | `a5a20390a990300e560927032b50f378cfafa90db40f339de2471e194b11090e` |
| evidence/t6-security-design.md | `a23b368e687df49f1f18adab24a7cfe7dd5e139e550ade6de985d74dd2572be6` |
| architecture.md | `0a06ee989134459a53c6df7166d35b9de2e5971e7c8706d507a5ebb69330ce15` |
| conformance.md | `58820d362d8cbc2f2b41cb0cc7663d5c26aaac6371f3674c5ec455e034add92a` |
| experiments.md (live documentation) | `42a2504e37532660aa8832d0650a42e79362bc6517fad22c9742aba902f3ead6` |
| src/dynamic.rs | `e20fdcc7e661feac9c069c6592e29aa0a64e196fc098ebb9cbf9a49a70123bac` |
| src/reconstruction.rs | `98140dc0a188d2cf0551cf3b340e584fc5335e25f17fc355c09a66367751b384` |
| src/artifact.rs | `ac675e7ddefb0f16a9394fa1f1a83472bf4decca2a621dfe7747a27b2a2a50cf` |
| src/anchored.rs | `6ef6e2949e414644aac94e77c104a3fdda1bac756a0fcc05b43f01e910a60737` |
| src/delta.rs | `e01256db13e5d8d89333e4a0ddcda14dcdcb35f5a52cd5455322d4b3d61aa879` |
| Cargo.toml / Cargo.lock | `45215cb72b2d609506ced27e4c60f192856f559d43382647cc863da13c46e58f` / `aaf70b9ecf4dbbefc4d6c1cb34a3eabb7762860884f100497a22f92fd70d75c8` |

Derived sizes only: DynamicReady payload L=1216+32v+16K+40E+320N, where E counts distinct map-object entries; FullOnly L=1120+32v. Total file adds1040. Encoded pool=320N bytes (320MiB at N=2^20), separate from retained projective pool memory and all buffer/decode/public/journal capacities. No measured time/memory gain or universal 2GiB fit is asserted. Canonicalization, decompression, subgroup/MSM/proof/row checks, zero-mark reconstruction and zeroization have costs to measure. Trusted validated producer and conditional Groth16/T1 assumptions remain necessary; AEAD/provider do not establish projection correctness, setup provenance, issuer freshness, application authorization, erasure or future timing privacy. T2 source token/checksum chains alone are not durable authentication.

## 9. Required discriminating tests and next gate

Before any persistence acceptance: golden header/payload offsets and exhaustive reserved/enum/count/overflow/EOF mutations; instrumented rejection before decoded allocation/group operations for incompatible identities/caps/roles/cursors; authenticated malformed producer fixtures as well as unauthenticated tampering. Check original/augmented same-N separation and all five public-value alterations. Round-trip N=2/8/16/32/64/128/256, every phase/stage/stream/overlay prefix, InitialReadyAlias versus distinct Ready, both modes/nondefault FullOnly roles, near-max saturated lifetime counts, no-op/overshoot/same-generation revision and map-alias patterns. Compare every canonical pool point/field and all metadata, then two distinct resumed promotions, common-r/s target raw group elements and independently verified ordinary proofs; no projective-triple equality claim.

Exercise byte-budget/global-live peaks and actual capacities, entropy second-draw/failure/duplicates/exhaustion, busy/journal rejection, whole-store valid-file rollback/cross-session swaps, provider restart limitation, key/session invalidation at every boundary, concurrent stale writers, unknown CAS with late completion and definitive fencing, no-follow/source substitution/no-replace collisions, every write/file-sync/close/publish/reopen/directory-sync/CAS/cleanup interruption, exact missing/corrupt trusted commit rebuild and actual sync-tier capability. P2-E6a limits remain max16MiB per record/128MiB test artifacts, sole serialized execution owner and existing watchdog ceilings; no new run is authorized by this review.

Nine-part return: scope T6 wire proposal; deviations explicit mode/point/capacity equivalence and trusted provenance; file this document only; identities above; commands/outcomes read-only/no runtime evidence; measurements versus claims derived sizes only; evidence accepted documents/frozen private schema; security limits external trust/validated producer/capability limits; next gate parent offset/provider/dependency/ownership acceptance, medium implementation, independent high/parent source review and fresh adversarial/round-trip evidence.
