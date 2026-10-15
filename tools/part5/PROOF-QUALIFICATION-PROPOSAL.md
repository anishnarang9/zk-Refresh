# V3 Full/Anchor proof qualification: source-only proposal

October 15, 2026. ROOT owns all build/runtime grants. No Cargo or proof command
has run under this proposal. The only new Rust source is an intentionally failing
context-admission scaffold. It has no proof/setup execution path. Positive proof
implementation follows ROOT's observed red test and source review.

The accepted setup runner at
`artifacts/dynark/part5/v3-setup-runner-frozen-001/credential-v3-bounded-qualification`
and its original source/target remain untouched. The new proof package never
contains a setup mode or writes any existing key, witness or receipt.

## Accepted identities and interfaces

| Item | SHA-256 / identity |
| --- | --- |
| Accepted setup manifest | `d31f82e3f147e31b30074b3a570a9d7945c5e1f5d3f3dd74172801abbe984918` |
| Accepted package-check report | `4a8d521fc0890d10878932c67f39629b673dc4f537082b167c4f873bb0212c81` |
| Shared package | `61d941890d823433468048dd1bd91da80c1bf7e1b3d2b6f5d509077a47ed06c8` |
| Circuit | `eae99530daf7331037f2d1c6dc93ccc582603bd448f38d06e6469c734e8252fe` |
| Matrix | `da82ee7cfbe33f6780032bece071a4c2a11d84d4744ba230f4c5149ceb72a471` |
| Engine PK | `14ddfd5773edda5cf02771ebfe2ac4e7af18437848d7822d6d28e2e0085bb671` |
| Engine extended VK | `2611d58c8c8d0b0c1f2c3f0facc4516e5c08e1fb3a7f14b16e32b948bc8f3c70` |
| Raw PK file | `879563839a95ab1a9e5a44b316ba86290918a5cf522863c1ddc58379365293bc` |
| Raw ordinary VK file | `87edb4608c2140f3c7fddc8503e49b68931cda973711ce2c831bd44f1b98a875` |
| Original frozen setup executable | `a32006a2d73edf8c42202a78e4b6ab6ff91ff5f84090820e31cde65680b659e5` |
| Original setup launcher source | `2ac7f3f2b81627800ac9e5c13b0318bb38fde2d46354f94437b4b76d532e8cb6` |
| Original setup local lock | `ba64f07e07c2a5fdf80e0b93c7290c65bc829b35a9231677b703e1b105fd1e5e` |
| R1CS | `976e9a76356ad015f0e4c587ccd79bba601b5caf80817b561aa4ca5442656888` |
| WASM | `fbf73cff59660574add16ba8acafe824a9d57e0c91f23557b6462979b85c9aa6` |
| Compiled symbols | `d2d66e238bdc0a731c86c1897c2978d23908dcc19460582cc873dc2d41e5dbf0` |
| Profile | `2e5d26564fb055e70cff924c4cb6e296509030b8c0062130f86ad5af783f7918` |
| Semantic schema | `eabfaa2d95e4abc9126b87a04e94397091c103891e92dbaefaafba79cf3b26d4` |
| Accepted 52-case relation report | `1878dff43be66019b077c1398805e044e659238b6e74800904e66c803241d044` |

The six ordered public fields are
`[root,issuerHash,notBefore,notAfter,actionHash,policyHash]`, with seven VK IC
entries including constant one. Enforce Original BN254,793681 rows,784796
assignment fields,4257583 matrix terms and radix-2 domain1048576.

The new proof binary authenticates the original setup manifest against the
accepted hash and checks its original setup executable/source/lock provenance
against the values above. It must **not** compare those old provenance fields to
its own new executable/source/lock. Its own compiler-embedded source/lock and
ROOT-measured executable hashes are separately named proof-launcher provenance.
Every key hash is subordinate to the externally authenticated setup receipt;
no imported manifest establishes its own authority.

Reuse the reviewed bounded loader: public profile/compiler files accept0644 or
0600 with static pins; private manifests, WTNS/public files and PK/VK require
owned0600, regular non-symlink files and bounds. Authenticate received PK bytes
before unchecked codec parsing, reject trailing bytes, and immediately use
`PublicPackage::new` for one full key/subgroup/dimension/identity validation.
Require canonical seven-IC ordinary VK bytes equal the package projection.
The raw ordinary file hash is distinct from the still separately versioned
six-field adapter's tagged ordinary VK identity.

## Proposed source and artifact paths

Initial source-only scaffold (RED gate subsequently accepted; current GREEN review is in `PROOF-RUNNER-V1-GREEN-REVIEW.md`):

- `circuits/credential-v3-bounded/qualification/proof-runner-v1/Cargo.toml`
- `circuits/credential-v3-bounded/qualification/proof-runner-v1/src/main.rs`

The new package is `credential-v3-bounded-proof-qualification-v1` and uses the
reviewed dependency versions with a separately generated local lock. After the
red gate, propose focused owned modules `src/artifacts.rs`, `src/context.rs`,
`src/ordinary.rs` and the positive `src/main.rs`; no production API change.
A proposed `tools/part5/prepare_proof_inputs_v1.py` prepares a protected packet
and binds original corpus inputs to complete WTNS coordinates. The source-only GREEN implementation now exists; it is not yet built or qualified.

Use a separate target and future executable:

```
artifacts/dynark/part5/v3-proof-runner-v1-build-001/
artifacts/dynark/part5/v3-proof-runner-v1-build-001/release/credential-v3-bounded-proof-qualification-v1
```

Future assigned private outputs, all fresh0700 directories/create-new0600 files:

```
artifacts/dynark/part5/v3-proof-contexts-v1-private/packet.json
artifacts/dynark/part5/v3-proof-contexts-v1-private/symbol-input-map.json
artifacts/dynark/part5/v3-full-corpus-001/
artifacts/dynark/part5/v3-anchor-pilot-001/
artifacts/dynark/part5/v3-anchor-corpus-001/
```

The existing accepted assignments manifest is
`artifacts/dynark/part5/v3-accepted-assignments-001-private/assignments.json`.
Its trusted expected hash comes from ROOT's protected receipt, never the file.
The setup manifest is `artifacts/dynark/part5/v3-development-setup-001/setup-manifest.json`;
the package-check report is `artifacts/dynark/part5/v3-package-check-001/package-check-report.json`.

A private proof-context packet pins those receipts, the accepted assignments
manifest, the symbol mapping and each original input JSON under
`artifacts/dynark/part5/v3-witness-corpus-001/`. It lists all nine named base/near
pairs and synthetic issuer-enrollment/version, policy/version and allocation
metadata. These synthetic metadata are qualification authority inputs, not real
issuer enrollment/status. Packet hash is a separate ROOT grant argument.

## Credential/action identity and cache boundaries

Before proofs, derive the bounded input-wire mapping structurally from the
pinned `.sym`, with no per-certificate source offsets. Require all six public
and745 declared private input coordinates to have unambiguous in-range witness
indices; reject missing, duplicate, aliased or eliminated required input symbols.
Match every original canonical input scalar to its complete WTNS coordinate.
If the compiler's map cannot support this check, stop for review; do not accept
host-supplied credential labels in its place. This is a full-witness provenance
check, not incremental witness generation.

Derive credential identity from those matched inputs, not a caller's arbitrary
name: the synthetic enrolled issuer/version and SHA256(actual signed TBS), with
package/profile/schema, signed issuerHash/AKI, signed policyHash and holder-key
binding. Stable identity excludes replaceable slot; slot/allocation epoch and
root/version are separate registry context. Define all hash preimages with
versioned tags, lengths and canonical BE scalars in the reviewed context module.
Action binding includes the exact canonical BE32 actionHash and policy/version.
The current corpus signs synthetic field values; those are mathematical proof
inputs, not evidence of a reconstructed application action-v2 request.

The proof runner enforces these checks before reusing a private Anchor:

1. Same package/profile/schema, credential identity, issuer enrollment/version,
   signed policy/version, signer/holder key, action hash and signature, slot and
   allocation epoch. Changed credential, holder, issuer, AKI, org/group policy,
   action or allocation routes to a new Full path and private Anchor.
2. For the qualified retry shape, all nonroot public fields and every private
   input except one Merkle sibling are identical. Root/version/generation must
   advance consistently. Root equality or rollback is not a root-refresh case.
3. Compute sorted canonical deltas from the two complete checked witnesses;
   preserve constant one. Before public updating-table/Anchor preparation,
   check8192-entry and11M quadratic-pair limits with `Transition::validate_target`
   on the validated base and exact near public fields; record full support/work
   statistics and exact target relation satisfaction. No silent cap expansion.
4. Each private Anchor is newly created from that credential's base assignment
   and its own credential/action binding and generation. Its committed
   `anchor_state` includes the captured assignment/root and private projections.
   Keep root/version in the outer context and require transition base binding
   to match the actual Anchor. Check the Anchor binding is unchanged by update.
5. Mutated credential/action/package/generation/anchor-state bindings, swapping
   another holder's target/input/witness/signature and relabeling one cache as
   another must fail before a refresh is emitted. Test stale/replayed generation,
   changed policy/version and slot reallocation explicitly. No two private
   anchors are shared; no v2 cache, projections, blinders or anchor state import.
6. A mismatch is a typed failure or fresh Full start; it never silently reuses
   another credential's cache. Dropped/failed state does not replace an accepted
   context. No private Anchor persistence or durable-restart reuse is exposed.

The engine contract in `crates/dynark-bn254/src/anchored.rs` explicitly calls
`UpdatingMaterial` immutable public updating tables. `prepare` accepts only
`PublicPackage` and `Limits`; stored fields are package identity, lagrange group
tables, weights and diagonal tables, with no credential/action/assignment/blinders.
Its `check` enforces package and domain; clones share table storage. Therefore
one **new v3 package-bound** UpdatingMaterial may be shared inside a single Anchor
corpus process. Prepare it once, charge its full time/memory to that session, and
report both total session cost and the per-credential Anchor preparation cost.
Do not report a credential cost that silently excludes shared preparation.
Every `Anchor` remains sensitive independent private state and is dropped before
the next credential's anchor is constructed. No v2 material/cache is accepted.

The public proof statement hides certificate identity. If two credentials satisfy
identical public fields, ordinary verification alone cannot identify which
credential/cache generated a proof. Do not claim cross-holder ordinary rejection
for identical statements; local context and captured Anchor binding enforce
cache isolation. Changed public statements are separately tested below.

## Full corpus, then independent Anchor pilot/corpus grants

The training selection is exactly `credential_0` through `credential_8` with
all nine `_unrelated_refresh` pairs: eight layouts encoded by cryptography.x509,
two issuer keys, three holder keys, and the independent OpenSSL case 8. Read inputs,
WTNS and public values through the authenticated packet; no new setup or signing
key is needed for these retained mathematical statements.

Full mode loads one package and validates each pair sequentially. Per credential:
Full(base),Full(near),a separately randomized Full(near); serialize/decode each
ordinary proof canonically, independently verify under the same ordinary VK and
six fields, and require the two near proof byte strings differ. For each proof,
change each of the six public fields by Fr+1 and require rejection. Also reject
base-proof/near-root and near-proof/base-root. Exact totals:27 Full proofs,
27 positive checks,162 altered-public negatives and18 cross-root negatives,
207 ordinary checks. Bind all report counts to actually executed operations.

Anchor pilot selects only `credential_8` (OpenSSL), using its own validated base
and near. After preflight, prepare public v3 UpdatingMaterial once; create one
new private base Anchor; refresh to the exact near assignment/public statement;
verify the ordinary proof, all six changed-public negatives and old-root negative.
Match its near public statement to the authenticated, already verified Full
receipt for that case; randomized proof bytes need not match. This receipt
comparison is not counted as another ordinary-verifier call. Run the private binding negatives
above while one Anchor is live, and require its binding remains immutable.

The all-nine Anchor mode is a separately granted process. It loads the same
immutable public package once, prepares new public UpdatingMaterial once and
creates/drops nine independent private anchors sequentially. No pilot-private
cache reuse, no material persistence/recovery shortcut. It produces9 refreshed
proofs,9 positives,54 altered-public and9 old-root negatives:72 ordinary checks.
Across Full+Anchor corpus gates the qualification total is36 ordinary proofs
(27 Full+9 Anchor) and279 ordinary checks. The pilot is additional paid work: running Full corpus, pilot and all-nine
Anchor corpus executes37 proofs and287 ordinary checks in total (pilot adds
one proof/eight checks), even though the final corpus coverage itself has36
proofs/279 checks. Local binding/preflight negatives are reported separately
and are never counted as proofs or ordinary checks.

## Historical cost and proposed resource envelopes

The reviewed v2 proof gate took1214.6seconds: package import53.65s, three Full
proofs/negatives7.03s, public UpdatingMaterial454.95s, private Anchor creation
696.73s and refresh/negatives0.95s. Sampled peak RSS was1454997504bytes.
These are planning evidence, not measured v3 results or speedup claims. The
accepted v3 package check alone took44.552s and about1.091GiB sampled RSS.

| Proposed separate gate | Wall | Aggregate RSS | New output | Scope |
| --- | --- | --- | --- | --- |
| Local offline lock |30s|256MiB|4MiB|New proof package only |
| Intended one-test red |180s|2GiB|512MiB|New target; exactly one assertion failure |
| Positive unit tests |180s|2GiB|512MiB|One thread; no actual proof/setup |
| Release build |300s|4GiB|512MiB|One Cargo job; new target/binary |
| Protected packet/map preflight |180s|512MiB|16MiB|Hash/stream inputs/symbols; no proofs |
| All-nine Full corpus |600s|4GiB|64MiB|One package load,27 Full proofs |
| One OpenSSL Anchor pilot |1800s|4GiB|128MiB|One material preparation+one private Anchor |
| All-nine Anchor corpus, only after pilot review |10800s|4GiB|128MiB|One material preparation+nine private anchors |

Full planning estimate2–5minutes; Anchor pilot15–25minutes; all-nine Anchor
about2hours before extra negative/runtime overhead, with a3-hour provisional
wall cap. These estimates must be replaced with actual v3 samples. The pilot
is paid work and its public/private preparations cannot be omitted from totals.
The full-corpus Anchor grant remains conditional on pilot time/memory/support.
One heavy job, four Rayon workers, one Cargo job, OMP1. ROOT's external
bounded_runner samples the owned process tree, preserves finite private logs
and kills/cleans descendants on any cap. No automatic retry or cap increase.

### Pilot stop criteria

Stop before public UpdatingMaterial if any identity/provenance/input-to-witness
link, complete relation, cache binding, accepted pair classification,8192 delta
or11M pair preflight fails. A newly supported shape requires separate review.
Stop the active pilot on any global1800s/4GiB/128MiB limit, runtime/RNG error,
ordinary positive rejection, unexpected negative acceptance, Anchor/context
mutation or cleanup uncertainty. Preserve the exact last completed stage, failed
operation, elapsed work and private partial output. Record stage start/done
before and after material preparation, Anchor creation and update so ROOT can
observe a slow stage without treating it as progress-free work.

Do not launch all-nine Anchor merely because one refresh verified. ROOT first
reviews total paid pilot cost, peak RSS, material/Anchor preparation and delta/pair
statistics. Pilot failure or over-cap stops this candidate; no weaker profile,
new setup, cache cross-contamination, bypass or hidden retry repairs the gate.

## Exact initial RED packet and future interfaces

New scaffold pins:

- Cargo.toml SHA256: `7768c6770b1d6dad8bdb47641d38e5d655d7dd167f8036e07884b26dbf8d3d93`
- src/main.rs SHA256: `e408ad68af1a4164c1c9a4620e7c9ff3f632f0a0306d7567152f3c49546cb0a4`

Historical RED state: ROOT accepted exactly one executed deliberate assertion failure, exit101,44.057s, under the reviewed caps. Current GREEN source pins and pending unit command are recorded separately in `PROOF-RUNNER-V1-GREEN-REVIEW.md`. No GREEN Cargo build or proof has run.
Environment for every future Cargo command:

```
CARGO_BUILD_JOBS=1
RAYON_NUM_THREADS=4
OMP_NUM_THREADS=1
CARGO_TARGET_DIR=/Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-proof-runner-v1-build-001
```

Exact proposed lock and red commands, under separate finite monitors:

```sh
/Users/anishnarang/.cargo/bin/cargo generate-lockfile --offline --manifest-path /Users/anishnarang/Zk-refresh/circuits/credential-v3-bounded/qualification/proof-runner-v1/Cargo.toml
/Users/anishnarang/.cargo/bin/cargo test --offline --locked --manifest-path /Users/anishnarang/Zk-refresh/circuits/credential-v3-bounded/qualification/proof-runner-v1/Cargo.toml tests::same_credential_action_root_only_refresh_is_admitted -- --exact --test-threads=1
```

Proposed fresh receipts:
`artifacts/dynark/part5/v3-proof-runner-v1-lock-monitor-001/`,
`v3-proof-runner-v1-lock-bounded-001.json`,
`v3-proof-runner-v1-red-monitor-001/`,
`v3-proof-runner-v1-red-bounded-001.json`.
Exactly one executed intended assertion and exit101 are required for red; a
compile/resource failure or zero tests does not establish the gate. Positive
context/loader/proof implementation and green/release commands require subsequent
review. ROOT measures and freezes the eventual proof executable separately.

Runtime entrypoints after accepted GREEN implementation/build (`PROOF_PACKET_SHA` and `FULL_REPORT_SHA` are mandatory ROOT-authenticated pins):

```sh
/Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-proof-runner-v1-build-001/release/credential-v3-bounded-proof-qualification-v1 full-corpus /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-proof-contexts-v1-private/packet.json "$PROOF_PACKET_SHA" /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-full-corpus-001
/Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-proof-runner-v1-build-001/release/credential-v3-bounded-proof-qualification-v1 anchor-pilot /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-proof-contexts-v1-private/packet.json "$PROOF_PACKET_SHA" /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-full-corpus-001/proof-report.json "$FULL_REPORT_SHA" /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-anchor-pilot-001
/Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-proof-runner-v1-build-001/release/credential-v3-bounded-proof-qualification-v1 anchor-corpus /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-proof-contexts-v1-private/packet.json "$PROOF_PACKET_SHA" /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-full-corpus-001/proof-report.json "$FULL_REPORT_SHA" /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-anchor-corpus-001
```

All output paths must initially be absent. Reports contain public artifact/key
identities, case labels, executed checks, paid stage timings and support/resource
statistics; no credential fingerprints, assignments, keys, blinders, projections
or private caches. Ordinary proof files/public statements remain private pending
separate adapter/app evidence. Dynamic,Selective,incremental witness generation,
automatic mode selection and persisted Anchor reload remain disabled.

## Genuine held-out import gate after final implementation freeze

Do not generate a holdout now. First freeze exact circuit/profile/R1CS/WASM/
symbols/schema, setup/PK/ordinary VK/package, final proof runner, client/signer,
registry adapter, six-field ordinary adapter and actual application source/ELF
hashes. Record the separate identities and freeze timestamp in a ROOT receipt.
Then generate/import a new set without edits to source or setup.

Propose four independently OpenSSL-encoded supported certificates, with two
fresh issuer and four fresh holder keys, new positive 16-byte serials, valid
UTCTime periods, varied signed AKI/org/group and layouts 0/3/4/7. Fresh means no
training-key reuse. Keep all DER, WTNS, proofs, registry/action state and synthetic
signer capabilities private. Preserve signer capability for the full acceptance
window, because the earlier training corpus deliberately discarded its keys.
Private synthetic signer files/handles are test-only, protected0700/0600 and
never in Git/logs; no real key or production signer qualification is implied.

For **each** new certificate under the same frozen setup:

1. Import/admit the unseen DER; enroll the fresh issuer modulus+AKI through the
   application authority, enable its signed policy and current authenticated
   registry/status. Account/state enrollment is allowed; code/setup edits are
   not. One signed policyHash/config,policy_id=canonical BE32 policyHash; multiple
   issuers may share a config, another org/group policy uses another config under
   the same circuit/setup.
2. Finalize a fresh exact work request/action-v2 and nonce, sign its canonical
   actionHash using that holder's private synthetic signer, generate Full witness
   and randomized Full proof, verify ordinary+matching six-field adapter+actual
   loaded app, and observe one queue append/consumption.
3. Use a **new** finalized request/nonce for the refresh scenario. It starts with
   its own Full base before publication of an unrelated revocation. Keep that
   request unconsumed; publish the unrelated authoritative root, regenerate a
   complete witness, Anchor-refresh the same action and verify ordinary/app
   authorization at the new root. The stale old-root proof must not execute.
   A consumed baseline Full action cannot double as an unconsumed retry.
4. For another unconsumed action, revoke the held-out credential itself. Reject
   its old-root proof at execution-current app checks and reject a current-root
   active-leaf witness/proof attempt; observe no queue effect/nonce consumption.
   The old proof can remain mathematically valid for its old statement; do not
   claim revocation destroys that proof.

Record per-certificate preparation, public/material and private Anchor costs,
peak memory, Full/refresh/witness/transport/app timings and failed work. Preserve
source/setup/key hashes before and after. A source repair or profile expansion
invalidates this cohort's held-out status: freeze again and generate a genuinely
fresh cohort. Mathematical training proofs do not replace this test. Loaded app
verification, real issuer/status policy, production ceremony and external security
audit remain distinct evidence boundaries.
