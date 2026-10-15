# V3 complete-witness corpus qualification proposal

This is a proposal awaiting ROOT review and a fresh resource grant. No witness,
setup or proof job has run under this proposal. The circuit, profile and compiled
R1CS remain frozen at the successful first compile.

## Scope and expected result

Generate one private corpus with two issuer keys, three holder keys, all eight
supported DER layouts, varied serials/dates/org/group/AKI and one independent
OpenSSL-encoded certificate. Discard synthetic private keys after generating the
signed inputs. No source-generation step consumes certificates.

The exact corpus contains 52 cases: 18 positives (nine credentials and their
unrelated-root refresh pairs) and 34 negatives. Negatives include own-revocation,
incorrect public issuer/policy bindings, actual issuer-signed malformed profile
bytes, signed changed organization/AKI with stale bindings, and an invalid layout.
The actual WASM receives inputs directly, bypassing Python admission. Only an
explicit circuit assertion counts as an expected negative result; runtime,
serialization, resource and loader failures stop the run as failures.

Every positive writes a complete private WTNS and independently checks all
793,681 R1CS rows, canonical field bounds, constant one and exact ordered six
public fields. Retain all eighteen complete witnesses for later separately
granted Full/Anchor qualification. This stage executes no setup, proof, Solana
application, incremental witness path or performance extrapolation.

## Resource proposal

Runtime is unmeasured for v3. Planning estimate: 2–8 minutes for the complete
suite; expected working memory below 2 GiB, with a conservative 4-GiB aggregate
RSS stop. These are estimates, not observed results. Each complete WTNS is about
25.1 MB; eighteen account for about 452.1 MB. Private inputs, public statements,
loader copy and report add a few MB. The 640-MiB output cap leaves bounded margin.

| Stage | Wall stop | Aggregate RSS stop | New output stop | Processes |
| --- | --- | --- | --- | --- |
| Corpus generation | 60 s | 512 MiB | 4 MiB | Python plus sequential OpenSSL child |
| Loader/unit guard | 10 s | 128 MiB | 4 MiB | One Node; no WASM instantiation |
| Actual WASM + complete R1CS | 900 s | 4 GiB | 640 MiB | One Node plus at most one sequential Python checker |

The checker child has its own 60-second timeout. ROOT's external monitor must
apply the aggregate wall/RSS/output caps, capture finite stdout/stderr and kill
the owned process tree on any limit. Stop on the first unexpected acceptance,
positive rejection, complete-relation failure, identity mismatch or runtime
error. Preserve reports, private partial output and paid work. No automatic
retry after failure or a cap. Fresh output directories must be absent initially.
Directories are 0700; corpus, WTNS, statements, loader copies and reports are 0600.

## Exact sequential commands

Working directory: `/Users/anishnarang/Zk-refresh`. ROOT first reviews/freezes
the exact helper sources and their dependencies, confirms the compiler artifacts
match the hashes below and checks both output directories are absent.

Corpus generation (lightweight, but include it in the finite recorded run):

```sh
/Library/Frameworks/Python.framework/Versions/3.14/bin/python3 -B -m tools.part5.corpus --private-out /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-witness-corpus-001
```

Loader guard (no actual WASM instantiated):

```sh
/Users/anishnarang/.nvm/versions/node/v24.10.0/bin/node /Users/anishnarang/Zk-refresh/tools/part5/tests/test_witness_runner.cjs
```

Actual relation qualification, only after the preceding stages and ROOT review:

```sh
/Users/anishnarang/.nvm/versions/node/v24.10.0/bin/node --max-old-space-size=1024 /Users/anishnarang/Zk-refresh/tools/part5/witness_suite.cjs /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-compile-001 /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-witness-corpus-001 /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-witness-qualification-001 /Library/Frameworks/Python.framework/Versions/3.14/bin/python3 /Users/anishnarang/Zk-refresh/tools/part5/witness_check.py /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-compile-001/credential.r1cs
```

The protected `v3-witness-qualification-001/report.json` contains only case names,
classifications, aggregate relation counts, durations and public compiler
artifact identities. Raw values, witnesses and credential fingerprints remain
private. ROOT should hash the private corpus before/after execution in its
protected receipt; do not put credential fingerprints in a public report.

## Frozen compiler identities

- R1CS: `976e9a76356ad015f0e4c587ccd79bba601b5caf80817b561aa4ca5442656888`
- WASM: `fbf73cff59660574add16ba8acafe824a9d57e0c91f23557b6462979b85c9aa6`
- Generated calculator: `cc2d37b2cff2a589dd86f8636f1a1dc9fe4a854550b021aa0cea2e235d14e942`
- circomlib Poseidon constants: `94c9e4b5ea891ab4d1ba626f1d719f8c661014d9b628f6096c803f75f39e3eee`

## Qualification helper identities

These are the reviewed proposal sources; ROOT should recheck before execution.

| Helper | SHA-256 |
| --- | --- |
| `credential_profile.py` | `c960f3d2bb8e72c28c0d6a9164b6eaa17ec2ff4ef36a7e0af23811737470f2e6` |
| `corpus.py` | `8f829e472ac59c52b498235828baa98f5aa9c1aef11f93dbefc576dab7206fed` |
| `poseidon.py` | `82d6a93d2af03f17fe340eb7a2d0edbd47dd774ef205d7332b956c2e8c743d68` |
| `witness_suite.cjs` | `dc8056906e0a6bd709fb6bfdd9eafc4be7db0bf692884e36a1d00b4d40a227be` |
| `witness_check.py` | `5c972a36497100cb63b4a24b966b6fc6cce56a8e86dd9896c3656f63af10f763` |
| `tests/test_qualification.py` | `af9d8656e2768c3ae0488f8373bb4cf8d50e209b8c0649be087d8c35af7bc76b` |
| `tests/test_witness_runner.cjs` | `c919c63009c87a20d0fd92673c93f84017e86716c9019bdfc3c0d23aabcbc657` |

## Limits after a pass

A pass establishes finite synthetic complete-witness relation coverage for these
inputs under this frozen R1CS. It does not establish Full/Anchor proof acceptance,
a reusable setup, loaded application verification, real issuer enrollment/status,
OS/token signing, production ceremony, general PKIX, an external security audit
or the frozen-artifact unseen-certificate product gate. Those require subsequent
individually reviewed work.
