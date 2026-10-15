# Bounded v3 compiled-witness corpus result

The frozen `credential-v3-bounded-der-v1` circuit was compiled with Circom
2.2.3, then exercised against a fresh synthetic corpus generated independently
of the original v2 fixture. The R1CS SHA-256 was
`976e9a76356ad015f0e4c587ccd79bba601b5caf80817b561aa4ca5442656888`;
the WASM SHA-256 was
`fbf73cff59660574add16ba8acafe824a9d57e0c91f23557b6462979b85c9aa6`.
Both identities were checked again before the run.

The corpus contained 52 cases: nine new certificates spanning all eight
declared layouts and one OpenSSL-encoded variation, plus an unrelated-root
refresh for each, and 34 malformed or ineligible inputs. It used two synthetic
issuer keys and three holder keys, varied signed policy bytes, serials and
validity intervals, and direct circuit inputs for deliberate host-admission
bypasses. Its private inputs and 18 resulting complete witnesses remain in
ignored 0700/0600 artifacts.

The supervised qualification passed: all 18 accepted cases generated complete
WTNS assignments, each with 784,796 canonical fields and six exact ordered
public inputs, and an independent streaming checker evaluated all 793,681
R1CS constraints per assignment. The checker evaluated 14,286,258 rows in
total. All 34 negative cases stopped at a circuit assertion, including own
revocation, changed signed authorization fields with stale public bindings,
wrong issuer/policy publics, malformed signed profile bytes and an invalid
layout selector. No unexpected acceptance or runtime/serialization failure was
counted as a pass.

| Measured boundary | Observed | Approved stop |
| --- | ---: | ---: |
| Corpus generation wall time | 0.692 s | 60 s |
| Corpus peak sampled workload RSS | 48,545,792 B | 512 MiB |
| Corpus output growth | 362,776 B | 4 MiB |
| Complete witness suite wall time | 155.595 s | 900 s |
| Suite peak sampled workload RSS | 512,147,456 B | 4 GiB |
| Suite output growth | 452,075,946 B | 640 MiB |

The [individual case report](/Users/anishnarang/Zk-refresh/results/dynark/part5/v3-witness-qualification-001.json)
records each case's generation and complete-relation time and classification;
the [corpus monitor](/Users/anishnarang/Zk-refresh/results/dynark/part5/v3-witness-corpus-bounded-001.json)
and [suite monitor](/Users/anishnarang/Zk-refresh/results/dynark/part5/v3-witness-bounded-001.json)
record the process-tree samples, limits, exits and cleanup. Both supervised
commands exited zero without hitting a stop, and no owned child process
remained. `tools/part5/WITNESS-PROPOSAL.md` records the exact commands and
helper identities.

This result establishes complete witness and relation coverage for the tested
synthetic corpus under one frozen R1CS. One shared public setup/package, Full
and DYNARK-refreshed proofs, per-holder cache isolation, v3 application
verification, complete refresh economics and frozen-artifact unseen-credential
acceptance remain open. No incremental witness path is exposed.
