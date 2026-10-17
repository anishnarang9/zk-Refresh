# V3 signed-history k=1 training application check

This is one engineering pair under the registered two-certificate training
fixture. It is separate from the four-pair-per-count, held-out campaign. The
controlled demo issuer issued two bounded X.509/RSA certificates. A signed
initial source observation issued both leaves into R0; a signed unrelated
revocation and publisher successor established finalized R1. Rust historical
replay from the empty tree and finalized config, issuer, publisher, request and
queue accounts checked the exact allocation history. Both modes used the same
credential, action, complete R0/R1 inputs and witnesses, setup, ordinary VK,
proof binary, loaded ELF and byte-identical R1 ledger clone inventory.

| Whole bounded session | Full | Anchor |
| --- | ---: | ---: |
| Wall time | 115.326 s | 1244.766 s |
| Proof stage | 46.551 s | 1175.714 s |
| Public updating material | 0 | 447.573 s |
| Private Anchor preparation | 0 | 682.496 s |
| Refresh and ordinary verification | n/a | 0.982 s |
| Sampled peak owned-tree RSS | 1,513,160,704 B | 1,347,895,296 B |
| Sampled storage growth | 219,352,400 B | 219,352,422 B |
| Protected transaction | 825 B, 181,026 CU | 825 B, 181,026 CU |

Anchor cost **1129.440 s more** than Full in this pair. Both finalized exactly
one queue append and request consumption on separate matching ledger clones;
each replay failed. The stale R0 Full wire failed under R1 current-root policy.
An independent third R1 clone then published a signed own-leaf revocation at
R2. Both the R0 Full and R1 Anchor wires failed with policy error 713; the
finalized request and queue hashes stayed unchanged. Its branch result passed,
while its outer command returned 1 because the supervised validator exited on
SIGINT during cleanup. The outer report shows no stop reason or residual owned
processes. That exit is preserved in the receipt.

The matched-pair checker verifies the invocation, signed-history flags,
identical inputs/witnesses and final protected state. Its source-order fix
matches the storage roots actually registered with the bounded runner. The
scrubbed receipts are
[`v3-matched-k1-pair-history-001.json`](../../../results/dynark/part5/v3-matched-k1-pair-history-001.json)
(SHA-256 `6265ce079fbe52661822fe81c3aee8b18bf16882bc43c8f7622c6764d24615d6`)
and [`v3-own-revocation-evidence-history-001.json`](../../../results/dynark/part5/v3-own-revocation-evidence-history-001.json)
(SHA-256 `9e4fd3173ca119270b9e7dc08418d2062034e5279c08c9f6a7c9f9e3fa8d2c3f`).
The raw bounded wall/RSS/storage summaries are adjacent to those receipts.
Private DER, signer keys, witnesses, proofs, signed envelopes, account bytes and
ledger clones remain in owner-only ignored `artifacts/dynark/part5/` paths.

Recheck the scrubbed pair with `python3 -B tools/part5/compare_v3_matched_k1.py`
and the exact `--full-*`/`--anchor-*` artifact paths in the private session
invocations. Recheck the holder revocation with
`python3 -B tools/part5/verify_v3_own_revocation.py` and the private config,
status and outer paths named in its receipt. The original k=1 freeze is
[`v3-matched-k1-freeze-history-001.json`](../../../results/dynark/part5/v3-matched-k1-freeze-history-001.json).
The measured debug harness executable was rebuilt for subsequent campaign
work after this run, so a fresh k=1 replay must rebuild the freeze-pinned
source and reestablish its executable hash before using the private ledger.

This pair does not establish a break-even count or a held-out credential
result. Complete-tree CPU accounting remains unqualified; only whole-session
wall time is directly compared. The k=1 Full path performed the previously
registered Anchor-support preflight, so its timing is engineering evidence
and is not pooled with the amended fair campaign. The single-sibling,
same-action training pattern is synthetic and does not measure issuer churn.
