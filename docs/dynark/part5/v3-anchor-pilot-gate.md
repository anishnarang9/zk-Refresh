# V3 Anchor proof pilot

On October 15, 2026, the bounded proof runner completed one DYNARK Anchor
refresh for `credential_8`, the retained credential issued through the
independent OpenSSL route. It loaded the same frozen development public package
and seven-IC ordinary VK used by the nine-credential Full proof gate. No new
trusted setup ran, and no private Anchor cache was persisted.

The runner validated the complete base/near pair, prepared public updating
material once, created a new private Anchor bound to this credential/action/root
version, and refreshed it for the unrelated-root near case. The refreshed
ordinary proof verified under the six current public fields. Six altered-public
checks and one cross-root check rejected, for eight ordinary checks including
the positive verification. Seven engine binding mutations and 135 local context
mutations rejected. The Anchor binding was unchanged by refresh.

The complete bounded session took **1,487.118 seconds** of measured runtime.
Public updating-material preparation took **732.500 seconds** and this
credential's private Anchor preparation took **704.394 seconds**. Refresh plus
ordinary verification took **0.922 seconds**. Sampled peak owned-tree RSS was
**1,577,566,208 bytes** and sampled positive storage growth was **7,136 bytes**.
The process exited 0 without a resource stop, runner error, or residual owned
process. Its protected proof report is
`artifacts/dynark/part5/v3-anchor-pilot-001/proof-report.json`, SHA-256
`066f23b237eabaf3d70854dba7ece6bede9a7be0c5c80becde08dfff19982245`.
The external bounded receipt is
`results/dynark/part5/v3-anchor-pilot-bounded-001.json`, SHA-256
`8f983c4d91147647820d1a75f2846818739235781fb1f2797ee7db6957e44c27`.

This is **one retained training credential** and a synthetic action/issuer
context. The report correctly records `admitted: false` and
`application_verified: false`. The other eight credentials have Full proofs
but no Anchor refresh yet. A single 0.922-second refresh does not amortize the
measured public and private preparation. Complete v3 witness generation remains
required; no incremental witness path is exposed. A broader bounded Anchor
corpus and actual v3 application execution are separate gates before any
product or economic claim.
