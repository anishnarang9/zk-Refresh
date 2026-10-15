# V3 Full proof corpus gate

On October 15, 2026, the isolated v3 proof runner loaded the one frozen
development public package and completed Full proving for nine credential
base/near pairs. The corpus varies holders, issuers, serials, validity periods,
signed policy fields and permitted DER layouts; `credential_8` was issued by
an independent OpenSSL path. All pairs use the same circuit, proving material
and seven-IC ordinary VK.

The actual run produced **27** independently randomized Full proofs: one base,
one near, and a second near proof per credential. All 27 verified under the
six ordered public fields. It also executed 162 changed-public negative checks
and 18 cross-root negatives, for **207 ordinary checks** in total. The nine
preflights validated complete base/near witnesses and relation support before
proving. Each near transition had 5,081 delta entries and 5,664,300 counted
pair visits under the reviewed limits. Local context mutation checks recorded
135 rejections. The runner report records `passed: true`, one public package
load, no new setup, no public updating-material preparation, and no persisted
private cache.

The bounded process exited 0 in 111.276 seconds, with no cap stop or residual
owned process. Sampled peak owned-tree RSS was 1,432,174,592 bytes; sampled
positive storage growth was 17,210 bytes. The package import took 40.746
seconds. Three Full proofs plus per-case verification took about 7.2–7.5
seconds for each credential in this one session. The protected proof report is
`artifacts/dynark/part5/v3-full-corpus-001/proof-report.json`, SHA-256
`68c417fde7d283b9b946d207a57cbe27c0b3b9da4de23e68fbced9c404152c75`.
The external bounded receipt is
`results/dynark/part5/v3-full-corpus-bounded-001.json`, SHA-256
`6501660363c99da40eeb2bbf975fbf1e37afa5903d8137af8ac14c024a325ff4`.

These are retained training credentials and synthetic action/issuer metadata.
The proof report correctly records `admitted: false` and
`application_verified: false`. No incremental witness path is exposed. DYNARK
Anchor refresh, actual v3 registry/client/application authorization and the
frozen unseen-credential cohort are separate gates.
