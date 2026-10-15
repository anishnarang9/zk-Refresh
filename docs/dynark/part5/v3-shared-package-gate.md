# V3 shared public package and complete assignments

The exact v3 development setup was reloaded from its externally pinned
manifest and PK/VK file hashes on October 15, 2026. The frozen launcher checked
the Original-reduction six-field descriptor, full key validity and expected
engine package identity, then compared the canonical ordinary VK bytes with
the package projection. It loaded **one** public package and validated all 18
accepted complete witness assignments against that same package. The nine
credential pairs retained identical nonroot public fields and different
unrelated-revocation roots. This establishes package/assignment compatibility
for the fixed corpus without any per-certificate setup.

The protected report says `passed`, 18 complete assignments, nine root-refresh
pairs, one package load and seven ordinary VK IC entries. It repeats package
identity `61d941890d823433468048dd1bd91da80c1bf7e1b3d2b6f5d509077a47ed06c8`
and raw ordinary VK file SHA-256
`87edb4608c2140f3c7fddc8503e49b68931cda973711ce2c831bd44f1b98a875`.
The authenticated setup manifest SHA-256 was
`d31f82e3f147e31b30074b3a570a9d7945c5e1f5d3f3dd74172801abbe984918`;
the separate private 18-assignment manifest was SHA-256
`15006bcb133cf56fd76d22443dbc7f6cc51b7673a4802bf4c80155af8321808f`.

Under a reviewed 600-second, 4-GiB sampled RSS, 64-MiB new-output envelope,
the independent monitor recorded 44.552 seconds, 1,091,469,312 bytes sampled
peak workload RSS, 3,831 bytes positive storage growth, exit zero, no stop and
no residual owned process. Its scrubbed receipt is
`results/dynark/part5/v3-package-check-bounded-001.json`; the scrubbed package
summary is `results/dynark/part5/v3-package-check-summary-001.json` (SHA-256
`4a8d521fc0890d10878932c67f39629b673dc4f537082b167c4f873bb0212c81`).
The private witness files, PK and assignment manifest stay under ignored
owner-only artifacts.

No v3 Full or DYNARK-refreshed proof, six-field Solana adapter, application
authorization or frozen unseen-credential acceptance has passed. The report's
`admitted: false` marks that product/application boundary; it does not negate
the recorded public-package and relation checks.
