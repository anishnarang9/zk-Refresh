# Training-010 matrix registration

Verified 2026-10-18 from the owner-only public receipts and the registered matrix files. This note records smoke qualification and matrix registration; it does not report a completed matrix result.

## Smoke-002 gate

The separate k=5 Full smoke passed its whole-session gate:

- Outer owner `v3-campaign-full-k5-training-010-smoke-002`: `passed: true`, exit 0, no stop reason or runner error, zero owned processes remaining, cleanup status known.
- Session report: `passed: true`, mode `full`, target count 5, `effect_verified: true`.
- Proof report: `passed: true`, mode `campaign-full-k5`, update count 5, six proofs and 52 ordinary checks. Its source identity matches the Training-010 source freeze.
- Effect report: `passed: true`, one application effect, request consumed, stale R0 rejected.

The effect control status is intentionally recorded as `failed`: the validator was stopped by SIGINT after the verified effect (`exit_code: -2`, reaped, not graceful), so `ledger_reuse_requires_review: true`. The session runner accepted this through its reviewed-shutdown gate; the runner itself exited 0 and was reaped. This status does not authorize reuse of the smoke clone. The smoke is not a matrix slot.

| Artifact | SHA-256 |
| --- | --- |
| Smoke outer report | `de106b61cf0a18061656f6ff256700cbf93a8a3794a12ae1c20d54a8a9bf693d` |
| Smoke session report | `867da2158e664d1102fb77c099458ce68eb1c5a18edfd982a42dad7df8c5c746` |
| Smoke proof report | `2b5b59874d911479bfee25c83f63193d7b10f4f276c7d38d358278a7d3c14c60` |
| Smoke effect report | `3efd8264f6f82899023aff3febb5b7e0f6ff80ce4a6b0ac07d5392f2b324b6bd` |
| Smoke effect control status | `4a631aa9608372a7639bf34be56740938786743fb24efe12a9cc7fdb4551d2a2` |
| Training-010 proof source freeze | `4a2f71902f8f11d590496f1fd7af58f1a33caa783f56bb135575dd63e89d7030` |
| Proof source closure identity | `3333839fa918833c7d95c95cd03a2924532666dc66e28e1745588982de6024f7` |

## Registered matrix pins and order

The manifest at `results/dynark/part5/v3-campaign-matrix-training-010.json` has raw file SHA-256 `4f86a4f2cac6437ea2ddd7d0a39eff8037bc40749e801ff9e86685661855481e`. The validated plan at `results/dynark/part5/v3-campaign-matrix-training-010-plan.json` has SHA-256 `94645a6bb6133bb0352fb0690735e4cfaddcf072079138199dbd56463cef5a1f`. The plan embeds canonical manifest digest `adc0c420f57ce26f766d09457d39b6e7603f1d05a94d533f846806d1d6c3ec8f`; this matches the driver's canonical-JSON digest and the started output's input manifest. The output copy and plan match these registered files.

All manifest tool hashes matched the current files during this check. Key pins are:

| Tool | Path | SHA-256 |
| --- | --- | --- |
| Isolated proof runner | `artifacts/dynark/part5/v3-proof-runner-training-010` | `093659cec842945fd3db15e9e51087b5717d71dcb375fdf60ced58279a5ad19a` |
| Campaign effect supervisor | `harness/tests/queue_v3_local_campaign_effect.py` | `01f27ef23626b235605fca823a0af55e120169885ef7583b79bb8913524fbf39` |
| Effect helper module | `harness/tests/queue_v3_local_execute.py` | `df6fd4ff07bab02fffc8f05c3c58e2e744432a37b23c0ee25bb4addcc2fd430e` |
| Bounded session runner | `results/dynark/part5/session_runner.py` | `77fc4107089d14039af8726051e174a9b6508e09c13b07e2ac1bcc083eec5429` |
| Campaign session script | `tools/part5/run_v3_campaign_session.py` | `ec829bad3b7bee77c50f143da032af706a0d789360b4cee92d16e0bcf06853c6` |
| Effect runner binary | `harness/target/debug/build/zk-fresh-benchmark/0d22d099108927cf/out/queue_v3-0d22d099108927cf` | `7d065e967bb38bcb06e4bf5de6506a94d042301314627b720daa8c19c203b2ff` |
| Matrix driver | `tools/part5/run_v3_campaign_matrix.py` | `a24b7035bbc73032a96a38358a3e68fd0ef9eaa9d7381be781300317faa13ce8` |

The plan has 60 slots: four repetitions, each visiting target counts `0, 1, 2, 5, 10`. Within each count, the mode order is:

| Repetition | Mode order |
| --- | --- |
| 1 | Full, Anchor, Coalesced Full |
| 2 | Anchor, Coalesced Full, Full |
| 3 | Full, Coalesced Full, Anchor |
| 4 | Coalesced Full, Anchor, Full |

## Execution status and limits

The serial driver has initialized `artifacts/dynark/part5/v3-matrix-training-010` with its input manifest, matrix plan, campaign state, and first slot directory (`slot-r1-k0-full`). No `sequence-receipt.json` exists yet. Treat the matrix as in progress; there is no grid result until the final sequence receipt validates all 60 slots and their order.

The campaign envelope is 129,600 seconds (36 hours). The manifest pins each slot's runtime, RSS, and storage limits: RSS is 4 GiB and storage is 512 MiB; runtime varies by count and mode (900–3,300 seconds, with Anchor receiving 2,400–3,300 seconds). The proof stage sets `RAYON_NUM_THREADS=4`. Child CPU time is recorded, but the manifest has no separate CPU-time quota. The matrix driver runs slots serially.
