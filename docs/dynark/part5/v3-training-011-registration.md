# Training-011 registration and launch

**Launch evidence checked 2026-10-18 06:09 UTC.** Training-011 is a fresh registered measurement after the [Training-010 sleep interruption](v3-training-010-sleep-interruption.md). This note records registration and launch only; no completed matrix, economics result, break-even result, or heldout acceptance is established.

## Registered identities

| Artifact | SHA-256 |
|---|---|
| Fresh Training-011 manifest, raw bytes | `0b7f6340a34d43e1c1680c1f306a993b36a409e13fc427d24e207df4fa676a96` |
| Fresh Training-011 manifest, canonical JSON | `0b7f6340a34d43e1c1680c1f306a993b36a409e13fc427d24e207df4fa676a96` |
| Actual generated Training-011 matrix plan, raw bytes | `e2b93eaaf756332da274f6407acb4f0d65af63ccab6608ae964a2529663b66ee` |
| Source Training-010 manifest, raw bytes | `4f86a4f2cac6437ea2ddd7d0a39eff8037bc40749e801ff9e86685661855481e` |

The manifest is `results/dynark/part5/v3-campaign-matrix-training-011.json`. The generated plan contains 60 ordered slots: four repetitions × counts `{0, 1, 2, 5, 10}` × Full, Anchor, and coalesced Full. The registered whole-campaign envelope is 129,600 seconds (36 hours). This is a runtime ceiling, not a completion estimate.

The current campaign-state receipt binds the manifest above and records:

- Start: `2026-10-18T06:06:58.227544+00:00`.
- Deadline: `2026-10-19T18:06:58.227544+00:00`.

The [public input projection](../../../results/dynark/part5/v3-training-011-public-projection-001/index.json) has index SHA-256 `57def2c1f1c2cb540226153899f055d8853824791456a24598df80f45bf0dd5c`. Its independent verifier passed the exact three-file inventory, public byte pins, source-index bindings, tool allowlist, and registered 60-slot plan. The two raw source SHA-256 values in that index were rehashed against the current private manifest and plan. This verifies the published design projection and its current source linkage; it does not verify session, effect, or final matrix receipts.

## Sleep prevention and remaining gates

The campaign was launched under `caffeinate -is`. A read-only power assertion check at 06:09 UTC showed both `PreventSystemSleep` and `PreventUserIdleSystemSleep` active under the campaign's caffeinate owner; the host was drawing AC power. These are observed launch-time protections, not proof that the entire campaign remained awake or completed within its envelope.

After successful completion, require all 60 contiguous verified slot receipts and the final verified sequence receipt. Run `tools/part5/audit_v3_campaign_clock_drift.py` with the matrix-pinned Python before economics reconciliation: every bounded outer report's UTC elapsed time must agree with its monotonic duration within the declared tolerance (at most five seconds). Preserve a failed drift audit as failed measurement evidence; do not pool interrupted or sleep-contaminated attempts into matched savings. Training-010's partial receipts remain separate historical evidence.

Only after the complete-grid, receipt, ownership/cleanup, and clock-drift gates pass may the economics pipeline evaluate strict-positive Full-minus-Anchor savings, sampled break-even, and the 20% target. Heldout freeze, fresh issuance, case execution, acceptance, and heldout economics remain separate future gates.
