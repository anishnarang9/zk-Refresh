# Training-010 first three-mode group evidence

**Independent read-only verification:** 2026-10-18 04:37 UTC. This records the first **3 of 60** ordered slots only: repetition 1, `k = 0`, Full, Anchor, then coalesced Full.

| Sequence | Mode | Bounded outer seconds |
|---:|---|---:|
| 1 | Full | 110.489 |
| 2 | Anchor | 1,313.390 |
| 3 | Coalesced Full | 110.269 |

The three receipts form a contiguous chain from a null predecessor, with each subsequent receipt pinning the preceding receipt's SHA-256. Their UTC session intervals do not overlap. Every outer report passed with exit 0, no censoring, no stop reason or runner error, zero remaining owned processes, and known cleanup. Each session passed and recorded `effect_verified=true`; its pinned effect report passed with exactly one effect and request consumption. Each `k=0` proof report passed with one proof and seven ordinary checks. Session, proof/packet, effect-config, nested monitor, effect-status/report, clone, and receipt pins were rechecked against current bytes.

The Full/Anchor/coalesced group matches on freeze, cohort, authenticated root/report, exact request, source identities, outer environment, and common-cost accounting flags; there were no identity mismatches. The current manifest's executable/helper pins, frozen client and registry source bundles, and application source identity were independently rehashed and matched. The corrected proof executable is `artifacts/dynark/part5/v3-proof-runner-training-010`, SHA-256 `093659cec842945fd3db15e9e51087b5717d71dcb375fdf60ced58279a5ad19a`.

Nested effect supervisors retain status `failed` after reviewed validator SIGINT cleanup: validator exit -2, reaped, not graceful; application runner exit 0 and reaped. Their verified finalized effects remain established, but `ledger_reuse_requires_review=true`. This is not a claim of graceful validator shutdown.

## Exact evidence pins

Manifest: `results/dynark/part5/v3-campaign-matrix-training-010.json`; raw-file SHA-256 `4f86a4f2cac6437ea2ddd7d0a39eff8037bc40749e801ff9e86685661855481e`, canonical manifest SHA-256 `adc0c420f57ce26f766d09457d39b6e7603f1d05a94d533f846806d1d6c3ec8f`.

For each mode below, receipt/outer/session/proof paths are respectively:

- `artifacts/dynark/part5/v3-matrix-training-010/slot-r1-k0-MODE/slot-receipt.json`
- `artifacts/dynark/part5/v3-matrix-training-010/slot-r1-k0-MODE/outer-report.json`
- `artifacts/dynark/part5/v3-matrix-training-010/slot-r1-k0-MODE/work/session-report.json`
- `artifacts/dynark/part5/v3-matrix-training-010/slot-r1-k0-MODE/work/proof/proof-report.json`
- Effect: `artifacts/dynark/part5/application-v3-matrix-training-010-r1-k0-MODE-effect/effect-report.json`

Substitute the exact `full`, `anchor`, or `coalesced-full` mode from the table for `MODE`; paths are relative to the repository root. Raw keys, witness data, and logs are not reproduced here.

| Mode | Artifact | SHA-256 |
|---|---|---|
| `full` | receipt | `e54e3339df92f4f0a938c11336c99a8b6e8c1edf800277c5dc0bcb8490d1c0f1` |
| `full` | outer | `aba6ab9f63ee52fa4b0379802435bd0d307f92cf2d60d754f69e87070753b3b4` |
| `full` | session | `cba672db41da5a4dcacc3f537630cbd3d6d16af111330275b80d9c51b8f0caa9` |
| `full` | proof | `b197ac22b87feb155d4c3e941109ee0fb637fc35dbe8e2c794c829d19a2e1f54` |
| `full` | effect | `d56d87fbaadf37de43b627932fe572f87063fb1302cff1f04211680e25b427d0` |
| `anchor` | receipt | `97e474b5eb740e465fc81c411a029642efec11353909ba021ab2ee85623d8f79` |
| `anchor` | outer | `69b4de94afd5307ec951fa9bfdd288f2677c014011b49c71570c392f9c2c07ef` |
| `anchor` | session | `1c997e69a39e1dd904826673b9d6e70e1e48cf794f58b263a0888588c127d0be` |
| `anchor` | proof | `75306eaf6907cab5f6d142604964c052966c8627f5b26c9e687cd15a435e0c63` |
| `anchor` | effect | `27f59bcaae4412ed80175bd6c003d7231b3a0fffe74aefcbadeefbd8802b84ed` |
| `coalesced-full` | receipt | `8a194ea4caf50028afefe627eb488726a68a6e4f1bde76734a44ee2065c49f0a` |
| `coalesced-full` | outer | `eeec0746432799128578dadae436329c38d09fba276999dc35543dbfc3e92e9c` |
| `coalesced-full` | session | `3bab7bf4c6d7d2eaf9e24efd93e377e7849908c2ba43d0d3c7f851dfe5681e29` |
| `coalesced-full` | proof | `c07065c841e5fb21378978314ad79148025f9d4d1388d3c585e9d5bee6dc1baf` |
| `coalesced-full` | effect | `52ba4abeafbbf80c37d0cf2d002aafe5a3e3c4a35ad65329578fe4d3de725040` |

## Limits of this snapshot

This is one directly observed three-mode group, not a complete grid. It establishes no registered total-cost result, measured break-even, 20% savings outcome, or held-out issuance/acceptance result. The listed durations are bounded session walls, not reconciled totals including prior common preparation and clone costs. Complete-tree CPU remains unqualified. Prior failed development attempts remain separate disclosures and are not pooled into these matched measurements. The active matrix may advance beyond this dated snapshot.
