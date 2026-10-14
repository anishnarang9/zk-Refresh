# Complete credential replay under the fixed budget

October 14, 2026. Replay004 completed the registered near, middle, far and new-action cases in one fresh run. It used the unchanged synthetic BN254/Original credential relation, matching before-state anchors and source005. Earlier failed or interrupted runs are preserved and excluded from these results.

The fixed allowance was 2,100 seconds, 4 GiB sampled workload-tree RSS, 2 GiB output growth and four compute workers, with one heavy workload. Runner duration was 1,782.059603 seconds; 7,927 samples observed a 1,459,421,184-byte peak RSS and 453,150,160-byte output growth. Exit was zero with no resource stop, runner error or host cause, and verified zero-process cleanup. Whole-command CPU observations were 4,789.33 user seconds and 28.42 system seconds; these are not per-stage CPU measurements. Sampled limits can miss brief peaks and exclude the additional monitor planning reserve.

## Correctness and work

All three actual-support calculations matched the independent quadratic oracle. Six independently randomized anchored proofs and three full comparators passed ordinary raw and decoded verification; every altered-public correctness attempt was rejected. All nine streamed anchor checks found unchanged state. Thirty supplied-witness and ten complete-refresh near pairs also verified, with two warm pairs excluded. The final ledger reconciled 48 anchored proofs, 46 full proofs, 188 ordinary checks, 50 altered-public attempts, one cache-import verification and 51 charged cross-term calls totaling 259,311,654 pairs, below the 300-million whole-run limit.

| Case | Changed coordinates | Nonzero A/B rows | Cross-term pairs | Fast/oracle equality |
|---|---:|---:|---:|---|
| Near | 5,081 | 2,390 / 2,370 | 5,664,300 | Equal |
| Middle | 2,541 | 1,195 / 1,185 | 1,416,075 | Equal |
| Far | 509 | 239 / 237 | 56,643 | Equal |

The new-action census counted 10,311,177,852 nonzero-support pairs, distinct from the historical 10,502,938,566 touched-support product. Anchor reuse returned `AnchorBinding` before validation, entropy or cross work. Full fallback verified and rejected all five altered publics. No new-action Cartesian traversal ran.

## Near-case refresh measurements

| Pipeline | Paired samples | Anchored median, seconds | Full median, seconds | Median paired Full/Anchor ratio |
|---|---:|---:|---:|---:|
| Supplied witness | 30 | 1.710784 | 2.254241 | 1.317684 |
| Complete local refresh | 10 | 5.067440 | 5.584775 | 1.120560 |

Order was counterbalanced: fifteen/fifteen and five/five pairs began with each method. Supplied-witness ranges were 1.701571–1.842690 seconds anchored and 2.221045–2.401808 full; complete-refresh ranges were 4.848029–5.435238 and 5.400140–6.858086. The median paired ratio is computed from each pair and differs from dividing the two medians. These are repeated observations of one fixed near fixture, not distinct-root churn or tail-latency estimates.

Complete refresh includes fresh witness generation, canonical import and required validation, delta construction where applicable, proof production, encoding, verification and teardown. Public-package import and anchor loading/preparation lie outside these refresh windows. This run observed 93.503974 seconds for package import/identity and 13.377794 seconds for retained legacy-anchor import. Fresh middle and far preparation, including full capture and two private projections, took 692.786095 and 694.029828 seconds. Each prior private anchor was released first. These separate costs must not be omitted from session economics or added twice to overlapping totals.

Middle and far each have two anchored correctness observations and one full comparator, not latency distributions. Actual-support field-oracle timings are one observation per case and exclude group encoding; they do not establish a new crossover. Production retains Quadratic under the separate registered negative comparison. This run contains no dynamic reconstruction or recovery, no session break-even result, and no average-device, original-zkey, Solana or production claim.

Parent inspected the raw report, byte-identical duplicate, full stderr, final host/cleanup records and case events; independently reconciled all measured pair indices, orders, outcomes and statistics; and matched all 55 frozen source/helper hashes. Raw report: `artifacts/dynark/phase-2/fixed-budget/replay-runtime-004-primary.json`, SHA256 `b0131e456595ccf6751706c917adafcc4f817159bbb0eea76b7e969b9b116bd8`. Source manifest: [replay-source-freeze-005.json](../../../../results/dynark/phase-2/credential/replay-source-freeze-005.json). The [execution record](oct14-execution.md) preserves prior failures and subsequent gates.
