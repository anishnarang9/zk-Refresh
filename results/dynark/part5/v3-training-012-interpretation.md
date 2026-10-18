# Training-012 matrix interpretation

The publisher-qualified Training-012 evidence covers 60 serial training slots: four repetitions at each of `k = 0, 1, 2, 5, 10`, in Full, semi-dynamic Anchor, and coalesced-Full modes. The [public report](v3-training-012-public-metrics-001/report.md) and [offline-verifiable metrics capsule](v3-training-012-public-metrics-001/metrics.json) contain 20 matched Full/Anchor pairs. The capsule SHA-256 is `4b3914d405202bb1e3b711ea88dd6fca627e721c620cea14816f2507e1c9f582`; the publisher source commit is `0329c4755e03d90169ee8c1662f09ae996a89189`.

| Updates | Median Full total | Median Anchor total | Median paired Full minus Anchor | Median savings |
| ---: | ---: | ---: | ---: | ---: |
| 0 | 175.8 s | 1,310.4 s | -1,133.7 s | -644.8% |
| 1 | 209.1 s | 1,344.6 s | -1,135.6 s | -543.8% |
| 2 | 238.7 s | 1,371.0 s | -1,131.3 s | -474.5% |
| 5 | 325.0 s | 1,453.3 s | -1,128.2 s | -347.0% |
| 10 | 479.2 s | 1,595.7 s | -1,117.1 s | -233.2% |

All 20 paired Full-minus-Anchor differences were negative. No repetition crossed a strict-positive break-even at any sampled `k`, so break-even was **not observed through `k=10`**. The registered 20% total-savings target was not met at any sampled count. No crossover beyond the measured grid is inferred.

Each total adds directly timed source-import-through-effect session wall time to separately timed common preparation, staging, exact signed-history transition, and that mode's ledger clone preparation. These are measured **component sums**, not one directly timed complete arm. The clock audit passed all 60 slots within its five-second tolerance; its largest absolute discrepancy was 0.040 seconds. The local effect transactions sampled 825 bytes and 5,000 lamports each; Full used 184,352 compute units and Anchor used 184,352–184,364. Sampled peak owned-tree RSS spanned 1.30–1.98 GiB for Full and 1.37–2.06 GiB for Anchor; sampled storage growth spanned 194.2–445.7 MB and 194.2–550.2 MB, respectively. These resource and transaction ranges are publisher-side observations from the withheld economics reports, not claims independently recoverable from the public capsule. Complete process-tree CPU accounting is unqualified.

Development setup took 21.340 seconds and cohort preparation 0.983 seconds, disclosed separately rather than charged per request. The synthetic signed-history schedule is a training workload. This comparison evaluates semi-dynamic Anchor, not fully dynamic DYNARK, and it does not establish a directly timed whole-application benefit or heldout acceptance. The public verifier recomputes the capsule's pair arithmetic and checks its receipt/projection bindings; independent validation of private session truth requires the withheld reports.
