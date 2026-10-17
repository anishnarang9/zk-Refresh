# v3 matched k=1 application pilot, 2026-10-17

This is one training-credential pair under freeze-003 (`50e07d1cd0312a7bf41d609a7fedc5e2435e4120877cf14671f33cc8a2c1329d`). The two modes used byte-identical base and near inputs, witnesses, request, roots, setup, ordinary VK, proof binary, loaded ELF, and cloned pre-execution ledger inventory. Each mode generated two randomized proofs, performed 16 ordinary Groth16 checks, and executed one protected R1 effect on its own ledger clone. The comparator checks those identities and the equal final protected config, issuer, request and queue bytes. The two final registry-head bytes differ because the clones finalized at different slots.

| Measured item | Full | DYNARK Anchor |
| --- | ---: | ---: |
| Bounded outer session wall | 117.356 s | 1,255.928 s |
| Paid proof-command work | 46.632 s | 1,186.043 s |
| Public Anchor preparation | 0 | 450.336 s |
| Private Anchor preparation | 0 | 689.955 s |
| Refresh plus ordinary verification | not applicable | 0.939 s |
| Sampled peak owned-tree RSS | 1,467,138,048 B | 1,432,190,976 B |
| Sampled peak storage growth | 219,352,316 B | 219,352,338 B |
| Protected Execute transaction | 825 B / 180,436 CU | 825 B / 180,436 CU |

Anchor was **1,138.572 s slower** in outer-session wall time, or 10.702 times Full's wall time. Its public and private preparation together cost 1,140.292 s. The warm 0.939 s refresh is therefore not a session benefit. Both bounded runs passed their registered 2,400 s wall, 4 GiB owned RSS and 1 GiB storage caps and left no owned processes. The application branch supervisor reports `failed` only because it treats the expected SIGINT validator shutdown as exit `-2`; both branch reports independently mark the effect verified.

Interpretation is limited. Full in this pilot still performed a roughly 0.430 s Anchor-support preflight; a fair pooled campaign must omit that Full-only extra. The pre-staged ledger, credential issuance, issuer enrollment, source update, and ledger cloning were outside the timed command, and the registry-history authentication flag is false. The outer monitor records only partial `wait4` CPU, so complete-tree CPU savings are unqualified. This is one k=1 training pair, not a distribution, a measured break-even, held-out acceptance, or an application benefit. The registered 0/1/2/5/10 root-change campaign and signed historical-source integration remain necessary before a final result.

Reproducibility: the scrubbed [pair receipt](../../../results/dynark/part5/v3-matched-k1-pair-001.json) names the matched artifact identities, stage times, effect checks and outer receipt hashes. Its inputs are [Full outer receipt](../../../results/dynark/part5/v3-matched-k1-full-outer-003.json) and [Anchor outer receipt](../../../results/dynark/part5/v3-matched-k1-anchor-outer-002.json). The checked comparator is `tools/part5/compare_v3_matched_k1.py`; run it with the five recorded artifact paths for each mode and a fresh output path.
