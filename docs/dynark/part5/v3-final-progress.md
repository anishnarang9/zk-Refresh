# V3 X.509 final application progress ledger

Updated 2026-10-20 20:04 EDT, during prefreeze source integration. This file records the
resume point; recheck the live process tree, files, and hashes before acting.

| Item | Current state |
| --- | --- |
| Work branch | `codex/engine-focus-oct14`; pushed through `2cfc746`. Finalizer, acceptance verifier, and freeze inventory source are staged for the next commit. |
| Final acceptance attempt | Expected Training-027, not frozen or issued; reserve its number only after source and executable checks |
| Next variant | 00, after the new cohort receipt and eight manifests pass |
| Heavy owner PID/session | None. The deployment pilot and bounded runner build both exited with known cleanup; recheck live process tree and AC before another heavy launch. |
| Last case exit | Training-025 case 03 exited 1 at `positive_full:disabled-config-negative`; 12 earlier steps passed, no fragment |
| Accepted historical cases | Training-025 variants 00–02 have complete core-path fragments; not reusable as a final eight-case cohort |
| Preserved freeze | Training-026 `freeze.json` SHA-256 `d96643daff635d59234f7e9adf6356a18e437ff6e34e702e59a95d7b980c4283`; inventory SHA-256 `0504c0198989cf60671093bc1625a2a8a4f4850e5eb2a0db8b08888eaad4a782` |
| Current failures | Loaded expired-status 0/8; loaded capacity 0/1; direct whole-session pairs 0/4. Training-025 case 03 failure preserved. |
| Source progress | Capacity Rust compiled with 4 focused unit tests. Runner 004 was built by a bounded uncensored owner and installed at SHA-256 `792941a8ea02929224f9c155323b891b988cbc4956bf8372fb90ad0a9f47f02d`; all ten queue test names are listed, including expiry and capacity. Seeded whole-session source, qualified historical setup accounting, and capacity producer/supervisor are pushed. Finalizer refresh/fill replay, bounded proof receipts, and externally measured stage/proof/clone cost pass 101 integrated focused tests with the producer, analyzer, acceptance verifier, and freeze inventory. No loaded capacity execution yet. |
| Loaded seed/deploy pilot | Seed 003 passed with a pinned local SBPF V0 compatibility profile. Deployment pilot 002 finalized the exact ELF (`298c8c84c504038bafea858370a42872f03b016a09adbadd396dd4322991b99c`), then stopped its validator by reviewed SIGINT. Its outer owner exited 1 uncensored with zero remaining children; the independent `queue_v3_blank_seed.review_prepare` gate passed. Pilot roots are private and preserved; no application case or negative result was produced. |
| Host gate | AC disconnected after the earlier pilots; macOS recorded clamshell sleep at 19:00 EDT. At 20:01 EDT AC is connected and charging at 67%, with no heavy owner. Recheck AC and lid before launch; do not infer the earlier case-03 cause from this separate sleep. |
| Next gate | Commit/push staged source, freeze Training-027 from the independently reviewed prepare-002 status, issue a fresh cohort, and launch variant 00 under the global lock. Capacity loaded proof/negative and direct pairs remain separate later gates. |

Training-012's completed 20 training pairs lost for Anchor at every registered
update count through 10. Its component-sum timing is retained without a rerun.
The primary final economic workload and target are predeclared in
`v3-final-acceptance-protocol-2026-10-19.md`.
