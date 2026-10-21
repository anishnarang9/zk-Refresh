# V3 X.509 final application progress ledger

Updated 2026-10-20 20:14 EDT, after case 00 launch. This file records the
resume point; recheck the live process tree, files, and hashes before acting.

| Item | Current state |
| --- | --- |
| Work branch | `codex/engine-focus-oct14`; pushed through `f6afe48`. Frozen source is unchanged; only this ledger edit is pending. |
| Final acceptance attempt | Training-027 freeze and cohort published; eight manifests built. Case 00 is running, not yet accepted. |
| Next variant | 01 only after case 00 has a successful owner exit, complete passed journal and fragment, and clean bounded-child receipts. Stop on the first failure. |
| Heavy owner PID/session | `v3-heldout-training-027-00` launched at 20:14 EDT under the stable `.v3-heldout-heavy.lock` and `caffeinate -is`; private owner is `artifacts/dynark/part5/v3-heldout-launch-training-027-00`. Recheck the live process tree and exit-code file. |
| Last case exit | Training-025 case 03 exited 1 at `positive_full:disabled-config-negative`; 12 earlier steps passed, no fragment |
| Accepted historical cases | Training-025 variants 00–02 have complete core-path fragments; not reusable as a final eight-case cohort |
| Preserved freeze | Training-026 `freeze.json` SHA-256 `d96643daff635d59234f7e9adf6356a18e437ff6e34e702e59a95d7b980c4283`; inventory SHA-256 `0504c0198989cf60671093bc1625a2a8a4f4850e5eb2a0db8b08888eaad4a782` |
| Training-027 issuance | Fresh freeze SHA-256 `9ce4bb4f55f29b8b9808804c40f58ca1986e398aae50e54e80ef913729acec72`; prior-key inventory SHA-256 `c98b90d74a23b70a1c169f589c9e6dc6f4a2841f516ddbeb6b1716d8752df637` with 210 keys. The bounded cohort owner passed in 2.003s, uncensored with zero remaining owned processes. Its parent observation pins receipt SHA-256 `5a4429a3697c3eb8c7c6576da3bd2b3036bb70eb6ace584799d4ca4bded72df0`: eight certificates, eight holders, four issuers, four OpenSSL issuances, variants 0–7. Eight new manifests pin runner-004 and proof-runner-training-010. Issuance is pending application gates. |
| Current failures | Loaded expired-status 0/8; loaded capacity 0/1; direct whole-session pairs 0/4. Training-025 case 03 failure preserved. |
| Source progress | Capacity Rust compiled with 4 focused unit tests. Runner 004 was built by a bounded uncensored owner and installed at SHA-256 `792941a8ea02929224f9c155323b891b988cbc4956bf8372fb90ad0a9f47f02d`; all ten queue test names are listed, including expiry and capacity. Seeded whole-session source, qualified historical setup accounting, and capacity producer/supervisor are pushed. Finalizer refresh/fill replay, bounded proof receipts, and externally measured stage/proof/clone cost pass 101 integrated focused tests with the producer, analyzer, acceptance verifier, and freeze inventory. No loaded capacity execution yet. |
| Loaded seed/deploy pilot | Seed 003 passed with a pinned local SBPF V0 compatibility profile. Deployment pilot 002 finalized the exact ELF (`298c8c84c504038bafea858370a42872f03b016a09adbadd396dd4322991b99c`), then stopped its validator by reviewed SIGINT. Its outer owner exited 1 uncensored with zero remaining children; the independent `queue_v3_blank_seed.review_prepare` gate passed. Pilot roots are private and preserved; no application case or negative result was produced. |
| Training-012 prerequisite | Exact live revalidation failed because the runner-004 build overwrote Training-012's pinned shared Cargo output path. Expected SHA-256 `7d065e967bb38bcb06e4bf5de6506a94d042301314627b720daa8c19c203b2ff`; current file `792941a8ea02929224f9c155323b891b988cbc4956bf8372fb90ad0a9f47f02d`. No exact copy was found among the user-home queue_v3 executables or 30 large retained artifacts. Historical source `a40a7b6` rebuilt under an isolated bounded owner and exited 0 uncensored with zero children, but its binary hashes to `773f5c29a09944f4fd3c94e08046c6217c492f9fc614c029f1912ab418fd2e7a`; source-path metadata differs. A read-only diagnostic that bypassed only the overwritten live pin revalidated all 60 receipts, 20 pairs, clock audit, economics, reconciliation, and total summary. The registered exact gate remains failed. The user explicitly approved proceeding with a disclosed one-pin exception at 20:12 EDT; this does not relabel the gate as passed. Preserve all old matrix outputs and pins. |
| Host gate | AC disconnected after the earlier pilots; macOS recorded clamshell sleep at 19:00 EDT. AC was connected and lid open at case 00 launch. Continue checking power and sleep; do not infer the earlier case-03 cause from this separate sleep. |
| Next gate | Review case 00's live journal and bounded receipts, then its final fragment and cleanup. Only then launch case 01 serially. Loaded capacity and direct pairs remain separate later gates. |

Training-012's completed 20 training pairs lost for Anchor at every registered
update count through 10. Its component-sum timing is retained without a rerun.
The primary final economic workload and target are predeclared in
`v3-final-acceptance-protocol-2026-10-19.md`.
