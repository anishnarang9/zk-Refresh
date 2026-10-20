# V3 X.509 final application progress ledger

Updated 2026-10-19 23:45 EDT, during prefreeze source integration. This file records the
resume point; recheck the live process tree, files, and hashes before acting.

| Item | Current state |
| --- | --- |
| Work branch | `codex/engine-focus-oct14`; protocol `26153bf`, ledger `cb7af71`, expiry runner `07a3af3` pushed |
| Final acceptance attempt | Expected Training-027, not frozen or issued; reserve its number only after source and executable checks |
| Next variant | 00, after the new cohort receipt and eight manifests pass |
| Heavy owner PID/session | None after a short locked Cargo unit run; recheck live process tree before any heavy launch |
| Last case exit | Training-025 case 03 exited 1 at `positive_full:disabled-config-negative`; 12 earlier steps passed, no fragment |
| Accepted historical cases | Training-025 variants 00–02 have complete core-path fragments; not reusable as a final eight-case cohort |
| Preserved freeze | Training-026 `freeze.json` SHA-256 `d96643daff635d59234f7e9adf6356a18e437ff6e34e702e59a95d7b980c4283`; inventory SHA-256 `0504c0198989cf60671093bc1625a2a8a4f4850e5eb2a0db8b08888eaad4a782` |
| Current failures | Loaded expired-status 0/8; loaded capacity 0/1; direct whole-session pairs 0/4. Training-025 case 03 failure preserved. |
| Source progress | Expiry runner v2 committed: fresh focused Python check 88 passed and 56 subtests. Capacity Rust module compiled, its 3 unit tests passed; fixture producer/supervisor and loaded proof remain outstanding. Seeded prepare and final acceptance verifier are in independent source workstreams. |
| Next gate | Integrate and focused-test capacity fixture/supervision and seeded whole-session timer, then pin a new runner and create a new source freeze. |

Training-012's completed 20 training pairs lost for Anchor at every registered
update count through 10. Its component-sum timing is retained without a rerun.
The primary final economic workload and target are predeclared in
`v3-final-acceptance-protocol-2026-10-19.md`.
