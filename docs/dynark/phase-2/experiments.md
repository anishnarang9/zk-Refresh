# Experiments and serial execution queue

October 10, 2026. Queue coordinator: orchestrator. No credential-scale setup, preprocessing, proof or allocation run is currently authorized. Inspect active jobs before transferring the slot. Code edits may proceed in disjoint ownership; heavy measurements never overlap.

## P2-E1: trusted full comparator

Recorded before implementation. Hypothesis: an isolated product wrapper preserves the exact original QAP and constant-one assignment, validates inputs, and produces ordinary independently accepted proofs with fallible secure randomness. It also distinguishes equal-domain original and augmented reductions.

Owner/execution slot: `t1_full`, GPT-6.1 Sol high, exclusively for small T1 build/tests. Four Rayon threads. Small tests at most five minutes and 1 GiB process RSS; build at most ten minutes and 2 GiB incremental build storage. No credential-scale input, setup or cache preparation. Stop on limit, mismatched oracle, source mutation or entropy-contract defect; preserve failures. Watchdog/helper code, if needed, must be authored by the worker.

Source: root starting `0365566`; reference pin and local patch hashes recorded before copying. Preserve probe lockfile versions. Test artifacts are small public synthetic relations and fresh development keys; deterministic equality fixtures are test-only. Record resolved dependency/lockfile, source and executable hashes, command/environment, fixed shapes, sample counts and exact outputs. These are correctness trials, not performance claims; no warm-up policy or tail claim applies.

Acceptance: all T1 fixtures from the approved plan, ordinary crates.io ark-groth16 acceptance and explicit altered-statement false, typed failures without panic, immutable package sharing, no test RNG production reachability. Independently rerun consequential tests after worker handoff. Run unchanged probe regression tests serially; preserve reference failures as expected regressions only where already asserted by its tests.

Outputs: `results/dynark/phase-2/t1/` for scrubbed aggregate reports; protected logs/artifacts under `artifacts/dynark/phase-2/t1/`. No secret scalar, witness, raw private state or key dump in reports/commits. A file checksum identifies content but is not authentication.
