# Experiments and serial execution queue

October 10, 2026. Queue coordinator: orchestrator. No credential-scale setup, preprocessing, proof or allocation run is currently authorized. Inspect active jobs before transferring the slot. Code edits may proceed in disjoint ownership; heavy measurements never overlap.

## P2-E1: trusted full comparator

Recorded before implementation. Hypothesis: an isolated product wrapper preserves the exact original QAP and constant-one assignment, validates inputs, and produces ordinary independently accepted proofs with fallible secure randomness. It also distinguishes equal-domain original and augmented reductions.

Owner/execution slot: `t1_full`, GPT-6.1 Sol high, exclusively for small T1 build/tests. Four Rayon threads. Small tests at most five minutes and 1 GiB process RSS; build at most ten minutes and 2 GiB incremental build storage. No credential-scale input, setup or cache preparation. Stop on limit, mismatched oracle, source mutation or entropy-contract defect; preserve failures. Watchdog/helper code, if needed, must be authored by the worker.

Source: root starting `0365566`; reference pin and local patch hashes recorded before copying. Preserve probe lockfile versions. Test artifacts are small public synthetic relations and fresh development keys; deterministic equality fixtures are test-only. Record resolved dependency/lockfile, source and executable hashes, command/environment, fixed shapes, sample counts and exact outputs. These are correctness trials, not performance claims; no warm-up policy or tail claim applies.

Acceptance: all T1 fixtures from the approved plan, ordinary crates.io ark-groth16 acceptance and explicit altered-statement false, typed failures without panic, immutable package sharing, no test RNG production reachability. Independently rerun consequential tests after worker handoff. Run unchanged probe regression tests serially; preserve reference failures as expected regressions only where already asserted by its tests.

Outputs: `results/dynark/phase-2/t1/` for scrubbed aggregate reports; protected logs/artifacts under `artifacts/dynark/phase-2/t1/`. No secret scalar, witness, raw private state or key dump in reports/commits. A file checksum identifies content but is not authentication.

## P2-E2: canonical transitions and immutable anchors

Recorded before T2 implementation; opens only after T1 review and independent rerun. Owner will be a fresh Sol high worker with explicit transfer of the crate/fork boundary. Small tests at most ten minutes/1 GiB RSS; build at most ten minutes/2 GiB target growth, four Rayon threads. No credential-scale preparation is authorized by this initial record.

Hypothesis: normalized full-coordinate additive transitions and exact anchor binding preserve raw quotient/proof equality with dense target calculations, including cancellation, overlap, public-only-C changes, no-op and reverse updates. File import is bounded by declared file/section/count/entry/allocation ceilings before allocating or performing group arithmetic. Invalid fields, indices, instance split, coordinate-one mutation, target public mismatch, package/setup/action/credential/generation mismatch return typed errors. Entropy failure changes no anchor state.

Independent oracle: polynomial quotient coefficients/encoding and target proof components under common test r/s, followed by ordinary randomized verification. Preserve reference quadratic cross terms. Track touched entries/rows and nonzero rows separately. Generalized shapes include assignment counts above/below N and original/augmented reductions where supported; unsupported shapes are explicit errors. Expected paths `results/dynark/phase-2/t2/` and protected `artifacts/dynark/phase-2/t2/`. Hash sources, lockfile and tiny synthetic fixture identities; retain commands, failed trials and exact comparisons. Stop on mismatch, panic, entropy bypass, baseline mutation or resource bound.

Actual near/middle/far replay requires a separate recorded budget after the small gate. Prefer consuming trusted, hash-matching E2 public/anchor artifacts without repreparing. Compare exact before identities before pairing any cache. The eventual replay must compute a delta from its actual named base; no assumption that independently generated fixture trees share an anchor.

## P2-E3a: public-twiddle allocation microexperiment

Recorded before implementation. Opens after T1 acceptance; it is independent of T2 edits and is not a credential-scale preparation. Sole assigned source will be `crates/dynark-bn254/src/bin/phase2-glv-ablation.rs` (inline tests) and `results/dynark/phase-2/representation/glv/`, with no manifest/lib/vendor changes. Sol medium owns instrumentation and an exact implementation of the T0-reviewed reuse recipe; parent/Sol high must review the multiplication equality before any product integration. This is the second coding worker, at most.

Hypothesis: cached signed decompositions of repeated public twiddles reduce allocation traffic and warm multiplication time enough to repay construction/retention for some repeat counts. Compare unchanged pinned BN254 multiplication with identical endomorphism/sign/joint multiplication using its exact cached decomposition. Do not rewrite the scalar algorithm, change dependencies, cache secret scalars or modify the supported product path. Test decomposition relation, point equality (identity/generator/random/projectively rescaled points), zero/one/minus-one/order-boundary scalars, forward/inverse twiddles and normalization.

Preflight finite point/scalar/repetition counts. Public synthetic microinputs only, supported small domains through N=4096; implementation must keep measured multiply count within 100,000 total per run. Tests/diagnostics/timing each at most five minutes/256 MiB runtime RSS; build at most ten minutes/1 GiB process-tree RSS/2 GiB target growth. One named execution owner at a time; coordinate with T2 and parent before running. No actual credential projection, setup or new dependency permitted.

Use at least 30 counterbalanced measured batches after explicit excluded warm-ups, including decomposition/table construction separately and total cold/warm repeat scenarios. Separate allocation-instrumented diagnostics from timing; record requested live/peak/traffic/calls versus structural table bytes and RSS. No precision claim from short noisy batches; publish all samples, conditions and negative outcomes. Keep or reject based on total paid work and retained memory, not warm timing alone. It establishes a kernel hypothesis only; any full preparation or session claim requires later exact vector equality and separately budgeted end-to-end trials.
