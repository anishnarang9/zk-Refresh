# V3 application benefit intake — October 16, 2026

Status: Gate 0 source inspection; no new proof, application effect, or benefit result.

## Checkout and identities

- Work branch and upstream: `codex/engine-focus-oct14`; both resolved to `b28b579bd35bd8fddefe993d72720af92938c0a8` at intake. The remote branch matched. There was no tracked diff and no active bounded proof, Cargo build/test, Circom, or local-validator process. Extensive unrelated untracked files remain untouched.
- The plan explicitly continues this branch and uses retained ignored public and private artifacts, so work proceeds in this checkout. Stage exact reviewed paths only.
- The retained development setup manifest SHA-256 was checked on disk as `d31f82e3f147e31b30074b3a570a9d7945c5e1f5d3f3dd74172801abbe984918`; the raw ordinary VK file SHA-256 was `87edb4608c2140f3c7fddc8503e49b68931cda973711ce2c831bd44f1b98a875`. The recorded engine package identity is `61d941890d823433468048dd1bd91da80c1bf7e1b3d2b6f5d509077a47ed06c8`. Package identity is not a file digest. Recheck circuit, profile, compiled witness, adapter and eventual loaded ELF identities at their actual gates.

## Source and authority map

| Boundary | Owning source and current status |
| --- | --- |
| Public plan → exact action | `program/examples/export_v3_request_fixture.rs` builds a finalized request and V3F1 from `RequestPlan`, then checks V3F1 and exports V3F2 with five PDAs and the action at bytes `[164:196]`. A public V3P1 plan input is still absent. |
| Private credential/signer → worker | `tools/part5/prepare_v3_request_fixture.py` verifies bounded DER, issuer/policy, active membership and holder action signature, then makes V3Q1. The Rust-finalized action has not yet been connected to it. |
| Complete witness/relation | `crates/dynark-native-client/src/v3_input_worker.rs`, `v3_input_map.rs`, `v3_relation.rs` compare the 751 compiler-mapped scalars, six publics and all 793,681 R1CS rows of a complete 784,796-coordinate WTNS. The relation checker grants no authorization. |
| Native authority and Full proof | `crates/dynark-native-client/src/v3_setup.rs` checks the shared package. `v3_binding.rs::open_full` returns `Unsupported`; `v3_binding.rs` and `v3_action.rs` are not exported from the native library, only included by tests. `crates/dynark-v3-current-state/src/lib.rs::ConfiguredVerifier::new` returns `Unavailable`, despite internal current-state checks. |
| Ordinary proof and program | `crates/dynark-solana-adapter/src/v3.rs` encodes six ordered publics plus proof as 448 bytes. `program/src/application_runtime_v3.rs` performs Execute preflight and ordinary verification, then returns `Unavailable`; its reviewed private atomic queue effect is disconnected. |
| Loaded effect and measurement | The local supervisor and finalized account-byte procedure in `harness/tests/queue_v2_supervisor.py` are v2-specific. The v3 proof qualification runner consumes prebuilt witnesses and reports no application verification. `results/dynark/phase-2/bootstrap/bounded_runner.py` samples wall/RSS/storage, not CPU. No matched v3 complete-session harness exists. |

## Edit ownership at intake

- Lane A owns only `program/examples/` and focused request-builder tests in `program/tests/` for the V3P1 public plan. The private Python signer bridge under `tools/part5/` remains reserved to the lead until Lane A's public wire is reviewed.
- Lane B owns focused `crates/dynark-native-client/src/v3*.rs` and native tests. `crates/dynark-v3-current-state/` remains read-only until the lead explicitly transfers its authority boundary. `open_full` must stay closed until that boundary is concrete.
- The lead reserves `program/src/application_runtime_v3.rs`, local-validator harness files, measurement tooling, evidence, commits and pushes. A future Lane C receives runtime ownership only after the request-bound Full proof gate and an explicit transfer. The lead owns measurement protocol (Lane D); heldout generation/evidence (Lane E) starts only after artifact freeze.
- Each worker inspects targeted status and diff, edits only its assigned paths, runs small noncompeting tests, and returns evidence. The lead schedules one heavyweight job at a time and stages exact paths.

## Gate order and evidence limit

Lock the V3P1 → V3F1 → V3F2 → V3Q1 contract, connect a fresh training credential to one genuine request-bound Full proof, integrate authenticated current state and the native Full path, then enable the tested queue effect. A second unconsumed request supplies the unrelated-root refresh case. The existing v3 corpus (27 Full proofs, 207 ordinary checks) and one Anchor pilot remain training-stage evidence with synthetic actions. They are not application execution or net benefit. Freeze the measurement method in `v3-matched-session-protocol.md` before tuning; freeze all product artifacts before generating the eight heldout credentials.
