# Proof-runner checkpoint repair evidence

## Failure and repair

Training-009 slot 10 (`r1-k5-full`) stopped in proof qualification at cumulative checkpoint generation 3 with `registered update count`; it produced no slot receipt. The failed proof log is `artifacts/dynark/part5/v3-matrix-training-009/slot-r1-k5-full/work/proof.stderr.log`, and the session report records proof exit 1. The original packet remains at `artifacts/dynark/part5/v3-matrix-training-009/slot-r1-k5-full/work/packet.json`.

Commit `362d598` fixes the guard to admit intermediate cumulative checkpoint generations through 10 while the packet parser continues to restrict registered terminal counts to 0, 1, 2, 5, and 10. The Training-010 bounded test report is `artifacts/dynark/part5/v3-proof-runner-training-010-tests-report.json`; its stdout records 24 tests passed, and its monitor report records exit 0, no stop reason, and clean process cleanup. The bounded release-build report is `artifacts/dynark/part5/v3-proof-runner-training-010-release-report.json` and also records exit 0 and clean cleanup. The isolated executable `artifacts/dynark/part5/v3-proof-runner-training-010` has SHA-256 `093659cec842945fd3db15e9e51087b5717d71dcb375fdf60ced58279a5ad19a`.

## Direct k=5 smoke

The first direct smoke used the original Training-009 packet and stopped immediately with `request-only training identities` (`artifacts/dynark/part5/v3-proof-smoke-training-009-r1-k5-corrected-001/stderr.log`). Its bounded report records exit 1 in 0.549 seconds.

The second smoke used an owner-only diagnostic copy at `artifacts/dynark/part5/v3-proof-smoke-training-009-r1-k5-diagnostic-002/packet.json`. A read-only comparison found its only changed top-level field was `proof_source_identity`; the original packet hash remains `2aee0679a3a5336e4d1f6eac24b09efa7016dbd7ea30e006e7885a2dd9880e5e`. The diagnostic packet hash is `9c448d3f446d8fe2f5b2fdbd243993b715ccdca58c9f969c8f4834bf892643ef`, and its source closure is `3333839fa918833c7d95c95cd03a2924532666dc66e28e1745588982de6024f7`.

The bounded smoke report is `artifacts/dynark/part5/v3-proof-smoke-training-009-r1-k5-corrected-report-002.json`; it records exit 0, no stop reason, and 60.316 seconds. The generated proof report at `artifacts/dynark/part5/v3-proof-smoke-training-009-r1-k5-corrected-proof-002/proof-report.json` has SHA-256 `678a082ea31d606a8d35b701d842d932482a34045c737d82a5abe405738984d0` and records:

- `passed: true`, mode `campaign-full-k5`, update count 5, and the diagnostic packet hash above.
- Six Full proofs and 52 ordinary checks: 6 positive, 36 altered-public, and 10 cross-root checks.
- Completed checkpoints at generations 0 through 5, including 3, 4, and 5.
- `setup_executed: false`, `private_cache_persisted: false`, `application_verified: false`, and `admitted: false`.

## Evidence limits

This is proof-only qualification on a relabeled copy of an existing cumulative-training packet. It shows the corrected runner processed that copy through generations 3–5. It does not show that the canonical packet builder emits the new source identity, validate a held-out freeze, produce an application effect, or complete a campaign slot. The original Training-009 packet and slot artifacts were left unchanged; the original packet hash was rechecked after the smoke.
