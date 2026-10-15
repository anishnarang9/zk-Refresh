# V3 publisher-head tests-first boundary

The 13-test host suite in `program/tests/application_v3_publisher_head.rs`
specifies a per-config, per-issuer, per-publisher PDA with an exact 280-byte
record and an exact 179-byte bind instruction. A publisher-signed transaction
commits the raw SHA-256 envelope digest and exact predecessor sequence/digest,
root/version, source head, and both eligibility epochs. This contract does not
claim that the program parses or verifies detached JSON or Ed25519 envelopes;
the configured offchain verifier must do so against finalized PDA state.

The focused bounded RED run compiled and executed one parser test. It failed
at the expected `AppInstruction::parse` assertion because opcode 13 is not
implemented. Twelve other tests were filtered. The [receipt](../../../results/dynark/part5/v3-publisher-head-red-bounded-001.json)
records exit 101, no resource cap or runner error, no residual owned process,
1.938 seconds, 192,577,536 bytes sampled peak owned-tree RSS, and 8,825,902
bytes sampled logical target growth. Private stdout/stderr remain in
`artifacts/dynark/part5/v3-publisher-head-red-monitor-001`.

The host syscall model covers allocation, including prefunded empty PDAs, but
cannot establish real Solana transaction rollback or loaded SBF behavior. Those
remain separate acceptance gates after the implementation passes this suite.
