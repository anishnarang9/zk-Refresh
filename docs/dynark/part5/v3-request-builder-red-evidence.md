# Request-plan builder tests-first gate

The committed positive test `program/tests/v3_request_builder.rs` requires a
public request plan to be staged through the application `Request` methods,
finalized, and exported as an exact 2,874-byte V3F1 frame. It independently
derives the five PDAs, action preimage/hash, ordered six public fields, decoded
account bytes, and V3F2 exporter output. Its 777-byte payload crosses the
512-byte staging chunk boundary. The plan uses non-fixture account, root,
issuer, policy, nonce, recipient, and creator values.

The fresh bounded `cargo test --offline --locked --manifest-path
program/Cargo.toml --test v3_request_builder --no-run` receipt is
`results/dynark/part5/v3-request-builder-red-002.json`. It exited 101 in
2.787 measured seconds, with a sampled 180,912,128-byte owned-tree RSS peak.
There was no cap stop, runner error, or remaining owned process. Compiler
diagnostics were only E0422 for the absent `RequestPlan` and E0425 for the
absent `build_request_fixture`; the protected stderr is outside Git. This is
an intended RED, not a passing application test.

The builder's inputs remain untrusted public development metadata. Its
output cannot establish holder possession, credential eligibility, current
issuer enrollment, authenticated chain state, or a valid proof. Those checks
belong to later native, program, and loaded-ELF gates.
