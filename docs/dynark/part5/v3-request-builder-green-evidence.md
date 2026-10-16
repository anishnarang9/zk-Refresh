# Public request-plan builder gate

`program/examples/export_v3_request_fixture.rs` now accepts a public
`RequestPlan`. It validates the configured v3 circuit, package, schema,
profile and ordinary VK identities through the application codec; derives
the config, request and queue PDAs; stages payload and the ordered writable
request/queue metas with the application upload methods; finalizes the
request; derives the exact action and six public fields; and emits the checked
2,874-byte V3F1 transport. The existing V3F1 exporter reconstructs the
derived V3F2 identities and action preimage from those bytes.

The focused positive test passed 1/1 under the bounded runner:
`results/dynark/part5/v3-request-builder-green-001.json`. Its measured
duration was 8.190 seconds, sampled owned-tree RSS peak 173,162,496 bytes,
and sampled debug-target storage growth peak 3,900,772 bytes. There was no
cap stop, runner error or remaining owned process. The test compared decoded
application accounts, independent PDA/action derivation, exact V3F1 bytes
and V3F2 output; the payload crossed a staging chunk boundary.

The existing exporter suite also passed 4/4 after the source change under
`results/dynark/part5/v3-request-export-regression-001.json` (3.707 measured
seconds, no cap stop or runner error). It covers exact stream transport and
malformed or mismatched fixture rejection.

This is local construction of a development request fixture. The plan and
bytes are not authenticated live Solana accounts, and this result establishes
no holder signature, certificate eligibility, current issuer publication,
proof, queue effect or unseen-credential acceptance.

Those focused tests subsequently passed 4/4 under
`results/dynark/part5/v3-request-builder-adversarial-001.json` (2.809
measured seconds, no cap stop or runner error). They show that a root-only
change updates public field 0, and an issuer-only change updates public field
1 and the issuer PDA, while both preserve the action preimage/hash. Payload,
nonce and policy changes each alter the action. Wrong package/profile pins and
payloads above 1,024 bytes are rejected. This verifies local encoding
separation; actual eligibility and current-state enforcement remain open.
