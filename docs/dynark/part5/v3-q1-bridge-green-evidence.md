# Private V3Q1 request input bridge

`tools/part5/prepare_v3_request_fixture.py::build_v3q1` now admits a
supported synthetic DER credential and issuer modulus, checks the signed
issuer/policy bindings, recomputes a depth-10 active membership root from
the certificate TBS digest and selected path, signs the supplied canonical
BE32 action through the retained protected holder key, and verifies that
signature under the admitted holder modulus. It emits the exact 1,918-byte
V3Q1 input for the pinned native worker. The only accepted selectors are
the active and unrelated-root paths; a revoked own leaf cannot be represented
as active.

The focused bounded run in
`results/dynark/part5/v3-q1-bridge-green-001.json` passed 7/7 tests in
1.074 measured seconds. The existing fixture suite also passed 3/3 under
`results/dynark/part5/v3-q1-regression-001.json`. Neither run stopped at a
resource cap, encountered a runner error, or left an owned process. Private
DER, PEM, signatures and candidate bytes remained outside tracked evidence.

The unit test supplies a canonical action value to this boundary. It does
not prove that the action came from a finalized request or authenticated
onchain account. A Rust-derived request action, complete WTNS/relation,
ordinary Full proof, current-state preflight and protected queue effect are
still required before application authorization or submission readiness.
