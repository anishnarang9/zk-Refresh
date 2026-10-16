# Development v3 request fixture wire

The program's `export_fixture` function derives the finalized action-v2 hash
and five account PDAs from its own `Config` and `Request` codecs. A fixed binary
transport lets the training proof harness consume that result without
reimplementing the action serializer in Python. This transport is local test
data. It does not authenticate a live account, issuer, signer or network.

`V3F1` input is exactly 2,874 bytes: four magic bytes; program ID (32 bytes);
current time (signed 64-bit little-endian); `CONFIG_LEN=381` and
`REQUEST_LEN=2249` (each unsigned 32-bit little-endian); six ordered canonical
32-byte big-endian public fields; then the exact encoded config and request.
The exporter must decode and canonically re-encode both accounts and call the
existing pure `export_fixture` checks. A caller-controlled public action hash
is accepted only when it equals the action derived from the finalized request.

`V3F2` output contains four magic bytes; config, issuer, request, queue and
publisher-head PDAs in that order (five 32-byte values); the canonical
big-endian action field (32 bytes); a little-endian 32-bit preimage length; and
the exact action-v2 preimage. Output length is `200 + preimage_length`. The
holder signs SHA-256 of the 32-byte action field, and the resulting signature
must be checked under the imported credential's holder modulus before witness
generation.

The tests-first compile gate failed only because `export_fixture_from_wire`
was absent (`E0425`); see
`results/dynark/part5/v3-request-wire-red-001.json`. The bounded GREEN run
then passed both exporter tests in 5.042 seconds with no cap stop; see
`v3-request-wire-green-001.json`. An adversarial follow-up passed all three
tests, rejecting wrong magic, lengths, trailing bytes and a mismatched
canonical action; see `v3-request-wire-negative-001.json`. The pure wire
function is implemented.

Bounded binary transport, a request-bound Full proof and application execution
remain separate gates.

The next local harness bridge should use the example as a bounded binary
stdin/stdout filter: read exactly one 2,874-byte `V3F1` record and reject any
extra byte before writing `V3F2`. This keeps the action serializer in Rust
while the protected synthetic holder key stays solely with the signer. The
filter must emit no diagnostic text on stdout and must fail without partial
output on malformed input. It is a development transport, not an issuer or
chain authority.
