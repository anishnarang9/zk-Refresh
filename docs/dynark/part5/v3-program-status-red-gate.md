# V3 issuer status: tests-first RED gate

The v3 Observe instruction must carry an explicit authenticated active bit. The
old 82-byte wire has no such bit and could turn a signed inactive issuer fact
into an active observation. This revision uses an exact 83-byte wire, with the
canonical active byte at offset 66. Both config and issuer eligibility epochs
remain signed predecessors.

The frozen tests in `program/tests/application_v3_status.rs` (SHA-256
`ff43bdf392ef162e214195849b5bd05580e96e03271f778ceefe601ad0b484ac`)
cover the new parser, old-wire rejection, negative-fact advancement, later
active observation and explicit rebinding, epoch changes, source authority,
freshness, and sequence checks.

One focused tests-first run compiled and failed at the expected assertion:
the old parser rejected the new 83-byte inactive observation. It ran one test
with five filtered, exited 101 in 2.333 seconds, and hit no runtime, RSS, or
storage cap. Sampled peak owned-tree RSS was 229,326,848 bytes; sampled
storage growth was 6,744,403 bytes. No owned process remained. The bounded
receipt is `results/dynark/part5/v3-status-red-bounded-001.json` (SHA-256
`aef5194acce9d900387565d0ad9782b39ba5801a6baa9ca171bd93e0361edbd9`).

This RED gate only demonstrates that the old parser lacks the required
status bit. It does not establish that the revision or the application Execute
path works. The 83-byte wire and all six tests must pass before that claim.
