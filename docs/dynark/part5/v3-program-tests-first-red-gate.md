# V3 program tests-first RED gate

The first bounded parser attempt on October 15, 2026 compiled the program
library but stopped at a test-only type error: a new assertion compared v2 and
v3 `Result` values whose error enums differ. It executed no test. Its receipt
is `results/dynark/part5/v3-program-slice1-red-bounded-001.json`, SHA-256
`752fd34adf4e83497a8ce97db4c7c745098627409bb2aee37a22a6b2f6135406`.
The test expression was corrected to compare the unwrapped 32-byte hashes;
the v3 behavior stubs were unchanged.

The fresh second attempt compiled and executed exactly
`v3_parser_is_six_fields_exact_and_cannot_accept_v2_transport`. It failed at
the intended assertion: the v3 parser returned `Err(Unavailable)` where the
test expected the exact 450-byte six-public-field Execute instruction. Nineteen
other v3 tests were filtered. Cargo exited 101 in 2.374 seconds; the bounded
runner recorded no cap stop, error or residual owned process. Peak sampled
owned-tree RSS was 230,375,424 bytes and positive storage growth 4,693,660
bytes. The second receipt is
`results/dynark/part5/v3-program-slice1-red-bounded-002.json`, SHA-256
`6d4ed031af60de7da1c07f77f741a844a3f3050923a10b74a3565167beb0547e`.

At this gate, all v3 state/parser methods are fail-closed scaffolds and v3
runtime dispatch cannot verify a proof or write application state. The test
suite includes strict config and issuer eligibility epochs so a status
observation signed before disable cannot be relabeled after re-enable. GREEN
implementation and a separate loaded-ELF application gate remain pending.
