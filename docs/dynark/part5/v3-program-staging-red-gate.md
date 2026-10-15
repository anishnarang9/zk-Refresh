# V3 request staging: tests-first RED gate

The frozen 11-test host target covers exact v3 request PDA creation and
account allocation, creator authority, owner/privilege/size checks, bounded
sequential payload and ordered metadata uploads, duplicate rejection,
finalization of immutable action bytes, cancellation, expiry and nonce
tombstones. Request staging is preparatory; live issuer status, proof
verification and queue append remain Execute gates.

The focused bounded test compiled and failed at the intended first upload
assertion: the current runtime returned `Custom(799)` (`Unavailable`) instead
of accepting an authorized sequential payload chunk. One test failed with ten
filtered; runtime was 2.418 seconds, sampled peak owned-tree RSS 230,653,952
bytes, sampled storage growth 9,540,571 bytes, no cap/runner error/residual.
The receipt is `results/dynark/part5/v3-staging-red-bounded-001.json` (SHA-256
`5013bae00a78734c5b6a53fc058604ab143befb1d84959095305c47356c955b2`).
The frozen test source is `program/tests/application_v3_staging.rs` (SHA-256
`0a9b52f9fac68652707860ba07d6a9c82ead7f85f5ec28a2bc3a9f3cc4a9cd66`).

The host CPI stub models fresh CreateAccount only. This RED establishes the
missing handler, not runtime allocation/rollback, proof acceptance or an
atomic queue effect. Those require later loaded-ELF tests.
