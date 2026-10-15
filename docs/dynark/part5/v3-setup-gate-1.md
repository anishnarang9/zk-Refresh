# V3 shared setup qualification: first gate

October 15, 2026. The bounded successor circuit and 52-case complete-witness
suite were frozen before the qualification package was built. The compiled R1CS
SHA-256 is `976e9a76356ad015f0e4c587ccd79bba601b5caf80817b561aa4ca5442656888`.
No v3 trusted setup, public package, Full proof, or refreshed proof exists yet.

The new package-local offline lockfile generation exited zero in 0.606 seconds,
with sampled peak workload RSS of 73,416,704 bytes and 26,819 bytes of output
growth. `Cargo.lock` SHA-256 is
`ba64f07e07c2a5fdf80e0b93c7290c65bc829b35a9231677b703e1b105fd1e5e`.
Its dependency versions and checksums match the reviewed v2 lock; only the
local package name differs.

The one intended decoder test then **failed as designed** at the unimplemented
WTNS decoder: one test executed, zero passed, one failed, Cargo exit 101. It
took 42.471 seconds; sampled peak workload RSS was 469,942,272 bytes and
output growth was 173,438,485 bytes. Neither job hit its bound, and both left
zero owned processes. The scaffold source SHA-256 was
`498da550e32eb9629021276c8a36d5747ae8cd78b2deae7b87a34048f2fa9c24`.

The local primary receipts are under
`artifacts/dynark/part5/v3-prover-{lock,red}-bounded-001.json` and
`artifacts/dynark/part5/v3-prover-red-source-freeze-001.json`. Their SHA-256
values are, respectively,
`8d3c6ee04d53a437c68783bc8968a0cbeb97bf782c5343d7a0d88c3b5e345723`,
`ae154933b5dae9a47607279815f38d9ad3393b0c47e50aced2b58a6914099d9d`,
and `6523dc3aa803371a40fe9044461f194d7dc50ff81f9f76b7bd8c5a229d67b962`.
The red test was observed before positive decoder/setup implementation. The
next gate is source and test review, followed by separately bounded unit and
release builds. A passing build does not authorize setup or proofs by itself.
