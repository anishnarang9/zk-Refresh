# V2 application SBF build gate

The actual versioned queue application built under the reviewed local SBF
supervisor on October 15, 2026. This is a build result, not a loaded-validator
or protected-effect result. The separate ELF is at
`artifacts/dynark/part5/application-v2-sbf-build-001/elf/zk_fresh_program.so`
and has SHA-256
`e20d0df801e49e211a5b791d2f1c284240568049656edf8991b7cc00dbe7e639`
(186,984 bytes). The legacy verifier ELF remains SHA-256
`12185308051b933f65dc2ff5a8c25a097ac7968385be31523327f4d196667c20`.

The launcher authenticated the builder and all five `program/src` files plus
the local manifest and lock, refused extra local source modules or includes,
used offline/locked single-job tooling, built into a fresh versioned output,
and checked both build streams for SBF stack warnings. The control status says
`passed` and the child exited zero. The independent process-tree monitor says
`passed`, with no resource stop or residual owned process. Under caps of
180 seconds, 4 GiB sampled workload RSS and 512 MiB positive storage growth,
it measured 2.194 seconds, 298,860,544 bytes sampled peak RSS and 191,385 bytes
sampled positive storage growth. Cached toolchain/build state was available;
these numbers do not represent a clean build.

- Reviewed build config SHA-256:
  `8c227cca49e6f533edc6d1ad2302d5d6afa2e49e85f70b6cbd27a81f090f7ac9`.
- Supervisor source SHA-256:
  `ca81e27ae59b070ad9098429dbf7061a6fdc38f0cad1f808e80dc3fc8463a3ef`.
- Scrubbed bounded receipt: `results/dynark/part5/application-v2-sbf-bounded-001.json`.
- Protected build status:
  `artifacts/dynark/part5/application-v2-sbf-control-001/status.json`.

The next local gate must load these exact ELF bytes into the persisted local
validator, verify RPC-loaded program identity and genesis, and exercise the
synthetic request. No devnet program, transaction or authority is implied by
this build.
