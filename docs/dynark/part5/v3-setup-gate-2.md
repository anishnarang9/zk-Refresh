# V3 shared setup Gate 2: launcher unit tests

The frozen `credential-v3-bounded` qualification launcher passed its offline,
locked unit gate on October 15, 2026. The command ran one Cargo job, one test
thread and four Rayon workers under a 180-second, 2-GiB sampled workload RSS,
512-MiB positive storage-growth monitor. Twelve tests passed, none failed or
were ignored. The monitor measured 2.154 seconds, 239,403,008 bytes sampled
peak workload RSS, 2,668,882 bytes sampled peak positive storage growth, exit
zero, no resource stop and no residual owned process. These are test-build
conditions, not setup or proof measurements.

- Launcher `src/main.rs` SHA-256:
  `2ac7f3f2b81627800ac9e5c13b0318bb38fde2d46354f94437b4b76d532e8cb6`.
- Package-local `Cargo.lock` SHA-256:
  `ba64f07e07c2a5fdf80e0b93c7290c65bc829b35a9231677b703e1b105fd1e5e`.
- Protected monitor report SHA-256:
  `6d83e2c22f61d05e6ded47ac9eaf12049e0161e5d55f26afdf0672e704a2fe54`.
- Scrubbed report: `results/dynark/part5/v3-prover-unit-gate-002.json`.

The launcher pins the frozen R1CS, WASM, profile and accepted 52-case witness
report. It has a one-time OS-CSPRNG development setup mode and a separate
public-package reload mode. The reload path authenticates the manifest and PK
file hashes before decoding, then calls `PublicPackage::new` for complete key,
shape and package-identity checks. Its source and lock digests are recorded as
provenance; ROOT's reviewed executable and receipt pins supply authority.

This gate did not execute setup, load a generated package, generate a proof or
authorize an application request. The release build, one shared setup and
18-assignment reload still require separate finite execution gates.
