# V3 qualification release build

The reviewed six-field `credential-v3-bounded` setup/package launcher built
offline and locked in release mode on October 15, 2026. Its executable SHA-256
is `a32006a2d73edf8c42202a78e4b6ab6ff91ff5f84090820e31cde65680b659e5`
(1,756,928 bytes). A byte-identical, owner-readable/executable frozen copy is
under `artifacts/dynark/part5/v3-setup-runner-frozen-001/`, with a protected
directory and no writable mode bits. ROOT must rehash it before setup and
package reload. A future proof binary uses a separate versioned target so it
cannot overwrite this setup runner.

The independent monitor recorded exit zero, no resource stop or residual owned
process, 71.486 seconds, 529,186,816 bytes sampled peak workload RSS and
169,956,515 bytes sampled positive storage growth. The limits were 300 seconds,
4 GiB sampled RSS and 512 MiB new output, with one Cargo job, four Rayon
workers and offline/locked dependencies. These are build measurements, not
setup, package-import or proof measurements. The build emitted existing vendor
and engine warnings; the new launcher emitted none.

- Source `main.rs` SHA-256:
  `2ac7f3f2b81627800ac9e5c13b0318bb38fde2d46354f94437b4b76d532e8cb6`.
- Package-local `Cargo.lock` SHA-256:
  `ba64f07e07c2a5fdf80e0b93c7290c65bc829b35a9231677b703e1b105fd1e5e`.
- Protected monitor receipt SHA-256:
  `c5457770b7df42e94525bb7feb2815f2d66f83b1177cdb421b0aea14b9900ec2`.
- Scrubbed receipt: `results/dynark/part5/v3-prover-release-bounded-001.json`.

No v3 setup, public package reload, Full proof or Anchor proof has yet run.
The next gate must create only one development setup for the frozen R1CS and
record its exact PK/VK/package identities before any certificate-specific
qualification or application adapter is admitted.
