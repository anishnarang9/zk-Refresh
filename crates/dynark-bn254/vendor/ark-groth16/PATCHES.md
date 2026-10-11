# Isolated T1 snapshot and patch boundary

Source repository: `experiments/dynark/vendor/DYNARK_`, upstream commit
`c73a380df86d8f5d195f1e20c8a1d86a7dce084b`. Before copying,
`results/dynark/phase-2/t1/reference-snapshot.json` recorded the manifest, README,
all 15 Rust source files and repository-root Apache/MIT license hashes.
No embedded Git metadata, examples, benches, build outputs or private artifacts
were copied. The upstream manifest retains its package name/version `ark-groth16
0.5.0`; the registry verifier of the same name/version is a distinct dependency
source. All resolved dependencies preserve the probe lock identities.

Two preexisting reference patches are preserved byte-for-byte:

1. `dynark_generator.rs`: A/B column arrays use assignment count, not padded N.
2. `dynark_prover.rs`: anchored update uses one OsRng instance instead of test_rng.

The recorded diff SHA256 is
`cce04ed6e83262cfbbb934fe035a77b57c6e54620cf95bf9598c714d241321e0`.
T1 adds **no arithmetic patches** to these source files. Wrapper code in
`../../src` validates matrices/queries/domain/identity and the complete assignment,
then calls the seven-transform quotient and explicit-assignment prover retaining
coordinate one. It verifies that the Nth quotient coefficient is zero before
using the matching N-1 H query.

## Remaining vendor scope

This source retains experimental unchecked APIs, infallible entropy paths,
explicit-blinder and unblinded/raw-state APIs, the known-bad matrix wrapper,
and unreviewed dynamic/cache routines. They are not exported through
`dynark-bn254` and are outside its product proof boundary. Direct dependency on
this vendor crate is not a supported secure product proof API. T1 exposes a
consuming constructor that accepts this key type; it does not re-export the
vendor Groth16 type, modules, setup, prove/update methods or convenience RNGs.
All exported product proof calls use the caller `RngCore + CryptoRng` fallible
boundary. Future modes must reuse that boundary and receive separate review.
