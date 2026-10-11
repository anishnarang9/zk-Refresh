# Bounded BN254 full prover (Phase 2 T1)

`PublicPackage` owns one immutable proving key and effective matrix set behind
an Arc. Cloning a package shares its allocation; no updating key/private cache
is created. `ordinary_verifying_key()` copies only the instance verification
query for the independent crates.io ark-groth16 verifier.

Construction consumes the caller's vendor key and original matrices, descriptor,
and **trusted expected PackageIdentity**. `inspect_identity` derives hashes for
an audit/development manifest. Comparing a manifest derived from the same
untrusted inputs does not authenticate a setup. Production callers must obtain
that expected identity through a separate trustworthy channel and establish
setup provenance. Supplied R1CS/WASM/profile digests identify metadata; T1 does
not execute or authenticate a witness generator or prove it matches the R1CS.
The exact ordered public schema must match its digest and instance count.

Identities bind canonical matrix content, all supplied artifact digests,
BN254, exact original or instance-A-augmented row reduction (including one),
radix-two root order omega^i and domain content, seven-transform quotient,
format/serialization version, and canonical PK/VK content. Matrix ordering and
explicit zero/duplicate entries affect identity even if relations are equivalent.
Original and augmented rows are distinct reductions at equal padded N. Checked
key dimensions and trusted content identities are required; hashes alone do not
prove that setup algebra was honestly generated for the claimed relation.

`validate_assignment` accepts exactly v 32-byte canonical field encodings,
checks z0=1 and the exact expected public vector, then checks all reduced R1CS
rows. It returns an opaque `ValidatedAssignment`, tied to the exact package.
Full validation work must be included in future performance comparisons.

`prove` returns a complete ordinary proof, exact public vector/package and the
caller-assigned generation, or a typed error. T1 is stateless: this generation
is not an authenticated persistence commitment and provides no anti-rollback
protection. No sensitive assignment, quotient, raw state or blinder is exported.
The caller supplies `rand` 0.8 RngCore + CryptoRng. Only try_fill_bytes is used;
two independent field elements use unbiased masked 254-bit rejection sampling,
with at most 128 draws per element. Failure on either element returns no proof.
Zero is a possible uniform sample, never a hidden fallback/convenience API.
The trait cannot certify that a caller actually supplies secure fresh entropy.

Supported shapes have a radix-two padded domain N>=2 within BN254 two-adicity;
v, raw constraint rows, reduced rows, k (including one) and N are distinct.
Query lengths, matrix bounds/counts, canonical group validity and denominator
points are checked before proof arithmetic. T2 will add bounded file import;
T1 consumes already allocated matrices/key rather than parsing arbitrary files.
Allocation exhaustion is not modeled as a recoverable Rust error.

Run the small conformance suite with four Rayon threads:

```
RAYON_NUM_THREADS=4 cargo test --locked --manifest-path crates/dynark-bn254/Cargo.toml --test full_conformance
```

Use the Phase 2 bounded runner and sole execution slot when running project
experiments. The tests alone use deterministic tiny synthetic setup/blinders,
and also exercise caller OsRng proofs. They do not establish production setup,
original zkey/Solana compatibility, quantitative BN254 security, or later engine
phases. The independent ordinary verifier is crates.io ark-groth16 0.5.0; the
product quotient/prover is the isolated pinned reference source. See
`vendor/ark-groth16/PATCHES.md` for retained experimental API limits.
