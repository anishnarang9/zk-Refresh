# V3 registry tree GREEN source review

The accepted one-test RED compiled and failed the independent exact leaf
assertion: exit101,34.081s, six filtered tests, no cap/error/residual process.
Receipt SHA256: `676a1fb2f87e82bd44a343d356b798ce47b3545f3296eaa0b2994a74238bfeae`.

GREEN source is authored but **no GREEN Cargo/test/heavy command has run**.
Only the two v3 source files below changed. Existing lib/v2 protocol/storage,
seven committed tests, public vectors, Cargo.toml and Cargo.lock are unchanged.

## Exact pins

| File | SHA256 |
| --- | --- |
| `crates/credential-registry/src/v3/tree.rs` | `798eadc673f459b88431df97b8c33f29da2a8fbaf77ff7318a76b549302af6ab` |
| `crates/credential-registry/src/v3/mod.rs` | `df9643b19348ff31473a3e4a63583904813fbe0f482a1f789329ecc5fcc79d27` |
| `crates/credential-registry/src/lib.rs` | `74b0f31e048c2fe56656a00fba967555039d4faf060f42b308b4eab391f72ff9` |
| `crates/credential-registry/tests/v3_tree.rs` | `447ea126df79ff675dd9755325850e1dca95ca13e82308caf746dfc8e8eda227` |
| `crates/credential-registry/tests/vectors/v3-membership-v1.json` | `5fe328c2fcb56bd039fced406d43e7df37cd91e341f6b388b5ccf53a98bee2a3` |
| `crates/credential-registry/Cargo.toml` | `394f5f86e31c6f0f3617e7a4cc36022c7d05205f875590131b580e6c5022bb83` |
| `crates/credential-registry/Cargo.lock` | `0c6053b17473af31354e18a4aed172d5fd7a45041b9912c86d79b73c5a1f17fc` |

## Implementation and boundary

- Fixed Poseidon(5) leaf domain2026101504; no caller-selected domain.
- Raw SHA256 digest splits into unsigned BE128 halves; it is never reduced as
  a single Fr. Slot below1024 and active boolean become scalar inputs.
- Hash inputs and received root/siblings are canonical BE32 strictly below Fr;
  no modular reduction. Parents use circomlib Poseidon(2)(left,right).
- Ten-level tree; empty leaves zero, inactive allocated leaves retain digest
  with active=0. Empty initialization hashes one identical pair per level.
- Paths are leaf upward, direction `(slot >> level) & 1`.
- Set calculates the leaf and all ten parents before the first mutation.
- Root comparison rejects incorrect membership; inactive-commitment verification
  is supported for math integrity, not application authorization.
- No protocol, enrollment, revocation history, source, freshness, current-head,
  signer, cache or application authority is implemented by tree membership.

The mod.rs change only replaces stale RED documentation. Later authenticated
protocol observations and publisher bindings must include **both config and
issuer eligibility epochs**; enrollment_version remains evidence version.
No protocol/snapshot code was added in this slice.

Rustfmt and tracked diff whitespace checks pass. Compiler/test success remains
pending. Independent vector provenance and the original RED command are in
`REGISTRY-V3-TREE-RED-PROPOSAL.md`.

## Exact proposed bounded GREEN gate

After a separate ROOT grant, recheck pins and fresh monitor/report paths, then:

```sh
env CARGO_BUILD_JOBS=1 RAYON_NUM_THREADS=4 OMP_NUM_THREADS=1 CARGO_TARGET_DIR=/Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-registry-tree-build-001 python3 -B /Users/anishnarang/Zk-refresh/results/dynark/phase-2/bootstrap/bounded_runner.py --owner part5-v3-registry-tree-green-001 --cwd /Users/anishnarang/Zk-refresh --private-output /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-registry-tree-green-monitor-001 --report /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-registry-tree-green-bounded-001.json --runtime-seconds 180 --rss-bytes 2147483648 --storage-bytes 536870912 --storage-path /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-registry-tree-build-001 --poll-seconds 0.25 -- /Users/anishnarang/.cargo/bin/cargo test --offline --locked --manifest-path /Users/anishnarang/Zk-refresh/crates/credential-registry/Cargo.toml --test v3_tree -- --test-threads=1
```

Scope: exactly the seven committed v3 integration tests, including v2/v3
cross-verification. No setup, witness/proof or protocol test job. Existing v2
source behavior remains unchanged and its namespaced tree is exercised by the
committed cross-version test.

Caps:180s wall,2GiB sampled owned-tree RSS,512MiB logical output growth;
one Cargo job/four Rayon workers/OMP1. Existing separate RED target is reused.
Expected warm build plus these small trees:5–30s, below0.5GiB RSS and100MiB
additional output; enforce the caps regardless. Both monitor/report paths were
absent at review. ROOT retained exclusive authority over the heavy queue.

Accept only seven executed passing tests, exit0, no cap/runner error and no
residual owned processes. Preserve stdout/stderr/warnings and exact bounded
receipt. Stop on failure without retry, cap increase or protocol implementation.
