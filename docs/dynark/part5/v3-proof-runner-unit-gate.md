# V3 proof runner unit gate

On October 15, 2026, the isolated `credential-v3-bounded-proof-qualification-v1`
package passed its bounded offline Rust unit gate. The command and immutable
source hashes are recorded in `tools/part5/PROOF-RUNNER-V1-GREEN-REVIEW.md`.

The captured stdout reports **15 passed, 0 failed, 0 ignored**. The external
bounded runner exited 0 after 2.488 seconds, with no cap stop or residual owned
process. Sampled peak owned-tree RSS was 268,320,768 bytes; sampled target/log
storage growth was 11,170,713 bytes. The report is
`artifacts/dynark/part5/v3-proof-runner-v1-green-bounded-001.json`, SHA-256
`77de0b1b71f9bcfaed5c565c6545a218f8b10eac018a607c02bc503a0f153546`.
Its protected stdout and stderr SHA-256 values are
`396a9fbfbb9bce662330e4118ebf83d71d7309c7db9740c802f4d0f7e629c2e2`
and `bfb00105ff85d259e397d45ac6eb7f029a31a83f59d2059662c95b4a53647441`.
The stderr contains existing vendor/dependency warnings and no test failure.

This gate exercises packet, artifact, context, and accounting contracts with
small inputs. It does not generate a v3 Full or Anchor proof, import the large
proving key for a proof run, verify the Solana application, or establish
multi-credential runtime and memory costs. Those are separate gates.
