# V3 public ordinary VK projection

A deterministic public-only extractor read the pinned 456-byte Ark ordinary
VK, checked its SHA-256, canonical encoding, seven IC points and adapter-tagged
digest, then emitted the 896 canonical Solana coordinate bytes. The output is
alpha, beta, gamma, delta and seven ordered IC points; G2 components use the
reviewed c1/c0 order. No setup, proof, credential, witness or private key was
read during this extraction.

The [bounded receipt](../../../results/dynark/part5/v3-vk-projection-bounded-001.json)
records exit 0, 1.921 seconds, 183,812,096 bytes sampled peak owned-tree RSS,
4,601,355 bytes sampled target growth, no cap and no residual process. The
private output is 896 bytes, mode 0600, SHA-256
`b3321c0bbc47f8775de86539f04b38e7768c8cefd58d7e62619f99d8b1103c94`.
It remains under `artifacts/dynark/part5/v3-vk-projection-monitor-001/`.

The extractor is source-controlled for reproducibility. The program still
needs the reviewed embedded constant, direct proof verification tests, and
the separate Execute/effect integration.
