# Six-field Solana adapter red gate

The additive v3 adapter tests executed against deliberately failing stubs on
October 15, 2026. Nine tests ran: two independent contract/preserved-v2 checks
passed, and seven failed at the intended six-field digest, parser and verifier
stubs. Cargo compiled successfully; the expected exit code was 101, with no
resource stop or residual owned process. The old five-field adapter source
prefix and its ordinary-VK tag remained unchanged.

The bounded offline/locked test run took 54.693 seconds under a 180-second,
2-GiB sampled RSS and 512-MiB storage-growth envelope. The sampled peaks were
477,872,128 bytes RSS and 203,228,224 bytes positive output growth; the first
build compiled dependencies. The scrubbed monitor receipt is
`results/dynark/part5/v3-adapter-red-bounded-001.json`, with protected test
stdout/stderr in `artifacts/dynark/part5/v3-adapter-red-monitor-001/`.

The tested stub SHA-256 was
`0525ae698e0fd3e227ae47c23e3340fe64a950330b2382135fe6b29325141f11`;
the v3 boundary test SHA-256 was
`c8ca38a6bf9872a638aea1f1838a67e78787bc29cab7ce532e4a6892e9164956`.
The next gate requires a separate successful implementation/test run. This red
gate proves neither the six-field adapter nor v3 application verification.
