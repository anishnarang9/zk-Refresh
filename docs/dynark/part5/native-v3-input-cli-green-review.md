# V3 private complete-input CLI candidate gate

The bounded v3 input worker now reads a fixed request from an owner-only
directory and writes a fixed candidate response through exclusive private
file creation. It checks owner, mode, type, link count, exact size, no-follow
opens, stable file handles and metadata. The CLI remains silent and rejects
invalid input without reusing an existing output. It invokes the unchanged
pure mathematical builder and carries no chain authorization capability.

The [CLI receipt](../../../results/dynark/part5/native-v3-input-cli-green-bounded-001.json)
records 12/12 passing tests, 1.707 seconds, 80,953,344 bytes sampled peak
owned-tree RSS and 4,391 bytes sampled test-directory growth. The
[pure-builder regression](../../../results/dynark/part5/native-v3-input-cli-regression-bounded-001.json)
records 7/7 passing tests. Neither run hit a cap or left an owned process.
Private output remains under `artifacts/dynark/part5/`.

The Rust standard client has not yet constructed an authenticated request or
compared this candidate to a complete witness and R1CS relation. No Full or
Anchor application proof follows from this CLI gate alone.
