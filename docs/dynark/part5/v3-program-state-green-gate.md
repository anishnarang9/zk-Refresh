# V3 application state and parser GREEN gate

On October 15, 2026, the bounded offline program test target passed all **24**
v3 state and parser tests. They cover exact 381-byte config and 374-byte issuer
encodings, request/queue padding, versioned PDA domains, the 450-byte six-field
Execute wire, fixed circuit/package/profile/schema/tagged-VK identities,
administrator/publisher/source authority, status freshness, and exact source
and root predecessors. Delayed Observe and Bind transactions signed before
config or issuer disable/re-enable reject under both lifecycle epochs. A fresh
source observation and publisher bind then restores eligibility. The canonical
action-v2 preimage and reduced hash match the unchanged v2 encoding.

The bounded process exited 0 in **3.009 seconds** with 24 passed, zero failed,
ignored or filtered. It recorded no cap stop, runner error or residual owned
process. Sampled peak owned-tree RSS was **319,389,696 bytes** and positive
storage growth was **10,376,584 bytes**. The external receipt is
`results/dynark/part5/v3-program-slice1-green-bounded-001.json`, SHA-256
`b3561d206d45ace5329fa3094ca1e6305c4bfde6063da5d12950220c7885abd6`.

The loaded v3 runtime remains deliberately fail closed: `process` returns
`Unavailable`, performs no account write, and has no six-field proof verifier.
The generated v3 VK source is identity metadata only. Actual account/PDA
authentication, administrative state writes, protected queue effect, loaded
ELF verification and replay tests are separate gates. This state test result
does not establish application authorization.
