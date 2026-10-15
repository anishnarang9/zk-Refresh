# Native v3 observed source sequence gate

Sequence zero is a sentinel for an unobserved source. The client must reject
it even if other supplied records have equal zero sequences and otherwise
coherent fields. An initialized root version zero can still be valid when a
genuine nonzero source observation is present.

The focused RED test returned `Ok(())` where `StaleIssuer` was required: one
failure, 26 filtered, 0.404 seconds, no cap or residual process. The focused
`v3_input::tests` suite then passed all six cases in 2.349 seconds, 21 filtered,
with no cap or residual process. The sampled peak owned RSS was 239,616,000
bytes; positive storage growth was 599,909 bytes. Public receipts are
`results/dynark/part5/native-v3-zero-source-red-bounded-001.json` and
`results/dynark/part5/native-v3-observe-green-bounded-001.json` (SHA-256
`6cf08a318ce04498acf43f8d00ab6216b5c8df449c7948dc9db3b4538a0af723`
and `e64711be80db0cf584d681b04eadf818f6ca48d15132b48c6bb6377451edde97`).
The reviewed source SHA-256 is
`8cf5450a92c65623d5c7490ea94a52a6ea94b6595d3f76435f0bba713aa83ad5`.

These tests exercise supplied records. An authenticated chain adapter and
issuer source verification remain separate gates.
