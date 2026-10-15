# V3 Execute preflight candidate gate

The read-only preflight checks the six canonical public fields against actual
ordered accounts, exact v3 PDAs/codecs, issuer eligibility, current publisher
head, strictly live source observation, finalized request, action-v2 hash and
queue replay/capacity state. It has no mutable borrow, CPI, proof verification,
or queue effect. Program Execute dispatch remains `Unavailable`.

The [focused bounded receipt](../../../results/dynark/part5/v3-preflight-green-bounded-001.json)
records 8/8 passing tests (2.703 seconds, 184,565,760 bytes sampled peak
owned-tree RSS, 6,809,908 bytes sampled target growth). The
[regression receipt](../../../results/dynark/part5/v3-preflight-regression-bounded-001.json)
records 69/69 passing v3 host tests. Neither run reached a resource cap or left
an owned process. Private command logs remain under `artifacts/dynark/part5/`.

These tests establish a local structural gate only. They do not authenticate
external RPC finality, verify an ordinary proof, or demonstrate an on-chain
authorization. The next program slice must integrate proof verification and
atomic effect in the actual runtime and then load the resulting ELF locally.
