# Native v3 input candidate structural gate

The Rust client now has a private, non-authorizing transport around the pinned
v3 input worker. It checks fixed request and response sizes, canonical fields,
all 751 independently reconstructed input scalars, and exact summary/request
binding. A bounded child runs a fixed Python interpreter and executes a
same-handle hashed script snapshot. Invocation files are private and removed
on return; cancellation and timeout reap the child.

The [focused receipt](../../../results/dynark/part5/native-v3-input-transport-green-bounded-001.json)
records 5/5 passing structural tests (2.733 seconds, 276,250,624 bytes
sampled peak owned-tree RSS). The [library regression](../../../results/dynark/part5/native-v3-input-transport-regression-bounded-001.json)
records 31 passed, one ignored. Neither run reached a cap or left an owned
process. Private diagnostics remain under `artifacts/dynark/part5/`.

The positive is synthetic and intentionally invalid as a credential. A real
worker roundtrip and admitted credential/action/state source are not yet
tested. The result is only an input candidate; complete WTNS equality, R1CS
validation and an independently verified Full proof remain separate gates.
