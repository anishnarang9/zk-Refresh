# V3 Execute negative integration RED gate

The new host test starts with a structurally eligible finalized request and
checks 15 invalid Execute cases. They cover request replay states, queue
capacity, disabled policy, inactive/expired issuer observation, changed root or
publisher head, expired request, wrong action/public policy and invalid proof.
For every rejection it snapshots account owner, lamports and bytes and requires
no queue append or request consumption.

The [bounded RED receipt](../../../results/dynark/part5/v3-execute-negative-red-bounded-001.json)
records one passed fixture-identity test and one intended failure: all 15
Execute cases currently return `Unavailable` (custom error 799) instead of
their expected policy or proof error. The run exited 101 with no cap or
residual owned process. Logs remain under
`artifacts/dynark/part5/v3-execute-negative-red-monitor-001/`.

The retained public corpus proof has actionHash 12345, whereas a real request
uses SHA-256 of its action-v2 preimage reduced to the field. A positive
append/consume test needs a newly generated Full proof for that exact request
under the same shared setup. The synthetic proof must never be accepted as
application authorization. This RED gate does not demonstrate an effect,
loaded SBF execution or actual own-leaf revocation.
