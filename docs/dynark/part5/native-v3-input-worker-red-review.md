# V3 complete-input worker tests-first boundary

The new non-authorizing worker contract accepts one fixed 1,918-byte request:
admitted DER, issuer modulus, canonical action field, holder signature, slot,
ten siblings and expected root/issuer/policy fields. Its proposed fixed
24,495-byte response contains the existing 459-byte admission summary and
all 751 canonical Circom inputs in declared order. No caller-provided JSON,
offset, path bit or input scalar is an authority. The RED scaffold performs no
file I/O or cryptographic work and keeps the Full admission path closed.

The test source generates independent `cryptography.x509` credentials and
issuer/holder RSA signatures in memory. It specifies all eight admitted
layouts, exact field output, changed issuer/policy/action/signature, every
sibling, slot and root, revoked leaf and coherent unrelated-root refresh.
Reference source and Poseidon constants have fixed test pins. The scaffold's
declared dependency pins are intentionally unenforced until GREEN source
review; the eventual complete R1CS and concrete chain authority remain
separate gates.

The first launcher invocation stopped before running because its monitored
storage root contained the private output directory. The corrected fresh
[bounded RED receipt](../../../results/dynark/part5/native-v3-input-worker-red-bounded-002.json)
records one test error exactly at `NotImplementedError`, exit 1, no resource
cap or runner error, no residual owned process, 0.569 seconds and 40,173,568
bytes sampled peak owned-tree RSS. Private stderr is under
`artifacts/dynark/part5/native-v3-input-worker-red-monitor-002`.
