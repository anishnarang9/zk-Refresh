# Native v3 complete-relation admission gate

The next client boundary accepts one **non-authorizing** complete assignment.
Its inputs are the admitted shared v3 setup, the authenticated compiler symbol
map, a candidate returned by the fixed native input worker, canonical input
JSON, a complete WTNS, Full mode and an operation deadline. None of these
objects authenticates issuer enrollment, a finalized request, current chain
state or a holder signer. `V3BoundWitness::open_full` remains closed until
those authorities are connected.

The relation checker derives the exact 14-key compact JSON serialization from
the worker's 751 canonical field scalars and compares the bytes with the
calculator input. The six public fields are in the frozen order `root`,
`issuerHash`, `notBefore`, `notAfter`, `actionHash`, `policyHash`. The other
inputs are `layout`, `slot`, TBS bytes, issuer modulus and signature limbs,
holder signature limbs, ten Merkle siblings and ten path bits. No candidate
JSON field, certificate offset or supplied coordinate index can redefine this
mapping.

WTNS admission requires the exact 25,113,548-byte version-2 container for 784,796
canonical BN254 field values, constant one, and the candidate's six public
values. Every one of the 751 candidate scalars must equal its coordinate from
the fixed-hash `credential.sym` map. Only then does the shared
`PublicPackage::validate_assignment` check all 793,681 relation rows against
the six public values. A private result may hold the validated assignment;
the caller cannot construct, deserialize, inspect or relabel it.

The first positive test uses a fresh independent `cryptography.x509` training
credential and a private synthetic action/tree. Rejections should cover an
altered canonical JSON byte, an altered private WTNS input coordinate, an
altered public field, malformed/noncanonical WTNS and non-Full mode. Keep the
separate pinned Python full-R1CS preflight as independent test evidence; it is
not the native admission decision. Run setup loading and relation checks under
the serialized bounded queue, record release-mode resource costs, and remove
all private fixture files on every return path.

A passing relation gate permits a later randomized Full proof test. It does
not make a synthetic request executable or satisfy the frozen unseen-credential
acceptance gate.
