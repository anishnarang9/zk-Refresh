# Six-field application boundary for the bounded credential profile

This is the October 15 design decision for the successor application. The
`credential-v3-bounded-der-v1` relation has six ordered public fields:
`root, issuerHash, notBefore, notAfter, actionHash, policyHash`. The existing
five-field v2 program and verifier key cannot admit it. A v3 program must use
a distinct instruction/account version, six-field ordinary VK adapter and
tagged key identity. It must not relabel the v2 key or alter action-v2 bytes
without a separate schema review.

One application config enables exactly one signed `policyHash`; its
`policy_id` is the canonical 32-byte big-endian field encoding of that hash.
Execution checks equality with public input six. A config can enroll multiple
eligible issuer hashes, each bound to the exact profile, circuit and enabled
policy. Another signed organization/group policy uses another config and its
own queue, while all configs for the same frozen profile can share one public
proving/setup package. A new individual certificate within an enabled tuple
does not create a new circuit or trusted setup.

The issuer enrollment authority must validate the declared CA key, signed AKI,
chain and purpose for this development profile before enabling its
`issuerHash`. A valid certificate signature alone does not enroll an issuer or
enable its signed organization/group policy. The program checks enabled
issuer and policy state, fresh authenticated status, and the execution-current
published root. The publisher binds each issuer observation's exact source
sequence/digest to the root/version used for execution. Any later root or
source advance fences execution until a new binding is published. This binds
two onchain authorities; it does not establish that an external issuer has
published every real-world revocation.

The setup package is independent of the holder, certificate serial/name/key,
issuer key/AKI, validity interval, supported encoding layout, and signed
policy values. Witness, holder signer, private cache, registry leaf/path,
request nonce and action remain separately scoped. The standard client must
derive the layout from strict DER admission, select an enrolled config and
current authenticated head, and reject unsupported/ineligible credentials with
an explicit reason. These are implementation requirements; no v3 application
proof, queue effect or unseen-credential acceptance is claimed here.
