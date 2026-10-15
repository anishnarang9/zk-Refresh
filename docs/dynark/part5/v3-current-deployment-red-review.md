# V3 finalized deployment verifier tests-first boundary

The new `dynark-v3-current-state` crate has an acyclic boundary: it depends on
the registry and program codecs, and does not depend on the native client. The
public production constructor and the authorization capability still have no
minting path. A private scripted transport in one unit test requests the
program, ProgramData, config and Clock together at finalized commitment with
a minimum context slot. The positive bytes are synthetic; the test claims no
real RPC, deployment, signature or application authorization.

Offline lock generation succeeded for 238 packages in 0.719 seconds, with
123,256,832 bytes sampled peak owned-tree RSS and no cap. The generated
`Cargo.lock` SHA-256 is
`8ca05eae384a5bdc3add252b4fc56a5f31762c048178650bfe3775dfdb52622f`.
The [lock receipt](../../../results/dynark/part5/v3-current-lock-001.json)
records the bounded command.

The first [bounded RED receipt](../../../results/dynark/part5/v3-current-red-001.json)
records a successful offline compile followed by one expected failure:
`verify_deployment` returned `Unavailable` where the scripted test expected a
verified finalized slot. It took 66.945 seconds, reached 567,296,000 bytes
sampled peak owned-tree RSS and 281,051,112 bytes sampled target growth, with
no cap, runner error or residual owned process. Private stdout/stderr are under
`artifacts/dynark/part5/v3-current-red-001`.

GREEN must authenticate the configured genesis, loader/ProgramData linkage,
exact ELF bytes and upgrade authority, config owner/codec/PDA, coherent
finalized context and bounded Clock use before returning deployment evidence.
The configured pins must come from a reviewed application deployment identity;
publicly constructible pin fields alone cannot establish trust. Signed source,
publisher head, request, membership and restart verification remain distinct
later gates. The existing JSON-only publisher route stays rejecting.
