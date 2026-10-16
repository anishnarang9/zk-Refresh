# Bound v3 Full proof gate

The native complete-relation checker now accepts one fresh training assignment
and rejects six altered inputs. Its `V3CheckedRelation` is deliberately opaque:
the relation alone says nothing about a finalized request, holder signer,
issuer enrollment or current chain state. No caller may relabel a checked
assignment with a credential or action after the check.

When a concrete trusted state adapter exists, `V3BoundWitness::open_full`
should construct the fixed worker request from the
imported DER, issuer modulus, exact prepared BE32 action, verified holder
signature and authenticated six-field state. It must compare the worker's
candidate to the complete calculator input and WTNS using the admitted symbol
map and `V3CheckedRelation::check`. Only this boundary may consume the checked
assignment through a crate-private method; do not expose a public assignment
accessor or a proof method on the unbound relation. Its private binding must
record the same package/profile/schema, certificate and holder, issuer/status,
root and source version, action, slot, allocation and generation used to
produce the witness. Recheck it before proving and submission. The public
`open_full` entry remains closed while that authority is absent; an
implementable state trait or coherent caller record does not supply it.

For a bound assignment or the private training validation, use
`dynark_bn254::prove` with fresh `CryptoRng`, then verify
the resulting ordinary proof independently under the admitted package's
ordinary VK and six exact public values. The six-field adapter is a downstream
bridge: its 448-byte proof/public wire must pass both ordinary and Solana
verification, then the v3 program host verifier. Keep its key commitments
separate from the circuit/profile/package and later application ELF hashes.

The next tests-first slices are (1) cheap altered credential/action/signature/
state binding rejection, (2) one bounded fresh request-bound **training** Full
proof with private signer and complete witness, and (3) exact adapter and
program host verification, followed by Execute preflight reaching its
currently disconnected effect gate. The private training harness may validate
the same complete assignment through the engine before proving; it must not
expose a public accessor or use a synthetic state provider as live authority.
Private DER, keys, WTNS and proof material stay outside Git under a fresh
owner-only directory. Only after positive Execute verification should the
reviewed atomic queue effect be connected and tested.
