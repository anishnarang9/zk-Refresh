# Fresh v3 request-bound training proof bridge

The next training case uses a newly issued supported-profile certificate and
its private holder signer from `tools/part5/prepare_v3_request_fixture.py`.
The older complete-relation fixture signs a toy action and cannot establish
application binding. This bridge is local test data; it does not authenticate
live chain accounts, issuer enrollment or current publication.

## Program-owned request construction

A small Rust builder should accept bounded **public** credential/membership
metadata and an explicit development request plan: program and network
identity, administrator/publisher, creator, nonce, recipient, work type,
payload, deadline and time. The builder must use `Config` and `Request` codecs
and the runtime PDA functions. It stages the request, uploads payload and
ordered metas within `MAX_CHUNK`/`MAX_META_CHUNK`, finalizes it, then derives
the canonical action with `action_hash`. The minimal protected effect uses the
request PDA and queue PDA as the two relevant program-owned writable metas.
Circuit, package, profile, schema and ordinary VK identities come from the
reviewed v3 key module, never from certificate content.

The builder emits one exact 2,874-byte `V3F1` frame with six ordered BE32
public fields, including the Rust-derived action. Pass that frame through the
checked exporter to obtain `V3F2`, its five derived PDAs and the exact action
preimage. Preserve the finalized config/request bytes for the later host
execution test. An old action paired with a changed request, payload, nonce,
policy or ordered account metadata must fail the exporter check or produce a
different action. A root-only change may retain the same action for an
unconsumed request; the new proof must bind the new current root. Public
builder inputs remain untrusted until the application validates authoritative
account state.

## Private signer and witness ownership

The Python fixture owns fresh issuer/holder keys and DER under an owner-only
directory. It imports the DER through the standard profile, derives signed
issuer/policy hashes and an active depth-10 membership path, then signs
SHA-256 of the exported canonical BE32 action through its retained holder
key. Verify the signature under the imported holder modulus before creating
`V3Q1`. The witness request carries the exact action in BE32 and root,
issuer, policy and path fields in canonical LE32. The native worker, pinned
calculator, complete relation checker and shared public package must agree
on all six public fields and all 751 compiler-mapped private input scalars.
No certificate-specific source edit, offset edit or setup import is allowed.

## Tests-first handoff

Use separate owners and files for (1) the Rust request builder and its
positive/action-substitution tests, (2) the private signer/fixture integration
and altered action/signature/root tests, and (3) the request-bound Full proof
and host application verification. The retained synthetic relation fixture
stays unchanged. Keep one serialized bounded heavyweight queue and private
keys, DER, witnesses and proofs outside Git. A positive training proof is an
integration milestone; the frozen eight-credential acceptance gate remains
separate.
