# Frozen unseen-credential acceptance gate

This gate runs only after the v3 circuit/profile, setup, proof runner, registry,
client, signer interface, ordinary adapter, application source and loaded ELF
are frozen with separate hashes. The current nine-pair proof corpus is retained
training data and cannot substitute for this gate: it discarded signer keys
and used synthetic action fields and membership paths.

After the freeze, generate eight supported certificates with four fresh issuer
keys and eight fresh holder keys, no training-key reuse. Cover all eight
declared DER layouts, different positive 16-byte serials and validity periods,
at least two signed organization/group policies and varied signed AKIs. At
least four certificates must be issued through an independent OpenSSL route;
the remaining encodings may use the separately reviewed profile generator.
Keep all private keys/signers, DER, witnesses, proofs and membership data in
protected outputs outside Git. Record an independent issuance/import receipt
that proves creation after the freeze. The client must admit them without a
source edit, offset edit or new setup.

For **each** certificate, with the same frozen public VK/setup:

1. Enroll its qualifying issuer/AKI and enable the exact signed policy under
   administrator authority. Before enrollment or under the wrong policy,
   authorization must fail. Obtain fresh authenticated source observation,
   current publication and active v3 membership from an independent current
   head.
2. Finalize a unique immutable action-v2 request, have that holder sign the
   exact canonical actionHash, generate a complete witness and randomized
   Full proof, and execute through the loaded v3 application. Verify one exact
   queue append and request consumption at finalized commitment. Replaying
   the consumed request, including with a fresh proof, must fail without a
   second effect.
3. Finalize a **different unconsumed** request/action. Establish its Full base,
   then publish an unrelated revocation. Reject the old-root proof at the
   execution-current application. Generate a complete current witness and a
   DYNARK Anchor refresh for the same action, independently verify the
   ordinary proof and execute once under the new root. Compare complete and
   incremental witnesses only if an incremental v3 path is actually exposed.
4. Finalize another unconsumed request, revoke this credential's own leaf and
   publish the new root/status. Reject the old-root proof at execution and
   reject any attempted current-root active-leaf witness/proof. Confirm no
   queue append or request consumption from the rejected authorization.

Include malformed and ineligible DER, wrong issuer, changed signed policy,
stale status, disabled issuer/config, wrong account order/privileges/owners,
modified action, malformed proof, queue capacity and ambiguous submission/
restart cases. Record preparation time, total complete refresh time, per
credential memory and paid public/private Anchor preparation. Public setup
reuse, private cache isolation, holder/action separation and no source/setup
hash drift are explicit acceptance checks.

Passing this gate would establish a bounded supported-profile development
application. Real issuer purpose/enrollment operations, upstream revocation
freshness, production signer security, production setup ceremony and devnet
authorities still require their own review before a production-readiness claim.
