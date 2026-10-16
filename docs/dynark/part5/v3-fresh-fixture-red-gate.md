# Fresh retained v3 credential fixture: tests-first boundary

The next request-bound proof needs a newly issued supported certificate with
its holder signing key still available in a protected local directory. The
existing nine-pair proof corpus discarded its signers, and its synthetic
actions cannot be rebound to a finalized application request.

The first focused test requires `prepare` to create a 952-byte DER certificate
and a matching holder PEM in a fresh owner-only directory. Both files must be
regular, single-link and mode `0600`; `cryptography.x509` must parse the DER,
the holder private key must match the certificate public key, and the strict
bounded-profile importer must admit it under the returned issuer modulus. The
fixture uses synthetic keys and the declared test-only extension OIDs.

The bounded RED run exited 1 in 0.606 seconds at the intended
`NotImplementedError` stub. It hit no runtime, memory or storage cap and left
no owned process. The scrubbed receipt is
`results/dynark/part5/v3-fresh-fixture-red-001.json`; the private stderr is
retained outside Git. This RED establishes the missing credential fixture
contract only. It does not establish issuer enrollment, a request-bound
witness, proof or application effect.

The narrow GREEN uses `cryptography.x509` directly with new RSA-2048 issuer
and holder keys, random canonical serial and signed authorization extensions.
It checks strict profile admission before returning, and writes the DER and
holder PKCS#8 PEM through exclusive, owner-only file descriptors in the
supplied empty `0700` directory. The focused test passed in 0.437 seconds;
sampled peak owned-tree RSS was 36,601,856 bytes, with no cap stop or
remaining owned process. Its receipt is
`results/dynark/part5/v3-fresh-fixture-green-001.json`. The test removed its
temporary credential and key, and no generated private material was staged.
The fixture covers one supported layout. A second tests-first slice added
retained holder signing: the focused RED failed because `sign_action` did not
exist (`v3-retained-signer-red-001.json`). The GREEN reads the owner-only key
through a bounded same-handle path, accepts only a canonical 32-byte BN254
field, and signs those exact bytes with RSA-2048/PKCS#1 v1.5/SHA-256. The
certificate's holder public key verified the 256-byte result. Both fixture
tests passed in 0.589 seconds, with 38,780,928 bytes sampled peak RSS, no cap
stop, no remaining owned process and no retained temporary key. The receipt is
`results/dynark/part5/v3-retained-signer-green-001.json`.

This signer is a protected synthetic development fixture, not a production
signer capability. Active membership, a finalized request's action and a
request-bound proof remain separate gates.
