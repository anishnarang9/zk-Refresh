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
