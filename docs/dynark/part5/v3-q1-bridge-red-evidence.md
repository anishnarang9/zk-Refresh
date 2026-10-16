# Private request-action input bridge gate

`tools/part5/tests/test_v3_request_bound_bridge.py` freezes an exact V3Q1
contract for a fresh supported synthetic credential, retained holder key,
canonical BE32 action supplied at the boundary, and active or unrelated-root
membership. It checks the 1,918-byte frame, RSA holder signature, ten LE32
siblings, root/issuer/policy fields and the pinned input worker's accepted
candidate. It also requires rejection of a stale signature, wrong key,
altered path/root, revoked membership, invalid selectors and noncanonical
fields. The action input is not yet derived from a finalized application
request in this test.

The fresh bounded `python3 -B -m unittest
tools.part5.tests.test_v3_request_bound_bridge` receipt is
`results/dynark/part5/v3-q1-bridge-red-001.json`. It exited 1 in 1.071
measured seconds, with no cap stop, runner error or remaining owned process.
All seven tests failed at the single intentional missing `build_v3q1` entry;
the protected traceback is outside Git. This RED makes no credential,
relation, proof or application acceptance claim.
