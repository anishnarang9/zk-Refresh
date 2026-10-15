#!/usr/bin/env python3
"""Closed RED scaffold for a non-authorizing bounded-v3 input candidate.

Invocation: pinned-python this-script build ABSOLUTE_PRIVATE_DIRECTORY.
Future input/output files are request.bin/output.bin in a 0700 directory, each
0600, owner checked, regular, single-link, opened without following symlinks.
No CLI file I/O is enabled by this scaffold. It loads no repository module and
performs no parsing, signature verification, Poseidon, signing, or proving.
Only the Python standard library is imported, under the trusted runtime boundary.
The eventual implementation must freeze and verify its complete source closure
before doing cryptographic work; the declarations below alone verify nothing.

Fixed request (1,918 bytes), with half-open byte ranges:
    [0:4]       V3Q1
    [4:956]     admitted certificate DER, exactly 952 bytes
    [956:1212]  issuer modulus, unsigned BE256
    [1212:1244] reviewed canonical action field, BE32
    [1244:1500] holder signature, unsigned BE256
    [1500:1502] allocation slot, BE16, below 1024
    [1502:1822] ten canonical Fr siblings, LE32 each, leaf-first
    [1822:1854] expected root, canonical Fr LE32
    [1854:1886] expected issuerHash, canonical Fr LE32
    [1886:1918] expected policyHash, canonical Fr LE32

Fixed response (24,495 bytes): V3I1 || admission_summary[459] || fields[751][32].
The summary is the existing exact V3A1 admission wire format. Every field is a
canonical Fr LE32. Field order is INPUT_FIELDS below, arrays expanded index-first.
The six initial fields are the exact public order. RSA limbs use 17 little-endian
121-bit limbs, with only 112 significant bits in the seventeenth limb. TBS bytes
are byte-valued fields. Path bits derive solely from the allocation slot.

Rust will compare DER/TBS bytes, imported metadata, action/state bytes, integer
limbs, path bits, canonical encodings and all mapped coordinate values itself.
RSA validity and recomputed Poseidon issuer/policy/active-root claims rely on the
reviewed pinned worker; Rust has no independent implementation of those checks.
Candidate JSON must equal serialization independently built from those sources;
caller JSON is never a source of expected fields. Complete R1CS validation and a
concrete chain authority remain mandatory before any proof admission. This
scaffold, future candidate output, and caller-implemented state traits authorize
no credential, signer, chain state, or operation. open_full must remain closed.
"""

import sys

REQUEST_BYTES = 1918
RESPONSE_BYTES = 24495
FIELD_COUNT = 751
INPUT_FIELDS = (
    ('root', 1), ('issuerHash', 1), ('notBefore', 1), ('notAfter', 1),
    ('actionHash', 1), ('policyHash', 1), ('layout', 1), ('slot', 1),
    ('tbs', 672), ('issuerModulus', 17), ('issuerSignature', 17),
    ('holderSignature', 17), ('siblings', 10), ('pathIndices', 10),
)
# Reviewed source identities to enforce when implementation is authorized.
# These are fixed policy, never caller-supplied hash assertions.
SOURCE_PINS = {
    'tools/part5/credential_profile.py':
        'c960f3d2bb8e72c28c0d6a9164b6eaa17ec2ff4ef36a7e0af23811737470f2e6',
    'tools/part5/poseidon.py':
        '82d6a93d2af03f17fe340eb7a2d0edbd47dd774ef205d7332b956c2e8c743d68',
    'node_modules/circomlib/circuits/poseidon_constants.circom':
        '94c9e4b5ea891ab4d1ba626f1d719f8c661014d9b628f6096c803f75f39e3eee',
    'crates/dynark-native-client/workers/v3_admission_worker.py':
        '4ebb5c0201c3b98955d8fa0bc0ce8ce5f76104302b5e70f2a7359919e6b29a28',
    'crates/dynark-native-client/workers/v3_action_worker.py':
        '46692db2692d35f8624fde87ba9aa87239a5f8fab829a15a515a5a88ea6e80a6',
    'circuits/credential-v3-bounded/profile.json':
        '2e5d26564fb055e70cff924c4cb6e296509030b8c0062130f86ad5af783f7918',
}


class InputFailure(ValueError):
    """Typed rejection; never include credential, path, or signature bytes."""


def build(request):
    """Derive and verify the complete candidate; no caller output is admitted."""
    raise NotImplementedError('bounded-v3 input candidate remains closed')


def main():
    # CLI execution also stays closed; no file is opened or output created.
    if len(sys.argv) != 3 or sys.argv[1] != 'build':
        return 2
    raise NotImplementedError('bounded-v3 input candidate remains closed')


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except NotImplementedError:
        raise SystemExit(3) from None
    except InputFailure:
        raise SystemExit(2) from None
