"""Holder public-signature boundary; no key loading, signing or CLI.

The caller must authenticate the request and holder credential separately.
Verification consumes only public modulus, canonical BE32 action and signature.
"""
import hashlib


class ActionVerificationError(ValueError):
    """Public typed rejection without private data or exception details."""


def verify_action_signature(expected_holder_modulus_be, signer_holder_modulus_be,
                            action_be, signature):
    """Require key equality and RSA2048/e65537/SHA256/PKCS1-v1_5 verification."""
    for value, width in [(expected_holder_modulus_be, 256),
                         (signer_holder_modulus_be, 256),
                         (action_be, 32), (signature, 256)]:
        if type(value) is not bytes or len(value) != width:
            raise ActionVerificationError('bounded-v3 signature input rejected')
    if expected_holder_modulus_be != signer_holder_modulus_be:
        raise ActionVerificationError('bounded-v3 holder binding rejected')
    modulus = int.from_bytes(expected_holder_modulus_be, 'big')
    if modulus.bit_length() != 2048 or not modulus & 1:
        raise ActionVerificationError('bounded-v3 holder modulus rejected')
    scalar_modulus = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    if int.from_bytes(action_be, 'big') >= scalar_modulus:
        raise ActionVerificationError('bounded-v3 action encoding rejected')
    encoded_signature = int.from_bytes(signature, 'big')
    if encoded_signature >= modulus:
        raise ActionVerificationError('bounded-v3 signature encoding rejected')
    # The separately validated request preimage is reduced to canonical BE32
    # actionHash before this boundary. The RSA message is exactly that field.
    digest_info = (bytes.fromhex('3031300d060960864801650304020105000420')
                   + hashlib.sha256(action_be).digest())
    expected = b'\x00\x01' + b'\xff' * (253 - len(digest_info)) + b'\x00' + digest_info
    actual = pow(encoded_signature, 65537, modulus).to_bytes(256, 'big')
    if actual != expected:
        raise ActionVerificationError('bounded-v3 holder signature rejected')
    return None
