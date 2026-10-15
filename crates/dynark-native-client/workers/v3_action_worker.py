"""Tests-first holder signature boundary; no key loading, signing or CLI yet.

The caller must authenticate the request and holder credential separately.
Verification consumes only public modulus, canonical BE32 action and signature.
"""


class ActionVerificationError(ValueError):
    """Public typed rejection without private data or exception details."""


def verify_action_signature(expected_holder_modulus_be, signer_holder_modulus_be,
                            action_be, signature):
    """Require key equality and RSA2048/e65537/SHA256/PKCS1-v1_5 verification."""
    raise NotImplementedError('bounded-v3 holder signature verification unavailable')
