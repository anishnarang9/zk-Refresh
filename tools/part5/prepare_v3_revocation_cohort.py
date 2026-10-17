"""Create two signed bounded training credentials and explicit revocation roots.

The second certificate is a real issuer-signed registry leaf. This helper
authenticates neither registry history nor live application state; those require
the separately checked source observation and finalized account batch.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tools.part5.corpus import x509_certificate
from tools.part5.credential_profile import admit_certificate, public_bindings
from tools.part5.registry_v3_vectors import rebuild, siblings


def membership_for_pair(own_digest, unrelated_digest, slot):
    if (type(own_digest) is not bytes or len(own_digest) != 32
            or type(unrelated_digest) is not bytes or len(unrelated_digest) != 32
            or own_digest == bytes(32) or unrelated_digest == bytes(32)
            or own_digest == unrelated_digest or type(slot) is not int
            or not 0 <= slot < 1024):
        raise ValueError('distinct signed digest allocation required')
    other = slot ^ 1
    states = {
        'active': rebuild([(slot, own_digest, True), (other, unrelated_digest, True)]),
        'unrelated': rebuild([(slot, own_digest, True), (other, unrelated_digest, False)]),
        'own_revoked': rebuild([(slot, own_digest, False), (other, unrelated_digest, False)]),
    }
    result = {'slot': slot, 'unrelated_slot': other,
              'own_tbs_digest': own_digest.hex(),
              'unrelated_tbs_digest': unrelated_digest.hex()}
    for name, levels in states.items():
        result[name + '_root'] = levels[-1][0]
        result[name + '_siblings'] = [int(word, 16) for word in siblings(levels, slot)]
    if (result['active_root'] == result['unrelated_root']
            or result['unrelated_root'] == result['own_revoked_root']
            or sum(a != b for a, b in zip(result['active_siblings'],
                                           result['unrelated_siblings'])) != 1):
        raise ValueError('revocation transition is not one sibling change')
    return result


def create(output):
    if not isinstance(output, Path) or not output.is_absolute() or output.resolve() != output:
        raise ValueError('canonical absolute output required')
    original = output.lstat()
    if (not stat.S_ISDIR(original.st_mode) or original.st_uid != os.getuid()
            or stat.S_IMODE(original.st_mode) != 0o700):
        raise ValueError('owner-only output directory required')
    fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        if ((opened.st_dev, opened.st_ino) != (original.st_dev, original.st_ino)
                or os.listdir(fd)):
            raise ValueError('fresh output required')
        issuer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        own = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        modulus = issuer.public_key().public_numbers().n
        own_der = x509_certificate(issuer, own, 0)
        other_der = x509_certificate(issuer, other, 2)
        own_parsed = admit_certificate(own_der, modulus)
        other_parsed = admit_certificate(other_der, modulus)
        own_issuer, policy = public_bindings(own_parsed, modulus)
        other_issuer, _ = public_bindings(other_parsed, modulus)
        if (len(own_der) != 952 or len(other_der) != 952
                or own_issuer != other_issuer or own_parsed['aki'] != other_parsed['aki']
                or own_parsed['tbs'] == other_parsed['tbs']):
            raise ValueError('two distinct supported certificates under one issuer required')
        membership = membership_for_pair(hashlib.sha256(own_parsed['tbs']).digest(),
                                         hashlib.sha256(other_parsed['tbs']).digest(),
                                         secrets.randbelow(1024))
        membership.update(issuer_hash=own_issuer, policy_hash=policy)
        pem = lambda key: key.private_bytes(serialization.Encoding.PEM,
                                            serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption())
        encoded = lambda value: (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
        receipt = {'schema': 'v3-two-signed-training-credentials-v1',
                   'training_only': True, 'registry_history_authenticated': False,
                   'live_state_authenticated': False,
                   'issuer_hash': str(own_issuer), 'policy_hash': str(policy),
                   'credential_sha256': hashlib.sha256(own_der).hexdigest(),
                   'unrelated_credential_sha256': hashlib.sha256(other_der).hexdigest(),
                   'membership_sha256': hashlib.sha256(encoded(membership)).hexdigest()}
        files = {'credential.der': own_der, 'holder.pem': pem(own),
                 'unrelated.der': other_der, 'unrelated-holder.pem': pem(other),
                 'issuer.pem': pem(issuer), 'issuer-modulus.bin': modulus.to_bytes(256, 'big'),
                 'membership.json': encoded(membership), 'cohort-receipt.json': encoded(receipt)}
        written = []
        try:
            for name, data in files.items():
                target = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=fd)
                written.append(name)
                with os.fdopen(target, 'wb') as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            os.fsync(fd)
            current = output.lstat()
            if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                raise ValueError('output directory changed')
        except Exception:
            for name in written:
                os.unlink(name, dir_fd=fd)
            raise
        return receipt
    finally:
        os.close(fd)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    print(json.dumps(create(args.output), sort_keys=True))
