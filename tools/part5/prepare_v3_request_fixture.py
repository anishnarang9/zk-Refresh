import datetime
import hashlib
import os
from pathlib import Path
import secrets
import stat

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import NameOID, ObjectIdentifier

from tools.part5.credential_profile import TEST_OIDS, admit_certificate


def prepare(directory):
    if not isinstance(directory, Path):
        raise ValueError('Path directory required')
    original = directory.lstat()
    if (not stat.S_ISDIR(original.st_mode) or original.st_uid != os.getuid()
            or stat.S_IMODE(original.st_mode) != 0o700):
        raise ValueError('fresh owner0700 directory required')
    directory = directory.resolve(strict=True)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(directory, flags)
    try:
        opened = os.fstat(descriptor)
        if ((opened.st_dev, opened.st_ino) != (original.st_dev, original.st_ino)
                or opened.st_uid != os.getuid() or stat.S_IMODE(opened.st_mode) != 0o700
                or os.listdir(descriptor)):
            raise ValueError('directory changed or not empty')
        issuer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        holder = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        issuer_modulus = issuer.public_key().public_numbers().n
        serial = bytes([secrets.randbelow(127) + 1]) + secrets.token_bytes(15)
        aki = hashlib.sha256(issuer.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).digest()[:20]
        organization, group = secrets.token_bytes(16), secrets.token_bytes(32)
        name = lambda text: x509.Name([x509.NameAttribute(
            NameOID.COMMON_NAME, text, _type=_ASN1Type.UTF8String)])
        builder = (x509.CertificateBuilder()
                   .issuer_name(name('Issuer ' + secrets.token_hex(16) + 'I'))
                   .subject_name(name('Holder ' + secrets.token_hex(8) + 'H'))
                   .public_key(holder.public_key()).serial_number(int.from_bytes(serial, 'big'))
                   .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
                   .not_valid_after(datetime.datetime(2028, 12, 31, tzinfo=datetime.timezone.utc)))
        extensions = [
            (x509.AuthorityKeyIdentifier(aki, None, None), False),
            (x509.KeyUsage(True, False, False, False, False, False, False, None, None), True),
            (x509.BasicConstraints(False, None), True),
            (x509.ExtendedKeyUsage([ObjectIdentifier(TEST_OIDS['purpose'])]), True),
            (x509.UnrecognizedExtension(ObjectIdentifier(TEST_OIDS['organization']),
                                       b'\x04\x10' + organization), True),
            (x509.UnrecognizedExtension(ObjectIdentifier(TEST_OIDS['group']),
                                       b'\x04\x20' + group), True),
        ]
        for extension, critical in extensions:
            builder = builder.add_extension(extension, critical)
        der = builder.sign(issuer, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
        parsed = admit_certificate(der, issuer_modulus)
        if len(der) != 952 or len(parsed['tbs']) != 672 or parsed['variant'] != 0:
            raise ValueError('unsupported certificate shape')
        holder_pem = holder.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption())
        for filename, data in [('credential.der', der), ('holder.pem', holder_pem)]:
            output = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=descriptor)
            with os.fdopen(output, 'wb') as target:
                os.fchmod(target.fileno(), 0o600)
                target.write(data)
                target.flush()
                os.fsync(target.fileno())
        current = directory.stat()
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError('directory changed')
        return {'credential_der': directory / 'credential.der',
                'holder_key_pem': directory / 'holder.pem',
                'issuer_modulus': issuer_modulus}
    finally:
        os.close(descriptor)


def sign_action(holder_key_pem: Path, action_be: bytes) -> bytes:
    fr = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    if type(action_be) is not bytes or len(action_be) != 32 or int.from_bytes(action_be, 'big') >= fr:
        raise ValueError('canonical BE32 action required')
    if not isinstance(holder_key_pem, Path):
        raise ValueError('Path private key required')
    directory_fd = key_fd = None
    try:
        original = holder_key_pem.lstat()
        if (not stat.S_ISREG(original.st_mode) or original.st_nlink != 1
                or original.st_uid != os.getuid() or stat.S_IMODE(original.st_mode) != 0o600
                or not 0 < original.st_size <= 4096):
            raise ValueError('private single-link0600 key required')
        parent = holder_key_pem.parent.resolve(strict=True)
        parent_info = parent.lstat()
        if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.getuid()
                or stat.S_IMODE(parent_info.st_mode) != 0o700):
            raise ValueError('owner0700 key directory required')
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        opened_parent = os.fstat(directory_fd)
        if ((opened_parent.st_dev, opened_parent.st_ino) != (parent_info.st_dev, parent_info.st_ino)
                or opened_parent.st_uid != os.getuid() or stat.S_IMODE(opened_parent.st_mode) != 0o700):
            raise ValueError('key directory changed')
        key_fd = os.open(holder_key_pem.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=directory_fd)
        before = os.fstat(key_fd)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_uid, info.st_mode,
                                 info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if identity(before) != identity(original):
            raise ValueError('private key changed')
        pem = bytearray()
        while len(pem) <= 4096:
            chunk = os.read(key_fd, 4097 - len(pem))
            if not chunk:
                break
            pem.extend(chunk)
        after = os.fstat(key_fd)
        named = os.stat(holder_key_pem.name, dir_fd=directory_fd, follow_symlinks=False)
        current_parent = parent.lstat()
        if (len(pem) != before.st_size or len(pem) > 4096
                or identity(after) != identity(before) or identity(named) != identity(before)
                or (current_parent.st_dev, current_parent.st_ino) != (opened_parent.st_dev, opened_parent.st_ino)
                or current_parent.st_uid != os.getuid() or stat.S_IMODE(current_parent.st_mode) != 0o700):
            raise ValueError('private key changed while reading')
        holder = serialization.load_pem_private_key(bytes(pem), password=None)
        if (not isinstance(holder, rsa.RSAPrivateKey) or holder.key_size != 2048
                or holder.public_key().public_numbers().e != 65537):
            raise ValueError('RSA2048 e65537 private key required')
        signature = holder.sign(action_be, padding.PKCS1v15(), hashes.SHA256())
        if len(signature) != 256:
            raise ValueError('RSA signature width')
        return signature
    except (OSError, TypeError) as error:
        raise ValueError('invalid private signer input') from error
    finally:
        if key_fd is not None:
            os.close(key_fd)
        if directory_fd is not None:
            os.close(directory_fd)


def build_membership(der: bytes, issuer_modulus: int) -> dict:
    from tools.part5.credential_profile import public_bindings
    from tools.part5.registry_v3_vectors import rebuild, siblings

    parsed = admit_certificate(der, issuer_modulus)
    issuer_hash, policy_hash = public_bindings(parsed, issuer_modulus)
    own_digest = hashlib.sha256(parsed['tbs']).digest()
    unrelated_digest = secrets.token_bytes(32)
    while unrelated_digest == own_digest or unrelated_digest == bytes(32):
        unrelated_digest = secrets.token_bytes(32)
    slot = secrets.randbelow(1024)
    other = slot ^ 1
    active = rebuild([(slot, own_digest, True), (other, unrelated_digest, True)])
    unrelated = rebuild([(slot, own_digest, True), (other, unrelated_digest, False)])
    revoked = rebuild([(slot, own_digest, False), (other, unrelated_digest, False)])
    return {
        'slot': slot, 'issuer_hash': issuer_hash, 'policy_hash': policy_hash,
        'active_root': active[-1][0],
        'active_siblings': [int(word, 16) for word in siblings(active, slot)],
        'unrelated_root': unrelated[-1][0],
        'unrelated_siblings': [int(word, 16) for word in siblings(unrelated, slot)],
        'own_revoked_root': revoked[-1][0],
        'own_revoked_siblings': [int(word, 16) for word in siblings(revoked, slot)],
    }
