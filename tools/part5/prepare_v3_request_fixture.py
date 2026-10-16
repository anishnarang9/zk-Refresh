import datetime
import hashlib
import os
from pathlib import Path
import secrets
import stat

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
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
