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


def build_v3q1(der: bytes, issuer_modulus: int, holder_key_pem: Path,
               action_be: bytes, membership: dict, root_kind: str = 'active') -> bytes:
    """Build a verified private V3Q1 candidate; it grants no application authority."""
    from tools.part5.credential_profile import FR, public_bindings, verify_rsa
    from tools.part5.registry_v3_vectors import h, leaf

    failure = 'invalid bounded-v3 request shape'
    try:
        if (type(der) is not bytes or len(der) != 952
                or type(issuer_modulus) is not int
                or issuer_modulus <= 0 or issuer_modulus.bit_length() != 2048
                or not issuer_modulus & 1
                or not isinstance(holder_key_pem, Path)
                or type(action_be) is not bytes or len(action_be) != 32
                or int.from_bytes(action_be, 'big') >= FR
                or type(membership) is not dict
                or type(root_kind) is not str or root_kind not in ('active', 'unrelated')):
            raise ValueError(failure)

        failure = 'invalid bounded-v3 membership fields'
        slot = membership['slot']
        path = membership[root_kind + '_siblings']
        root = membership[root_kind + '_root']
        issuer_hash, policy_hash = membership['issuer_hash'], membership['policy_hash']
        if (type(slot) is not int or not 0 <= slot < 1024
                or type(path) is not list or len(path) != 10):
            raise ValueError(failure)
        path = tuple(path)
        fields = path + (root, issuer_hash, policy_hash)
        if any(type(value) is not int or not 0 <= value < FR for value in fields):
            raise ValueError(failure)

        failure = 'bounded-v3 certificate admission failed'
        parsed = admit_certificate(der, issuer_modulus)
        failure = 'bounded-v3 issuer or policy binding failed'
        if (issuer_hash, policy_hash) != public_bindings(parsed, issuer_modulus):
            raise ValueError(failure)

        failure = 'bounded-v3 active membership root or path failed'
        digest = hashlib.sha256(parsed['tbs']).digest()
        node = leaf(digest, slot, True)
        for level, sibling in enumerate(path):
            node = h((sibling, node) if (slot >> level) & 1 else (node, sibling))
        if node != root:
            raise ValueError(failure)

        failure = 'bounded-v3 holder signing failed'
        signature = sign_action(holder_key_pem, action_be)
        failure = 'bounded-v3 holder key or action signature failed'
        if type(signature) is not bytes or len(signature) != 256:
            raise ValueError(failure)
        verify_rsa(parsed['holder_modulus'], action_be, signature)

        failure = 'bounded-v3 request encoding failed'
        request = (b'V3Q1' + der + issuer_modulus.to_bytes(256, 'big') + action_be
                   + signature + slot.to_bytes(2, 'big')
                   + b''.join(value.to_bytes(32, 'little') for value in fields))
        if len(request) != 1918:
            raise ValueError(failure)
        return request
    except Exception:
        # Signing and admission failures must not reveal private paths or bytes.
        raise ValueError(failure) from None


def build_v3p1(der: bytes, issuer_modulus: int, membership: dict, *, config_bytes: bytes,
               program_id: bytes, creator: bytes, nonce: bytes, recipient: bytes,
               request_type: int, deadline: int, payload: bytes, now: int) -> bytes:
    """Public local-development plan; caller Config bytes establish no live authority.

    Signed DER supplies issuer and validity. Its signed policy and the caller's
    synthetic active membership must exactly match Config; neither is overwritten.
    Rust Config::decode validates the account codec and generated identity pins.
    """
    import struct
    from tools.part5.credential_profile import FR, public_bindings

    try:
        parsed = admit_certificate(der, issuer_modulus)
        issuer, policy = public_bindings(parsed, issuer_modulus)
        root = membership['active_root']
        if (type(config_bytes) is not bytes or len(config_bytes) != 381
                or config_bytes[:8] != b'DYNCONF3'
                or type(root) is not int or not 0 <= root < FR
                or membership['issuer_hash'] != issuer or membership['policy_hash'] != policy
                or config_bytes[136:168] != policy.to_bytes(32, 'big')
                or config_bytes[332:364] != root.to_bytes(32, 'big')
                or any(type(value) is not bytes or len(value) != 32
                       for value in (program_id, creator, nonce, recipient))
                or type(payload) is not bytes or len(payload) > 1024
                or type(request_type) is not int or type(deadline) is not int
                or type(now) is not int):
            raise ValueError()
        return (b'V3P1' + program_id + struct.pack('<qI', now, 381) + config_bytes
                + b''.join(value.to_bytes(32, 'big') for value in
                           (issuer, parsed['not_before'], parsed['not_after']))
                + creator + nonce + recipient + struct.pack('<HqH', request_type, deadline, len(payload))
                + payload)
    except Exception:
        raise ValueError('invalid local-development public plan') from None


def _run_public_exporter(exporter: Path, plan_mode: bool, data: bytes, output_limit: int) -> bytes:
    """Run the local exporter with public stdin and bounded output/time; suppress diagnostics."""
    import selectors
    import subprocess
    import time

    process = None
    try:
        process = subprocess.Popen([str(exporter)] + (['--plan'] if plan_mode else []),
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 15
        # Both public inputs fit below PIPE_BUF; the reviewed exporter immediately reads stdin.
        process.stdin.write(data)
        process.stdin.close()
        output = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise ValueError()
                chunk = os.read(process.stdout.fileno(), output_limit + 1 - len(output))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > output_limit:
                    raise ValueError()
        if process.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
            raise ValueError()
        return bytes(output)
    except Exception:
        raise ValueError('local public exporter failed') from None
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait()
            for stream in (process.stdin, process.stdout):
                if stream is not None:
                    stream.close()


def finalize_v3p1(plan_wire: bytes, exporter: Path) -> dict:
    """Finalize a public plan through Rust and record its local exporter identity.

    V3F1/V3F2 and the binary digest are public fixture data. This is not a chain
    observation, issuer enrollment, credential authorization, or proof check.
    """
    from tools.part5.credential_profile import FR

    try:
        if (type(plan_wire) is not bytes or not 633 <= len(plan_wire) <= 1657
                or plan_wire[:4] != b'V3P1' or plan_wire[44:48] != (381).to_bytes(4, 'little')
                or len(plan_wire) != 633 + int.from_bytes(plan_wire[631:633], 'little')
                or not isinstance(exporter, Path)):
            raise ValueError()
        exporter = exporter.resolve(strict=True)
        digest = hashlib.sha256(exporter.read_bytes()).hexdigest()
        f1 = _run_public_exporter(exporter, True, plan_wire, 2874)
        if (type(f1) is not bytes or len(f1) != 2874 or f1[:4] != b'V3F1'
                or f1[4:44] != plan_wire[4:44]
                or f1[44:52] != (381).to_bytes(4, 'little') + (2249).to_bytes(4, 'little')
                or f1[244:625] != plan_wire[48:429]
                or f1[52:84] != plan_wire[380:412]
                or f1[84:180] != plan_wire[429:525]
                or f1[212:244] != plan_wire[184:216]
                or any(int.from_bytes(f1[start:start + 32], 'big') >= FR
                       for start in range(52, 244, 32))):
            raise ValueError()
        request = f1[625:]
        payload_len = len(plan_wire) - 633
        if (request[:8] != b'DYNREQ03'
                or request[40:104] != plan_wire[525:589]
                or request[104:136] != plan_wire[429:461]
                or request[136:168] != plan_wire[589:621]
                or request[168:170] != plan_wire[621:623][::-1]
                or request[170:178] != plan_wire[623:631][::-1]
                or request[178:182] != payload_len.to_bytes(2, 'big') * 2
                or request[182:185] != b'\x02\x01\x02'
                or request[1225:1225 + payload_len] != plan_wire[633:]):
            raise ValueError()
        f2 = _run_public_exporter(exporter, False, f1, 561)
        if (type(f2) is not bytes or len(f2) != 561 or f2[:4] != b'V3F2'
                or int.from_bytes(f2[196:200], 'little') != 361
                or f2[164:196] != f1[180:212]
                or request[8:40] != f2[4:36]
                or request[185:217] != f2[68:100]
                or request[250:282] != f2[100:132]
                or any(request[offset] != 2 for offset in (217, 282))
                or any(request[offset:offset + 32] != plan_wire[4:36] for offset in (218, 283))
                or (int.from_bytes(hashlib.sha256(f2[200:]).digest(), 'big') % FR).to_bytes(32, 'big')
                   != f2[164:196]
                or hashlib.sha256(exporter.read_bytes()).hexdigest() != digest):
            raise ValueError()
        return {'v3f1': f1, 'v3f2': f2, 'exporter_sha256': digest}
    except Exception:
        raise ValueError('invalid finalized local-development fixture') from None


def build_request_bound_v3q1(der: bytes, issuer_modulus: int, holder_key_pem: Path,
                            membership: dict, plan_wire: bytes, finalized: dict,
                            exporter: Path) -> bytes:
    """Sign only the exact Rust-finalized local request after checking all six publics.

    The returned V3Q1 contains private credential/signature material. Keep it in
    memory or owner-only ignored storage; never print it. No live state is admitted.
    """
    from tools.part5.credential_profile import public_bindings

    try:
        checked = finalize_v3p1(plan_wire, exporter)
        if type(finalized) is not dict or finalized != checked:
            raise ValueError()
        parsed = admit_certificate(der, issuer_modulus)
        issuer, policy = public_bindings(parsed, issuer_modulus)
        action = checked['v3f2'][164:196]
        expected = [membership['active_root'], issuer, parsed['not_before'],
                    parsed['not_after'], int.from_bytes(action, 'big'), policy]
        f1 = checked['v3f1']
        if (f1[52:244] != b''.join(value.to_bytes(32, 'big') for value in expected)
                or membership['issuer_hash'] != issuer or membership['policy_hash'] != policy):
            raise ValueError()
        return build_v3q1(der, issuer_modulus, holder_key_pem, action, membership)
    except Exception:
        raise ValueError('invalid private request-bound local-development fixture') from None
