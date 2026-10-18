#!/usr/bin/env python3
"""Issue one bounded demo certificate using supplied RSA keys after a freeze.

This does not generate acceptance keys or enroll an issuer. A cohort driver must
retain independent evidence of four fresh issuers/eight fresh holders and cover
all eight variants, including four independent OpenSSL issuances. An issuance
receipt proves this tool ran after its pinned freeze, not that imported keys
were newly generated. All inputs and outputs belong in owner-only ignored paths.

Parameters JSON has exactly variant, serial, not_before, not_after, organization,
group and aki. Dates are YYYY-MM-DDTHH:MM:SSZ; byte strings are lowercase hex.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import NameOID, ObjectIdentifier
from tools.part5.credential_profile import TEST_OIDS, admit_certificate, public_bindings


def _parameters(params):
    if type(params) is not dict or set(params) != {
            'variant', 'serial', 'not_before', 'not_after', 'organization', 'group', 'aki'}:
        raise ValueError('exact issuance parameters required')
    if (type(params['variant']) is not int or not 0 <= params['variant'] < 8
            or type(params['serial']) is not int or not 1 << 120 <= params['serial'] < 1 << 127):
        raise ValueError('bounded variant and positive 16-byte serial required')
    values = dict(params)
    for name, width in [('organization', 16), ('group', 32), ('aki', 20)]:
        if type(values[name]) is not str or not re.fullmatch('[0-9a-f]{%d}' % (2 * width), values[name]):
            raise ValueError('bounded signed field required')
        values[name] = bytes.fromhex(values[name])
    for name in ['not_before', 'not_after']:
        value = values[name]
        if type(value) is not str or not re.fullmatch(r'20[0-4][0-9]-\d\d-\d\dT\d\d:\d\d:\d\dZ', value):
            raise ValueError('canonical supported UTC date required')
        values[name] = datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)
    if values['not_before'] > values['not_after']:
        raise ValueError('ordered validity required')
    return values


def decode_parameters(raw):
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate issuance field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def issue_certificate(issuer, holder, parameters, encoder='cryptography'):
    values = _parameters(parameters)
    if (encoder not in ('cryptography', 'openssl')
            or any(not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 2048
                   or key.public_key().public_numbers().e != 65537 for key in (issuer, holder))
            or issuer.public_key().public_numbers() == holder.public_key().public_numbers()):
        raise ValueError('independent bounded RSA keys and supported encoder required')
    variant = values['variant']
    issuer_cn, holder_cn = ('I' * 24, 'H' * 40) if variant & 4 else ('I' * 40, 'H' * 24)
    if encoder == 'openssl':
        der = _openssl(issuer, holder, values, issuer_cn, holder_cn)
    else:
        tag = _ASN1Type.PrintableString if variant & 1 else _ASN1Type.UTF8String
        name = lambda cn: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn, _type=tag)])
        cert = (x509.CertificateBuilder().issuer_name(name(issuer_cn)).subject_name(name(holder_cn))
                .public_key(holder.public_key()).serial_number(values['serial'])
                .not_valid_before(values['not_before']).not_valid_after(values['not_after']))
        extensions = [
            (x509.AuthorityKeyIdentifier(values['aki'], None, None), False),
            (x509.KeyUsage(True, False, False, False, False, False, False, None, None), True),
            (x509.BasicConstraints(False, None), True),
            (x509.ExtendedKeyUsage([ObjectIdentifier(TEST_OIDS['purpose'])]), True),
            (x509.UnrecognizedExtension(ObjectIdentifier(TEST_OIDS['organization']), b'\x04\x10' + values['organization']), True),
            (x509.UnrecognizedExtension(ObjectIdentifier(TEST_OIDS['group']), b'\x04\x20' + values['group']), True),
        ]
        for extension, critical in reversed(extensions) if variant & 2 else extensions:
            cert = cert.add_extension(extension, critical)
        der = cert.sign(issuer, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
    parsed = admit_certificate(der, issuer.public_key().public_numbers().n)
    if (len(der) != 952 or parsed['variant'] != variant
            or any(parsed[name] != values[name] for name in ['aki', 'organization', 'group'])
            or any(parsed[name] != int(values[name].timestamp()) for name in ['not_before', 'not_after'])):
        raise ValueError('issued certificate differs from requested profile')
    return der


def _openssl(issuer, holder, values, issuer_cn, holder_cn):
    with tempfile.TemporaryDirectory(prefix='dynark-v3-issuance-') as directory:
        root = Path(directory)
        for name, key in [('issuer', issuer), ('holder', holder)]:
            _write(root / (name + '.pem'), key.private_bytes(serialization.Encoding.PEM,
                   serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        mask = 'MASK:0x2' if values['variant'] & 1 else 'utf8only'
        extensions = [
            'authorityKeyIdentifier=DER:' + (b'\x30\x16\x80\x14' + values['aki']).hex(':'),
            'keyUsage=critical,digitalSignature', 'basicConstraints=critical,CA:FALSE',
            'extendedKeyUsage=critical,' + TEST_OIDS['purpose'],
            TEST_OIDS['organization'] + '=critical,DER:' + (b'\x04\x10' + values['organization']).hex(':'),
            TEST_OIDS['group'] + '=critical,DER:' + (b'\x04\x20' + values['group']).hex(':'),
        ]
        if values['variant'] & 2:
            extensions.reverse()
        config = ('[req]\nprompt=no\ndistinguished_name=holder_dn\nstring_mask=' + mask
                  + '\n[holder_dn]\nCN=' + holder_cn + '\n[issuer_dn]\nCN=' + issuer_cn
                  + '\n[ca]\ndefault_ca=issuer\n[issuer]\ndatabase=index\nnew_certs_dir=.'
                  '\ncertificate=issuer.crt\nprivate_key=issuer.pem\nserial=serial'
                  '\ndefault_md=sha256\npolicy=policy\nx509_extensions=ext\nunique_subject=no'
                  '\n[policy]\ncommonName=supplied\n[ext]\nsubjectKeyIdentifier=none\n'
                  + '\n'.join(extensions) + '\n')
        _write(root / 'openssl.cnf', config.encode())
        _write(root / 'index', b'')
        _write(root / 'serial', (f"{values['serial']:032X}\n").encode())
        def run(*args):
            try:
                return subprocess.run(['openssl', *args], cwd=root, check=True,
                                      capture_output=True, timeout=30).stdout
            except (OSError, subprocess.SubprocessError):
                raise ValueError('independent OpenSSL issuance failed') from None
        run('req', '-new', '-x509', '-config', 'openssl.cnf', '-section', 'req',
            '-key', 'issuer.pem', '-subj', '/CN=' + issuer_cn, '-days', '1', '-sha256', '-out', 'issuer.crt')
        run('req', '-new', '-config', 'openssl.cnf', '-key', 'holder.pem', '-out', 'holder.csr')
        run('ca', '-batch', '-notext', '-preserveDN', '-config', 'openssl.cnf', '-in', 'holder.csr',
            '-startdate', values['not_before'].strftime('%y%m%d%H%M%SZ'),
            '-enddate', values['not_after'].strftime('%y%m%d%H%M%SZ'), '-out', 'holder.crt')
        return run('x509', '-in', 'holder.crt', '-outform', 'DER')


def _directory(path):
    if not isinstance(path, Path) or not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError('canonical private path required')
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('owner0700 directory required')


def _read(path, cap):
    _directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or not 0 < before.st_size <= cap):
            raise ValueError('bounded owner0600 file required')
        raw = stream.read(cap + 1)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                                 info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if (identity(os.fstat(stream.fileno())) != identity(before)
                or identity(path.lstat()) != identity(before) or len(raw) != before.st_size):
            raise ValueError('private input changed')
    return raw


def _write(path, data, directory_fd=None):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                 dir_fd=directory_fd)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        os.unlink(path, dir_fd=directory_fd)
        raise


def issue_to_directory(issuer_path, holder_path, parameters_path, freeze_path, output, encoder):
    _directory(output)
    if any(output.iterdir()):
        raise ValueError('fresh private output required')
    raw_freeze = _read(freeze_path, 65536)
    frozen = decode_parameters(raw_freeze)
    started = time.time_ns()
    tool_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    if (frozen.get('schema') != 'credential-v3-frozen-holdout-boundary-v1'
            or type(frozen.get('frozen_at_unix_ns')) is not int
            or not 0 < frozen['frozen_at_unix_ns'] < started
            or frozen.get('issuance_tool_sha256') != tool_sha):
        raise ValueError('earlier pinned issuance freeze required')
    issuer_raw, holder_raw = _read(issuer_path, 4096), _read(holder_path, 4096)
    issuer = serialization.load_pem_private_key(issuer_raw, password=None)
    holder = serialization.load_pem_private_key(holder_raw, password=None)
    parameters_raw = _read(parameters_path, 8192)
    parameters = decode_parameters(parameters_raw)
    der = issue_certificate(issuer, holder, parameters, encoder)
    parsed = admit_certificate(der, issuer.public_key().public_numbers().n)
    issuer_hash, policy_hash = public_bindings(parsed, issuer.public_key().public_numbers().n)
    public_digest = lambda key: hashlib.sha256(key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    receipt = dict(schema='v3-freeze-linked-demo-issuance-v1',
        freeze_receipt_sha256=hashlib.sha256(raw_freeze).hexdigest(), issuance_tool_sha256=tool_sha,
        issuance_started_unix_ns=started, issuance_completed_unix_ns=time.time_ns(),
        fresh_key_generation_proven=False, encoder=encoder, variant=parsed['variant'],
        parameters_sha256=hashlib.sha256(parameters_raw).hexdigest(),
        credential_sha256=hashlib.sha256(der).hexdigest(), tbs_sha256=hashlib.sha256(parsed['tbs']).hexdigest(),
        issuer_public_key_sha256=public_digest(issuer), holder_public_key_sha256=public_digest(holder),
        issuer_hash=str(issuer_hash), policy_hash=str(policy_hash),
        openssl_version=subprocess.run(['openssl', 'version'], check=True, capture_output=True,
            timeout=5, text=True).stdout.strip() if encoder == 'openssl' else None)
    for path, raw, cap in [(freeze_path, raw_freeze, 65536), (issuer_path, issuer_raw, 4096),
                           (holder_path, holder_raw, 4096), (parameters_path, parameters_raw, 8192)]:
        if _read(path, cap) != raw:
            raise ValueError('issuance input changed')
    _directory(output)
    original = output.lstat()
    directory_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    created = []
    try:
        opened = os.fstat(directory_fd)
        if (opened.st_dev, opened.st_ino) != (original.st_dev, original.st_ino) or os.listdir(directory_fd):
            raise ValueError('fresh unchanged output required')
        for name, data in [('credential.der', der), ('issuance-receipt.json',
                (json.dumps(receipt, sort_keys=True, separators=(',', ':')) + '\n').encode())]:
            _write(name, data, directory_fd)
            created.append(name)
        os.fsync(directory_fd)
        _directory(output)
        current = output.lstat()
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError('output directory changed')
    except Exception:
        for name in created:
            os.unlink(name, dir_fd=directory_fd)
        raise
    finally:
        os.close(directory_fd)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['issuer', 'holder', 'parameters', 'freeze', 'output']:
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--encoder', choices=['cryptography', 'openssl'], required=True)
    args = parser.parse_args()
    try:
        issue_to_directory(args.issuer, args.holder, args.parameters, args.freeze, args.output, args.encoder)
    except Exception:
        raise SystemExit('bounded demo issuance rejected') from None


if __name__ == '__main__':
    main()
