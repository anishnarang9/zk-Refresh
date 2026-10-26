#!/usr/bin/env python3
"""Create one synthetic prior-key control; it is not a prior credential."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


ROOT = Path(__file__).resolve().parents[2]
PART5 = ROOT / 'artifacts/dynark/part5'
FILENAME_PATTERN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]*\.pem')


def _fresh_target(output_path):
    declared_part5 = Path(PART5)
    path = Path(output_path)
    try:
        part5_info = declared_part5.lstat()
    except OSError as error:
        raise ValueError('artifacts/dynark/part5 must already exist') from error
    if not declared_part5.is_absolute() or not stat.S_ISDIR(part5_info.st_mode):
        raise ValueError('artifacts/dynark/part5 must be a canonical real directory')
    part5 = declared_part5.resolve(strict=True)
    try:
        parent_info = path.parent.lstat()
        canonical_parent = path.parent.resolve(strict=True)
    except OSError as error:
        raise ValueError('output parent must be artifacts/dynark/part5') from error
    if (not path.is_absolute() or not stat.S_ISDIR(parent_info.st_mode)
            or canonical_parent != part5
            or FILENAME_PATTERN.fullmatch(path.name) is None):
        raise ValueError('output must be a direct .pem child of artifacts/dynark/part5')
    if path.exists() or path.is_symlink():
        raise ValueError('fresh output path required')
    return path


def _write_new(path, raw):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as error:
        raise ValueError('fresh output path required') from error
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        directory_flags = os.O_RDONLY
        if hasattr(os, 'O_DIRECTORY'):
            directory_flags |= os.O_DIRECTORY
        if hasattr(os, 'O_NOFOLLOW'):
            directory_flags |= os.O_NOFOLLOW
        directory_fd = os.open(path.parent, directory_flags)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def create_seed(output_path):
    """Write one owner-only RSA-2048 SPKI public PEM and return only hashes."""
    path = _fresh_target(output_path)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    if public_key.key_size != 2048:
        raise ValueError('generated RSA public key must be 2048 bits')
    pem = public_key.public_bytes(serialization.Encoding.PEM,
                                  serialization.PublicFormat.SubjectPublicKeyInfo)
    der = public_key.public_bytes(serialization.Encoding.DER,
                                  serialization.PublicFormat.SubjectPublicKeyInfo)
    del private_key
    _write_new(path, pem)
    return {
        'pem_sha256': hashlib.sha256(pem).hexdigest(),
        'public_key_sha256': hashlib.sha256(der).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path,
                        help='fresh direct .pem child of artifacts/dynark/part5')
    args = parser.parse_args()
    try:
        hashes = create_seed(args.output)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(hashes, sort_keys=True))


if __name__ == '__main__':
    main()
