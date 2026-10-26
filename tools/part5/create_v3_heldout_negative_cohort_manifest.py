#!/usr/bin/env python3
"""Create prospective negative-cohort consistency inputs, never acceptance.

Call create_manifest(common_identities, expired_status_reports,
queue_capacity_reports, output). All pins are caller supplied; expectations
are never inferred from evidence reports. CLI --inputs is a strict JSON object
with exactly those three input fields, fixed by --inputs-sha256 supplied
separately. The output uses the existing cohort verifier's exact v1 schema.
This file contains private evidence paths and must remain owner only.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.part5 import verify_v3_heldout_negative_cohort as verifier

INPUT_FIELDS = {'common_identities', 'expired_status_reports', 'queue_capacity_reports'}


def _output(path):
    path = Path(path)
    if (not path.is_absolute() or path.exists() or path.is_symlink()
            or path.parent.resolve(strict=True) != path.parent or not path.parent.is_dir()):
        raise ValueError('fresh canonical nonsymlink output required')
    return path


def create_manifest(common_identities, expired_status_reports, queue_capacity_reports, output):
    """Validate caller-selected pins before writing one fresh private manifest."""
    output = _output(output)
    manifest = copy.deepcopy({'schema': verifier.SCHEMA,
                              'common_identities': common_identities,
                              'expired_status_reports': expired_status_reports,
                              'queue_capacity_reports': queue_capacity_reports})
    facts = verifier.validate_manifest(manifest)
    raw = (json.dumps(manifest, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    if len(raw) > verifier.MAX_MANIFEST_BYTES:
        raise ValueError('manifest exceeds size cap')
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(output, flags, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {**facts, 'manifest_sha256': hashlib.sha256(raw).hexdigest()}


def create_from_file(inputs, expected_sha256, output):
    """Read strictly decoded external pins from a separately byte-pinned file."""
    path = verifier._path(str(inputs))
    raw = verifier._pin(path, verifier.MAX_MANIFEST_BYTES, expected_sha256)
    data = verifier.public._json_object(raw, 'negative cohort inputs')
    verifier._fields(data, INPUT_FIELDS)
    return create_manifest(**data, output=output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--inputs-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        facts = create_from_file(args.inputs, args.inputs_sha256, args.output)
    except Exception as error:
        raise SystemExit(f'negative cohort manifest rejected ({type(error).__name__}); no result established') from None
    print(json.dumps(facts, sort_keys=True))


if __name__ == '__main__':
    main()
