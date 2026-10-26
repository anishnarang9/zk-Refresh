#!/usr/bin/env python3
"""Copy externally pinned heldout R0/R1 inputs for the v2 relation runner.

The manifest pins a freeze, full cohort, and eight indexed cases, each with a
context and R0/R1 receipt/input pair. Each pin is {path, sha256}. Receipt
assertions establish source provenance; this bridge does not establish circuit
satisfaction, live account authentication, proof validity, or application effect.
No certificate keys, exporter, compiled circuit, witness or proof is loaded.
"""
import argparse
import ctypes
import errno
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
from tools.part5 import generate_v3_heldout_keys as keys
from tools.part5 import prepare_v3_heldout_context as context
from tools.part5 import prepare_v3_heldout_source as source
from tools.part5.prepare_v3_revocation_cohort import membership_for_pair

SCHEMA = 'credential-v3-heldout-relation-inputs-v2'
ARRAYS = dict(tbs=672, issuerModulus=17, issuerSignature=17,
              holderSignature=17, siblings=10, pathIndices=10)
SCALARS = ('root', 'issuerHash', 'notBefore', 'notAfter', 'actionHash',
           'policyHash', 'layout', 'slot')


def _require(condition, reason):
    if not condition:
        raise ValueError(reason)


def _canonical_input(value):
    _require(type(value) is dict and set(value) == set(SCALARS) | set(ARRAYS),
             'exact circuit input fields required')
    def scalar(v):
        _require(type(v) is str and len(v) <= 77
                 and re.fullmatch(r'0|[1-9][0-9]*', v) is not None
                 and int(v) < source.FR, 'canonical circuit field required')
    for name in SCALARS:
        scalar(value[name])
    for name, count in ARRAYS.items():
        _require(type(value[name]) is list and len(value[name]) == count,
                 'exact circuit array shape required')
        for v in value[name]:
            scalar(v)


def _same_directory(output, fd, created):
    opened = os.fstat(fd)
    linked = output.lstat()
    _require((created.st_dev, created.st_ino) == (opened.st_dev, opened.st_ino)
             == (linked.st_dev, linked.st_ino)
             and stat.S_ISDIR(opened.st_mode) and opened.st_uid == os.getuid()
             and stat.S_IMODE(opened.st_mode) == 0o700,
             'private output directory changed')


def _write_new_at(directory_fd, name, raw):
    _require(type(name) is str and name and '/' not in name and name not in ('.', '..'),
             'plain output filename required')
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                 | os.O_CLOEXEC, 0o600, dir_fd=directory_fd)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw)
            stream.flush()
        os.fsync(fd)
        written = os.fstat(fd)
        linked = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        _require((written.st_dev, written.st_ino) == (linked.st_dev, linked.st_ino)
                 and stat.S_ISREG(written.st_mode) and written.st_uid == os.getuid()
                 and stat.S_IMODE(written.st_mode) == 0o600
                 and written.st_nlink == 1 and written.st_size == len(raw),
                 'private output file changed')
    finally:
        os.close(fd)


def _rename_no_replace(parent_fd, staged_name, output_name):
    if sys.platform != 'darwin':
        raise OSError(errno.ENOTSUP, 'atomic no-replace directory publication unavailable')
    rename = getattr(ctypes.CDLL(None, use_errno=True), 'renameatx_np', None)
    if rename is None:
        raise OSError(errno.ENOTSUP, 'atomic no-replace directory publication unavailable')
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                       ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(parent_fd, os.fsencode(staged_name), parent_fd,
              os.fsencode(output_name), 0x00000004) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), output_name)


def prepare(manifest_path, manifest_sha256, output):
    """Validate all sources before publishing exactly sixteen unchanged inputs."""
    snapshots = {}
    def load(pin, cap=65536):
        _require(type(pin) is dict and set(pin) == {'path', 'sha256'}
                 and type(pin['path']) is str and source._hash(pin['sha256']),
                 'externally pinned source required')
        path = Path(pin['path'])
        _require(path.is_absolute() and path.resolve(strict=True) == path,
                 'canonical pinned source path required')
        source.private_dir(path.parent)
        raw = source._read(path, cap, expected=pin['sha256'])
        if path in snapshots:
            _require(snapshots[path] == (raw, cap), 'conflicting source snapshots')
        snapshots[path] = (raw, cap)
        return source._json(raw), raw

    manifest, _ = load(dict(path=str(manifest_path), sha256=manifest_sha256))
    _require(type(manifest) is dict and set(manifest) == {'schema', 'freeze', 'cohort', 'cases'}
             and manifest['schema'] == SCHEMA, 'exact bridge manifest required')
    freeze, _ = load(manifest['freeze'])
    keys._freeze(Path(manifest['freeze']['path']), manifest['freeze']['sha256'], time.time_ns())
    cohort, _ = load(manifest['cohort'])
    freeze_sha, cohort_sha = manifest['freeze']['sha256'], manifest['cohort']['sha256']
    _require(cohort.get('freeze_sha256') == freeze_sha
             and cohort.get('frozen_at_unix_ns') == freeze['frozen_at_unix_ns']
             and type(cohort.get('generation_started_unix_ns')) is int
             and cohort['generation_started_unix_ns'] > freeze['frozen_at_unix_ns']
             and type(cohort.get('generation_completed_unix_ns')) is int
             and cohort['generation_completed_unix_ns'] >= cohort['generation_started_unix_ns'],
             'post-freeze cohort chronology required')
    cases = manifest['cases']
    _require(type(cases) is list and len(cases) == 8
             and all(type(c) is dict and set(c) == {'case_index', 'context', 'R0', 'R1'}
                     and type(c['case_index']) is int for c in cases)
             and sorted(c['case_index'] for c in cases) == list(range(8)),
             'eight unique indexed pairs required')
    outputs, envelopes = {}, []
    for case in sorted(cases, key=lambda c: c['case_index']):
        i = case['case_index']
        row, other = context._row_index(cohort, i)
        ctx, _ = load(case['context'], 16384)
        own_digest = bytes.fromhex(row['tbs_sha256'])
        member = membership_for_pair(own_digest, bytes.fromhex(other['tbs_sha256']),
                                     int.from_bytes(own_digest[:2], 'big') & 1023)
        roots = {k: f"{member[v]:064x}" for k, v in
                 [('R0', 'active_root'), ('R1', 'unrelated_root'), ('R2', 'own_revoked_root')]}
        membership = dict(slot=member['slot'], unrelated_slot=member['unrelated_slot'], **roots,
                          **{k: member[k] for k in ('active_siblings', 'unrelated_siblings', 'own_revoked_siblings')})
        _require(ctx.get('schema') == context.CASE_SCHEMA and ctx.get('heldout_acceptance') is False
                 and ctx.get('frozen_cohort') == dict(schema=context.COHORT_SCHEMA,
                     freeze_sha256=freeze_sha, cohort_receipt_sha256=cohort_sha)
                 and ctx.get('target') == context._public_certificate(row)
                 and ctx.get('unrelated') == context._public_certificate(other)
                 and ctx.get('membership') == membership,
                 'context differs from frozen credential and rebuilt pair')
        pair = ctx.get('pair_view')
        _require(type(pair) is dict and set(pair) == {'cohort_receipt_sha256', 'membership_sha256', 'stage_context_sha256'}
                 and all(source._hash(v) for v in pair.values()), 'pinned context pair required')
        receipts, inputs = {}, {}
        for variant, sibling, suffix in [('R0', 'active_siblings', ''), ('R1', 'unrelated_siblings', '_unrelated_refresh')]:
            entry = case[variant]
            _require(type(entry) is dict and set(entry) == {'receipt', 'input'}, 'receipt and input pins required')
            receipt, _ = load(entry['receipt'], 16384)
            inp, raw = load(entry['input'])
            _canonical_input(inp)
            expected = dict(schema=source.SCHEMA, variant=variant, case_index=i, target_variant=i,
                unrelated_variant=other['variant'],freeze_sha256=freeze_sha,cohort_receipt_sha256=cohort_sha,
                case_context_sha256=case['context']['sha256'], context_sha256=case['context']['sha256'],
                pair_receipt_sha256=pair['cohort_receipt_sha256'], membership_sha256=pair['membership_sha256'],
                stage_context_sha256=pair['stage_context_sha256'],membership_roots=roots,selected_root=roots[variant],
                issuer_index=row['issuer_index'],holder_index=row['holder_index'],target_der_sha256=row['credential_sha256'],
                target_tbs_sha256=row['tbs_sha256'],unrelated_der_sha256=other['credential_sha256'],
                issuer_public_key_sha256=row['issuer_public_key_sha256'],holder_public_key_sha256=row['holder_public_key_sha256'],
                action_hash=f"{int(inp['actionHash']):064x}",proof_created=False,application_effect=False,live_state_authenticated=False)
            _require(all(type(receipt.get(k)) is type(v) and receipt.get(k) == v for k,v in expected.items())
                     and type(receipt.get('artifacts_sha256')) is dict
                     and receipt['artifacts_sha256'].get('input.json') == entry['input']['sha256'],
                     'source receipt differs from exact input and frozen case')
            _require(inp['root'] == str(int(roots[variant],16))
                     and inp['issuerHash'] == row['issuer_hash'] and inp['policyHash'] == row['policy_hash']
                     and inp['notBefore'] == str(row['not_before_unix']) and inp['notAfter'] == str(row['not_after_unix'])
                     and inp['slot'] == str(member['slot']) and inp['siblings'] == list(map(str,member[sibling]))
                     and inp['pathIndices'] == [str((member['slot'] >> b) & 1) for b in range(10)],
                     'input public identity or rebuilt root/path differs')
            receipts[variant], inputs[variant] = receipt, inp
            name = f'holdout_{i}{suffix}'
            outputs[name + '.input.json'] = raw
            envelopes.append(dict(name=name, expect='accept', family='heldout'))
        r0, r1 = receipts['R0'], receipts['R1']
        _require(r1.get('r0_source_receipt_sha256') == case['R0']['receipt']['sha256']
                 and r0.get('transition_report_sha256') is None and r0.get('transition_context_sha256') is None
                 and source._hash(r1.get('transition_report_sha256')) and source._hash(r1.get('transition_context_sha256')),
                 'exact R0 to R1 source linkage required')
        for field in ('action_hash', 'stage_report_sha256', 'stage_plan_sha256',
                      'staged_request_sha256', 'finalized_action_transport_sha256'):
            _require(source._hash(r0.get(field)) and r0[field] == r1.get(field), 'same credential action and staged request required')
        _require(all(inputs['R0'][k] == inputs['R1'][k] for k in inputs['R0'] if k not in ('root','siblings'))
                 and [j for j,(a,b) in enumerate(zip(inputs['R0']['siblings'],inputs['R1']['siblings'])) if a != b] == [0],
                 'only root and one sibling may change')

    output = Path(output)
    _require(output.is_absolute() and not output.exists() and not output.is_symlink(), 'fresh output required')
    source.private_dir(output.parent)
    _require(output.parent.resolve(strict=True) / output.name == output, 'canonical output required')
    for path,(raw,cap) in snapshots.items():
        _require(source._read(path,cap) == raw, 'pinned source changed before publication')
    outputs['cases.json'] = source.encoded(envelopes)
    parent = output.parent
    parent_created = parent.lstat()
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _same_directory(parent, parent_fd, parent_created)
        staged_name = '.v3-heldout-relation-' + secrets.token_hex(16) + '.pending'
        os.mkdir(staged_name, mode=0o700, dir_fd=parent_fd)
        staged = parent / staged_name
        fd = os.open(staged_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                     | os.O_CLOEXEC, dir_fd=parent_fd)
        try:
            created = os.fstat(fd)
            source.private_dir(staged)
            _same_directory(staged, fd, created)
            _require(not os.listdir(fd), 'private output directory changed')
            for name, raw in outputs.items():
                _same_directory(staged, fd, created)
                _write_new_at(fd, name, raw)
                _same_directory(staged, fd, created)
            os.fsync(fd)
            _same_directory(staged, fd, created)
            _require(set(os.listdir(fd)) == set(outputs), 'private output directory changed')
            _same_directory(parent, parent_fd, parent_created)
            _rename_no_replace(parent_fd, staged_name, output.name)
            _same_directory(output, fd, created)
            os.fsync(parent_fd)
            _same_directory(output, fd, created)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
    return dict(input_count=16, setup_or_proofs_executed=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = prepare(args.manifest, args.manifest_sha256, args.output)
    except (ValueError, OSError, KeyError, TypeError):
        raise SystemExit('heldout relation input bridge rejected') from None
    print(source.encoded(result).decode(), end='')


if __name__ == '__main__':
    main()
