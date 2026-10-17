#!/usr/bin/env python3
"""Assemble eight pinned heldout case fragments into verifier input.

This tool only validates and joins existing references. It never runs a proof
or validator and never copies artifact contents into the manifest.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.part5 import generate_v3_heldout_keys as keygen

FRAGMENT_SCHEMA = 'credential-v3-heldout-acceptance-case-fragment-v1'
MANIFEST_SCHEMA = 'credential-v3-heldout-acceptance-manifest-v1'
VARIANTS = set(range(8))
FROZEN_ROLES = {'profile', 'r1cs', 'witness_executable', 'setup_manifest',
                'ordinary_vk', 'proof_runner', 'signer_interface',
                'ordinary_adapter', 'loaded_elf'}
SOURCE_ROLES = {'heldout_source_tool', 'training_helper', 'exporter',
                'request_fixture_bridge'}
PROOF_ROLES = {'packet_template', 'witness_js', 'relation_checker', 'node',
               'proof_runner', 'adapter_binary', 'bounded_supervisor', 'exporter'}
GLOBAL_FIELDS = ('freeze_receipt', 'cohort_receipt', 'frozen_files',
                 'frozen_bundles', 'application_source_manifest',
                 'application_source_files', 'source_files', 'proof_inputs')
CASE_FIELDS = ('variant', 'case_context', 'stage_context', 'pair_receipt',
               'membership', 'stage', 'transition', 'sources', 'branches',
               'run_manifest', 'run_journal', 'all_step_wall_seconds', 'shared_costs',
               'branch_wall_components', 'branch_wall_seconds',
               'shared_stage_transition_wall_seconds', 'branch_order',
               'proof_order')
COST_BRANCHES = {'full', 'unrelated_full', 'anchor', 'own_revocation'}


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       allow_nan=False) + '\n').encode()


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read(path, cap=4 * 1024 * 1024):
    path = Path(path)
    before = path.lstat()
    if (not path.is_absolute() or path.resolve(strict=True) != path
            or not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
            or before.st_nlink != 1 or before.st_mode & 0o022
            or before.st_size <= 0 or before.st_size > cap):
        raise ValueError('canonical bounded owner-controlled file required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if _identity(opened) != _identity(before):
            raise ValueError('input changed at open')
        raw = stream.read(cap + 1)
        if _identity(os.fstat(stream.fileno())) != _identity(before):
            raise ValueError('input changed during read')
    if len(raw) != before.st_size or _identity(path.lstat()) != _identity(before):
        raise ValueError('input changed after read')
    return raw


def _pinned_json(path, expected_sha256):
    raw = _read(path)
    if _sha(raw) != expected_sha256:
        raise ValueError('case fragment SHA-256 pin mismatch')
    return json.loads(raw, object_pairs_hook=_unique_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(
                          ValueError('non-finite JSON number')))


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def _verify_ref(ref, *, cap=512 * 1024 * 1024):
    if (type(ref) is not dict or set(ref) != {'path', 'sha256'}
            or type(ref['path']) is not str or not Path(ref['path']).is_absolute()
            or type(ref['sha256']) is not str or len(ref['sha256']) != 64
            or any(c not in '0123456789abcdef' for c in ref['sha256'])):
        raise ValueError('absolute pinned artifact reference required')
    if _sha(_read(ref['path'], cap)) != ref['sha256']:
        raise ValueError('artifact reference pin mismatch')


def _finite_cost(value):
    return (type(value) in (int, float) and math.isfinite(value)
            and value >= 0)


def _validate_cost_fields(case):
    _verify_ref(case['run_manifest'], cap=1024 * 1024)
    _verify_ref(case['run_journal'], cap=4 * 1024 * 1024)
    steps = case['all_step_wall_seconds']
    if (type(steps) is not dict or not steps
            or any(type(name) is not str or not name or not _finite_cost(value)
                   for name, value in steps.items())):
        raise ValueError('complete finite journal wall-time map required')
    shared = case['shared_costs']
    if (type(shared) is not dict
            or set(shared) != {'shared_stage_seconds', 'shared_transition_seconds'}
            or any(not _finite_cost(value) for value in shared.values())):
        raise ValueError('complete shared stage/transition cost totals required')
    components = case['branch_wall_components']
    if type(components) is not dict or set(components) != COST_BRANCHES:
        raise ValueError('complete four-branch wall-time components required')
    for name, row in components.items():
        if (type(row) is not dict
                or set(row) != {'proof_seconds', 'clone_seconds', 'effect_seconds',
                                'total_seconds'}
                or any(not _finite_cost(value) for value in row.values())):
            raise ValueError(f'complete finite {name} wall-time components required')
    totals = case['branch_wall_seconds']
    if (type(totals) is not dict or set(totals) != COST_BRANCHES
            or any(not _finite_cost(value) for value in totals.values())):
        raise ValueError('complete four-branch wall-time totals required')
    shared_parts = case['shared_stage_transition_wall_seconds']
    if (type(shared_parts) is not dict or set(shared_parts) != {'stage', 'transition'}
            or any(type(shared_parts[kind]) is not dict
                   or set(shared_parts[kind]) != {'A', 'B', 'C'}
                   or any(not _finite_cost(value)
                          for value in shared_parts[kind].values())
                   for kind in ('stage', 'transition'))):
        raise ValueError('complete A/B/C stage and transition wall times required')
    expected_branch_order = (['unrelated_full', 'anchor'] if case['variant'] % 2 == 0
                             else ['anchor', 'unrelated_full'])
    expected_proof_order = (['full', 'anchor'] if case['variant'] % 2 == 0
                            else ['anchor', 'full'])
    if (case['branch_order'] != expected_branch_order
            or case['proof_order'] != {'unrelated_compare': expected_proof_order}):
        raise ValueError('registered branch/proof order parity required')


def _verify_globals(globals_):
    if type(globals_) is not dict or set(globals_) != set(GLOBAL_FIELDS):
        raise ValueError('complete common acceptance identities required')
    for name in ('freeze_receipt', 'cohort_receipt', 'application_source_manifest'):
        _verify_ref(globals_[name])
    for mapping_name in ('frozen_files', 'source_files', 'proof_inputs',
                         'application_source_files'):
        mapping = globals_[mapping_name]
        if type(mapping) is not dict or not mapping:
            raise ValueError(f'complete {mapping_name} references required')
        expected_roles = {'frozen_files': FROZEN_ROLES,
                          'source_files': SOURCE_ROLES,
                          'proof_inputs': PROOF_ROLES}.get(mapping_name)
        if expected_roles is not None and set(mapping) != expected_roles:
            raise ValueError(f'complete pinned {mapping_name} roles required')
        for ref in mapping.values():
            _verify_ref(ref)
    bundles = globals_['frozen_bundles']
    if (type(bundles) is not dict or set(bundles) != {'registry', 'client'}
            or any(type(rows) is not list or not rows for rows in bundles.values())):
        raise ValueError('frozen registry and client bundles required')
    for rows in bundles.values():
        for row in rows:
            if type(row) is not dict or set(row) != {'path', 'artifact'}:
                raise ValueError('frozen bundle path and artifact reference required')
            _verify_ref(row['artifact'])


def _case_from_fragment(fragment):
    if (type(fragment) is not dict
            or fragment.get('schema') != FRAGMENT_SCHEMA
            or type(fragment.get('variant')) is not int
            or fragment['variant'] not in VARIANTS):
        raise ValueError('pinned heldout case fragment required')
    case = fragment.get('case')
    if case is None:
        case = {field: fragment[field] for field in CASE_FIELDS if field in fragment}
    if type(case) is not dict or set(case) != set(CASE_FIELDS):
        raise ValueError('complete normalized heldout case evidence required')
    if case.get('variant', fragment['variant']) != fragment['variant']:
        raise ValueError('fragment and case variants differ')
    case['variant'] = fragment['variant']
    if (type(case['stage']) is not dict or set(case['stage']) != {'A', 'B', 'C'}
            or type(case['transition']) is not dict
            or set(case['transition']) != {'A', 'B', 'C'}
            or type(case['sources']) is not dict
            or set(case['sources']) != {'A', 'B', 'C'}
            or any(type(case['sources'][slot]) is not dict
                   or set(case['sources'][slot]) != {'R0', 'R1'}
                   for slot in ('A', 'B', 'C'))):
        raise ValueError('complete independent A/B/C slot evidence required')
    if type(case['branches']) is not dict or set(case['branches']) != {
            'full', 'unrelated_full', 'anchor', 'own_revocation'}:
        raise ValueError('all four heldout branch references required')
    _validate_cost_fields(case)
    return case


def assemble(fragment_refs):
    if type(fragment_refs) not in (list, tuple) or len(fragment_refs) != 8:
        raise ValueError('exactly eight acceptance case fragments required')
    if any(type(ref) not in (list, tuple) or len(ref) != 2 for ref in fragment_refs):
        raise ValueError('each case fragment needs an explicit path and SHA-256 pin')
    normalized_paths = [Path(ref[0]) for ref in fragment_refs]
    if any(path.name != 'acceptance-case-fragment.json' for path in normalized_paths):
        raise ValueError('runner acceptance-case-fragment.json files required')
    if len({str(path) for path in normalized_paths}) != 8:
        raise ValueError('eight distinct case fragment paths required')
    fragments = [_pinned_json(path, ref[1])
                 for path, ref in zip(normalized_paths, fragment_refs)]
    first = fragments[0]
    globals_ = first.get('globals')
    if globals_ is None:
        globals_ = {name: first.get(name) for name in GLOBAL_FIELDS}
    _verify_globals(globals_)
    cases, seen = [], set()
    for fragment in fragments:
        current = fragment.get('globals')
        if current is None:
            current = {name: fragment.get(name) for name in GLOBAL_FIELDS}
        if _canonical(current) != _canonical(globals_):
            raise ValueError('case fragments disagree on byte-pinned common identities')
        if fragment['variant'] in seen:
            raise ValueError('duplicate heldout variant')
        case = _case_from_fragment(fragment)
        seen.add(case['variant'])
        cases.append(case)
    if seen != VARIANTS:
        raise ValueError('fragments must cover variants 0 through 7')
    return {'schema': MANIFEST_SCHEMA, **globals_,
            'cases': sorted(cases, key=lambda case: case['variant'])}


def write_manifest(manifest, output_dir):
    output_dir = Path(output_dir)
    if (not output_dir.is_absolute() or output_dir.exists() or output_dir.is_symlink()
            or output_dir.parent.resolve(strict=True) != output_dir.parent
            or not keygen._ignored(output_dir)):
        raise ValueError('fresh ignored output directory required')
    output_dir.mkdir(mode=0o700)
    info = output_dir.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError('owner0700 output directory required')
    path = output_dir / 'heldout-acceptance-manifest.json'
    raw = (json.dumps(manifest, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return path, _sha(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fragment', action='append', required=True,
                        help='PATH:SHA256 for one acceptance-case-fragment.json; pass exactly eight')
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()
    if len(args.fragment) != 8:
        raise SystemExit('exactly eight --fragment inputs required')
    try:
        fragment_refs = []
        for value in args.fragment:
            path, separator, pin = value.rpartition(':')
            if (not separator or len(pin) != 64
                    or any(char not in '0123456789abcdef' for char in pin)):
                raise ValueError('fragment input must be PATH:SHA256')
            fragment_refs.append((path, pin))
        manifest = assemble(fragment_refs)
        path, sha = write_manifest(manifest, args.output_dir)
    except Exception:
        raise SystemExit('heldout acceptance assembly rejected') from None
    print(json.dumps({'path': str(path), 'sha256': sha,
                      'fragments': [{'path': str(Path(item[0])), 'sha256': item[1]}
                                    for item in fragment_refs]}, sort_keys=True))


if __name__ == '__main__':
    main()
