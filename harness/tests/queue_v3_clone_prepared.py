#!/usr/bin/env python3
"""Import a stopped prepared-only ledger without inventing prepare provenance.

The imported status describes a byte copy, not a validator run. Stage must admit
the pinned source chain and reattest the loaded identity before transactions.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import stat

from harness.tests.queue_v3_clone_ledger import inventory, stale_admin_socket
from harness.tests.queue_v3_local_prepare import LIMITS, PORT_WAIT_SECONDS, ports_free

SCOPE = 'part5-v3-prepared-import'
SCHEMA = 'part5-v3-prepared-ledger-import-v1'


def _raw(path, cap=65536):
    path = Path(path)
    before = path.lstat()
    if (not path.is_absolute() or path.resolve(strict=True) != path
            or not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
            or before.st_size > cap):
        raise ValueError('canonical owner-only bounded import artifact required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode,
                                  value.st_nlink, value.st_uid, value.st_size,
                                  value.st_mtime_ns, value.st_ctime_ns)
        if identity(before) != identity(os.fstat(stream.fileno())):
            raise ValueError('import artifact changed at open')
        raw = stream.read(cap + 1)
        if (identity(before) != identity(os.fstat(stream.fileno()))
                or len(raw) != before.st_size):
            raise ValueError('import artifact changed during read')
    return raw


def _pin(ref):
    if type(ref) is not dict or set(ref) != {'path', 'sha256'}:
        raise ValueError('exact import source artifact pin required')
    raw = _raw(ref['path'])
    if hashlib.sha256(raw).hexdigest() != ref['sha256']:
        raise ValueError('prepared import source pin mismatch')
    return json.loads(raw)


def _directory(path):
    path = Path(path)
    info = path.lstat()
    if (not path.is_absolute() or path.resolve(strict=True) != path
            or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError('canonical owner-only import directory required')
    return path


def _tree(path):
    rows = inventory(_directory(path))
    for relative, kind, _, _ in rows:
        info = (Path(path) / relative).lstat()
        if kind == 'link' or (kind == 'file' and info.st_nlink != 1):
            raise ValueError('prepared import forbids linked ledger entries')
    _raw(Path(path) / 'genesis.bin', 16 * 1024 * 1024)
    return len(rows), hashlib.sha256(
        json.dumps(rows, separators=(',', ':')).encode()).hexdigest()


def review_source(source):
    if (type(source) is not dict
            or set(source) != {'config', 'status', 'monitor', 'monitor_owner'}):
        raise ValueError('exact source prepare provenance required')
    original, prior, monitor = (_pin(source[key]) for key in ('config', 'status', 'monitor'))
    loaded = prior.get('loaded_program', {})
    if (original.get('schema') != 1 or original.get('scope') != 'part5-v3-local-prepare'
            or original.get('outer_limits_required') != LIMITS
            or prior.get('schema') != 1 or prior.get('scope') != 'part5-v3-local-prepare'
            or prior.get('config_sha256') != source['config']['sha256']
            or prior.get('ledger') != str(Path(original['runtime_output']) / 'ledger')
            or prior.get('status') != 'failed' or prior.get('error_type') is not None
            or prior.get('application_effect') is not False
            or prior.get('prepared_application_accounts') is not False
            or prior.get('ledger_reuse_requires_review') is not True
            or prior.get('cleanup', {}).get('spawned') is not True
            or prior['cleanup'].get('reaped') is not True
            or prior['cleanup'].get('graceful') is not False
            or prior['cleanup'].get('exit_code') != -2
            or loaded.get('elf_match') is not True
            or loaded.get('elf_sha256') != original.get('elf_sha256')
            or loaded.get('program') != original.get('program')
            or any(type(loaded.get(key)) is not str or not loaded[key] for key in
                   ('genesis', 'programdata', 'program_account_sha256',
                    'programdata_account_sha256'))
            or monitor.get('schema') != 1
            or monitor.get('measurement') != 'bounded_complete_session'
            or monitor.get('owner') != source['monitor_owner']
            or monitor.get('passed') is not False or monitor.get('exit_code') != 1
            or monitor.get('censored') is not False
            or monitor.get('stop_reason') is not None
            or monitor.get('runner_error_type') is not None
            or monitor.get('cleanup_remaining_owned_processes') != 0
            or monitor.get('cleanup_status_unknown') is not False
            or type(monitor.get('sample_count')) is not int or monitor['sample_count'] < 1
            or type(monitor.get('duration_seconds')) not in (int, float)
            or not math.isfinite(monitor['duration_seconds']) or monitor['duration_seconds'] <= 0
            or 'prepared_import' in original):
        raise ValueError('reviewed stopped prepared-only source required')
    return original, prior, monitor


def _write(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(raw).hexdigest()


def clone(source, runtime, control):
    """Create new import config/status; never edit or relabel source receipts."""
    ports_free(timeout_seconds=PORT_WAIT_SECONDS)
    original, prior, _ = review_source(source)
    source_ledger = _directory(prior['ledger'])
    runtime, control = Path(runtime), Path(control)
    for path in (runtime, control):
        _directory(path.parent)
        if (not path.is_absolute() or path.exists() or path.is_symlink()
                or path.resolve() != path or path == source_ledger
                or path in source_ledger.parents or source_ledger in path.parents):
            raise ValueError('fresh disjoint prepared import destination required')
    if runtime == control or runtime in control.parents or control in runtime.parents:
        raise ValueError('disjoint prepared import runtime/control required')
    before = _tree(source_ledger)
    excluded_socket = stale_admin_socket(source_ledger)
    runtime.mkdir(mode=0o700)
    control.mkdir(mode=0o700)
    destination = runtime / 'ledger'
    shutil.copytree(source_ledger, destination, copy_function=shutil.copy2,
                    ignore=lambda directory, names: {'admin.rpc'}
                    if excluded_socket and Path(directory) == source_ledger else set())
    if before != _tree(source_ledger) or before != _tree(destination):
        raise ValueError('prepared source changed or imported copy differs')
    binding = {'schema': SCHEMA, 'source_prepare': source,
               'source': str(source_ledger), 'destination': str(destination),
               'entry_count': before[0], 'tree_sha256': before[1],
               'genesis_file_sha256': hashlib.sha256(
                   _raw(destination / 'genesis.bin', 16 * 1024 * 1024)).hexdigest(),
               'source_stable': True, 'copy_identical': True,
               'excluded_stale_admin_socket': excluded_socket}
    imported_config = {**original, 'scope': SCOPE, 'runtime_output': str(runtime),
                       'control_output': str(control), 'prepared_import': binding}
    config_path = control / 'import-config.json'
    config_sha = _write(config_path, imported_config)
    status = {'schema': 1, 'scope': SCOPE,
              'status': 'imported_pending_live_reattestation',
              'config_sha256': config_sha, 'ledger': str(destination),
              'loaded_program': prior['loaded_program'], 'prepared_import': binding,
              'application_effect': False, 'prepared_application_accounts': False,
              'loaded_identity_rechecked_after_restart': False}
    status_path = control / 'status.json'
    status_sha = _write(status_path, status)
    return {'config': str(config_path), 'config_sha256': config_sha,
            'status_path': str(status_path), 'status_sha256': status_sha,
            'monitor': source['monitor']['path'],
            'monitor_sha256': source['monitor']['sha256'],
            'monitor_owner': source['monitor_owner'],
            'runtime': str(runtime), 'control': str(control),
            'tree_sha256': before[1], 'source_ledger': str(source_ledger)}


def review_import(prior, monitor, original, config):
    """Validate opt-in copied provenance immediately before live stage restart."""
    binding = original.get('prepared_import')
    if type(binding) is not dict or binding.get('schema') != SCHEMA:
        raise ValueError('explicit prepared import provenance required')
    source_original, source_prior, source_monitor = review_source(binding['source_prepare'])
    expected_original = {**source_original, 'scope': SCOPE,
                         'runtime_output': original['runtime_output'],
                         'control_output': original['control_output'],
                         'prepared_import': binding}
    source = Path(source_prior['ledger'])
    destination = Path(original['runtime_output']) / 'ledger'
    if (original != expected_original or prior.get('scope') != SCOPE
            or prior.get('schema') != 1
            or prior.get('status') != 'imported_pending_live_reattestation'
            or prior.get('config_sha256') != config['prior_config_sha256']
            or prior.get('prepared_import') != binding
            or prior.get('ledger') != str(destination)
            or config.get('ledger') != str(destination)
            or binding.get('source') != str(source)
            or binding.get('destination') != str(destination)
            or destination == source or destination in source.parents or source in destination.parents
            or binding.get('source_stable') is not True
            or binding.get('copy_identical') is not True
            or prior.get('loaded_program') != source_prior['loaded_program']
            or config.get('expected_genesis') != source_prior['loaded_program']['genesis']
            or prior.get('loaded_identity_rechecked_after_restart') is not False
            or prior.get('application_effect') is not False
            or prior.get('prepared_application_accounts') is not False
            or 'cleanup' in prior
            or config.get('prior_monitor_owner') != binding['source_prepare']['monitor_owner']
            or config.get('prior_monitor_sha256') != binding['source_prepare']['monitor']['sha256']
            or monitor != source_monitor):
        raise ValueError('prepared import source/destination provenance mismatch')
    expected_tree = (binding.get('entry_count'), binding.get('tree_sha256'))
    if (expected_tree != _tree(source) or expected_tree != _tree(destination)
            or hashlib.sha256(_raw(destination / 'genesis.bin', 16 * 1024 * 1024)).hexdigest()
               != binding.get('genesis_file_sha256')):
        raise ValueError('prepared import byte inventory changed before stage')
    return str(destination)
