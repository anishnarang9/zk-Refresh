"""Light per-case expiry integration checks; all retained evidence is synthetic."""
import copy
import json
import shutil
from pathlib import Path

import pytest

from tools.part5 import run_v3_heldout_case as runner
from tools.part5.tests import test_finalize_v3_expired_status_negative as fixtures

save = fixtures.save


@pytest.mark.parametrize('variant', range(8))
def test_each_variant_clones_expiry_before_transition(tmp_path, variant):
    case = object.__new__(runner.HeldoutCaseRunner)
    case.variant = variant
    calls = []

    class Journal:
        def run_step(self, name, *, inputs, job, reuse=None, **kwargs):
            calls.append(name)
            return job()

    case.journal = Journal()

    def clone(request, root, stage, *, label='r0'):
        receipt = save(tmp_path / (label + '.json'),
                       {'stage_report_sha256': stage['report_sha256']})
        monitor = save(tmp_path / (label + '-monitor.json'), {'duration_seconds': 1})
        return {'label': label, 'receipt': receipt['path'], 'receipt_sha256': receipt['sha256'],
                'monitor': monitor['path'], 'monitor_sha256': monitor['sha256']}

    case._clone_r0 = clone
    clones = case._positive_full_r0_clones(tmp_path, {'report_sha256': 'a' * 64})
    assert 'expired_status' in clones
    assert calls[-1] == 'positive_full:expired-status-clone'


def test_expiry_wall_cost_counts_three_steps_once_and_fails_closed():
    names = ('positive_full:expired-status-clone', 'positive_full:expired-status-negative',
             'positive_full:expired-status-finalize')
    steps = {name: {'status': 'passed', 'wall_seconds': wall}
             for name, wall in zip(names, (2.5, 40, 0.75))}
    assert runner.expired_status_negative_wall_seconds(steps) == 43.25
    for bad in (None, True, float('nan'), float('inf'), -1):
        broken = copy.deepcopy(steps)
        broken[names[1]]['wall_seconds'] = bad
        with pytest.raises(ValueError):
            runner.expired_status_negative_wall_seconds(broken)
    with pytest.raises(ValueError):
        runner.expired_status_negative_wall_seconds({names[0]: steps[names[0]]})


@pytest.fixture
def retained():
    fixture = fixtures.FinalizerTests(methodName='test_synthetic_complete_retained_bundle_and_reviewed_sigint_positive')
    fixture.setUp()
    try:
        yield fixture
    finally:
        fixture.doCleanups()


def test_finalized_sidecar_reuse_reopens_loaded_evidence_and_snapshots(retained):
    case = object.__new__(runner.HeldoutCaseRunner)
    manifest = retained.with_positive()
    root = retained.root / 'integration'
    root.mkdir()
    result = case._finalize_expired_status(root, manifest)
    sidecar = json.loads(Path(result['sidecar']).read_bytes())
    assert set(sidecar) == runner.EXPIRED_STATUS_SIDECAR_KEYS
    assert sidecar['variant'] == retained.config['variant']
    assert case._expired_status_sidecar_verified(result['sidecar'], result['sidecar_sha256'])
    before = Path(retained.candidate['snapshots'][0]['before']['path'])
    before.write_bytes(b'changed')
    assert not case._expired_status_sidecar_verified(result['sidecar'], result['sidecar_sha256'])


def test_finalization_requires_same_wire_loaded_success(retained):
    case = object.__new__(runner.HeldoutCaseRunner)
    root = retained.root / 'integration'
    root.mkdir()
    with pytest.raises(ValueError, match='same-wire positive loaded Full'):
        case._finalize_expired_status(root, retained.manifest)
    assert not (root / 'sidecar.json').exists()


def test_finalization_reuse_rejects_old_schema_and_extra_fields(retained):
    case = object.__new__(runner.HeldoutCaseRunner)
    root = retained.root / 'integration'
    root.mkdir()
    result = case._finalize_expired_status(root, retained.with_positive())
    sidecar = json.loads(Path(result['sidecar']).read_bytes())
    for change in ({'schema': 'old'}, {'extra': True}, {'variant': 7}):
        changed = save(root / 'changed.json', {**sidecar, **change})
        assert not case._expired_status_sidecar_verified(changed['path'], changed['sha256'])


def test_loaded_supervisor_and_finalizer_are_ordered_separate_journal_steps(retained, monkeypatch):
    case = object.__new__(runner.HeldoutCaseRunner)
    case.variant = retained.config['variant']
    case.toolpaths = {'expired_status_negative': retained.config['runner']}
    root = retained.root / 'integration'
    root.mkdir()
    manifest = retained.with_positive()
    refs = manifest['refs']
    config = retained.config
    files = {role: Path(refs[role]['path']).read_bytes()
             for role in ('candidate', 'supervisor_status', 'monitor', 'monitor_invocation')}
    for role in files:
        Path(refs[role]['path']).unlink()
    # The fixture's monitor-private directory exists; real fresh invocation uses
    # a new directory. Remove its retained report so it is freshly created below.
    private_report = Path(refs['monitor_invocation']['path']).parent / 'report.json'
    private_report.unlink()
    private_report.parent.rmdir()
    snapshot_files = {p: p.read_bytes() for p in Path(config['output_dir']).rglob('*') if p.is_file()}
    shutil.rmtree(config['output_dir'])
    shutil.rmtree(config['control_output'])
    prepared = {'config': config, 'config_ref': refs['config'],
                'source_pins': manifest['source_pins'], 'positive_full': manifest['positive_full'],
                'monitor': Path(refs['monitor']['path']),
                'monitor_dir': Path(refs['monitor_invocation']['path']).parent}
    monkeypatch.setattr(case, '_expired_status_inputs', lambda *args: prepared)
    calls = []

    class Journal:
        def run_step(self, name, *, inputs, job, reuse=None, **kwargs):
            calls.append((name, inputs))
            result = job()
            if name == 'positive_full:expired-status-negative':
                assert result['setup_wall_seconds'] >= 0
                assert result['supervisor_wall_seconds'] == 40
                assert result['wall_seconds'] == result['setup_wall_seconds'] + 40
            assert reuse(result)
            return result

    case.journal = Journal()

    def bounded(owner, command, monitor_dir, monitor_path, *, runtime, storage_paths=(), env=None):
        assert calls[-1][0] == 'positive_full:expired-status-negative'
        assert owner == config['owner']
        assert command[-4:] == ['--config', refs['config']['path'], '--config-sha256', refs['config']['sha256']]
        assert runtime == 180
        assert env == {'P5_V3_EXPIRED_STATUS_NEGATIVE_SCOPE': 'part5-v3-expired-status-negative'}
        assert set(map(str, storage_paths)) == {config[p] for p in ('ledger', 'output_dir', 'control_output')}
        for path, raw in snapshot_files.items():
            save(path, raw)
            path.chmod(0o600)
        for role, raw in files.items():
            save(refs[role]['path'], raw)
        save(private_report, files['monitor'])
        return json.loads(files['monitor'])

    case.bounded_run = bounded
    result = case._expired_status_negative('positive_full', root, {}, {}, {}, {}, {})
    assert [name for name, _ in calls] == ['positive_full:expired-status-negative',
                                         'positive_full:expired-status-finalize']
    assert case._expired_status_sidecar_verified(result['sidecar'], result['sidecar_sha256'])


def test_old_fragment_root_is_rejected_without_writing(tmp_path, monkeypatch):
    manifest = {'variant': 0}
    fragment = tmp_path / 'acceptance-case-fragment.json'
    fragment.write_bytes(runner.encoded({'schema': 'credential-v3-heldout-acceptance-case-fragment-v1'}))
    before = fragment.read_bytes()
    save(tmp_path / 'run-id.json', {'schema': 'credential-v3-heldout-run-id-v1', 'run_id': '1' * 32})
    save(tmp_path / 'run-journal.json', {'schema': runner.JOURNAL_SCHEMA})
    before_files = {p: p.read_bytes() for p in tmp_path.iterdir()}
    monkeypatch.setattr(runner, 'validate_manifest', lambda _manifest: ({}, {}, {}))
    monkeypatch.setattr(runner, '_private_dir', lambda path, **kwargs: Path(path))
    identity = runner.digest(runner.encoded(manifest))
    with pytest.raises(ValueError, match='fragment schema'):
        runner.HeldoutCaseRunner(manifest, tmp_path,
            run_manifest_ref={'path': str(tmp_path / 'manifest.json'), 'sha256': 'a' * 64},
            manifest_sha256=identity)
    assert {p: p.read_bytes() for p in tmp_path.iterdir()} == before_files
    assert fragment.read_bytes() == before


def test_input_config_binds_case_full_proof_clone_and_frozen_sources(retained, monkeypatch):
    from tools.part5 import build_v3_expired_status_negative_inputs as builder
    from tools.part5 import finalize_v3_expired_status_negative as finalizer

    case = object.__new__(runner.HeldoutCaseRunner)
    case.variant = retained.config['variant']
    case.run_id = '1' * 32
    case.freeze_doc = {}
    case.manifest = {'freeze_receipt': retained.config['freeze_report'],
                     'freeze_sha256': retained.config['freeze_sha256'],
                     'runner': retained.config['runner'], 'runner_sha256': retained.config['runner_sha256'],
                     'frozen_files': {'loaded_elf': {'path': retained.config['expected_elf'],
                                                   'sha256': retained.config['expected_elf_sha256']}}}
    monkeypatch.setattr(runner, 'REPO', finalizer.REPO)
    pins = retained.manifest['source_pins']
    monkeypatch.setattr(builder, '_frozen_bundle_source_pins', lambda *args: pins)
    monkeypatch.setattr(case, '_art', lambda request, label: str(retained.root / label))
    config = retained.config
    stage = {'root': config['stage_root'], 'config': config['stage_config'],
             'config_sha256': config['stage_config_sha256'], 'status_path': config['stage_status'],
             'status_sha256': config['stage_status_sha256'], 'report': config['stage_report'],
             'report_sha256': config['stage_report_sha256'], 'plan': config['stage_plan'],
             'plan_sha256': config['stage_plan_sha256']}
    source = {'receipt': config['source_receipt'], 'receipt_sha256': config['source_receipt_sha256']}
    proof_doc = json.loads(Path(config['full_proof_receipt']).read_bytes())
    proof_doc['artifacts'] = {'proof/request_bound_training_full_base.proof': {
        'path': config['full_proof'], 'sha256': config['full_proof_sha256']}}
    proof_ref = save(retained.root / 'runner-proof-receipt.json', proof_doc)
    proof = {'receipt': proof_ref['path'], 'receipt_sha256': proof_ref['sha256'],
             'wires': proof_doc['wires']}
    clone = {'label': 'expired-status-r0', 'ledger': config['ledger'],
             'receipt': config['clone_receipt'], 'receipt_sha256': config['clone_receipt_sha256']}
    positive = {key: retained.positive[role]['path'] for key, role in (
        ('config', 'config'), ('report', 'report'), ('status_path', 'status'), ('monitor', 'monitor'))}
    positive['monitor_owner'] = retained.positive['monitor_owner']
    # The actual Execute monitor uses <name>/invocation.json alongside <name>.json.
    positive_monitor = Path(positive['monitor'])
    private = positive_monitor.with_suffix('')
    private.mkdir()
    shutil.copyfile(retained.positive['monitor_invocation']['path'], private / 'invocation.json')
    root = retained.root / 'case-request'
    root.mkdir()
    prepared = case._expired_status_inputs('positive_full', root, stage, source, proof, clone, positive)
    assert prepared['config']['variant'] == case.variant
    assert prepared['config']['full_proof_receipt_sha256'] == proof_ref['sha256']
    assert prepared['config']['clone_receipt_sha256'] == clone['receipt_sha256']
    assert prepared['config']['owner'].startswith(f'heldout-v{case.variant:02d}-')
    assert prepared['source_pins'] == pins
    assert json.loads(Path(prepared['config_ref']['path']).read_bytes()) == prepared['config']
    pins.pop(next(iter(pins)))
    with pytest.raises(ValueError, match='absent from frozen'):
        case._expired_status_inputs('positive_full', root, stage, source, proof, clone, positive)
