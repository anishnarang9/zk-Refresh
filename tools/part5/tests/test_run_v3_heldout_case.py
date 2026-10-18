import importlib.util
import hashlib
import json
from pathlib import Path
import sys
import time

import pytest

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tools.part5 import assemble_v3_heldout_acceptance as assembler
from tools.part5 import build_v3_heldout_run_manifest as manifest_builder
from tools.part5 import verify_v3_heldout_acceptance as verifier
from harness.tests import queue_v3_local_disabled_config_negative as disabled_negative

MODULE_PATH = Path(__file__).resolve().parents[1] / 'run_v3_heldout_case.py'
spec = importlib.util.spec_from_file_location('run_v3_heldout_case', MODULE_PATH)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def test_request_matrix_uses_three_distinct_actions_and_matched_b_clones():
    requests = runner.request_matrix()
    assert [row['name'] for row in requests] == ['positive_full', 'unrelated_compare', 'own_revocation']
    assert len({row['request_slot'] for row in requests}) == 3
    unrelated = requests[1]
    assert unrelated['proof_modes'] == ['full', 'anchor']
    assert unrelated['branches'] == [
        {'name': 'unrelated_full', 'clone': 'r1_full_clone', 'mode': 'full'},
        {'name': 'anchor', 'clone': 'r1_anchor_clone', 'mode': 'anchor'},
    ]
    assert requests[2]['proof_modes'] == ['anchor']
    assert requests[2]['branches'][0]['mode'] == 'own-revocation'


def test_positive_full_r0_clones_complete_between_stage_and_transition(tmp_path):
    class Journal:
        def __init__(self):
            self.calls = []
            self.completed = []

        def run_step(self, name, *, inputs, job, reuse=None, category=None):
            self.calls.append((name, inputs))
            result = job()
            self.completed.append(name)
            return result

    case_runner = object.__new__(runner.HeldoutCaseRunner)
    case_runner.journal = Journal()
    case_runner._verify_record = runner.HeldoutCaseRunner._verify_record
    wall_by_label = {'r0': 1.25, 'disabled-config-r0': 2.5,
                     'ambiguous-restart-r0': 3.75}
    clone_steps = ['positive_full:r0-clone',
                   'positive_full:disabled-config-clone',
                   'positive_full:ambiguous-restart-clone']

    def stage(req, root, case_root, context, prepared):
        return {'report_sha256': 'b' * 64, 'wall_seconds': 4.0}

    def clone(request, root, stage, *, label='r0'):
        return {'label': label, 'receipt': label + '-receipt',
                'receipt_sha256': 'a' * 64,
                'wall_seconds': wall_by_label[label]}

    def transition(req, root, case_root, stage):
        assert case_runner.journal.completed == ['positive_full:stage', *clone_steps]
        return {'report_sha256': 'c' * 64, 'wall_seconds': 5.0}

    case_runner._stage = stage
    case_runner._clone_r0 = clone
    case_runner._transition = transition
    stage_result, transition_result, clones = case_runner._stage_transition(
        'positive_full', tmp_path / 'root', tmp_path, {'case_context_sha256': 'd' * 64},
        {'status_sha256': 'e' * 64})

    assert [name for name, _ in case_runner.journal.calls] == [
        'positive_full:stage', *clone_steps, 'positive_full:transition']
    stage_sha = stage_result['report_sha256']
    assert [inputs for _, inputs in case_runner.journal.calls[1:4]] == [
        {'stage_report_sha256': stage_sha},
        {'stage_report_sha256': stage_sha, 'label': 'disabled-config-r0'},
        {'stage_report_sha256': stage_sha, 'label': 'ambiguous-restart-r0'}]
    assert [clones[key]['wall_seconds'] for key in
            ('r0', 'disabled_config', 'ambiguous_restart')] == [1.25, 2.5, 3.75]
    assert transition_result['report_sha256'] == 'c' * 64


def test_application_artifact_names_are_stable_per_run_and_fresh_between_runs():
    one = runner.application_artifact_name(3, 'a' * 32, 'positive_full', 'runtime')
    assert one == runner.application_artifact_name(3, 'a' * 32, 'positive_full', 'runtime')
    assert one != runner.application_artifact_name(3, 'b' * 32, 'positive_full', 'runtime')
    assert one.startswith('application-v3-heldout-03-')


def test_run_manifest_reference_pins_file_and_matches_journal_identity(tmp_path):
    manifest = {'schema': runner.RUN_SCHEMA, 'variant': 3}
    raw = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    path = tmp_path / 'case-03.json'
    path.write_bytes(raw)

    reference, manifest_sha256 = runner.run_manifest_identity(path, raw, manifest)

    assert reference == {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}
    assert manifest_sha256 == hashlib.sha256(runner.encoded(manifest)).hexdigest()
    assert manifest_sha256 != reference['sha256']


def test_runner_role_requires_python_executable_not_supervisor_script(tmp_path):
    python = tmp_path / 'python3'
    python_raw = f'#!{sys.executable}\npass\n'.encode()
    python.write_bytes(python_raw)
    python.chmod(0o700)

    session_runner = REPO / 'results/dynark/part5/session_runner.py'
    session_runner_raw = session_runner.read_bytes()

    assert runner._read(python, hashlib.sha256(python_raw).hexdigest(),
                        executable=True) == python_raw
    try:
        runner._read(session_runner, hashlib.sha256(session_runner_raw).hexdigest(),
                     executable=True)
    except ValueError as error:
        assert 'executable' in str(error)
    else:
        raise AssertionError('session_runner.py must not satisfy the Python executable role')


def test_python_executable_is_not_accepted_without_frozen_queue_runner_identity(tmp_path):
    python = tmp_path / 'python3'
    python_raw = f'#!{sys.executable}\npass\n'.encode()
    python.write_bytes(python_raw)
    python.chmod(0o700)

    try:
        runner.validate_runner_bundle(
            str(REPO / manifest_builder.freeze_tool.RUNNER_BINARY),
            hashlib.sha256(python_raw).hexdigest(),
            [{'path': manifest_builder.freeze_tool.RUNNER_BINARY,
              'artifact': {'path': str(REPO / manifest_builder.freeze_tool.RUNNER_BINARY),
                           'sha256': 'a' * 64}}],
        )
    except ValueError as error:
        assert 'frozen registry bundle' in str(error)
    else:
        raise AssertionError('Python executable without the frozen queue runner identity was accepted')


def test_manifest_builder_rejects_non_queue_runner_path(tmp_path):
    python = tmp_path / 'python3'
    python.write_text(f'#!{sys.executable}\npass\n')
    python.chmod(0o700)
    try:
        manifest_builder.build(None, None, None, None, None, None, None, None,
                               python, tmp_path / 'manifests', None)
    except ValueError as error:
        assert 'heldout queue runner binary' in str(error)
    else:
        raise AssertionError('manifest builder accepted Python as the queue test runner')


def test_manifest_builder_requires_exact_well_formed_freeze_identity_map():
    identities = {role: 'a' * 64
                  for role in manifest_builder.keygen.IDENTITY_ROLES}
    assert manifest_builder._frozen_identities({'identities': identities}) == identities

    for invalid in (
        {**identities, 'unexpected': 'b' * 64},
        {role: value for role, value in identities.items()
         if role != 'circuit'},
        {**identities, 'circuit': 'not-a-sha256'},
    ):
        try:
            manifest_builder._frozen_identities({'identities': invalid})
        except ValueError as error:
            assert 'exact frozen identity map' in str(error)
        else:
            raise AssertionError('manifest builder accepted an inexact freeze identity map')


def test_manifest_builder_proof_binary_ref_must_match_frozen_identity(tmp_path):
    proof_binary = tmp_path / 'v3-proof-runner-training-010'
    proof_binary.write_bytes(b'corrected proof runner')
    proof_binary.chmod(0o700)
    proof_sha = hashlib.sha256(proof_binary.read_bytes()).hexdigest()
    identities = {'proof_runner': proof_sha}

    assert manifest_builder._proof_runner_ref(proof_binary, identities) == {
        'path': str(proof_binary), 'sha256': proof_sha}

    with pytest.raises(ValueError, match='frozen proof runner identity'):
        manifest_builder._proof_runner_ref(proof_binary, {'proof_runner': '0' * 64})


def test_case_manifest_requires_same_explicit_proof_runner_path_and_hash(tmp_path):
    proof_binary = tmp_path / 'v3-proof-runner-training-010'
    proof_binary.write_bytes(b'corrected proof runner')
    proof_binary.chmod(0o700)
    proof_sha = hashlib.sha256(proof_binary.read_bytes()).hexdigest()
    direct_ref = {'path': str(proof_binary), 'sha256': proof_sha}

    assert runner.validate_proof_runner_reference(
        direct_ref, dict(direct_ref), proof_sha) == direct_ref

    other_binary = tmp_path / 'another-runner'
    other_binary.write_bytes(proof_binary.read_bytes())
    other_binary.chmod(0o700)
    with pytest.raises(ValueError, match='same frozen proof runner reference'):
        runner.validate_proof_runner_reference(
            direct_ref, {'path': str(other_binary), 'sha256': proof_sha}, proof_sha)
    with pytest.raises(ValueError, match='same frozen proof runner reference'):
        runner.validate_proof_runner_reference(
            direct_ref, {**direct_ref, 'sha256': '0' * 64}, proof_sha)


def test_journal_records_one_running_step_and_resumes_only_matching_pins(tmp_path):
    journal = runner.RunJournal(tmp_path / 'journal.json', manifest_sha256='a' * 64)
    with journal:
        result = journal.run_step(
            'stage-A', inputs={'config': 'b' * 64},
            job=lambda: {'status': 'passed', 'stage_report_sha256': 'c' * 64},
        )
    assert result['status'] == 'passed'
    assert result['inputs'] == {'config': 'b' * 64}
    called = []
    with journal:
        resumed = journal.run_step(
            'stage-A', inputs={'config': 'b' * 64},
            job=lambda: called.append(True),
            reuse=lambda saved: saved['status'] == 'passed' and saved['stage_report_sha256'] == 'c' * 64,
        )
    assert resumed['stage_report_sha256'] == 'c' * 64
    assert called == []
    raw = json.loads((tmp_path / 'journal.json').read_text())
    assert raw['schema'] == runner.JOURNAL_SCHEMA
    assert raw['steps']['stage-A']['status'] == 'passed'


def test_journal_rejects_changed_inputs_for_completed_step(tmp_path):
    journal = runner.RunJournal(tmp_path / 'journal.json', manifest_sha256='a' * 64)
    with journal:
        journal.run_step('stage-A', inputs={'config': 'b' * 64},
                         job=lambda: {'status': 'passed'})
    try:
        with journal:
            journal.run_step('stage-A', inputs={'config': 'd' * 64}, job=lambda: {})
    except ValueError as error:
        assert 'inputs changed' in str(error)
    else:
        raise AssertionError('changed pins must invalidate a resumable step')


def test_journal_preserves_failed_attempt_wall_time_in_successful_retry(tmp_path, monkeypatch):
    journal = runner.RunJournal(tmp_path / 'journal.json', manifest_sha256='a' * 64)
    times = iter((10.0, 10.1, 11.1, 20.0, 20.2, 21.7, 22.0))
    monkeypatch.setattr(runner.time, 'monotonic', lambda: next(times))
    inputs = {'config': 'b' * 64}

    with pytest.raises(RuntimeError, match='first attempt failed'):
        with journal:
            journal.run_step(
                'proof-B', inputs=inputs,
                job=lambda: (_ for _ in ()).throw(RuntimeError('first attempt failed')),
                category='stage')

    failed = journal._read()['steps']['proof-B']
    assert failed['status'] == 'failed'
    assert failed['failed_attempt_wall_seconds'] == [pytest.approx(1.0)]
    assert failed['failed_attempt_count'] == 1

    with journal:
        result = journal.run_step(
            'proof-B', inputs=inputs,
            job=lambda: {'status': 'passed', 'wall_seconds': 99.0},
            category='stage')

    assert result['status'] == 'passed'
    assert result['failed_attempt_wall_seconds'] == [pytest.approx(1.0)]
    assert result['failed_attempt_count'] == 1
    assert result['wall_seconds'] == pytest.approx(2.5)
    assert journal._read()['costs']['shared_stage_seconds'] == pytest.approx(2.5)


def test_journal_rejects_changed_inputs_after_failed_attempt(tmp_path):
    journal = runner.RunJournal(tmp_path / 'journal.json', manifest_sha256='a' * 64)
    with pytest.raises(RuntimeError, match='first attempt failed'):
        with journal:
            journal.run_step(
                'proof-B', inputs={'config': 'b' * 64},
                job=lambda: (_ for _ in ()).throw(RuntimeError('first attempt failed')))

    with pytest.raises(ValueError, match='inputs changed'):
        with journal:
            journal.run_step('proof-B', inputs={'config': 'd' * 64},
                             job=lambda: {'status': 'passed'})


def test_journal_rejects_legacy_failed_step_without_measured_time(tmp_path):
    journal = runner.RunJournal(tmp_path / 'journal.json', manifest_sha256='a' * 64)
    with journal:
        document = journal._read()
        document['steps']['proof-B'] = {
            'status': 'failed', 'inputs': {'config': 'b' * 64}}
        journal._save(document)
        with pytest.raises(ValueError, match='unmeasured prior failed attempt'):
            journal.run_step('proof-B', inputs={'config': 'b' * 64},
                             job=lambda: {'status': 'passed'})


def test_journal_rejects_hard_interruption_with_unknown_work_time(tmp_path):
    journal = runner.RunJournal(tmp_path / 'journal.json', manifest_sha256='a' * 64)
    with journal:
        document = journal._read()
        document['steps']['stage-A'] = {
            'status': 'running', 'inputs': {'config': 'b' * 64},
            'started_monotonic': time.monotonic() - 1.0,
            'started_unix_ns': time.time_ns() - 1_000_000_000}
        journal._save(document)
        called = []
        with pytest.raises(ValueError, match='interrupted attempt.*unknown work time'):
            journal.run_step('stage-A', inputs={'config': 'b' * 64},
                             job=lambda: called.append(True))
        assert called == []
        assert journal._read()['steps']['stage-A']['status'] == 'running'
        assert journal._read()['costs']['shared_stage_seconds'] == 0.0


def test_pair_view_preparation_is_inside_the_timed_journal_step(tmp_path, monkeypatch):
    from tools.part5 import prepare_v3_heldout_context as context_builder

    def prepare(_cohort, _sha, variant, output):
        time.sleep(0.02)
        case = json.dumps({'target': {'variant': variant}}).encode()
        pair = json.dumps({'heldout_acceptance': False}).encode()
        (output / 'case-context.json').write_bytes(case)
        (output / 'cohort-receipt.json').write_bytes(pair)
        return {'case_context_sha256': hashlib.sha256(case).hexdigest(),
                'pair_receipt_sha256': hashlib.sha256(pair).hexdigest()}

    monkeypatch.setattr(context_builder, 'prepare', prepare)
    trial = runner.HeldoutCaseRunner.__new__(runner.HeldoutCaseRunner)
    trial.output_root = tmp_path
    trial.variant = 0
    trial.manifest = {'cohort_root': str(tmp_path), 'cohort_sha256': 'a' * 64,
                      'base_prepare_config_sha256': 'b' * 64}
    trial.journal = runner.RunJournal(tmp_path / 'run-journal.json', 'c' * 64)
    trial._prepare = lambda *_: (_ for _ in ()).throw(RuntimeError('stop after pair view'))

    with pytest.raises(RuntimeError, match='stop after pair view'):
        trial.run()

    step = trial.journal._read()['steps']['pair-view']
    assert step['status'] == 'passed'
    assert step['wall_seconds'] >= 0.02
    assert step['case_context_sha256'] == hashlib.sha256(
        (tmp_path / 'pair-view/case-context.json').read_bytes()).hexdigest()


def test_subprocess_status_path_stays_separate_from_journal_state(tmp_path):
    status_path = tmp_path / 'control' / 'status.json'
    status_path.parent.mkdir()
    status_path.write_text('{"status":"failed"}\n')
    artifact = runner.status_artifact(status_path)
    journal = runner.RunJournal(tmp_path / 'journal.json', manifest_sha256='a' * 64)
    with journal:
        result = journal.run_step(
            'prepare', inputs={'template': 'b' * 64},
            job=lambda: {'status': 'passed', **artifact})
    assert result['status'] == 'passed'
    assert result['status_path'] == str(status_path)
    resumed_job = []
    with journal:
        resumed = journal.run_step(
            'prepare', inputs={'template': 'b' * 64},
            job=lambda: resumed_job.append(True),
            reuse=lambda saved: runner.HeldoutCaseRunner._verify_record(
                saved, path_fields=('status_path',), hash_fields=('status_sha256',)))
    assert resumed['status'] == 'passed'
    assert resumed['status_path'] == str(status_path)
    assert resumed_job == []


def test_transition_ledger_comes_from_pinned_stage_status_and_prepare_runtime(tmp_path):
    runtime = tmp_path / 'runtime'
    ledger = runtime / 'ledger'
    genesis = 'genesis-from-loaded-prepare'
    prepare_config = tmp_path / 'prepare-config.json'
    prepare_status = tmp_path / 'prepare-status.json'
    stage_config = tmp_path / 'stage-config.json'
    stage_report = tmp_path / 'stage-report.json'

    def write_json(path, value):
        raw = runner.encoded(value)
        path.write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    prepare_config_sha = write_json(prepare_config, {'runtime_output': str(runtime)})
    loaded = {'genesis': genesis, 'elf_sha256': 'a' * 64, 'program': 'program',
              'programdata': 'programdata', 'program_account_sha256': 'b' * 64,
              'programdata_account_sha256': 'c' * 64}
    prepare_status_sha = write_json(prepare_status, {
        'config_sha256': prepare_config_sha, 'ledger': str(ledger),
        'loaded_program': loaded})
    stage_config_value = {
        'scope': 'part5-v3-local-stage',
        'prior_config': str(prepare_config),
        'prior_config_sha256': prepare_config_sha,
        'prior_status': str(prepare_status),
        'prior_status_sha256': prepare_status_sha,
        'expected_genesis': genesis,
        'ledger': str(ledger),
        'stage_output': str(tmp_path / 'stage-output'),
    }
    stage_config_sha = write_json(stage_config, stage_config_value)
    report_sha = write_json(stage_report, {
        'schema': 'part5-v3-local-stage-v1', 'passed': True, 'genesis': genesis})
    stage_status = tmp_path / 'stage-status.json'
    stage_status_sha = write_json(stage_status, {
        'status': 'failed', 'stage_verified': True, 'ledger_reuse_requires_review': True,
        'config_sha256': stage_config_sha, 'stage_report_sha256': report_sha,
        'stage_output': stage_config_value['stage_output'], 'loaded_program': loaded,
        'validator_cleanup': {'spawned': True, 'reaped': True, 'graceful': False,
                              'exit_code': -2},
        'runner_cleanup': {'spawned': True, 'reaped': True, 'exit_code': 0}})

    assert runner.transition_ledger({
        'config': str(stage_config), 'config_sha256': stage_config_sha,
        'report': str(stage_report), 'report_sha256': report_sha,
        'status_path': str(stage_status), 'status_sha256': stage_status_sha,
    }) == str(ledger)

    # Status from queue_v3_local_stage.py intentionally has no ledger field.
    assert 'ledger' not in json.loads(stage_status.read_text())


def test_transition_ledger_rejects_stage_config_that_disagrees_with_prepare(tmp_path):
    runtime = tmp_path / 'runtime'
    prepare_config = tmp_path / 'prepare-config.json'
    prepare_status = tmp_path / 'prepare-status.json'
    stage_config = tmp_path / 'stage-config.json'
    stage_report = tmp_path / 'stage-report.json'

    def write_json(path, value):
        raw = runner.encoded(value)
        path.write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    prepare_config_sha = write_json(prepare_config, {'runtime_output': str(runtime)})
    loaded = {'genesis': 'loaded-genesis', 'elf_sha256': 'a' * 64, 'program': 'program',
              'programdata': 'programdata', 'program_account_sha256': 'b' * 64,
              'programdata_account_sha256': 'c' * 64}
    prepare_status_sha = write_json(prepare_status, {
        'config_sha256': prepare_config_sha, 'ledger': str(runtime / 'ledger'),
        'loaded_program': loaded})
    stage_output = str(tmp_path / 'stage-output')
    config_sha = write_json(stage_config, {
        'scope': 'part5-v3-local-stage', 'prior_config': str(prepare_config),
        'prior_config_sha256': prepare_config_sha,
        'prior_status': str(prepare_status), 'prior_status_sha256': prepare_status_sha,
        'expected_genesis': 'other-genesis', 'ledger': str(runtime / 'ledger'),
        'stage_output': stage_output,
    })
    report_sha = write_json(stage_report, {
        'schema': 'part5-v3-local-stage-v1', 'passed': True, 'genesis': 'other-genesis'})
    status_path = tmp_path / 'stage-status.json'
    status_sha = write_json(status_path, {
        'status': 'failed', 'stage_verified': True, 'ledger_reuse_requires_review': True,
        'config_sha256': config_sha,
        'stage_report_sha256': report_sha, 'stage_output': stage_output,
        'loaded_program': loaded,
        'validator_cleanup': {'spawned': True, 'reaped': True, 'graceful': False,
                              'exit_code': -2},
        'runner_cleanup': {'spawned': True, 'reaped': True, 'exit_code': 0}})

    with pytest.raises(ValueError, match='stage status/config/report binding or prepare provenance mismatch'):
        runner.transition_ledger({
            'config': str(stage_config), 'config_sha256': config_sha,
            'report': str(stage_report), 'report_sha256': report_sha,
            'status_path': str(status_path), 'status_sha256': status_sha,
        })


def test_stage_acceptance_rejects_stale_config_report_and_ledger_pins(tmp_path):
    runtime = tmp_path / 'runtime'
    prepare_config = tmp_path / 'prepare-config.json'
    prepare_status = tmp_path / 'prepare-status.json'
    stage_config_path = tmp_path / 'stage-config.json'
    genesis = 'loaded-genesis'

    def write_json(path, value):
        raw = runner.encoded(value)
        path.write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    prepare_config_sha = write_json(prepare_config, {'runtime_output': str(runtime)})
    prepare_status_sha = write_json(prepare_status, {
        'config_sha256': prepare_config_sha, 'ledger': str(runtime / 'ledger'),
        'loaded_program': {'genesis': genesis, 'elf_sha256': 'a' * 64,
                           'program': 'program', 'programdata': 'programdata',
                           'program_account_sha256': 'b' * 64,
                           'programdata_account_sha256': 'c' * 64}})
    config = {
        'scope': 'part5-v3-local-stage', 'prior_config': str(prepare_config),
        'prior_config_sha256': prepare_config_sha,
        'prior_status': str(prepare_status), 'prior_status_sha256': prepare_status_sha,
        'expected_genesis': genesis, 'ledger': str(runtime / 'ledger'),
        'stage_output': str(tmp_path / 'stage-output'),
    }
    config_sha = write_json(stage_config_path, config)
    report = {'schema': 'part5-v3-local-stage-v1', 'passed': True, 'genesis': genesis}
    report_sha = hashlib.sha256(runner.encoded(report)).hexdigest()
    status = {'status': 'failed', 'stage_verified': True,
        'ledger_reuse_requires_review': True,
        'config_sha256': config_sha, 'stage_report_sha256': report_sha,
        'stage_output': config['stage_output'],
        'loaded_program': json.loads(prepare_status.read_text())['loaded_program'],
        'validator_cleanup': {'spawned': True, 'reaped': True, 'graceful': False,
                              'exit_code': -2},
        'runner_cleanup': {'spawned': True, 'reaped': True, 'exit_code': 0}}

    assert runner.verified_stage_ledger(config, config_sha, status, report, report_sha) == config['ledger']

    for stale_status in (
        {**status, 'config_sha256': 'b' * 64},
        {**status, 'stage_report_sha256': 'c' * 64},
    ):
        with pytest.raises(ValueError, match='stage status/config/report binding'):
            runner.verified_stage_ledger(config, config_sha, stale_status, report, report_sha)

    # A new prepare ledger with the same genesis cannot be substituted into a stage.
    swapped = {**config, 'ledger': str(tmp_path / 'new-runtime' / 'ledger')}
    with pytest.raises(ValueError, match='stage status/config/report binding'):
        runner.verified_stage_ledger(swapped, config_sha, status, report, report_sha)


def test_all_step_wall_times_require_every_completed_journal_step():
    result = runner.all_step_wall_seconds({'steps': {
        'prepare': {'status': 'passed', 'wall_seconds': 1},
        'proof': {'status': 'passed', 'wall_seconds': 2.5},
    }})
    assert result == {'prepare': 1.0, 'proof': 2.5}
    try:
        runner.all_step_wall_seconds({'steps': {
            'prepare': {'status': 'passed', 'wall_seconds': 1},
            'proof': {'status': 'running'},
        }})
    except ValueError as error:
        assert 'verified wall duration' in str(error)
    else:
        raise AssertionError('incomplete journal costs must not be published')


def test_acceptance_bundle_maps_each_request_to_one_shared_slot():
    requests = {
        'positive_full': {'stage': 'stage-A', 'transition': 'transition-A',
                          'r0_source': 'r0-A', 'r1_source': 'r1-A'},
        'unrelated_compare': {'stage': 'stage-B', 'transition': 'transition-B',
                              'r0_source': 'r0-B', 'r1_source': 'r1-B'},
        'own_revocation': {'stage': 'stage-C', 'transition': 'transition-C',
                           'r0_source': 'r0-C', 'r1_source': 'r1-C'},
    }
    slots = runner.acceptance_slot_bundles(
        requests, stage_bundle=lambda value: value,
        transition_bundle=lambda value: value,
        source_bundle=lambda value: value)
    assert slots == {
        'stage': {'A': 'stage-A', 'B': 'stage-B', 'C': 'stage-C'},
        'transition': {'A': 'transition-A', 'B': 'transition-B', 'C': 'transition-C'},
        'sources': {'A': {'R0': 'r0-A', 'R1': 'r1-A'},
                    'B': {'R0': 'r0-B', 'R1': 'r1-B'},
                    'C': {'R0': 'r0-C', 'R1': 'r1-C'}},
    }


def test_acceptance_branch_bundle_has_proof_separate_from_result():
    branches = runner.acceptance_branch_bundles({
        'full': {'effect': {'result': 'full-result', 'proof': 'proof-A',
                            'replay_proof': 'fresh-proof-A',
                            'r0_clone': 'r0-clone'}},
        'unrelated_full': {'effect': {'result': 'full-B', 'proof': 'proof-B'},
                           'clone': 'clone-B-full'},
        'anchor': {'effect': {'result': 'anchor-B', 'proof': 'anchor-proof-B'},
                   'clone': 'clone-B-anchor'},
        'own_revocation': {'effect': {'result': 'own-C', 'proof': 'proof-C',
                                     'current_r2_witness_rejection': 'r2-rejection'},
                           'clone': 'clone-C'},
    }, result_bundle=lambda result: result['result'],
       proof_bundle=lambda proof: proof,
       clone_bundle=lambda clone: clone)
    assert branches == {
        'full': {'result': 'full-result', 'proof': 'proof-A',
                 'replay_proof': 'fresh-proof-A', 'r0_clone': 'r0-clone'},
        'unrelated_full': {'result': 'full-B', 'proof': 'proof-B', 'r1_clone': 'clone-B-full'},
        'anchor': {'result': 'anchor-B', 'proof': 'anchor-proof-B', 'r1_clone': 'clone-B-anchor'},
        'own_revocation': {'result': 'own-C', 'proof': 'proof-C', 'r1_clone': 'clone-C',
                           'current_r2_witness_rejection': 'r2-rejection'},
    }


def test_case_fragment_shape_matches_assembler_and_verifier_contracts(tmp_path):
    requests = {
        'positive_full': {'stage': 'stage-A', 'transition': 'transition-A',
                          'r0_source': 'r0-A', 'r1_source': 'r1-A'},
        'unrelated_compare': {'stage': 'stage-B', 'transition': 'transition-B',
                              'r0_source': 'r0-B', 'r1_source': 'r1-B'},
        'own_revocation': {'stage': 'stage-C', 'transition': 'transition-C',
                           'r0_source': 'r0-C', 'r1_source': 'r1-C'},
    }
    slots = runner.acceptance_slot_bundles(
        requests, stage_bundle=lambda value: value,
        transition_bundle=lambda value: value, source_bundle=lambda value: value)
    result_shapes = {}
    proof_shapes = {}
    for name in verifier.BRANCHES:
        result_shapes[name] = {'report': 'report', 'status': 'status',
            'outer': 'outer', 'config': 'config', 'monitor': 'outer',
            'monitor_owner': 'owner', 'wires': {}, 'accounts': {}}
        if name != 'full':
            result_shapes[name]['signed_history'] = 'history'
        if name == 'full':
            result_shapes[name]['wires'] = {'full': 'full-wire',
                                            'replay_full': 'fresh-full-wire'}
            proof_shapes[name] = {'receipt': 'full-proof', 'artifacts': {}}
        elif name == 'unrelated_full':
            result_shapes[name]['wires'] = {'full': 'full-wire',
                'anchor': 'anchor-wire', 'full_near': 'full-near-wire'}
            proof_shapes[name] = {
                'full': {'receipt': 'full-proof', 'artifacts': {}},
                'anchor': {'receipt': 'anchor-proof', 'artifacts': {}},
            }
        else:
            result_shapes[name]['wires'] = {'full': 'full-wire',
                                             'anchor': 'anchor-wire'}
            proof_shapes[name] = {'receipt': name + '-proof', 'artifacts': {}}
    branch_inputs = {
        name: {'effect': {'result': result_shapes[name], 'proof': proof_shapes[name]},
               ('r0_clone' if name == 'full' else 'clone'): 'clone-ref'}
        for name in verifier.BRANCHES
    }
    branch_inputs['full']['effect']['replay_proof'] = {
        'receipt': 'fresh-full-proof', 'artifacts': {}}
    r2_rejection = tmp_path / 'r2-rejection.json'
    r2_rejection_raw = b'{"outcome":"fixture"}\n'
    r2_rejection.write_bytes(r2_rejection_raw)
    branch_inputs['own_revocation']['effect']['current_r2_witness_rejection'] = {
        'path': str(r2_rejection),
        'sha256': hashlib.sha256(r2_rejection_raw).hexdigest()}
    emitted_branches = runner.acceptance_branch_bundles(
        branch_inputs, result_bundle=lambda value: value['result'],
        proof_bundle=lambda value: value,
        clone_bundle=lambda value: {'receipt': value})
    journal_path = tmp_path / 'run-journal.json'
    journal_raw = b'{"schema":"fixture"}\n'
    journal_path.write_bytes(journal_raw)
    run_manifest = {'schema': runner.RUN_SCHEMA, 'variant': 0}
    run_manifest_raw = (json.dumps(run_manifest, sort_keys=True, indent=2) + '\n').encode()
    run_manifest_path = tmp_path / 'case-00.json'
    run_manifest_path.write_bytes(run_manifest_raw)
    run_manifest_ref, _ = runner.run_manifest_identity(
        run_manifest_path, run_manifest_raw, run_manifest)
    branches = ('full', 'unrelated_full', 'anchor', 'own_revocation')
    branch_components = {name: {'proof_seconds': 0.0, 'clone_seconds': 0.0,
                                'effect_seconds': 0.0, 'total_seconds': 0.0}
                         for name in branches}
    branch_components['own_revocation']['r2_active_witness_seconds'] = 0.0
    fragment = {'schema': assembler.FRAGMENT_SCHEMA, 'variant': 0,
        'case_context': {'path': '/unused/case.json', 'sha256': 'a' * 64},
        'stage_context': {'path': '/unused/stage.json', 'sha256': 'b' * 64},
        'pair_receipt': {'path': '/unused/pair.json', 'sha256': 'c' * 64},
        'membership': {'path': '/unused/membership.json', 'sha256': 'd' * 64},
        **slots, 'branches': emitted_branches,
        'disabled_config_negative': {'path': str(r2_rejection),
            'sha256': hashlib.sha256(r2_rejection_raw).hexdigest()},
        'ambiguous_restart': {'path': str(r2_rejection),
            'sha256': hashlib.sha256(r2_rejection_raw).hexdigest()},
        'run_manifest': run_manifest_ref,
        'run_journal': {'path': str(journal_path),
                        'sha256': hashlib.sha256(journal_raw).hexdigest()},
        'all_step_wall_seconds': {'prepare': 1.0},
        'disabled_config_negative_wall_seconds': 2.0,
        'ambiguous_restart_wall_seconds': 3.0,
        'shared_costs': {'shared_stage_seconds': 0.0,
                         'shared_transition_seconds': 0.0},
        'branch_wall_components': branch_components,
        'branch_wall_seconds': {name: 0.0 for name in branches},
        'shared_stage_transition_wall_seconds': {
            'stage': {'A': 0.0, 'B': 0.0, 'C': 0.0},
            'transition': {'A': 0.0, 'B': 0.0, 'C': 0.0}},
        'branch_order': ['unrelated_full', 'anchor'],
        'proof_order': {'unrelated_compare': ['full', 'anchor']}}
    normalized = assembler._case_from_fragment(fragment)
    assert set(normalized) == set(assembler.CASE_FIELDS)
    assert set(normalized['branches']) == set(verifier.BRANCHES)
    assert normalized['disabled_config_negative'] == fragment['disabled_config_negative']
    for name, bundle in normalized['branches'].items():
        clone = 'r0_clone' if name == 'full' else 'r1_clone'
        expected = {'result', 'proof', clone}
        if name == 'full':
            expected.add('replay_proof')
        if name == 'own_revocation':
            expected.add('current_r2_witness_rejection')
        assert set(bundle) == expected
        expected_result = {'report', 'status', 'outer', 'config', 'monitor',
                           'monitor_owner', 'wires', 'accounts'}
        if name != 'full':
            expected_result.add('signed_history')
        assert set(bundle['result']) == expected_result


def test_disabled_config_sidecar_reuse_requires_every_pinned_snapshot(tmp_path):
    payload = b'heldout-negative-pin'
    artifact = tmp_path / 'pin.bin'
    artifact.write_bytes(payload)
    artifact.chmod(0o600)
    ref = {'path': str(artifact), 'sha256': hashlib.sha256(payload).hexdigest()}
    sidecar = {'schema': runner.DISABLED_CONFIG_SIDECAR_SCHEMA, 'variant': 0,
        'stage_report_sha256': 'a' * 64, 'stage_plan_sha256': 'b' * 64,
        'r0_source_receipt_sha256': 'c' * 64, 'full_proof_receipt_sha256': 'd' * 64,
        'clone_receipt': ref, 'full_wire': ref, 'config': ref, 'rust_config': ref,
        'status': ref, 'outer': ref, 'report': ref,
        'eligible_accounts': {name: ref for name in runner.NEGATIVE_ACCOUNT_NAMES},
        'before_accounts': {name: ref for name in runner.NEGATIVE_ACCOUNT_NAMES},
        'after_accounts': {name: ref for name in runner.NEGATIVE_ACCOUNT_NAMES},
        'issuer_eligible_accounts': {name: ref for name in runner.NEGATIVE_ACCOUNT_NAMES},
        'issuer_before_accounts': {name: ref for name in runner.NEGATIVE_ACCOUNT_NAMES},
        'issuer_after_accounts': {name: ref for name in runner.NEGATIVE_ACCOUNT_NAMES}}
    sidecar_path = tmp_path / 'sidecar.json'
    sidecar_path.write_text(json.dumps(sidecar, sort_keys=True))
    sidecar_path.chmod(0o600)
    sidecar_sha = hashlib.sha256(sidecar_path.read_bytes()).hexdigest()
    assert runner.HeldoutCaseRunner._disabled_config_sidecar_verified(
        sidecar_path, sidecar_sha)
    bad = json.loads(sidecar_path.read_text())
    bad['issuer_after_accounts']['request']['sha256'] = '0' * 64
    sidecar_path.write_text(json.dumps(bad, sort_keys=True))
    assert not runner.HeldoutCaseRunner._disabled_config_sidecar_verified(
        sidecar_path, hashlib.sha256(sidecar_path.read_bytes()).hexdigest())


def test_disabled_config_negative_missing_child_report_has_bounded_diagnostics(
        tmp_path, monkeypatch):
    artifacts = tmp_path / 'artifacts'
    monkeypatch.setattr(runner, 'ARTIFACTS', artifacts)
    case_runner = object.__new__(runner.HeldoutCaseRunner)
    case_runner.variant = 0
    case_runner.run_id = 'a' * 32
    case_runner.manifest = {
        'frozen_files': {'loaded_elf': {'sha256': 'b' * 64}},
        'runner': '/private/runner', 'runner_sha256': 'c' * 64,
    }
    case_runner.toolpaths = {'disabled_config_negative': Path('/private/child.py')}

    def failed_child(owner, command, monitor_dir, monitor_path, **kwargs):
        outer = {'exit_code': 1, 'stop_reason': None, 'passed': False}
        monitor_dir.mkdir(mode=0o700)
        (monitor_dir / 'stderr.log').write_text('bounded monitor stderr secret marker')
        monitor_path.write_bytes(runner.encoded(outer))
        Path(kwargs['storage_paths'][0]).mkdir(mode=0o700, parents=True)
        control = Path(kwargs['storage_paths'][1])
        control.mkdir(mode=0o700, parents=True)
        (control / 'status.json').write_text('{"status":"failed"}\n')
        (control / 'runner.stderr.log').write_text('child stderr secret marker')
        return outer

    case_runner.bounded_run = failed_child
    stage_report_path = tmp_path / 'stage-report.json'
    stage_report_path.write_bytes(runner.encoded({
        'program': 'program-key', 'genesis': 'genesis-key'}))
    stage = {
        'report': str(stage_report_path),
        'report_sha256': runner.digest(stage_report_path.read_bytes()),
        'root': str(tmp_path / 'stage-root'),
        'plan': str(tmp_path / 'stage-plan'), 'plan_sha256': 'd' * 64,
        'config': str(tmp_path / 'stage-config'), 'config_sha256': 'e' * 64,
        'status_path': str(tmp_path / 'stage-status'), 'status_sha256': 'f' * 64,
        'monitor': str(tmp_path / 'stage-monitor'), 'monitor_sha256': '1' * 64,
        'monitor_owner': 'stage-owner',
    }
    proof = {'wires': {'r0_full_wire': {'path': str(tmp_path / 'full.wire'),
                                        'sha256': '2' * 64}}}
    clone = {'ledger': str(tmp_path / 'ledger'), 'receipt': str(tmp_path / 'clone.json'),
             'receipt_sha256': '3' * 64}
    output = Path(case_runner._art('positive_full', 'disabled-config-negative'))
    control = Path(case_runner._art(
        'positive_full', 'disabled-config-negative-control'))

    with pytest.raises(ValueError) as caught:
        case_runner._disabled_config_negative(
            'positive_full', tmp_path, stage, {'receipt_sha256': '4' * 64},
            proof, clone)

    message = str(caught.value)
    assert 'missing report' in message
    assert 'exit_code=1' in message
    assert 'stop_reason=None' in message
    assert str(tmp_path / 'disabled-config-negative' / 'outer.json') in message
    assert str(tmp_path / 'disabled-config-negative' / 'monitor' / 'stderr.log') in message
    assert str(control / 'runner.stderr.log') in message
    assert str(control / 'status.json') in message
    assert str(output / 'disabled-config-negative-report.json') in message
    assert 'secret marker' not in message


def test_acceptance_costs_include_full_branch_wall_and_shared_setup_wall():
    costs = runner.acceptance_wall_costs({
        'positive_full:proof-full': {'wall_seconds': 10},
        'positive_full:r0-clone': {'wall_seconds': 2},
        'positive_full:execute': {'wall_seconds': 3},
        'unrelated_compare:proof-full': {'wall_seconds': 11},
        'unrelated_compare:proof-anchor': {'wall_seconds': 12},
        'unrelated_compare:unrelated_full:clone': {'wall_seconds': 4},
        'unrelated_compare:unrelated_full:effect': {'wall_seconds': 5},
        'unrelated_compare:anchor:clone': {'wall_seconds': 6},
        'unrelated_compare:anchor:effect': {'wall_seconds': 7},
        'own_revocation:proof-anchor': {'wall_seconds': 13},
        'own_revocation:r1-clone': {'wall_seconds': 8},
        'own_revocation:effect': {'wall_seconds': 9},
        'own_revocation:r2-active-witness': {'wall_seconds': 4},
        'positive_full:ambiguous-restart-clone': {'status': 'passed', 'wall_seconds': 3.5},
        'positive_full:ambiguous-restart': {'status': 'passed', 'wall_seconds': 6.0},
        'positive_full:stage': {'wall_seconds': 1.25},
        'positive_full:transition': {'wall_seconds': 2.5},
        'unrelated_compare:stage': {'wall_seconds': 1.5},
        'unrelated_compare:transition': {'wall_seconds': 2.75},
        'own_revocation:stage': {'wall_seconds': 1.75},
        'own_revocation:transition': {'wall_seconds': 3.0},
    })
    assert costs['branch_wall_seconds'] == {
        'full': 15, 'unrelated_full': 20, 'anchor': 25, 'own_revocation': 34}
    assert costs['branch_wall_components']['own_revocation']['r2_active_witness_seconds'] == 4
    assert costs['shared_stage_transition_wall_seconds'] == {
        'stage': {'A': 1.25, 'B': 1.5, 'C': 1.75},
        'transition': {'A': 2.5, 'B': 2.75, 'C': 3.0}}
    assert runner.ambiguous_restart_wall_seconds({
        'positive_full:ambiguous-restart-clone': {
            'status': 'passed', 'wall_seconds': 3.5},
        'positive_full:ambiguous-restart': {
            'status': 'passed', 'wall_seconds': 6.0}}) == 9.5
    assert costs['branch_wall_seconds']['full'] == 15


def test_ambiguous_restart_wall_cost_requires_both_independent_steps():
    with pytest.raises(ValueError, match='ambiguous-restart journal wall time'):
        runner.ambiguous_restart_wall_seconds({
            'positive_full:ambiguous-restart-clone': {
                'status': 'passed', 'wall_seconds': 3.5},
            'positive_full:ambiguous-restart': {
                'status': 'failed', 'wall_seconds': 6.0}})


def test_disabled_config_negative_wall_cost_is_separate_from_matched_branches():
    costs = runner.disabled_config_negative_wall_seconds({
        'positive_full:disabled-config-clone': {'status': 'passed', 'wall_seconds': 2.5},
        'positive_full:disabled-config-negative': {'status': 'passed', 'wall_seconds': 4.0},
    })
    assert costs == 6.5
    with pytest.raises(ValueError, match='disabled-config journal wall time'):
        runner.disabled_config_negative_wall_seconds({
            'positive_full:disabled-config-clone': {'status': 'passed', 'wall_seconds': 2.5},
            'positive_full:disabled-config-negative': {'status': 'failed', 'wall_seconds': 4.0},
        })


def test_ambiguous_restart_sidecar_pins_status_proxy_and_all_ten_account_files(tmp_path):
    tmp_path = tmp_path.resolve()

    def save(path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = value if isinstance(value, bytes) else runner.encoded(value)
        path.write_bytes(raw)
        path.chmod(0o600)
        return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}

    variant = 0
    stage_report_sha = 'a' * 64
    stage_plan_sha = 'b' * 64
    source_sha = 'c' * 64
    full_proof_sha = 'd' * 64
    replay_proof_sha = 'e' * 64
    proxy_sha = 'f' * 64
    elf_sha = '8' * 64
    output, control = tmp_path / 'execute-output', tmp_path / 'control-output'
    context = save(tmp_path / 'stage-context.json', b'{"training_only":true}\n')
    ledger = tmp_path / 'ledger'
    ledger.mkdir()
    full_wire = save(tmp_path / 'full.wire', b'full-wire')
    replay_wire = save(tmp_path / 'replay-full.wire', b'replay-full-wire')
    clone = save(tmp_path / 'clone-report.json', {
        'schema': 'part5-v3-heldout-r0-ledger-clone-v1',
        'stage_report_sha256': stage_report_sha,
        'heldout_acceptance': False, 'copy_identical': True,
        'destination': str(ledger), 'application_effect': False,
        'loaded_identity_rechecked_after_restart': False})
    pre_hashes, final_hashes, pre_paths, final_paths = [], [], [], []
    pre_refs, final_refs = {}, {}
    for name in runner.AMBIGUOUS_ACCOUNT_NAMES:
        pre_refs[name] = save(output / f'pre-submit-{name}.bin', f'pre:{name}'.encode())
        final_refs[name] = save(output / f'final-{name}.bin', f'final:{name}'.encode())
        pre_hashes.append(pre_refs[name]['sha256'])
        final_hashes.append(final_refs[name]['sha256'])
        pre_paths.append(pre_refs[name]['path'])
        final_paths.append(final_refs[name]['path'])
    pre_report = save(output / 'pre-submit-report.json', {
        'schema': 'part5-v3-ambiguous-pre-submit-v1', 'training_only': True,
        'application_effect': False, 'request_consumed': False,
        'stage_report_sha256': stage_report_sha, 'stage_plan_sha256': stage_plan_sha,
        'wire_sha256': full_wire['sha256'], 'account_sha256': pre_hashes})
    signature = '1' * 64
    proxy_receipt = save(control / 'proxy-receipt.json', {
        'schema': 'queue-v3-ambiguous-rpc-proxy-receipt-v1',
        'status': 'response_dropped', 'target_wire_sha256': full_wire['sha256'],
        'transaction_sha256': '9' * 64, 'signature': signature,
        'matching_submissions': 1, 'duplicate_matching_submissions': 0,
        'duplicate_rejected': False, 'forward_attempted': 1,
        'forwarded': 1, 'response_dropped': True})
    finality_receipt_value = {
        'schema': 'part5-v3-ambiguous-finality-receipt-v1',
        'signature': signature,
        'signature_status': {'slot': 4, 'confirmationStatus': 'finalized', 'err': None},
        'transaction': {'slot': 4, 'meta': {'err': None}, 'signatures': [signature]},
    }
    finality_receipt = save(control / 'finality-receipt.json', finality_receipt_value)
    proxy_script = REPO / 'harness/tests/queue_v3_ambiguous_rpc_proxy.py'
    config_value = {
        'schema': 'part5-v3-local-ambiguous-restart-supervisor-v1',
        'scope': 'part5-v3-local-ambiguous-restart',
        'proxy_port': 19500, 'proxy_script': str(proxy_script),
        'proxy_script_sha256': proxy_sha,
        'stage_report_sha256': stage_report_sha,
        'stage_plan_sha256': stage_plan_sha,
        'heldout_r0_clone_report_sha256': clone['sha256'],
        'full_wire': full_wire['path'], 'full_wire_sha256': full_wire['sha256'],
        'replay_full_wire': replay_wire['path'],
        'replay_full_wire_sha256': replay_wire['sha256'],
        'expected_program': 'program-key', 'expected_genesis': 'genesis-key',
        'expected_elf_sha256': elf_sha,
        'runner_sha256': '7' * 64, 'ledger': str(ledger),
        'context': context['path'], 'context_sha256': context['sha256'],
        'execute_output': str(output), 'control_output': str(control),
    }
    config = save(tmp_path / 'supervisor-config.json', config_value)
    status = save(control / 'status.json', {
        'schema': 1, 'scope': 'part5-v3-local-ambiguous-restart',
        'status': 'passed', 'heldout_acceptance': True, 'error_type': None,
        'config_sha256': config['sha256'], 'proxy_receipt_sha256': proxy_receipt['sha256'],
        'finality_receipt_path': finality_receipt['path'],
        'finality_receipt_sha256': finality_receipt['sha256'],
        'pre_submit_report_sha256': pre_report['sha256'],
        'stage_report_sha256': stage_report_sha, 'stage_plan_sha256': stage_plan_sha,
        'heldout_r0_clone_report_sha256': clone['sha256'],
        'full_wire_sha256': full_wire['sha256'],
        'replay_full_wire_sha256': replay_wire['sha256'],
        'proxy_script_sha256': proxy_sha, 'expected_elf_sha256': elf_sha,
        'expected_program': 'program-key', 'expected_genesis': 'genesis-key',
        'runner_sha256': '7' * 64, 'context_sha256': context['sha256'],
        'ledger_path_sha256': hashlib.sha256(str(ledger).encode()).hexdigest(),
        'proxy_receipt_verified': True, 'expected_transport_failure': True,
        'runner_exit_code': 1, 'proxy_status': 'response_dropped',
        'matching_submissions': 1, 'retry_count': 0,
        'transaction_sha256': '9' * 64,
        'ledger_genesis_sha256_after_stop': 'a' * 64,
        'restart_identity_verified': True, 'signature_finalized_success': True,
        'five_account_reconciliation_verified': True,
        'prepositive_snapshot_saved_by_runner': True, 'cleanup_verified': True,
        'effect_count': 1, 'request_consumed': True, 'queue_appends': 1,
        'application_effect': True, 'signature_sha256': hashlib.sha256(
            signature.encode()).hexdigest(), 'signature_finalized_slot': 4,
        'pre_submit_account_sha256': pre_hashes,
        'final_account_sha256': final_hashes, 'final_account_paths': final_paths,
        'loaded_program_before': {'program': 'program-key', 'genesis': 'genesis-key',
                                  'elf_sha256': elf_sha, 'elf_match': True},
        'loaded_program_after': {'program': 'program-key', 'genesis': 'genesis-key',
                                 'elf_sha256': elf_sha, 'elf_match': True},
    })
    outer = save(tmp_path / 'outer.json', {
        'schema': 1, 'measurement': 'bounded_complete_session',
        'owner': 'heldout-v00-positive_full-ambiguous-restart',
        'passed': True, 'exit_code': 0, 'stop_reason': None,
        'runner_error_type': None, 'cleanup_remaining_owned_processes': 0,
        'cleanup_status_unknown': False, 'duration_seconds': 1.25,
        'sample_count': 1,
        'limits': {'runtime_seconds': 180, 'owned_tree_rss_bytes': 4294967296,
                   'storage_growth_bytes': 268435456, 'poll_seconds': 0.1},
    })
    save(control / 'runner.stderr.log', b'RPC sendTransaction transport failed')
    sidecar = {
        'schema': runner.AMBIGUOUS_RESTART_SIDECAR_SCHEMA, 'variant': variant,
        'stage_report_sha256': stage_report_sha, 'stage_plan_sha256': stage_plan_sha,
        'r0_source_receipt_sha256': source_sha,
        'full_proof_receipt_sha256': full_proof_sha,
        'replay_proof_receipt_sha256': replay_proof_sha,
        'clone_receipt': clone, 'full_wire': full_wire,
        'replay_full_wire': replay_wire, 'config': config, 'status': status,
        'outer': outer, 'proxy_receipt': proxy_receipt,
        'finality_receipt': finality_receipt,
        'pre_submit_report': pre_report, 'pre_submit_accounts': pre_refs,
        'final_accounts': final_refs,
    }
    sidecar_path = tmp_path / 'sidecar.json'
    sidecar_raw = json.dumps(sidecar, sort_keys=True, indent=2).encode() + b'\n'
    sidecar_path.write_bytes(sidecar_raw)
    sidecar_path.chmod(0o600)
    inputs = {
        'variant': variant, 'stage_report_sha256': stage_report_sha,
        'stage_plan_sha256': stage_plan_sha, 'r0_source_receipt_sha256': source_sha,
        'full_proof_receipt_sha256': full_proof_sha,
        'replay_proof_receipt_sha256': replay_proof_sha,
        'clone_receipt_sha256': clone['sha256'],
        'full_wire_sha256': full_wire['sha256'],
        'replay_full_wire_sha256': replay_wire['sha256'],
        'supervisor_script_sha256': '6' * 64, 'proxy_script_sha256': proxy_sha,
        'frozen_elf_sha256': elf_sha, 'proxy_port': 19500,
    }
    sidecar_sha = hashlib.sha256(sidecar_raw).hexdigest()
    assert runner.HeldoutCaseRunner._ambiguous_restart_sidecar_verified(
        sidecar_path, sidecar_sha, inputs)

    receipt_path = Path(finality_receipt['path'])
    receipt_path.write_bytes(runner.encoded({**finality_receipt_value,
                                             'transaction': {
                                                 **finality_receipt_value['transaction'],
                                                 'signatures': []}}))
    assert not runner.HeldoutCaseRunner._ambiguous_restart_sidecar_verified(
        sidecar_path, sidecar_sha, inputs)
    receipt_path.write_bytes(runner.encoded(finality_receipt_value))
    receipt_path.unlink()
    assert not runner.HeldoutCaseRunner._ambiguous_restart_sidecar_verified(
        sidecar_path, sidecar_sha, inputs)
    receipt_path.write_bytes(runner.encoded(finality_receipt_value))

    changed = json.loads(sidecar_path.read_text())
    changed['status']['sha256'] = '0' * 64
    changed_raw = json.dumps(changed, sort_keys=True, indent=2).encode() + b'\n'
    sidecar_path.write_bytes(changed_raw)
    assert not runner.HeldoutCaseRunner._ambiguous_restart_sidecar_verified(
        sidecar_path, hashlib.sha256(changed_raw).hexdigest(), inputs)


def test_disabled_config_supervisor_binds_all_six_five_account_snapshots(tmp_path):
    report = {}
    for group in disabled_negative.SNAPSHOT_GROUPS:
        rows, hashes = [], []
        for name in disabled_negative.ACCOUNT_NAMES:
            path = tmp_path / group / f'{name}.bin'
            path.parent.mkdir(exist_ok=True)
            payload = f'{group}:{name}'.encode()
            if group == 'after':
                payload = f'before:{name}'.encode()
            if group == 'issuer_after':
                payload = f'issuer_before:{name}'.encode()
            path.write_bytes(payload)
            path.chmod(0o600)
            sha = hashlib.sha256(payload).hexdigest()
            rows.append({'name': name, 'path': str(path), 'sha256': sha})
            hashes.append(sha)
        report[group + '_accounts'] = rows
        report[group + '_sha256'] = hashes
    assert disabled_negative._check_snapshots(report, tmp_path)
    report['issuer_after_accounts'][0]['sha256'] = '0' * 64
    with pytest.raises(ValueError, match='snapshot ref mismatch'):
        disabled_negative._check_snapshots(report, tmp_path)


def test_disabled_config_supervisor_passes_pinned_stage_context(tmp_path):
    context = tmp_path / 'stage-context.json'
    context.write_bytes(b'{"training_only":true}\n')
    context.chmod(0o600)
    expected = hashlib.sha256(context.read_bytes()).hexdigest()
    stage = {'context': str(context), 'context_sha256': expected}
    assert disabled_negative._context_env(stage) == {
        'P5_V3_CONTEXT': str(context), 'P5_V3_CONTEXT_SHA256': expected}
    context.write_bytes(b'{"training_only":false}\n')
    with pytest.raises(ValueError, match='pinned staged training context'):
        disabled_negative._context_env(stage)


def test_reviewed_outer_accepts_actual_session_runner_sigint_schema():
    # Accepted `application-v3-local-execute-bounded-006.json` has no
    # measurement/censored fields; the verified inner report is its evidence.
    outer = {'schema': 1, 'passed': False, 'exit_code': 1,
             'stop_reason': None, 'runner_error_type': None,
             'cleanup_remaining_owned_processes': 0,
             'cleanup_status_unknown': False, 'duration_seconds': 12.0,
             'sample_count': 60}
    assert runner.reviewed_application_outer(outer)
    censored_legacy = dict(outer, censored=True)
    assert not runner.reviewed_application_outer(censored_legacy)
    incomplete = dict(outer, cleanup_status_unknown=True)
    assert not runner.reviewed_application_outer(incomplete)


def test_reviewed_r1_anchor_accepts_failed_status_with_verified_inner_report():
    outer = {'schema': 1, 'passed': False, 'exit_code': 1,
             'stop_reason': None, 'runner_error_type': None,
             'cleanup_remaining_owned_processes': 0,
             'cleanup_status_unknown': False, 'duration_seconds': 53.05,
             'sample_count': 270}
    status = {'status': 'failed', 'error_type': None, 'branch_verified': True,
              'mode': 'anchor', 'application_effect': True, 'effect_count': 1,
              'branch_report_sha256': 'a' * 64,
              'validator_cleanup': {'spawned': True, 'reaped': True,
                                    'graceful': False, 'exit_code': -2},
              'runner_cleanup': {'spawned': True, 'reaped': True,
                                 'graceful': False, 'exit_code': 0}}
    report = {'schema': 'part5-v3-r1-branch-v1', 'passed': True,
              'mode': 'anchor', 'application_effect': True, 'effect_count': 1,
              'request_consumed': True}
    assert runner.reviewed_r1_branch(outer, status, report, 'anchor')
    assert not runner.reviewed_r1_branch(outer, status, report, 'full')
    report['request_consumed'] = False
    assert not runner.reviewed_r1_branch(outer, status, report, 'anchor')
    own_status = dict(status, mode='own-revocation', application_effect=False,
                      effect_count=0)
    own_report = {'schema': 'part5-v3-r1-branch-v1', 'passed': True,
                  'mode': 'own-revocation', 'application_effect': False,
                  'effect_count': 0, 'request_consumed': False}
    assert runner.reviewed_r1_branch(outer, own_status, own_report, 'own-revocation')
    own_report['request_consumed'] = True
    assert not runner.reviewed_r1_branch(outer, own_status, own_report, 'own-revocation')
    status['branch_verified'] = False
    assert not runner.reviewed_r1_branch(outer, status, report, 'anchor')


def _write_private_json(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    path.write_bytes(raw)
    path.chmod(0o600)
    return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}


def test_cohort_observation_pin_binds_successful_parent_to_cohort(tmp_path):
    cohort_root = tmp_path / 'cohort'
    cohort_root.mkdir(mode=0o700)
    freeze_sha = 'a' * 64
    cohort_sha = 'b' * 64
    observation = {
        'schema': 'credential-v3-heldout-cohort-parent-observation-v1',
        'freeze_sha256': freeze_sha,
        'prior_key_inventory_sha256': 'c' * 64,
        'wall_started_unix_ns': 10,
        'wall_completed_unix_ns': 20,
        'monotonic_started_ns': 30,
        'monotonic_completed_ns': 40,
        'child_exit_code': 0,
        'builder_source_sha256': 'd' * 64,
        'observer_source_sha256': 'e' * 64,
        'output_path_sha256': hashlib.sha256(str(cohort_root).encode()).hexdigest(),
        'cohort_receipt_sha256': cohort_sha,
        'preexisting_output': False,
        'creation_time_basis': 'observer_parent_started_child_after_freeze',
        'openssl_invocation_observed': False,
    }
    ref = _write_private_json(tmp_path / 'observation.json', observation)

    assert manifest_builder.validate_cohort_observation(
        ref, freeze_sha, cohort_sha, 'c' * 64, cohort_root) == ref
    with pytest.raises(ValueError, match='cohort parent observation'):
        manifest_builder.validate_cohort_observation(
            ref, freeze_sha, cohort_sha, 'f' * 64, cohort_root)
    with pytest.raises(ValueError, match='cohort parent observation'):
        manifest_builder.validate_cohort_observation(
            {**ref, 'sha256': 'f' * 64}, freeze_sha, cohort_sha,
            'c' * 64, cohort_root)

    for key, bad_value in (
        ('schema', 'other'), ('freeze_sha256', 'f' * 64),
        ('cohort_receipt_sha256', 'd' * 64),
        ('prior_key_inventory_sha256', 'invalid'),
        ('output_path_sha256', 'a' * 64), ('child_exit_code', 1),
        ('preexisting_output', True), ('wall_started_unix_ns', 0),
        ('wall_completed_unix_ns', 9), ('monotonic_started_ns', 41),
        ('creation_time_basis', 'other'), ('openssl_invocation_observed', True),
        ('builder_source_sha256', 'invalid'),
    ):
        changed = {**observation, key: bad_value}
        bad_ref = _write_private_json(tmp_path / f'bad-{key}.json', changed)
        with pytest.raises(ValueError, match='cohort parent observation'):
            manifest_builder.validate_cohort_observation(
                bad_ref, freeze_sha, cohort_sha, 'c' * 64, cohort_root)
    incomplete = dict(observation)
    del incomplete['observer_source_sha256']
    bad_ref = _write_private_json(tmp_path / 'bad-schema.json', incomplete)
    with pytest.raises(ValueError, match='cohort parent observation'):
        manifest_builder.validate_cohort_observation(
            bad_ref, freeze_sha, cohort_sha, 'c' * 64, cohort_root)
    outside = tmp_path / 'outside'
    outside.mkdir(mode=0o700)
    outside_ref = _write_private_json(outside / 'observation.json', observation)
    with pytest.raises(ValueError, match='cohort parent observation'):
        manifest_builder.validate_cohort_observation(
            outside_ref, freeze_sha, cohort_sha, 'c' * 64, cohort_root)
    bad_mode = _write_private_json(tmp_path / 'bad-mode.json', observation)
    Path(bad_mode['path']).chmod(0o644)
    with pytest.raises(ValueError, match='cohort parent observation'):
        manifest_builder.validate_cohort_observation(
            bad_mode, freeze_sha, cohort_sha, 'c' * 64, cohort_root)


def test_case_runner_requires_and_checks_pinned_cohort_observation(tmp_path):
    cohort_root = tmp_path / 'cohort'
    cohort_root.mkdir(mode=0o700)
    freeze_sha = 'a' * 64
    cohort_sha = 'b' * 64
    observation = {
        'schema': 'credential-v3-heldout-cohort-parent-observation-v1',
        'freeze_sha256': freeze_sha,
        'prior_key_inventory_sha256': 'c' * 64,
        'wall_started_unix_ns': 10,
        'wall_completed_unix_ns': 20,
        'monotonic_started_ns': 30,
        'monotonic_completed_ns': 40,
        'child_exit_code': 0,
        'builder_source_sha256': 'd' * 64,
        'observer_source_sha256': 'e' * 64,
        'output_path_sha256': hashlib.sha256(str(cohort_root).encode()).hexdigest(),
        'cohort_receipt_sha256': cohort_sha,
        'preexisting_output': False,
        'creation_time_basis': 'observer_parent_started_child_after_freeze',
        'openssl_invocation_observed': False,
    }
    ref = _write_private_json(tmp_path / 'observation.json', observation)
    manifest = {'cohort_observation': ref, 'cohort_root': str(cohort_root),
                'freeze_sha256': freeze_sha, 'cohort_sha256': cohort_sha}
    freeze_doc = {'schema': 'credential-v3-frozen-holdout-boundary-v1'}
    cohort_doc = {'schema': 'credential-v3-heldout-issuance-cohort-v1',
                  'freeze_sha256': freeze_sha,
                  'prior_key_inventory_sha256': 'c' * 64}

    assert runner.validate_cohort_observation(
        manifest, freeze_doc, cohort_doc) == ref
    Path(ref['path']).chmod(0o644)
    with pytest.raises(ValueError, match='cohort observation'):
        runner.validate_cohort_observation(manifest, freeze_doc, cohort_doc)
    Path(ref['path']).chmod(0o600)
    minimal = dict(observation)
    del minimal['openssl_invocation_observed']
    manifest['cohort_observation'] = _write_private_json(
        tmp_path / 'minimal.json', minimal)
    with pytest.raises(ValueError, match='cohort observation'):
        runner.validate_cohort_observation(manifest, freeze_doc, cohort_doc)
    manifest['cohort_observation'] = ref
    mismatch_doc = {**cohort_doc, 'prior_key_inventory_sha256': 'f' * 64}
    with pytest.raises(ValueError, match='cohort observation'):
        runner.validate_cohort_observation(manifest, freeze_doc, mismatch_doc)
    with pytest.raises(ValueError, match='cohort observation'):
        runner.validate_cohort_observation(
            {**manifest, 'cohort_observation': {**ref, 'sha256': 'f' * 64}},
            freeze_doc, cohort_doc)
    manifest['cohort_observation'] = _write_private_json(
        tmp_path / 'bad-exit.json', {**observation, 'child_exit_code': 9})
    with pytest.raises(ValueError, match='cohort observation'):
        runner.validate_cohort_observation(manifest, freeze_doc, cohort_doc)
    outside = tmp_path / 'outside'
    outside.mkdir(mode=0o700)
    manifest['cohort_observation'] = _write_private_json(
        outside / 'observation.json', observation)
    with pytest.raises(ValueError, match='cohort observation'):
        runner.validate_cohort_observation(manifest, freeze_doc, cohort_doc)
    del manifest['cohort_observation']
    with pytest.raises(ValueError, match='cohort observation'):
        runner.validate_cohort_observation(manifest, freeze_doc, cohort_doc)
