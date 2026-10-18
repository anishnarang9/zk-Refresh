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
                               python, tmp_path / 'manifests')
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


def test_journal_charges_interrupted_interval_without_recounting_artifact_time(
        tmp_path, monkeypatch):
    journal = runner.RunJournal(tmp_path / 'journal.json', manifest_sha256='a' * 64)
    times = iter((102.0, 102.1, 102.8, 103.0))
    monkeypatch.setattr(runner.time, 'monotonic', lambda: next(times))
    monkeypatch.setattr(runner.time, 'time_ns', lambda: 3_000_000_000)
    with journal:
        document = journal._read()
        document['steps']['stage-A'] = {
            'status': 'running', 'inputs': {'config': 'b' * 64},
            'started_monotonic': 100.0, 'started_unix_ns': 1_000_000_000}
        journal._save(document)
        result = journal.run_step(
            'stage-A', inputs={'config': 'b' * 64},
            job=lambda: {'status': 'passed', 'wall_seconds': 12.5},
            category='stage')
    assert result['failed_attempt_wall_seconds'] == [pytest.approx(2.0)]
    assert result['wall_seconds'] == pytest.approx(2.7)
    assert journal._read()['costs']['shared_stage_seconds'] == pytest.approx(2.7)


def test_journal_charges_costly_interrupted_attempt_before_successful_retry(
        tmp_path, monkeypatch):
    journal = runner.RunJournal(tmp_path / 'journal.json', manifest_sha256='a' * 64)
    times = iter((3700.0, 3700.1, 3700.5, 3700.6))
    monkeypatch.setattr(runner.time, 'monotonic', lambda: next(times))
    monkeypatch.setattr(runner.time, 'time_ns', lambda: 3_601_000_000_000)
    with journal:
        document = journal._read()
        document['steps']['unrelated_compare:proof-full'] = {
            'status': 'running', 'inputs': {'source': 'c' * 64},
            'started_monotonic': 100.0, 'started_unix_ns': 1_000_000_000}
        journal._save(document)
        result = journal.run_step(
            'unrelated_compare:proof-full', inputs={'source': 'c' * 64},
            job=lambda: {'status': 'passed', 'wall_seconds': 3600.0})
    assert result['failed_attempt_wall_seconds'] == [pytest.approx(3600.0)]
    assert result['failed_attempt_count'] == 1
    assert result['wall_seconds'] == pytest.approx(3600.4)


@pytest.mark.parametrize('clock_state', ['missing', 'mismatch'])
def test_journal_rejects_uncertain_interrupted_attempt_clocks(
        tmp_path, monkeypatch, clock_state):
    journal = runner.RunJournal(tmp_path / 'journal.json', manifest_sha256='a' * 64)
    monkeypatch.setattr(runner.time, 'monotonic', lambda: 200.0)
    monkeypatch.setattr(runner.time, 'time_ns', lambda: 20_000_000_000)
    with journal:
        document = journal._read()
        prior = {'status': 'running', 'inputs': {'source': 'd' * 64},
                 'started_monotonic': 100.0}
        if clock_state == 'mismatch':
            prior['started_unix_ns'] = 5_000_000_000
        document['steps']['proof-B'] = prior
        journal._save(document)
        called = []
        with pytest.raises(ValueError, match='start clocks|timing is uncertain'):
            journal.run_step('proof-B', inputs={'source': 'd' * 64},
                             job=lambda: called.append(True))
        assert called == []


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
        'run_manifest': run_manifest_ref,
        'run_journal': {'path': str(journal_path),
                        'sha256': hashlib.sha256(journal_raw).hexdigest()},
        'all_step_wall_seconds': {'prepare': 1.0},
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
