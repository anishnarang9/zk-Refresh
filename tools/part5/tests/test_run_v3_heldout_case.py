import importlib.util
import hashlib
import json
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tools.part5 import assemble_v3_heldout_acceptance as assembler
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


def test_journal_preserves_reported_wall_time_on_artifact_recovery(tmp_path):
    journal = runner.RunJournal(tmp_path / 'journal.json', manifest_sha256='a' * 64)
    with journal:
        result = journal.run_step(
            'stage-A', inputs={'config': 'b' * 64},
            job=lambda: {'status': 'passed', 'wall_seconds': 12.5},
            category='stage')
    assert result['wall_seconds'] == 12.5
    assert journal._read()['costs']['shared_stage_seconds'] == 12.5


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
                            'r0_clone': 'r0-clone'}},
        'unrelated_full': {'effect': {'result': 'full-B', 'proof': 'proof-B'},
                           'clone': 'clone-B-full'},
        'anchor': {'effect': {'result': 'anchor-B', 'proof': 'anchor-proof-B'},
                   'clone': 'clone-B-anchor'},
        'own_revocation': {'effect': {'result': 'own-C', 'proof': 'proof-C'},
                           'clone': 'clone-C'},
    }, result_bundle=lambda result: result['result'],
       proof_bundle=lambda proof: proof,
       clone_bundle=lambda clone: clone)
    assert branches == {
        'full': {'result': 'full-result', 'proof': 'proof-A', 'r0_clone': 'r0-clone'},
        'unrelated_full': {'result': 'full-B', 'proof': 'proof-B', 'r1_clone': 'clone-B-full'},
        'anchor': {'result': 'anchor-B', 'proof': 'anchor-proof-B', 'r1_clone': 'clone-B-anchor'},
        'own_revocation': {'result': 'own-C', 'proof': 'proof-C', 'r1_clone': 'clone-C'},
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
            result_shapes[name]['wires'] = {'full': 'full-wire'}
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
    emitted_branches = runner.acceptance_branch_bundles(
        branch_inputs, result_bundle=lambda value: value['result'],
        proof_bundle=lambda value: value,
        clone_bundle=lambda value: {'receipt': value})
    journal_path = tmp_path / 'run-journal.json'
    journal_raw = b'{"schema":"fixture"}\n'
    journal_path.write_bytes(journal_raw)
    branches = ('full', 'unrelated_full', 'anchor', 'own_revocation')
    branch_components = {name: {'proof_seconds': 0.0, 'clone_seconds': 0.0,
                                'effect_seconds': 0.0, 'total_seconds': 0.0}
                         for name in branches}
    fragment = {'schema': assembler.FRAGMENT_SCHEMA, 'variant': 0,
        'case_context': {'path': '/unused/case.json', 'sha256': 'a' * 64},
        'stage_context': {'path': '/unused/stage.json', 'sha256': 'b' * 64},
        'pair_receipt': {'path': '/unused/pair.json', 'sha256': 'c' * 64},
        'membership': {'path': '/unused/membership.json', 'sha256': 'd' * 64},
        **slots, 'branches': emitted_branches,
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
        assert set(bundle) == {'result', 'proof', clone}
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
        'positive_full:stage': {'wall_seconds': 1.25},
        'positive_full:transition': {'wall_seconds': 2.5},
        'unrelated_compare:stage': {'wall_seconds': 1.5},
        'unrelated_compare:transition': {'wall_seconds': 2.75},
        'own_revocation:stage': {'wall_seconds': 1.75},
        'own_revocation:transition': {'wall_seconds': 3.0},
    })
    assert costs['branch_wall_seconds'] == {
        'full': 15, 'unrelated_full': 20, 'anchor': 25, 'own_revocation': 30}
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
              'mode': 'anchor', 'application_effect': True, 'effect_count': 1}
    assert runner.reviewed_r1_branch(outer, status, report, 'anchor')
    assert not runner.reviewed_r1_branch(outer, status, report, 'full')
    status['branch_verified'] = False
    assert not runner.reviewed_r1_branch(outer, status, report, 'anchor')
