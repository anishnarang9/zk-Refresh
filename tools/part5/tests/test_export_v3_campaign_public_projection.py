import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.part5 import run_v3_campaign_matrix as matrix
from tools.part5 import export_v3_campaign_public_projection as tool


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def synthetic_inputs():
    counts = matrix.session.COUNTS
    modes = matrix.session.MODES
    limits = {
        str(count): {
            mode: {'runtime_seconds': 900, 'rss_bytes': 4 * 1024**3,
                   'storage_bytes': 512 * 1024**2}
            for mode in modes
        }
        for count in counts
    }
    evidence = {
        name: {'path': f'/Users/alice/private/{name}-SECRET.json', 'sha256': sha(name)}
        for name in ('freeze', 'cohort_receipt', 'context', 'stage_config',
                     'stage_report', 'stage_plan', 'stage_status', 'stage_monitor')
    }
    evidence.update({
        'cohort_root': '/Users/alice/private/cohort-SECRET',
        'stage_root': '/Users/alice/private/stage-SECRET',
        'stage_monitor_owner': 'user-alice-secret-stage-owner',
        'transitions': {
            str(count): {
                **{name: {'path': f'/Users/alice/private/k{count}-{name}-SECRET.json',
                          'sha256': sha(f'k{count}-{name}')}
                   for name in ('config', 'report', 'status', 'monitor')},
                'root': f'/Users/alice/private/k{count}-root-SECRET',
                'monitor_owner': f'user-alice-secret-k{count}',
            }
            for count in (1, 2, 5, 10)
        },
    })
    tool_names = matrix.tool_names_for_campaign('training-010')
    tools = {
        name: {'path': f'/Users/alice/private/{name}-SECRET.bin', 'sha256': sha(name)}
        for name in tool_names
    }
    manifest = {
        'schema': matrix.SCHEMA,
        'campaign_id': 'training-010',
        'campaign_runtime_seconds': matrix.CAMPAIGN_SECONDS,
        'output_root': '/Users/alice/private/v3-matrix-training-010-SECRET',
        'limits': limits,
        'evidence': evidence,
        'tools': tools,
    }
    manifest_canonical_sha256 = hashlib.sha256(matrix.canonical_json(manifest)).hexdigest()
    validated = {
        'manifest': manifest,
        'manifest_sha256': manifest_canonical_sha256,
        'driver_sha256': sha('matrix-driver'),
        'campaign_id': 'training-010',
        'limits': limits,
        'tools_manifest': tools,
        'tool_pins': {name: pin['sha256'] for name, pin in tools.items()},
    }
    slots = []
    for slot in matrix.slot_specs():
        label = f"r{slot['repetition']}-k{slot['target_count']}-{slot['mode']}"
        slots.append({
            **slot,
            'owner': f'user-alice-secret-{label}',
            'limits': limits[str(slot['target_count'])][slot['mode']],
            'identity_sha256': sha(f'identity-{label}'),
            'paths': {name: f'/Users/alice/private/{label}-{name}-SECRET'
                      for name in ('slot_root', 'clone_dir', 'clone_ledger', 'clone_report',
                                   'work_root', 'outer_private', 'outer_report',
                                   'session_report', 'slot_receipt', 'effect_output',
                                   'control_output')},
            'clone_argv': ['/Users/alice/private/clone-SECRET', label],
            'outer_argv': ['/Users/alice/private/python-SECRET', 'TOKEN-SECRET', label],
            'environment': {'SECRET_USER': 'alice-secret', 'TOKEN': 'TOKEN-SECRET'},
        })
    plan = {
        'schema': 'part5-v3-campaign-matrix-plan-v1',
        'manifest_sha256': manifest_canonical_sha256,
        'driver_sha256': validated['driver_sha256'],
        'campaign_id': 'training-010',
        'campaign_runtime_seconds': matrix.CAMPAIGN_SECONDS,
        'slot_count': len(slots),
        'slots': slots,
    }
    return manifest, validated, plan


class PublicCampaignProjectionTests(unittest.TestCase):
    def test_projection_keeps_hash_links_and_omits_paths_users_and_secrets(self):
        manifest, validated, plan = synthetic_inputs()

        public_manifest = tool.project_manifest(manifest, validated['manifest_sha256'])
        public_plan = tool.project_plan(plan)
        output = json.dumps({'manifest': public_manifest, 'plan': public_plan}, sort_keys=True)

        self.assertEqual(public_manifest['matrix_manifest_canonical_sha256'],
                         validated['manifest_sha256'])
        self.assertEqual(public_manifest['evidence']['freeze']['sha256'],
                         manifest['evidence']['freeze']['sha256'])
        self.assertEqual(public_manifest['tool_pins']['proof_binary']['sha256'],
                         manifest['tools']['proof_binary']['sha256'])
        self.assertEqual(public_plan['matrix_manifest_canonical_sha256'],
                         validated['manifest_sha256'])
        self.assertEqual(len(public_plan['slots']), 60)
        self.assertEqual(public_plan['slots'][0]['slot_identity_sha256'],
                         plan['slots'][0]['identity_sha256'])
        for forbidden in ('/Users/', 'alice', 'SECRET', 'TOKEN', 'outer_argv',
                          'clone_argv', 'output_root', 'owner', 'paths'):
            self.assertNotIn(forbidden, output)

    def test_projection_rejects_unknown_private_manifest_field(self):
        manifest, validated, _ = synthetic_inputs()
        manifest['access_token'] = 'TOKEN-SECRET'
        with self.assertRaisesRegex(ValueError, 'unknown matrix manifest fields'):
            tool.project_manifest(manifest, validated['manifest_sha256'])

    def test_projection_rejects_unknown_plan_slot_field(self):
        _, _, plan = synthetic_inputs()
        plan['slots'][0]['private_secret'] = 'TOKEN-SECRET'
        with self.assertRaisesRegex(ValueError, 'unknown matrix plan slot fields'):
            tool.project_plan(plan)

    def test_cli_writes_portable_projection_and_raw_identity_index(self):
        manifest, validated, plan = synthetic_inputs()
        manifest_raw = (json.dumps(manifest, sort_keys=True) + '\n').encode()
        plan_raw = (json.dumps(plan, sort_keys=True) + '\n').encode()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manifest_path = root / 'private-training010-manifest.json'
            plan_path = root / 'private-training010-plan.json'
            output = root / 'public'
            manifest_path.write_bytes(manifest_raw)
            plan_path.write_bytes(plan_raw)
            with mock.patch.object(tool.matrix, 'validate_manifest', return_value=validated), \
                    mock.patch.object(tool.matrix, 'plan_slots', return_value=plan['slots']), \
                    mock.patch('sys.argv', ['export_v3_campaign_public_projection',
                                            '--matrix-manifest', str(manifest_path),
                                            '--matrix-plan', str(plan_path),
                                            '--output-dir', str(output)]), \
                    contextlib.redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(tool.main(), 0)

            index_raw = (output / 'index.json').read_bytes()
            index = json.loads(index_raw)
            public_manifest_raw = (output / 'matrix-manifest.json').read_bytes()
            public_plan_raw = (output / 'matrix-plan.json').read_bytes()
            self.assertEqual(index['source_inputs']['matrix_manifest']['sha256'],
                             hashlib.sha256(manifest_raw).hexdigest())
            self.assertEqual(index['source_inputs']['matrix_manifest']['canonical_sha256'],
                             validated['manifest_sha256'])
            self.assertEqual(index['source_inputs']['matrix_plan']['sha256'],
                             hashlib.sha256(plan_raw).hexdigest())
            self.assertEqual(index['source_inputs']['matrix_plan']['manifest_canonical_sha256'],
                             validated['manifest_sha256'])
            self.assertEqual(index['public_files']['matrix_manifest']['path'],
                             'matrix-manifest.json')
            self.assertEqual(index['public_files']['matrix_manifest']['sha256'],
                             hashlib.sha256(public_manifest_raw).hexdigest())
            self.assertEqual(index['public_files']['matrix_plan']['sha256'],
                             hashlib.sha256(public_plan_raw).hexdigest())
            public_text = b''.join(path.read_bytes() for path in output.iterdir()
                                   if path.is_file()).decode()
            for forbidden in ('/Users/', 'alice', 'SECRET', 'TOKEN',
                              'private-training010-manifest.json',
                              'private-training010-plan.json'):
                self.assertNotIn(forbidden, public_text)
            self.assertNotIn('/Users/', stdout.getvalue())

    def test_export_refuses_plan_bound_to_different_manifest_without_output(self):
        manifest, validated, plan = synthetic_inputs()
        plan['manifest_sha256'] = 'f' * 64
        manifest_raw = (json.dumps(manifest, sort_keys=True) + '\n').encode()
        plan_raw = (json.dumps(plan, sort_keys=True) + '\n').encode()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manifest_path = root / 'matrix.json'
            plan_path = root / 'plan.json'
            output = root / 'public'
            manifest_path.write_bytes(manifest_raw)
            plan_path.write_bytes(plan_raw)
            with mock.patch.object(tool.matrix, 'validate_manifest', return_value=validated), \
                    mock.patch.object(tool.matrix, 'plan_slots', return_value=plan['slots']):
                with self.assertRaisesRegex(ValueError, 'plan does not match validated manifest'):
                    tool.export_public_projection(manifest_path, plan_path, output)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
