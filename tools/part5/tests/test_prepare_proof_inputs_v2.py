"""Fixture-only contract tests for the prospective v2 input preparer."""
import importlib.util
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tools.part5 import build_v3_heldout_packet_v2 as packet_builder

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / 'tools/part5/prepare_proof_inputs_v2.py'
SPEC = importlib.util.spec_from_file_location('prepare_proof_inputs_v2', TARGET)
module = importlib.util.module_from_spec(SPEC) if SPEC else None
if SPEC and TARGET.exists():
    SPEC.loader.exec_module(module)


class PrepareProofInputsV2Tests(unittest.TestCase):
    def _package_fixture(self, root):
        package_dir = root / 'docs/dynark/part5'
        package_dir.mkdir(parents=True)
        record_path = package_dir / 'v3-fresh-package-v2-package-pins.json'
        record = {
            'schema': module.package_output_pins.SCHEMA,
            'source_commit': 'e' * 40,
            'input_pins': {'path': module.INPUT_PINS_PATH, 'sha256': 'f' * 64},
            'setup_manifest': {
                'path': module.SETUP_MANIFEST_PATH, 'sha256': '1' * 64,
            },
            'package_check_report': {
                'path': module.PACKAGE_CHECK_PATH, 'sha256': '2' * 64,
            },
            'ordinary_vk': {'path': 'artifacts/dynark/part5/v3-development-setup-002/ordinary.vk', 'sha256': '3' * 64},
            'proving_key': {'path': 'artifacts/dynark/part5/v3-development-setup-002/proving.key', 'sha256': '4' * 64},
            'package_identity': {
                'matrix': '5' * 64, 'circuit': '6' * 64, 'pk': '7' * 64,
                'engine_extended_vk': '8' * 64, 'package': 'a' * 64,
            },
            'setup_launcher': {key: {'path': 'placeholder', 'sha256': '9' * 64}
                               for key in ('binary', 'source', 'manifest', 'lock')},
            'semantic_hashes': dict(module.package_output_pins.SEMANTIC_HASHES),
            'census': dict(module.package_output_pins.CENSUS),
            'ordered_public_inputs': list(module.package_output_pins.PUBLIC_INPUTS),
        }
        record_raw = (module.json.dumps(record, sort_keys=True) + '\n').encode()
        record_path.write_bytes(record_raw)
        record_path.chmod(0o600)
        for relative in (module.SETUP_MANIFEST_PATH, module.PACKAGE_CHECK_PATH,
                         'artifacts/dynark/part5/v3-development-setup-002/ordinary.vk',
                         'artifacts/dynark/part5/v3-development-setup-002/proving.key',
                         f'{module.COMPILE_ROOT}/credential.r1cs',
                         f'{module.COMPILE_ROOT}/credential_js/credential.wasm',
                         f'{module.COMPILE_ROOT}/credential.sym', module.PROFILE_PATH):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'fixture')
            path.chmod(0o600 if path.name != 'profile.json' else 0o644)
        (root / module.COMPILE_ROOT).chmod(0o700)
        (root / f'{module.COMPILE_ROOT}/credential_js').chmod(0o700)
        return record_path, record_raw, record

    def test_external_package_pin_digest_is_forwarded_to_v2_verifier(self):
        self.assertTrue(TARGET.exists(), 'v2 input preparer missing')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            record_path, raw, _ = self._package_fixture(root)
            real_received = module.received

            def fixture_received(path, cap, expected=None, **options):
                path = Path(path)
                if path == record_path:
                    return real_received(path, cap, expected, **options)
                expected_by_path = {
                    root / f'{module.COMPILE_ROOT}/credential.r1cs': module.package_output_pins.SEMANTIC_HASHES['r1cs_sha256'],
                    root / f'{module.COMPILE_ROOT}/credential_js/credential.wasm': module.package_output_pins.SEMANTIC_HASHES['wasm_sha256'],
                    root / f'{module.COMPILE_ROOT}/credential.sym': module.package_output_pins.SEMANTIC_HASHES['symbol_map_sha256'],
                    root / module.PROFILE_PATH: module.package_output_pins.SEMANTIC_HASHES['profile_sha256'],
                }
                if path in expected_by_path:
                    self.assertEqual(expected, expected_by_path[path])
                    return expected, b''
                return real_received(path, cap, expected, **options)

            with patch.object(module.package_output_pins, 'verify_file', return_value={
                    'schema': module.package_output_pins.SCHEMA,
                    'package_output_record_consistent': True,
                    'package_sha256': 'a' * 64}) as verifier, \
                    patch.object(module, 'received', side_effect=fixture_received):
                loaded = module.load_package_record(
                    record_path, __import__('hashlib').sha256(raw).hexdigest(), repo_root=root,
                )
        verifier.assert_called_once_with(
            record_path, __import__('hashlib').sha256(raw).hexdigest(), repo_root=root,
        )
        self.assertEqual(loaded['package_digest'], 'a' * 64)

    def test_heldout_report_requires_external_digest_and_exact_eight_pairs(self):
        self.assertTrue(TARGET.exists(), 'v2 input preparer missing')
        report = {
            'schema': module.SUITE_SCHEMA,
            'passed': True,
            'r1cs_sha256': module.package_output_pins.SEMANTIC_HASHES['r1cs_sha256'],
            'wasm_sha256': module.package_output_pins.SEMANTIC_HASHES['wasm_sha256'],
            'host_admission_bypassed': True,
            'setup_or_proofs_executed': False,
            'outputs_private': True,
            'cases': [],
            'accepted_count': 16,
            'rejected_count': 0,
        }
        for index in range(8):
            for name in (f'holdout_{index}', f'holdout_{index}_unrelated_refresh'):
                report['cases'].append({
                    'name': name, 'expected': 'accept', 'family': 'heldout',
                    'witness_elapsed_ms': 1.0,
                    'validation': {
                        'satisfied': True, 'constraints_checked': 793681,
                        'assignment_fields': 784796, 'matrix_entries': 4257583,
                        'max_row_terms': 4096,
                    },
                    'passed': True, 'complete_relation_check_ms': 1.0,
                })
        accepted = module.validate_heldout_report(report, 'c' * 64,
                                                   module.package_output_pins.SEMANTIC_HASHES['r1cs_sha256'],
                                                   module.package_output_pins.SEMANTIC_HASHES['wasm_sha256'])
        self.assertEqual(set(accepted), {case['name'] for case in report['cases']})
        with self.assertRaisesRegex(ValueError, 'external.*SHA|SHA.*external'):
            module.validate_heldout_report(
                report, None,
                module.package_output_pins.SEMANTIC_HASHES['r1cs_sha256'],
                module.package_output_pins.SEMANTIC_HASHES['wasm_sha256'],
            )
        report['cases'].pop()
        with self.assertRaises(ValueError):
            module.validate_heldout_report(report, 'c' * 64,
                                           module.package_output_pins.SEMANTIC_HASHES['r1cs_sha256'],
                                           module.package_output_pins.SEMANTIC_HASHES['wasm_sha256'])

    def test_v2_template_has_only_packet_builder_fields_and_v2_references(self):
        self.assertTrue(TARGET.exists(), 'v2 input preparer missing')
        context = {
            'package_digest': 'a' * 64,
            'setup_manifest_path': '/repo/artifacts/dynark/part5/v3-development-setup-002/setup-manifest.json',
            'setup_manifest_sha256': 'b' * 64,
            'package_check_path': '/repo/artifacts/dynark/part5/v3-package-check-002/package-check-report.json',
            'package_check_sha256': 'c' * 64,
            'r1cs_path': '/repo/artifacts/dynark/part5/v3-compile-002/credential.r1cs',
            'wasm_path': '/repo/artifacts/dynark/part5/v3-compile-002/credential_js/credential.wasm',
            'profile_path': '/repo/circuits/credential-v3-bounded/profile.json',
        }
        with tempfile.TemporaryDirectory() as directory:
            input_map = Path(directory).resolve() / 'symbol-input-map.json'
            input_map.write_text('{}')
            result = module.build_template(context, input_map, 'd' * 64)
        self.assertEqual(set(result), set(module.TEMPLATE_FIELDS))
        self.assertEqual(result['input_map_path'], str(input_map))
        self.assertEqual(result['input_map_sha256'], 'd' * 64)
        self.assertIn('v3-development-setup-002', result['setup_manifest_path'])
        self.assertIn('v3-package-check-002', result['package_check_path'])
        self.assertIn('v3-compile-002', result['r1cs_path'])

    def test_wire_map_uses_the_schema_required_by_proof_runner_v2(self):
        self.assertTrue(TARGET.exists(), 'v2 input preparer missing')
        source = TARGET.read_text()
        self.assertIn("INPUT_MAP_SCHEMA = 'credential-v3-bounded-input-wire-map-v1'", source)
        mapping = {name: index for index, name in enumerate(module.required_symbols(), 1)}
        self.assertEqual(
            module.input_map_document('a' * 64, mapping)['schema'],
            'credential-v3-bounded-input-wire-map-v1',
        )

    def test_bridge_copies_and_rehashes_builder_compatible_owner_only_case_files(self):
        self.assertTrue(TARGET.exists(), 'v2 input preparer missing')
        self.assertTrue(hasattr(module, '_copy_case'), 'heldout pair bridge helper missing')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source_dir = root / 'source'
            output_parent = root / 'pairs'
            source_dir.mkdir(mode=0o700)
            output_parent.mkdir(mode=0o700)
            source_files = {}
            for kind, content in (('wtns', b'fixture-wtns'),
                                  ('public', b'["1","2"]\n'),
                                  ('input', b'{"fixture":true}\n')):
                path = source_dir / f'{kind}.source'
                path.write_bytes(content)
                path.chmod(0o600)
                source_files[f'{kind}_path'] = str(path)
                source_files[f'{kind}_sha256'] = __import__('hashlib').sha256(content).hexdigest()
            destination = output_parent / 'base'
            copied = module._copy_case(source_files, destination)
            self.assertEqual(set(copied), {'directory', 'wtns_path', 'wtns_sha256',
                                            'public_path', 'public_sha256',
                                            'input_path', 'input_sha256'})
            self.assertEqual(Path(copied['wtns_path']).name, 'output.wtns')
            self.assertEqual(Path(copied['public_path']).name, 'public.json')
            self.assertEqual(Path(copied['input_path']).name, 'input.json')
            self.assertEqual(Path(copied['directory']).stat().st_mode & 0o777, 0o700)
            for key in ('wtns', 'public', 'input'):
                target = Path(copied[f'{key}_path'])
                self.assertEqual(target.read_bytes(), Path(source_files[f'{key}_path']).read_bytes())
                self.assertEqual(module.received(target, 65536)[0], source_files[f'{key}_sha256'])
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            builder_case = packet_builder._case(destination, 1, 0)
            self.assertEqual(Path(builder_case['wtns_path']).name, 'output.wtns')
            self.assertEqual(builder_case['wtns_sha256'], source_files['wtns_sha256'])

    def test_external_report_assignment_and_freeze_pins_are_rechecked(self):
        self.assertTrue(TARGET.exists(), 'v2 input preparer missing')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            root.chmod(0o700)
            paths = []
            digests = []
            for name in ('assignments.json', 'report.json', 'freeze.json'):
                path = root / name
                path.write_text('{}\n')
                path.chmod(0o600)
                paths.append(path)
                digests.append(__import__('hashlib').sha256(path.read_bytes()).hexdigest())
            module._recheck_external_inputs(
                paths[0], digests[0], paths[1], digests[1], paths[2], digests[2], 1,
            )
            paths[1].write_text('{"changed":true}\n')
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                module._recheck_external_inputs(
                    paths[0], digests[0], paths[1], digests[1], paths[2], digests[2], 1,
                )

    def test_input_scalar_map_and_wtns_link_reject_mismatched_public_coordinate(self):
        self.assertTrue(TARGET.exists(), 'v2 input preparer missing')
        inputs = {name: '1' for name in module.PUBLIC_NAMES}
        inputs.update(layout='0', slot='1')
        for name, count in module.ARRAYS:
            inputs[name] = ['0'] * count
        flat = module.flatten_inputs(inputs)
        mapping = {name: index for index, name in enumerate(module.required_symbols(), 1)}
        values = [1] + [flat[name] for name in module.required_symbols()] + [0] * 48
        count = len(values)
        header = (b'wtns' + (2).to_bytes(4, 'little') + (2).to_bytes(4, 'little')
                  + (1).to_bytes(4, 'little') + (40).to_bytes(8, 'little')
                  + (32).to_bytes(4, 'little') + module.FR.to_bytes(32, 'little')
                  + count.to_bytes(4, 'little') + (2).to_bytes(4, 'little')
                  + (32 * count).to_bytes(8, 'little'))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'fixture.wtns'
            path.write_bytes(header + b''.join(value.to_bytes(32, 'little') for value in values))
            path.chmod(0o600)
            module.verify_wtns_input_link(path, flat, mapping, expected_count=count)
            changed = dict(flat)
            changed['main.actionHash'] += 1
            with self.assertRaisesRegex(ValueError, 'coordinate'):
                module.verify_wtns_input_link(path, changed, mapping, expected_count=count)

    def test_heldout_pair_rejects_changed_action_even_with_valid_individual_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            root.chmod(0o700)
            report_path = root / 'report.json'
            report_path.write_text('{}\n')
            report_path.chmod(0o600)
            input_root = root / 'inputs'
            input_root.mkdir(mode=0o700)
            rows = []
            names = set()
            for index in range(8):
                for refreshed in (False, True):
                    name = f'holdout_{index}' + ('_unrelated_refresh' if refreshed else '')
                    names.add(name)
                    inputs = {key: '1' for key in module.PUBLIC_NAMES}
                    inputs.update(layout='0', slot='1')
                    for key, count in module.ARRAYS:
                        inputs[key] = ['0'] * count
                    if refreshed:
                        inputs['root'] = '2'
                        inputs['siblings'][0] = '1'
                    if index == 0 and refreshed:
                        inputs['actionHash'] = '2'
                    files = {
                        'wtns': (root / f'{name}.wtns', b'fixture-wtns'),
                        'public': (root / f'{name}-public.json',
                                   json.dumps([inputs[key] for key in module.PUBLIC_NAMES]).encode()),
                        'input': (input_root / f'{name}.input.json',
                                  json.dumps(inputs).encode()),
                    }
                    row = {'name': name}
                    for kind, (path, raw) in files.items():
                        path.write_bytes(raw)
                        path.chmod(0o600)
                        if kind != 'input':
                            row[f'{kind}_path'] = str(path)
                            row[f'{kind}_sha256'] = hashlib.sha256(raw).hexdigest()
                    rows.append(row)
            assignments = {
                'schema': module.ASSIGNMENTS_SCHEMA,
                'synthetic_only': True,
                'accepted_suite_path': str(report_path),
                'accepted_suite_sha256': 'a' * 64,
                'assignments': rows,
            }
            with patch.object(module, 'verify_wtns_input_link'), \
                    patch.object(module.profile, 'parse_tbs'):
                with self.assertRaisesRegex(ValueError, 'root-only'):
                    module._accepted_manifest(
                        assignments, 'a' * 64, report_path,
                        {name: {} for name in names}, input_root, 1, {},
                    )
                corrected = input_root / 'holdout_0_unrelated_refresh.input.json'
                corrected_inputs = json.loads(corrected.read_bytes())
                corrected_inputs['actionHash'] = '1'
                corrected.write_bytes(json.dumps(corrected_inputs).encode())
                public_path = root / 'holdout_0_unrelated_refresh-public.json'
                public_raw = json.dumps(
                    [corrected_inputs[key] for key in module.PUBLIC_NAMES]
                ).encode()
                public_path.write_bytes(public_raw)
                next(row for row in rows
                     if row['name'] == 'holdout_0_unrelated_refresh')['public_sha256'] = \
                    hashlib.sha256(public_raw).hexdigest()
                accepted = module._accepted_manifest(
                    assignments, 'a' * 64, report_path,
                    {name: {} for name in names}, input_root, 1, {},
                )
                self.assertEqual(len(accepted), 8)

    def test_symbol_map_uses_one_pinned_stable_file_read(self):
        self.assertTrue(hasattr(module, '_pinned_symbol_map'))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'credential.sym'
            names = module.required_symbols()
            raw = ''.join(f'0,{index},0,{name}\n'
                          for index, name in enumerate(names, 1)).encode()
            path.write_bytes(raw)
            path.chmod(0o600)
            expected = hashlib.sha256(raw).hexdigest()
            mapping = module._pinned_symbol_map(path, expected)
            self.assertEqual(mapping['main.root'], 1)
            self.assertEqual(len(mapping), len(names))
            with self.assertRaisesRegex(ValueError, 'digest'):
                module._pinned_symbol_map(path, '0' * 64)

            original = module.map_from_lines

            def replace_during_parse(lines):
                parsed = original(lines)
                path.write_bytes(b'changed\n')
                return parsed

            with patch.object(module, 'map_from_lines', side_effect=replace_during_parse):
                with self.assertRaisesRegex(ValueError, 'changed'):
                    module._pinned_symbol_map(path, expected)


if __name__ == '__main__':
    unittest.main()
