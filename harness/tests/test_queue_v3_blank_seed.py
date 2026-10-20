import copy
import contextlib
import importlib.util
import io
import json
import os
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from harness.tests import queue_v3_local_prepare as base
from harness.tests import queue_v3_local_stage as stage

MODULE = Path(__file__).with_name('queue_v3_blank_seed.py')
spec = importlib.util.spec_from_file_location('blank_seed', MODULE)
m = importlib.util.module_from_spec(spec)
if MODULE.exists():
    spec.loader.exec_module(m)


class BlankSeedTests(unittest.TestCase):
    def api(self):
        self.assertTrue(hasattr(m, 'build_manifest'), 'blank seed preparation contract missing')

    def write(self, path, value):
        raw = value if isinstance(value, bytes) else (json.dumps(value) + '\n').encode()
        path.write_bytes(raw)
        path.chmod(0o600)
        return {'path': str(path), 'sha256': base.sha(raw)}

    def fixture(self, root, program=None, payer=None):
        self.api()
        runtime = root / 'seed-runtime'; runtime.mkdir(mode=0o700)
        ledger = runtime / 'ledger'; ledger.mkdir(mode=0o700)
        for name in ('genesis.bin', 'validator-keypair.json', 'vote-account-keypair.json',
                     'stake-account-keypair.json'):
            self.write(ledger / name, name.encode())
        program = program or '3nqhgGtpPD8UyYMYtYFb4nBLntsW36gDUnzPXh5j9JNi'
        payer, genesis = payer or base.b58(bytes([12]) * 32), base.b58(bytes([13]) * 32)
        validator = self.write(root / 'validator', b'pinned validator')
        config = dict(schema=1, scope=m.CREATE_SCOPE, validator=validator['path'],
                      validator_sha256=validator['sha256'], program=program, payer=payer,
                      runtime_output=str(runtime), control_output=str(root / 'seed-control'),
                      outer_limits_required=base.LIMITS)
        config['owner_source'] = self.write(root / 'owner.py', b'owned seed creator')
        config['owner_manifest'] = self.write(root / 'run-manifest.json', {'manifest': True})
        config_ref = self.write(root / 'create-config.json', config)
        observation = dict(genesis=genesis, program=program, programdata=m.programdata_address(program),
                           payer=payer, finalized_slot=7, program_accounts_finalized_slot=8,
                           program_absent=True, programdata_absent=True,
                           application_accounts_empty=True, payer_lamports=1000000000,
                           payer_owner=base.b58(bytes(32)))
        status = dict(schema=1, scope=m.CREATE_SCOPE, status='failed',
                      config_sha256=config_ref['sha256'], ledger=str(ledger),
                      blank_verified=True, seed_observation=observation,
                      application_effect=False, prepared_application_accounts=False,
                      cleanup=dict(spawned=True, reaped=True, graceful=False, exit_code=-2))
        status_ref = self.write(root / 'create-status.json', status)
        monitor = dict(schema=1, measurement='bounded_complete_session', owner='blank-seed-test',
                       passed=False, exit_code=1, censored=False, stop_reason=None,
                       cleanup_remaining_owned_processes=0, cleanup_status_unknown=False,
                       duration_seconds=2., sample_count=2)
        monitor_ref = self.write(root / 'create-monitor.json', monitor)
        private = root / 'monitor'; private.mkdir(mode=0o700)
        invocation = dict(owner=monitor['owner'], cwd=str(base.REPO), started_at_utc='2026-10-20T00:00:00Z',
                          storage_roots=[str(private), str(root)],
                          argv=[sys.executable, config['owner_source']['path'], '--manifest',
                                config['owner_manifest']['path'], '--output-root', str(root),
                                '--seed-config', config_ref['path'], '--seed-config-sha256',
                                config_ref['sha256'], '--_create-seed'])
        invocation_ref = self.write(private / 'invocation.json', invocation)
        sources = dict(config=config_ref, status=status_ref, monitor=monitor_ref, invocation=invocation_ref,
                       monitor_owner='blank-seed-test')
        manifest = m.build_manifest(sources)
        manifest_ref = self.write(root / 'seed.json', manifest)
        return config, status, monitor, sources, manifest, manifest_ref

    def test_programdata_matches_installed_cli_vector(self):
        self.api()
        self.assertEqual(m.programdata_address('3nqhgGtpPD8UyYMYtYFb4nBLntsW36gDUnzPXh5j9JNi'),
                         'BvhDykQXrisyWsVYntUXQk8DZu8xSRwqSf5LeLo11SJZ')

    def test_seed_creation_and_resume_arguments_never_preload_application(self):
        self.api()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            argv = m.creation_argv('/validator', root / 'ledger', base.b58(bytes([12]) * 32))
            self.assertIn('--reset', argv)
            self.assertNotIn('--bpf-program', argv)
            resume = m.resume_argv('/validator', root / 'ledger')
            self.assertNotIn('--reset', resume)
            self.assertNotIn('--mint', resume)

    def test_seed_clone_pins_inventory_and_rejects_partial_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); root.chmod(0o700)
            config, _, _, _, manifest, ref = self.fixture(root)
            destination = root / 'copy'; destination.mkdir(mode=0o700)
            receipt = m.clone(ref, destination / 'ledger', config)
            self.assertEqual(receipt['tree_sha256'], manifest['tree_sha256'])
            self.assertTrue(receipt['copy_identical'])
            self.assertFalse(receipt['loaded_identity_rechecked_after_restart'])
            with self.assertRaises(ValueError):
                m.clone(ref, destination / 'ledger', config)
            self.write(Path(manifest['ledger']) / 'unexpected', b'drift')
            with self.assertRaises(ValueError):
                m.review_manifest(ref, config)

    def test_seed_source_observation_monitor_and_links_fail_closed(self):
        for mutation in ('program', 'application', 'monitor', 'cleanup', 'link'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(); root.chmod(0o700)
                config, status, monitor, sources, manifest, _ = self.fixture(root)
                if mutation == 'program': status['seed_observation']['program_absent'] = False
                if mutation == 'application': status['seed_observation']['application_accounts_empty'] = False
                if mutation == 'monitor': monitor['cleanup_remaining_owned_processes'] = 1
                if mutation == 'cleanup': status['cleanup']['graceful'] = True
                if mutation == 'link':
                    os.link(Path(manifest['ledger']) / 'genesis.bin', root / 'hardlink')
                sources['status'] = self.write(root / 'create-status.json', status)
                sources['monitor'] = self.write(root / 'create-monitor.json', monitor)
                with self.assertRaises(ValueError): m.build_manifest(sources)

    def test_live_blank_read_requires_empty_program_accounts_and_same_genesis(self):
        self.api()
        program, payer, genesis = (base.b58(bytes([i]) * 32) for i in (11, 12, 13))
        seed = dict(program=program, programdata=m.programdata_address(program),
                    payer=payer, genesis=genesis)
        class Proc:
            def poll(self): return None
        for mutation in (None, 'program', 'programdata', 'application', 'genesis', 'payer'):
            with self.subTest(mutation=mutation):
                calls = []
                def rpc(method, params):
                    calls.append((method, params))
                    if method == 'getGenesisHash':
                        return base.b58(bytes([14]) * 32) if mutation == 'genesis' and len(calls) > 1 else genesis
                    if method == 'getMultipleAccounts':
                        payer_account = {'owner': base.b58(bytes(32)), 'lamports': 100,
                                         'executable': False}
                        return {'context': {'slot': 7}, 'value': [
                            {} if mutation == 'program' else None,
                            {} if mutation == 'programdata' else None,
                            None if mutation == 'payer' else payer_account]}
                    return {'context': {'slot': 8}, 'value': [{}] if mutation == 'application' else []}
                if mutation:
                    with self.assertRaises(ValueError): m.observe_blank(rpc, Proc(), seed, timeout=1)
                else:
                    observation = m.observe_blank(rpc, Proc(), seed, timeout=1)
                    self.assertTrue(observation['application_accounts_empty'])
                    query = next(params for method, params in calls if method == 'getProgramAccounts')
                    self.assertEqual(query[1]['commitment'], 'finalized')
                    self.assertEqual(query[1]['minContextSlot'], 7)

    def test_deploy_argv_uses_explicit_loopback_signers_finalized_and_final(self):
        self.api()
        config = dict(solana_cli={'path': '/solana'}, program_signer={'path': '/program.json'},
                      deployment_payer={'path': '/payer.json'}, elf='/v3.so')
        argv = m.deploy_argv(config, Path('/buffer.json'))
        for forbidden in ('--skip-preflight', '--skip-feature-verify'):
            self.assertNotIn(forbidden, argv)
        for flag, value in [('--url', base.RPC.rstrip('/')), ('--program-id', '/program.json'),
                            ('--fee-payer', '/payer.json'), ('--keypair', '/payer.json'),
                            ('--commitment', 'finalized'), ('--buffer', '/buffer.json'),
                            ('--ws', 'ws://127.0.0.1:19000/'), ('--upgrade-authority', '/payer.json')]:
            self.assertIn(flag, argv)
            self.assertEqual(argv[argv.index(flag) + 1], value)
        self.assertIn('--final', argv); self.assertIn('--use-rpc', argv)

    def test_deployment_requires_blank_read_before_cli_and_exact_live_identity_after(self):
        self.api()
        self.assertTrue(hasattr(m, 'deploy'), 'measured deployment owner missing')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); root.chmod(0o700)
            config, _, _, _, manifest, ref = self.fixture(root)
            config.update(blank_seed=ref, solana_cli={'path': '/cli', 'sha256': '1' * 64},
                          program_signer={'path': '/program', 'sha256': '2' * 64},
                          deployment_payer={'path': '/payer', 'sha256': '3' * 64},
                          elf='/program.so', elf_sha256='4' * 64)
            identity = {'genesis': manifest['genesis'], 'program': manifest['program'],
                        'programdata': manifest['programdata'], 'upgrade_authority': None,
                        'elf_match': True, 'elf_sha256': config['elf_sha256']}
            order = []
            class Proc:
                def poll(self): return 0
                def wait(self, timeout=None): return 0
            def observe(*args, **kwargs):
                order.append('blank'); return {'observation': True}
            def spawn(*args, **kwargs): order.append('deploy'); return Proc()
            def loaded(*args, **kwargs): order.append('loaded'); return identity
            with patch.object(m, 'admit_deployment', return_value=manifest), \
                    patch.object(m, 'observe_blank', side_effect=observe), \
                    patch.object(m.subprocess, 'Popen', side_effect=spawn), \
                    patch.object(m.base, 'wait_loaded', side_effect=loaded):
                got, receipt = m.deploy(config, root, object(), object(), b'elf')
            self.assertEqual(order, ['blank', 'deploy', 'loaded'])
            self.assertEqual(got, identity)
            self.assertTrue(receipt['finalized_elf_verified'])
            self.assertEqual(receipt['exit_code'], 0)
            self.assertEqual(receipt['loaded_program'], identity)
            self.assertNotIn('--reset', receipt['argv'])

    def test_opt_in_prepare_clones_and_deploys_while_unseeded_path_stays_default(self):
        self.api()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); root.chmod(0o700)
            config, _, _, _, manifest, ref = self.fixture(root)
            runtime, control = root / 'arm-runtime', root / 'arm-control'
            config.update(runtime_output=str(runtime), control_output=str(control),
                          blank_seed=ref, elf='/elf', elf_sha256='4' * 64,
                          build_plan_sha256='5' * 64)
            plan = {'environment_remove': [], 'environment_required': {}, 'source_manifest': {'v3_vk': 'vk'}}
            calls = []
            def clone(*args):
                calls.append('clone'); path = runtime / 'ledger'; path.mkdir(mode=0o700)
                self.write(path / 'genesis.bin', b'genesis')
                return {'copy_identical': True}
            class Proc:
                def poll(self): return None
            def spawn(argv, **kwargs):
                calls.append('spawn'); self.assertNotIn('--reset', argv); return Proc()
            def deploy(*args):
                calls.append('deploy')
                return ({'elf_match': True}, {'finalized_elf_verified': True,
                        'predeployment_observation': {'payer': manifest['payer']}})
            cleanup = {'spawned': True, 'reaped': True, 'graceful': False, 'exit_code': -2}
            with patch.dict(os.environ, P5_V3_PREPARE_SCOPE='local-validator-prepare'), \
                    patch.object(base, 'blank_seed_module', return_value=m, create=True), \
                    patch.object(base, 'admit', return_value=(plan, b'elf', runtime, control, ['/validator'])), \
                    patch.object(m, 'clone', side_effect=clone), patch.object(m, 'deploy', side_effect=deploy), \
                    patch.object(base.subprocess, 'Popen', side_effect=spawn), \
                    patch.object(base, 'ports_free'), patch.object(base, 'checked'), \
                    patch.object(base.prep, 'check_manifest'), patch.object(base, 'cleanup', return_value=cleanup), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(base.run(config, '6' * 64), 1)
            self.assertEqual(calls, ['clone', 'spawn', 'deploy'])
            status = json.loads((control / 'status.json').read_bytes())
            self.assertEqual(status['preparation_kind'], m.KIND)
            self.assertFalse(status['cleanup']['graceful'])
            self.assertTrue(status['ledger_reuse_requires_review'])
            self.assertNotIn('error_type', status)
            self.assertEqual(status['mint'], manifest['payer'])

    def test_stage_explicit_seeded_provenance_dispatches_before_old_prepare_policy(self):
        self.api()
        self.assertTrue(hasattr(m, 'review_prepare'), 'seeded stage admission missing')
        prior = {'preparation_kind': m.KIND}
        with patch.object(stage, 'blank_seed_module', return_value=m, create=True), \
                patch.object(m, 'review_prepare') as review:
            stage.review_prior(prior, {'monitor': True}, {'blank_seed': {}}, {'config': True})
        review.assert_called_once_with(prior, {'monitor': True}, {'blank_seed': {}}, {'config': True})

    def signer_fixture(self, root, name, byte):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        private = bytes([byte]) * 32
        public = Ed25519PrivateKey.from_private_bytes(private).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return self.write(root / name, list(private + public)), base.b58(public)

    def test_actual_signer_pins_and_stage_provenance_mutations(self):
        self.api()
        self.assertTrue(hasattr(m, 'review_prepare'))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); root.chmod(0o700)
            program_ref, program = self.signer_fixture(root, 'program.json', 1)
            payer_ref, payer = self.signer_fixture(root, 'payer.json', 2)
            config, seed_status, monitor, _, manifest, ref = self.fixture(root, program, payer)
            runtime, control = root / 'arm-runtime', root / 'arm-control'
            runtime.mkdir(mode=0o700); control.mkdir(mode=0o700)
            cli_ref = self.write(root / 'cli', b'pinned cli')
            elf_ref = self.write(root / 'program.so', b'\x7fELF' + bytes(80))
            config.update(scope='part5-v3-local-prepare', blank_seed=ref, solana_cli=cli_ref,
                          program_signer=program_ref, deployment_payer=payer_ref,
                          elf=elf_ref['path'], elf_sha256=elf_ref['sha256'],
                          runtime_output=str(runtime), control_output=str(control))
            self.assertEqual(m.admit_deployment(config), manifest)
            imported = m.clone(ref, runtime / 'ledger', config)
            loaded = dict(program=program, programdata=manifest['programdata'], genesis=manifest['genesis'],
                          elf_sha256=elf_ref['sha256'], elf_match=True, upgrade_authority=None,
                          program_account_sha256='7' * 64, programdata_account_sha256='8' * 64)
            class Proc:
                def poll(self): return 0
                def wait(self, timeout=None): return 0
            with patch.object(m, 'observe_blank', return_value=seed_status['seed_observation']), \
                    patch.object(m.subprocess, 'Popen', return_value=Proc()), \
                    patch.object(m.base, 'wait_loaded', return_value=loaded):
                _, deployment = m.deploy(config, control, object(), object(), b'elf')
            prior = dict(schema=1, scope=config['scope'], preparation_kind=m.KIND,
                         config_sha256='9' * 64, status='failed', cleanup=seed_status['cleanup'],
                         ledger_reuse_requires_review=True, application_effect=False,
                         prepared_application_accounts=False, loaded_program=loaded,
                         ledger=str(runtime / 'ledger'), seed_import=imported, deployment=deployment)
            stage_config = dict(prior_config_sha256='9' * 64, ledger=prior['ledger'],
                                expected_genesis=manifest['genesis'], prior_monitor_owner=monitor['owner'])
            m.review_prepare(prior, monitor, config, stage_config)
            for mutation in ('seed_tree', 'source', 'destination', 'observation', 'deployment',
                             'loaded', 'cleanup', 'monitor'):
                with self.subTest(mutation=mutation):
                    wrong, wrong_monitor = copy.deepcopy(prior), copy.deepcopy(monitor)
                    if mutation == 'seed_tree': wrong['seed_import']['tree_sha256'] = 'f' * 64
                    if mutation == 'source': wrong['seed_import']['source'] = str(runtime / 'ledger')
                    if mutation == 'destination': wrong['seed_import']['destination'] = manifest['ledger']
                    if mutation == 'observation': wrong['deployment']['predeployment_observation']['program_absent'] = False
                    if mutation == 'deployment': wrong['deployment']['argv'].append('--skip-preflight')
                    if mutation == 'loaded': wrong['loaded_program']['genesis'] = base.b58(bytes([4]) * 32)
                    if mutation == 'cleanup': wrong['cleanup']['graceful'] = True
                    if mutation == 'monitor': wrong_monitor['censored'] = True
                    with self.assertRaises(ValueError):
                        m.review_prepare(wrong, wrong_monitor, config, stage_config)
            bad_signer = copy.deepcopy(config)
            bad_signer['program_signer'] = payer_ref
            with self.assertRaises(ValueError): m.admit_deployment(bad_signer)
            self.write(Path(program_ref['path']), list(bytes(64)))
            with self.assertRaises(ValueError): m.admit_deployment(config)

    def test_creation_reopens_pinned_validator_binary(self):
        self.api()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); root.chmod(0o700)
            config, _, _, sources, _, _ = self.fixture(root)
            self.write(Path(config['validator']), b'changed validator')
            with self.assertRaises(ValueError): m.build_manifest(sources)

    def test_creation_outer_invocation_is_bound_to_owner_source_config_and_manifest(self):
        self.api()
        for mutation in ('owner', 'config', 'manifest', 'source', 'coverage'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(); root.chmod(0o700)
                config, _, _, sources, _, _ = self.fixture(root)
                invocation = json.loads(Path(sources['invocation']['path']).read_bytes())
                if mutation == 'owner': invocation['owner'] = 'foreign-owner'
                if mutation == 'config': invocation['argv'][-2] = 'a' * 64
                if mutation == 'manifest': invocation['argv'][4] = '/different-manifest'
                if mutation == 'coverage': invocation['storage_roots'] = [str(root / 'monitor')]
                if mutation == 'source': self.write(Path(config['owner_source']['path']), b'drifted source')
                sources['invocation'] = self.write(Path(sources['invocation']['path']), invocation)
                with self.assertRaises(ValueError): m.build_manifest(sources)


if __name__ == '__main__':
    unittest.main()
