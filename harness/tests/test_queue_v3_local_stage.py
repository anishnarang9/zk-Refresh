import importlib.util
import json
from pathlib import Path
import signal
import tempfile
import unittest


spec = importlib.util.spec_from_file_location('v3_stage', Path(__file__).with_name('queue_v3_local_stage.py'))
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


class StageTests(unittest.TestCase):
    def test_generated_report_is_bounded_and_owner_only(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / 'report.json'
            report.write_bytes(b'{"passed":true}')
            report.chmod(0o600)
            raw, digest = stage.snapshot_generated(report, 64)
            self.assertEqual(json.loads(raw), {'passed': True})
            self.assertEqual(digest, stage.base.sha(raw))
            report.write_bytes(b'a' * 65)
            with self.assertRaises(ValueError):
                stage.snapshot_generated(report, 64)
            report.unlink()
            report.symlink_to(Path(directory) / 'target')
            with self.assertRaises((ValueError, OSError)):
                stage.snapshot_generated(report, 64)

    def test_stage_outputs_must_be_distinct_direct_children(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            left = root / 'application-v3-stage'
            right = root / 'application-v3-control'
            stage.validate_stage_paths(left, right, root)
            for invalid in (left, root / 'nested/application-v3-control', root / 'other'):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    stage.validate_stage_paths(left, invalid, root)

    def test_interrupted_prior_is_reviewed_before_reuse(self):
        genesis = 'genesis'
        prior = {'schema': 1, 'scope': 'part5-v3-local-prepare', 'config_sha256': 'a' * 64,
                 'application_effect': False, 'prepared_application_accounts': False,
                 'loaded_program': {'elf_match': True, 'elf_sha256': 'b' * 64,
                                    'program': 'program', 'genesis': genesis},
                 'ledger': '/ledger', 'cleanup': {'reaped': True, 'exit_code': -signal.SIGINT},
                 'ledger_reuse_requires_review': True, 'status': 'failed'}
        monitor = {'owner': 'part5-v3-local-prepare-001', 'stop_reason': None,
                   'runner_error_type': None, 'cleanup_remaining_owned_processes': 0,
                   'cleanup_status_unknown': False}
        original = {'elf_sha256': 'b' * 64, 'program': 'program'}
        config = {'prior_config_sha256': 'a' * 64, 'expected_genesis': genesis,
                  'ledger': '/ledger'}
        stage.review_prior(prior, monitor, original, config)
        second = dict(config, prior_monitor_owner='part5-v3-local-prepare-002')
        with self.assertRaises(ValueError):
            stage.review_prior(prior, monitor, original, second)
        stage.review_prior(prior, dict(monitor, owner='part5-v3-local-prepare-002'), original, second)
        prior['loaded_program']['genesis'] = 'changed'
        with self.assertRaises(ValueError):
            stage.review_prior(prior, monitor, original, config)


class ReplayPackageTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(callable(getattr(stage, "replay_environment", None)),
                        "stage replay admission is missing")

    def fixture(self, root):
        root = root.resolve()
        context = {'root': '11' * 32, 'issuer_hash': '22' * 32,
                   'policy_id': '33' * 32, 'aki': '44' * 32,
                   'not_before': 1, 'not_after': 1000}
        plan = {name: list(bytes.fromhex(context[name]))
                for name in ('root', 'issuer_hash', 'policy_id', 'aki')}
        plan.update(program=[5] * 32, genesis=[6] * 32, deadline=900,
                    payload=[0, 1, 2, 3], seed=[7] * 32, nonce=[8] * 32)
        files = {}
        for index, role in enumerate(('admin', 'publisher', 'source', 'creator')):
            plan[role] = [index + 10] * 32
            path = root / (role + '.json')
            path.write_text(json.dumps([index + 20] * 32 + plan[role]))
            path.chmod(0o600)
            files[path.name] = stage.base.sha(path.read_bytes())
        plan['recipient'] = plan['source']
        path = root / 'plan.json'
        path.write_text(json.dumps(plan)); path.chmod(0o600)
        files[path.name] = stage.base.sha(path.read_bytes())
        package = {'schema': 'part5-v3-stage-replay-v1',
                   'context_sha256': 'a' * 64, 'files': files}
        path = root / 'replay.json'
        path.write_text(json.dumps(package)); path.chmod(0o600)
        return {'path': str(path), 'sha256': stage.base.sha(path.read_bytes())}, context

    def test_valid_private_package_preserves_all_five_exact_pins(self):
        with tempfile.TemporaryDirectory() as directory:
            pin, context = self.fixture(Path(directory))
            env = stage.replay_environment({'replay_package': pin, 'context_sha256': 'a' * 64}, context)
            self.assertEqual(env, {'P5_V3_REPLAY_PACKAGE': pin['path'],
                                   'P5_V3_REPLAY_PACKAGE_SHA256': pin['sha256']})

    def test_wrong_plan_or_key_hash_is_rejected(self):
        for name in ('plan.json', 'admin.json', 'publisher.json', 'source.json', 'creator.json'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                pin, context = self.fixture(root)
                with (root / name).open('ab') as stream:
                    stream.write(b' ')
                with self.assertRaises(ValueError):
                    stage.replay_environment({'replay_package': pin, 'context_sha256': 'a' * 64}, context)

    def test_wrong_context_pin_or_plan_context_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            pin, context = self.fixture(Path(directory))
            for changed in ({'context_sha256': 'b' * 64}, {}):
                config = {'replay_package': pin, 'context_sha256': 'a' * 64, **changed}
                bad_context = context if changed else dict(context, root='ff' * 32)
                with self.assertRaises(ValueError):
                    stage.replay_environment(config, bad_context)

    def test_public_key_mismatch_rejected_even_when_re_pinned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pin, context = self.fixture(root)
            key = root / 'admin.json'
            key.write_text(json.dumps([99] * 64))
            package = json.loads((root / 'replay.json').read_bytes())
            package['files']['admin.json'] = stage.base.sha(key.read_bytes())
            (root / 'replay.json').write_text(json.dumps(package))
            pin['sha256'] = stage.base.sha((root / 'replay.json').read_bytes())
            with self.assertRaises(ValueError):
                stage.replay_environment({'replay_package': pin, 'context_sha256': 'a' * 64}, context)

    def test_nonprivate_and_symlink_package_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pin, context = self.fixture(root)
            for path in (root, root / 'admin.json'):
                original = path.stat().st_mode & 0o777
                path.chmod(0o755 if path == root else 0o644)
                with self.assertRaises(ValueError):
                    stage.replay_environment({'replay_package': pin, 'context_sha256': 'a' * 64}, context)
                path.chmod(original)
            alias = root / 'alias.json'; alias.symlink_to(root / 'replay.json')
            with self.assertRaises(ValueError):
                stage.replay_environment({'replay_package': dict(pin, path=str(alias)),
                                          'context_sha256': 'a' * 64}, context)

    def test_manifest_pin_and_exact_file_set_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            pin, context = self.fixture(root)
            config = {'replay_package': dict(pin, sha256='f' * 64), 'context_sha256': 'a' * 64}
            with self.assertRaises(ValueError):
                stage.replay_environment(config, context)
            package = json.loads((root / 'replay.json').read_bytes())
            package['files']['extra.json'] = 'f' * 64
            (root / 'replay.json').write_text(json.dumps(package))
            pin['sha256'] = stage.base.sha((root / 'replay.json').read_bytes())
            with self.assertRaises(ValueError):
                stage.replay_environment({'replay_package': pin, 'context_sha256': 'a' * 64}, context)

    def test_re_pinned_plan_must_match_each_context_field_and_validity(self):
        invalid = {'root': [99] * 32, 'issuer_hash': [99] * 32,
                   'policy_id': [99] * 32, 'aki': [99] * 32,
                   'deadline': 1001, 'recipient': [99] * 32, 'payload': [99]}
        for field, value in invalid.items():
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                pin, context = self.fixture(root)
                plan = json.loads((root / 'plan.json').read_bytes())
                plan[field] = value
                (root / 'plan.json').write_text(json.dumps(plan))
                package = json.loads((root / 'replay.json').read_bytes())
                package['files']['plan.json'] = stage.base.sha((root / 'plan.json').read_bytes())
                (root / 'replay.json').write_text(json.dumps(package))
                pin['sha256'] = stage.base.sha((root / 'replay.json').read_bytes())
                with self.assertRaises(ValueError):
                    stage.replay_environment({'replay_package': pin, 'context_sha256': 'a' * 64}, context)

    def test_absent_replay_keeps_default_and_clears_inherited_opt_in(self):
        self.assertEqual(stage.replay_environment({}, {}), {})
        env = {'P5_V3_REPLAY_PACKAGE': '/inherited', 'P5_V3_REPLAY_PACKAGE_SHA256': 'bad',
               'KEEP': 'yes'}
        stage.set_replay_environment(env, {})
        self.assertEqual(env, {'KEEP': 'yes'})

    def test_replay_requires_all_five_accounts_absent_before_funding(self):
        source = (Path(__file__).parents[1] / 'src/solana/queue_v3.rs').read_text()
        body = source.split('fn stage_with_context(campaign: bool)', 1)[1]
        self.assertTrue('if replay_plan_raw.is_some()' in body, 'replay ledger preflight is missing')
        gate = body.split('if replay_plan_raw.is_some()', 1)[1].split('let mut funding', 1)[0]
        for account in ('config', 'issuer', 'head', 'request', 'queue'):
            self.assertIn('a.' + account, gate)
        self.assertIn('rpc.account(&address)?.is_none()', gate)
        self.assertLess(body.index('rpc.account(&address)?.is_none()'), body.index('"requestAirdrop"'))

    def test_replay_deadline_covers_owner_ceiling_with_overflow_safe_live_clock(self):
        source = (Path(__file__).parents[1] / 'src/solana/queue_v3.rs').read_text()
        self.assertTrue('fn replay_deadline_covers_stage(' in source, 'replay deadline preflight is missing')
        helper = source.split('fn replay_deadline_covers_stage(', 1)[1].split('fn stage_with_context(', 1)[0]
        self.assertIn('checked_add(180)', helper)
        self.assertIn('deadline >= minimum', helper)
        self.assertEqual(stage.LIMITS['runtime_seconds'], 180)
        body = source.split('fn stage_with_context(campaign: bool)', 1)[1]
        gate = body.split('if replay_plan_raw.is_some()', 1)[1].split('let mut funding', 1)[0]
        self.assertIn('let replay_now = transport::clock(&rpc)?;', gate)
        self.assertIn('replay_deadline_covers_stage(replay_now, p.deadline)', gate)
        self.assertLess(gate.index('rpc.account('), gate.index('let replay_now'))

    def test_rust_replay_validation_precedes_any_funding_or_signing(self):
        source = (Path(__file__).parents[1] / 'src/solana/queue_v3.rs').read_text()
        body = source.split('fn stage_with_context(campaign: bool)', 1)[1]
        self.assertIn('stage_replay(', body)
        self.assertLess(body.index('stage_replay('), body.index('"requestAirdrop"'))
        self.assertIn('std::env::var_os("P5_V3_REPLAY_PACKAGE")', body)
        self.assertIn('seed: random_bytes()', body)
        self.assertIn('nonce: random_bytes()', body)
        self.assertIn('deadline: (now + 86_400).min(not_after)', body)


if __name__ == '__main__':
    unittest.main()
