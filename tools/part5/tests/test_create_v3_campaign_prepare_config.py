import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from harness.tests import queue_v3_build_prep
from harness.tests import queue_v3_local_prepare
from tools.part5 import create_v3_campaign_prepare_config as tool


class CampaignPrepareConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(
            dir=queue_v3_local_prepare.REPO / 'artifacts/dynark/part5',
            prefix='prepare-config-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

        self.builder = self.root / 'fake-cargo-build-sbf'
        self.builder.write_bytes(b'test builder executable identity')
        self.validator = self.root / 'fake-solana-test-validator'
        self.validator.write_bytes(b'test validator executable identity')
        self.sbf_output = self.root / 'application-v3-sbf-test'
        self.elf = self.sbf_output / 'elf/zk_fresh_program.so'

        manifest = queue_v3_build_prep.source_manifest(queue_v3_local_prepare.REPO)
        plan = queue_v3_build_prep.prepare_build(
            queue_v3_local_prepare.REPO, manifest, self.builder,
            hashlib.sha256(self.builder.read_bytes()).hexdigest(), self.sbf_output)
        self.elf.parent.mkdir(parents=True)
        self.elf.write_bytes(b'\x7fELF test program bytes')
        plan_path = self.root / 'build-plan.json'
        plan_path.write_text(json.dumps(plan, sort_keys=True) + '\n')
        plan_path.chmod(0o600)
        self.plan_path = plan_path

        self.args = argparse.Namespace(
            build_plan=str(plan_path),
            elf=str(self.elf),
            validator=str(self.validator),
            program='3nqhgGtpPD8UyYMYtYFb4nBLntsW36gDUnzPXh5j9JNi',
            mint='FXc3RRXBoicezpRWjcDgGPkZQCWKfH5KWazPFZ6GbUDj',
            runtime_output=str(self.root / 'application-v3-runtime'),
            control_output=str(self.root / 'application-v3-control'),
            output=str(self.root / 'application-v3-campaign-prepare-config.json'))

    @staticmethod
    def digest(raw):
        return hashlib.sha256(raw).hexdigest()

    def reject(self):
        with self.assertRaises((ValueError, FileExistsError, FileNotFoundError)):
            tool.create(self.args)
        self.assertFalse(Path(self.args.output).exists())

    def test_valid_config_matches_prepare_contract_and_pins_inputs(self):
        config_sha256 = tool.create(self.args)
        output = Path(self.args.output)
        raw = output.read_bytes()
        config = json.loads(raw)

        self.assertEqual(self.digest(raw), config_sha256)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(set(config), {
            'schema', 'scope', 'build_plan', 'build_plan_sha256', 'elf',
            'elf_sha256', 'validator', 'validator_sha256', 'program', 'mint',
            'runtime_output', 'control_output', 'outer_limits_required'})
        self.assertEqual(config['schema'], 1)
        self.assertEqual(config['scope'], 'part5-v3-local-prepare')
        self.assertEqual(config['outer_limits_required'], queue_v3_local_prepare.LIMITS)
        self.assertEqual(config['build_plan_sha256'], self.digest(self.plan_path.read_bytes()))
        self.assertEqual(config['elf_sha256'], self.digest(self.elf.read_bytes()))
        self.assertEqual(config['validator_sha256'], self.digest(self.validator.read_bytes()))
        self.assertFalse(Path(self.args.runtime_output).exists())
        self.assertFalse(Path(self.args.control_output).exists())
        queue_v3_local_prepare.admit(config)

    def test_stale_build_plan_source_pins_rejected(self):
        plan = json.loads(self.plan_path.read_bytes())
        plan['source_manifest']['source_pins']['program/src/lib.rs'] = '0' * 64
        self.plan_path.write_text(json.dumps(plan, sort_keys=True) + '\n')
        self.reject()

    def test_invalid_public_key_rejected(self):
        self.args.program = 'not-a-canonical-key'
        self.reject()

    def test_existing_runtime_output_rejected_without_modification(self):
        runtime = Path(self.args.runtime_output)
        runtime.mkdir(mode=0o700)
        marker = runtime / 'keep.txt'
        marker.write_text('preserve')
        with self.assertRaises((ValueError, FileExistsError)):
            tool.create(self.args)
        self.assertEqual(marker.read_text(), 'preserve')
        self.assertFalse(Path(self.args.output).exists())

    def test_existing_config_is_never_overwritten(self):
        output = Path(self.args.output)
        output.write_bytes(b'preserve')
        with self.assertRaises((ValueError, FileExistsError)):
            tool.create(self.args)
        self.assertEqual(output.read_bytes(), b'preserve')


if __name__ == '__main__':
    unittest.main()
