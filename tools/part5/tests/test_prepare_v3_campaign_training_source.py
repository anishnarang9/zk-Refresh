import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.part5 import prepare_v3_campaign_training_source as tool


class CampaignSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.stage, self.cohort, self.out = [self.root / n for n in ('stage', 'cohort', 'out')]
        for p in (self.stage, self.cohort, self.out):
            p.mkdir(mode=0o700)
        self.own = b'c' * 952
        self.member = dict(roots=list(range(1, 12)), holder_siblings=[[0] * 10] * 11)
        self.context = dict(root=f'{1:064x}', issuer_hash=f'{2:064x}', policy_id=f'{3:064x}',
            root_sequence=[f'{i:064x}' for i in range(1, 12)],
            initial_allocations=dict(tbs_digests=[tool.digest(b'tbs')], root_sequence_sha256='a' * 64))
        self.plan = {k: [0] * 32 for k in ('program', 'genesis', 'creator', 'nonce', 'recipient')}
        self.plan.update(root=list((1).to_bytes(32, 'big')), issuer_hash=list((2).to_bytes(32, 'big')),
            policy_id=list((3).to_bytes(32, 'big')), deadline=200, payload=[1, 2])
        config = bytearray(381)
        config[:8] = b'DYNCONF3'
        config[136:168] = bytes(self.plan['policy_id'])
        config[332:364] = bytes(self.plan['root'])
        self.config = bytes(config)
        self.request = b'q' * 2249
        self.save(self.cohort / 'credential-0.der', self.own)
        self.save(self.cohort / 'holder-0.pem', b'private-mock')
        self.save(self.cohort / 'issuer-modulus.bin', b'm' * 256)
        self.save(self.cohort / 'cohort-receipt.json', tool.encoded(
            dict(certificates=[dict(credential_sha256=tool.digest(self.own))])))
        self.save(self.cohort / 'membership.json', tool.encoded(self.member))
        self.save(self.root / 'context.json', tool.encoded(self.context))
        self.save(self.stage / 'config.bin', self.config)
        self.save(self.stage / 'request.bin', self.request)
        self.save(self.stage / 'plan.json', tool.encoded(self.plan))
        self.save(self.stage / 'signed-history.json', b'{}')
        allocation = tool.encoded(self.context['initial_allocations'])
        self.save(self.stage / 'initial-allocations.json', allocation)
        self.report = dict(schema='part5-v3-campaign-stage-v1',
            **{k: True for k in ('passed', 'training_only', 'registry_history_authenticated',
                'allocation_history_authenticated', 'upstream_source_authentication',
                'upstream_publisher_authentication')},
            application_effect=False, proof_created=False,
            plan_sha256=tool.digest(tool.encoded(self.plan)), signed_history_sha256=tool.digest(b'{}'),
            initial_allocations_sha256=tool.digest(allocation),
            account_sha256=[tool.digest(self.config), '', '', tool.digest(self.request), ''],
            transactions=[dict(scenario='v3-bind-head', blockTime=100)])
        self.save(self.stage / 'stage-report.json', tool.encoded(self.report))
        self.exporter = self.root / 'exporter'
        self.save(self.exporter, b'mock exporter')
        self.exporter.chmod(0o700)

    def save(self, path, raw):
        path.write_bytes(raw)
        path.chmod(0o600)

    def prepare(self, finalized=None):
        final = finalized or dict(exporter_sha256=tool.digest(self.exporter.read_bytes()),
                                  v3f1=b'0' * 625 + self.request)
        with mock.patch.object(tool, 'derive', return_value=self.context), \
             mock.patch.object(tool, 'checked_history'), \
             mock.patch.object(tool, 'admit_certificate', return_value={'tbs': b'tbs'}), \
             mock.patch.object(tool, 'public_bindings', return_value=(2, 3)), \
             mock.patch.object(tool.bridge, 'build_v3p1', return_value=b'plan'), \
             mock.patch.object(tool.bridge, 'finalize_v3p1', return_value=final), \
             mock.patch.object(tool.bridge, 'build_request_bound_v3q1'):
            return tool.prepare(self.stage, self.cohort, self.root / 'context.json', self.out, self.exporter)

    def test_writes_private_r0_source_and_pins(self):
        result = self.prepare()
        self.assertFalse(result['live_state_authenticated'])
        self.assertEqual(set(p.name for p in self.out.iterdir()), {
            'credential.der', 'holder.pem', 'issuer-modulus.bin', 'config.bin',
            'membership.json', 'parameters.json', 'source-receipt.json'})
        member = json.loads((self.out / 'membership.json').read_bytes())
        self.assertEqual(member['active_root'], 1)
        self.assertEqual(member['active_siblings'], [0] * 10)
        for p in self.out.iterdir():
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads((self.out / 'parameters.json').read_bytes())['now'], 100)

    def test_rejects_membership_schedule_mismatch_before_writing(self):
        self.member['roots'][1] = 55
        self.save(self.cohort / 'membership.json', tool.encoded(self.member))
        with self.assertRaisesRegex(ValueError, 'membership'):
            self.prepare()
        self.assertEqual(list(self.out.iterdir()), [])

    def test_rejects_finalized_root_mismatch_before_writing(self):
        raw = bytearray(self.config)
        raw[363] = 9
        self.save(self.stage / 'config.bin', bytes(raw))
        self.report['account_sha256'][0] = tool.digest(bytes(raw))
        self.save(self.stage / 'stage-report.json', tool.encoded(self.report))
        with self.assertRaisesRegex(ValueError, 'context'):
            self.prepare()
        self.assertEqual(list(self.out.iterdir()), [])

    def test_rejects_action_request_mismatch_before_writing(self):
        with self.assertRaisesRegex(ValueError, 'action'):
            self.prepare(dict(exporter_sha256=tool.digest(self.exporter.read_bytes()),
                              v3f1=b'0' * 625 + b'wrong'))
        self.assertEqual(list(self.out.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
