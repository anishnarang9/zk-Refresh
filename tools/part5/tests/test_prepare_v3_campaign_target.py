import copy
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

from tools.part5 import prepare_v3_campaign_target as tool
from harness.tests import test_queue_v3_local_campaign_transition as history_tests


class CampaignTargetTests(unittest.TestCase):
    def test_only_level_four_and_root_may_change(self):
        original = dict(root='1', siblings=['0'] * 10, actionHash='3', signature=['4'])
        target = copy.deepcopy(original)
        target['root'], target['siblings'][4] = '2', '9'
        tool.one_sibling_delta(original, target)
        for label, mutate in (
            ('wrong level', lambda v: v['siblings'].__setitem__(2, '9')),
            ('signature', lambda v: v['signature'].__setitem__(0, '5')),
            ('action', lambda v: v.__setitem__('actionHash', '7')),
            ('unchanged root', lambda v: v.__setitem__('root', '1')),
            ('short path', lambda v: v.__setitem__('siblings', ['1'])),
        ):
            changed = copy.deepcopy(target)
            mutate(changed)
            with self.subTest(label=label), self.assertRaises(ValueError):
                tool.one_sibling_delta(original, changed)

    def test_complete_worker_fields_and_publics_required(self):
        worker = types.SimpleNamespace(INPUT_FIELDS=[(k, 1) for k in tool.PUBLIC_NAMES] + [('siblings', 10), ('rest', 735)])
        fields = list(range(6)) + [0] * 745
        response = b'V3I1' + bytes(459) + b''.join(x.to_bytes(32, 'little') for x in fields)
        decoded = tool.decode_worker(worker, response, list(range(6)), 100)
        self.assertEqual(len(decoded['rest']), 735)
        for altered, expected in ((response[:-1], list(range(6))),
                                  (response, [1] * 6),
                                  (response[:-32] + (100).to_bytes(32, 'little'), list(range(6)))):
            with self.assertRaises(ValueError):
                tool.decode_worker(worker, altered, expected, 100)

    def test_signed_history_cannot_skip_or_mutate_a_checkpoint(self):
        inputs = history_tests.CampaignHistoryTests().signed_chain(10)
        self.assertEqual(len(tool.checked_history(*inputs)), 11)
        for mutation in ('remove', 'signature', 'root', 'count'):
            altered = copy.deepcopy(inputs)
            if mutation == 'remove':
                altered[0]['checkpoints'].pop(4)
            elif mutation == 'signature':
                altered[0]['checkpoints'][7]['publisher']['signature'][0] ^= 1
            elif mutation == 'root':
                altered[3]['checkpoints'][2]['root'] = '00' * 32
            else:
                altered[3]['target_count'] = 1
            with self.subTest(mutation=mutation), self.assertRaises(Exception):
                tool.checked_history(*altered)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.paths = {name: self.root / name for name in ('source', 'base', 'stage_root', 'transition_root', 'cohort_root', 'output')}
        for path in self.paths.values():
            path.mkdir(mode=0o700)
        self.args = dict(self.paths, context_path=self.root / 'context.json', generation=1,
                         source_receipt_sha256='a' * 64, base_receipt_sha256='b' * 64,
                         transition_report_sha256='c' * 64)

    def save(self, path, raw):
        path.write_bytes(raw)
        path.chmod(0o600)

    def test_generation_requires_integer_in_declared_range(self):
        for value in (0, 11, True, '1', 1.0):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'generation'):
                tool.prepare(**dict(self.args, generation=value))

    def test_source_receipt_hash_and_private_permissions_enforced(self):
        path = self.paths['source'] / 'source-receipt.json'
        self.save(path, b'{}')
        with self.assertRaises(ValueError):
            tool.prepare(**self.args)
        self.args['source_receipt_sha256'] = tool.digest(b'{}')
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            tool.prepare(**self.args)
        self.assertEqual(list(self.paths['output'].iterdir()), [])

    def test_output_must_be_private_empty_and_canonical(self):
        out = self.paths['output']
        out.chmod(0o755)
        with self.assertRaises(ValueError):
            tool.prepare(**self.args)
        out.chmod(0o700)
        self.save(out / 'existing', b'x')
        with self.assertRaises(ValueError):
            tool.prepare(**self.args)
        (out / 'existing').unlink()
        link = self.root / 'alias'
        link.symlink_to(out, target_is_directory=True)
        with self.assertRaises(ValueError):
            tool.prepare(**dict(self.args, output=link))

    def test_frozen_worker_bridge_and_relation_sources_match(self):
        helper = tool.load_preparer()
        worker = helper.load_worker()
        helper._module(tool.SUPPORT / 'prepare_v3_relation.py', helper.RELATION_HELPER_SHA)
        self.assertEqual(sum(count for _, count in worker.INPUT_FIELDS), 751)

    def synthetic_fixture(self):
        history, context, plan, report, staged = history_tests.CampaignHistoryTests().signed_chain(2)
        source, base, stage, transition, cohort = [self.paths[k] for k in
            ('source', 'base', 'stage_root', 'transition_root', 'cohort_root')]
        helper = tool.load_preparer()
        context.update(issuer_hash=f'{2:064x}', policy_id=f'{3:064x}')
        context['initial_allocations']['root_sequence_sha256'] = 'e' * 64
        roots = [int(x, 16) for x in context['root_sequence']]
        member = dict(roots=roots, holder_siblings=[[0] * 4 + [i] + [0] * 5 for i in range(11)])
        for name in ('program', 'genesis', 'creator', 'nonce', 'recipient'):
            plan[name] = [0] * 32
        plan.update(root=list(roots[0].to_bytes(32, 'big')), issuer_hash=list((2).to_bytes(32, 'big')),
                    policy_id=list((3).to_bytes(32, 'big')), deadline=200, payload=[1])
        params = {k: bytes(plan[k]).hex() for k in ('genesis', 'creator', 'nonce', 'recipient')}
        params.update(program_id=bytes(plan['program']).hex(), payload='01', request_type=1,
                      deadline=200, now=100, exporter_sha256='d' * 64)
        membership = dict(slot=0, issuer_hash=2, policy_hash=3, active_root=roots[0], active_siblings=member['holder_siblings'][0])
        config = bytearray(381)
        config[:8] = b'DYNCONF3'
        config[136:168] = bytes(plan['policy_id'])
        config[332:364] = bytes(plan['root'])
        config = bytes(config)
        stage_history = dict(history, checkpoints=history['checkpoints'][:1])
        staged.update(schema='part5-v3-campaign-stage-v1', passed=True, training_only=True,
            registry_history_authenticated=True, allocation_history_authenticated=True,
            upstream_source_authentication=True, upstream_publisher_authentication=True,
            application_effect=False, proof_created=False, transactions=[dict(scenario='v3-bind-head', blockTime=100)],
            plan_sha256=tool.digest(tool.encoded(plan)), signed_history_sha256=tool.digest(history_tests.compact(stage_history)),
            initial_allocations_sha256=tool.digest(tool.encoded(context['initial_allocations'])))
        # Only admission/tree arithmetic and the worker transport are synthetic.
        # The complete source/publisher signature verification remains real.
        commitments = tool.checked_history(history, context, plan, report, staged)
        def accounts(index):
            sd, pd = commitments[index]
            observation = history['checkpoints'][index]['source']['observation']
            issuer, head = bytearray(374), bytearray(280)
            root = bytes.fromhex(context['root_sequence'][index])
            seq, version = (index + 1).to_bytes(8, 'big'), index.to_bytes(8, 'big')
            issuer[:8], head[:8] = b'DYNISS03', b'DYNHEAD3'
            issuer[140:172], issuer[172], issuer[357] = bytes(plan['source']), 1, 1
            issuer[173:181], issuer[181:213] = seq, sd
            issuer[213:221] = observation['observed_at'].to_bytes(8, 'big', signed=True)
            issuer[221:229] = observation['valid_until'].to_bytes(8, 'big', signed=True)
            issuer[229:261], issuer[261:269], issuer[269:277], issuer[277:309] = root, version, seq, sd
            head[72:104], head[104:112], head[112:144] = bytes(plan['publisher']), seq, pd
            head[144:176] = commitments[index - 1][1] if index else bytes(32)
            head[176:208], head[208:216], head[216:224], head[224:256] = root, version, seq, sd
            cfg = bytearray(config)
            cfg[332:364], cfg[364:372] = root, version
            return [bytes(cfg), bytes(issuer), bytes(head), b'request', b'queue']
        for directory, row, index in ((stage, staged, 0), (transition, report, 2)):
            values = accounts(index)
            row['account_sha256'] = [tool.digest(v) for v in values]
            for name, value in zip(('config', 'issuer', 'head', 'request', 'queue'), values):
                self.save(directory / (name + '.bin'), value)
        for i in range(11):
            self.save(cohort / f'credential-{i}.der', b'c' * 952)
        self.save(cohort / 'issuer-modulus.bin', b'm' * 256)
        self.save(cohort / 'cohort-receipt.json', b'{}')
        self.save(cohort / 'membership.json', tool.encoded(member))
        self.save(self.root / 'context.json', tool.encoded(context))
        self.save(stage / 'plan.json', tool.encoded(plan))
        self.save(stage / 'signed-history.json', history_tests.compact(stage_history))
        self.save(stage / 'initial-allocations.json', tool.encoded(context['initial_allocations']))
        self.save(stage / 'stage-report.json', tool.encoded(staged))
        report.update(schema='part5-v3-campaign-transition-v1', passed=True,
            registry_history_authenticated=True, allocation_history_authenticated=True,
            request_unconsumed=True, application_effect=False,
            stage_report_sha256=tool.digest(tool.encoded(staged)), stage_plan_sha256=tool.digest(tool.encoded(plan)),
            context_sha256=tool.digest(tool.encoded(context)), base_root=context['root_sequence'][0],
            current_root=context['root_sequence'][2], root_sequence_sha256='e' * 64,
            transactions=[dict(err=None)] * 6, signed_history_sha256=tool.digest(history_tests.compact(history)))
        self.save(transition / 'signed-history.json', history_tests.compact(history))
        self.save(transition / 'transition-report.json', tool.encoded(report))
        self.args['transition_report_sha256'] = tool.digest(tool.encoded(report))
        raw = dict(zip(tool.SOURCE_BOUNDS, (b'c' * 952, b'holder', b'm' * 256, config,
                                           tool.encoded(membership), tool.encoded(params))))
        for name, value in raw.items():
            self.save(source / name, value)
        src = dict(schema='part5-v3-campaign-training-source-v1', training_only=True, application_effect=False,
            live_state_authenticated=False, proof_created=False, context_sha256=tool.digest(tool.encoded(context)),
            cohort_receipt_sha256=tool.digest(b'{}'), cohort_membership_sha256=tool.digest(tool.encoded(member)),
            root_sequence_sha256='e' * 64, stage_report_sha256=tool.digest(tool.encoded(staged)),
            stage_plan_sha256=staged['plan_sha256'], signed_history_sha256=staged['signed_history_sha256'],
            initial_allocations_sha256=staged['initial_allocations_sha256'], exporter_sha256='d' * 64,
            source_sha256={name: tool.digest(value) for name, value in raw.items()})
        self.save(source / 'source-receipt.json', tool.encoded(src))
        self.args['source_receipt_sha256'] = tool.digest(tool.encoded(src))
        def build(der, modulus, holder, action, member):
            return (b'V3Q1' + der + raw['issuer-modulus.bin'] + action + b's' * 256 + bytes(2)
                    + b''.join(v.to_bytes(32, 'little') for v in member['active_siblings'])
                    + b''.join(v.to_bytes(32, 'little') for v in (member['active_root'], 2, 3)))
        layout = helper.load_worker().INPUT_FIELDS
        def response(q):
            values = dict(zip(tool.PUBLIC_NAMES, [int.from_bytes(q[1822:1854], 'little'), 2, 10, 20, 4, 3]))
            values['siblings'] = [int.from_bytes(q[i:i+32], 'little') for i in range(1502, 1822, 32)]
            fields = []
            for name, count in layout:
                value = values.get(name, [0] * count)
                fields.extend([value] if type(value) is int else value)
            return b'V3I1' + bytes(459) + b''.join(x.to_bytes(32, 'little') for x in fields)
        worker = types.SimpleNamespace(INPUT_FIELDS=layout, build=response)
        q0 = build(raw['credential.der'], 0, None, (4).to_bytes(32, 'big'), membership)
        expected = [roots[0], 2, 10, 20, 4, 3]
        inp = tool.decode_worker(worker, response(q0), expected, helper.FR)
        relation = helper._module(tool.SUPPORT / 'prepare_v3_relation.py', helper.RELATION_HELPER_SHA)
        coordinates, internal = relation.coordinates(types.SimpleNamespace(FIELDS=layout))
        artifacts = {'request.bin': q0, 'summary.bin': bytes(459), 'input.json': tool.encoded(inp),
                     'public.json': tool.encoded([str(v) for v in expected]),
                     'input-coordinates.bin': coordinates, 'internal-coordinate.bin': internal}
        for name, value in artifacts.items():
            self.save(base / name, value)
        receipt = dict(schema='v3-request-bound-training-input-v1', training_only=True, proof_created=False,
            bridge_sha256=helper.BRIDGE_SHA, worker_sha256=helper.WORKER_SHA, exporter_sha256='d' * 64,
            **{key + '_sha256': tool.digest(raw[name]) for key, name in
               (('membership', 'membership.json'), ('parameters', 'parameters.json'), ('config', 'config.bin'))},
            artifact_sha256={name: tool.digest(value) for name, value in artifacts.items()})
        self.save(base / 'training-receipt.json', tool.encoded(receipt))
        self.args['base_receipt_sha256'] = tool.digest(tool.encoded(receipt))
        return context, worker, build

    def run_synthetic(self, context, worker, build):
        helper = tool.load_preparer()
        helper.load_worker = lambda: worker
        with mock.patch.object(tool, 'load_preparer', return_value=helper), \
             mock.patch.object(tool, 'derive', return_value=context), \
             mock.patch.object(tool, 'admit_certificate', return_value=dict(not_before=10, not_after=20)), \
             mock.patch.object(tool, 'public_bindings', return_value=(2, 3)), \
             mock.patch.object(tool.bridge, 'build_v3q1', side_effect=build):
            return tool.prepare(**self.args)

    def test_synthetic_complete_target_and_preserved_request_queue(self):
        inputs = self.synthetic_fixture()
        result = self.run_synthetic(*inputs)
        self.assertEqual(result['generation'], 1)
        self.assertEqual(result['signed_target_count'], 2)
        self.assertFalse(result['live_state_authenticated'])
        self.assertEqual(set(p.name for p in self.paths['output'].iterdir()),
                         set(tool.ARTIFACT_BOUNDS) | {'training-receipt.json'})
        for p in self.paths['output'].iterdir():
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)

    def test_mutated_queue_rejected_even_with_updated_report_hash(self):
        inputs = self.synthetic_fixture()
        transition = self.paths['transition_root']
        self.save(transition / 'queue.bin', b'changed queue')
        helper = tool.load_preparer()
        report = helper._json((transition / 'transition-report.json').read_bytes())
        report['account_sha256'][4] = tool.digest(b'changed queue')
        self.save(transition / 'transition-report.json', tool.encoded(report))
        self.args['transition_report_sha256'] = tool.digest(tool.encoded(report))
        with self.assertRaisesRegex(ValueError, 'preserved'):
            self.run_synthetic(*inputs)
        self.assertEqual(list(self.paths['output'].iterdir()), [])

    def test_generation_beyond_signed_history_rejected(self):
        inputs = self.synthetic_fixture()
        self.args['generation'] = 3
        with self.assertRaisesRegex(ValueError, 'transition'):
            self.run_synthetic(*inputs)
        self.assertEqual(list(self.paths['output'].iterdir()), [])

    def test_changed_training_helper_is_rejected(self):
        original = Path.read_bytes
        target = tool.SUPPORT / 'prepare_v3_request_bound_training.py'
        def changed(path):
            return b'changed' if path == target else original(path)
        with mock.patch.object(Path, 'read_bytes', changed), self.assertRaisesRegex(ValueError, 'frozen'):
            tool.load_preparer()


if __name__ == '__main__':
    unittest.main()
