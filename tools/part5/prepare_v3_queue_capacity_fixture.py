#!/usr/bin/env python3
"""Prepare a private, normally finalized 65-request capacity fixture.

Three explicit phases: stage under an external owner, proofs offline and serial,
and clone under a separate external owner after preparation has exited. No phase seeds queue bytes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
from harness.tests import queue_v3_local_queue_capacity_negative as capacity
from tools.part5 import prepare_v3_heldout_source as source
from tools.part5 import prepare_v3_heldout_proof as proof
from tools.part5 import build_v3_request_bound_anchor_packet as packet_builder
from tools.part5.credential_profile import admit_certificate, public_bindings
from harness.tests.queue_v3_clone_ledger import inventory, stale_admin_socket

SCHEMA = 'part5-v3-queue-capacity-producer-config-v1'
PROOF_SCHEMA = 'part5-v3-queue-capacity-full-proof-v1'
FIXTURE_SCHEMA = 'part5-v3-queue-capacity-fixture-v1'
PREPARATION_SCHEMA = 'part5-v3-queue-capacity-preparation-rust-v1'
MODE = 'campaign-coalesced-full-k0'
PACKAGE_FIELDS = ('package_digest', 'setup_manifest_path', 'setup_manifest_sha256',
                  'package_check_path', 'package_check_sha256', 'r1cs_path',
                  'wasm_path', 'profile_path', 'input_map_path', 'input_map_sha256')
REFERENCE_FIELDS = {'path', 'sha256'}
COUNTS = {'proofs': 1, 'positive_checks': 1, 'altered_public_checks': 6,
          'cross_root_checks': 0, 'ordinary_checks': 7}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def ref(path):
    raw, digest = capacity.execute.stage.snapshot_generated(Path(path), 1024**3)
    return {'path': str(path), 'sha256': digest}


def read(reference, cap=1024*1024, private=True):
    require(type(reference) is dict and set(reference) == REFERENCE_FIELDS, 'exact file reference required')
    return capacity._read_pinned(reference['path'], reference['sha256'], cap,
                                 'capacity fixture artifact', private=private)


def doc(reference, cap=1024*1024):
    value = capacity.execute.base.decode_json(read(reference, cap))
    require(type(value) is dict, 'capacity fixture JSON object required')
    return value


def write(path, value):
    capacity.execute.base.write_new(Path(path), value)
    return ref(path)


def single_full_packet(template, final_spec, application_stage, freeze_sha256,
                       history_sha256, root_schedule_sha256):
    """Use the existing proof binary's genuine zero-update single-Full mode."""
    require(final_spec.get('root_version') == 0
            and application_stage.get('base_root') == application_stage.get('near_root'),
            'zero-update single Full requires one unchanged root')
    require(all(name in template for name in PACKAGE_FIELDS), 'complete frozen package template required')
    for digest in (freeze_sha256, history_sha256, root_schedule_sha256):
        capacity._hash(digest, 'zero-update packet pin')
    return {**{name: template[name] for name in PACKAGE_FIELDS},
            'schema': 'credential-v3-cumulative-coalesced-request-v1',
            'synthetic_only': False, 'application_verified': False,
            'cohort': 'cumulative-training-v1', 'update_count': 0,
            'proof_source_identity': packet_builder.proof_source_identity(),
            'application_stage': application_stage,
            'freeze_receipt_sha256': freeze_sha256,
            'history_receipt_sha256': history_sha256,
            'root_schedule_sha256': root_schedule_sha256, 'final': dict(final_spec)}


def check_proof_receipt(receipt, row, wire):
    require(type(receipt) is dict and receipt.get('schema') == PROOF_SCHEMA
            and receipt.get('request_address') == row.get('request_address')
            and receipt.get('request_sha256') == row.get('request_sha256')
            and receipt.get('action_sha256') == row.get('action_sha256')
            and receipt.get('full_wire_verified') is True
            and receipt.get('complete_relation_checked') is True
            and receipt.get('mode') == MODE,
            'exact request/action-bound independently checked Full receipt required')
    require(len(wire) == 448 and wire[128:160].hex() == row['action_sha256']
            and receipt.get('wire', {}).get('sha256') == hashlib.sha256(wire).hexdigest(),
            'Full receipt must bind the complete wire and action')
    for field in ('witness', 'input', 'public', 'packet', 'proof_report', 'wire'):
        require(type(receipt.get(field)) is dict and set(receipt[field]) == REFERENCE_FIELDS,
                'complete witness/proof artifact provenance required')
    return True


def check_single_full_report(report, packet_pin, packet, binary_sha256):
    require(report.get('schema') == 'credential-v3-cumulative-proof-v1'
            and report.get('passed') is True and report.get('mode') == MODE
            and report.get('update_count') == 0 and report.get('counts') == COUNTS
            and report.get('packet_sha256') == packet_pin['sha256']
            and report.get('application_stage_pins') == packet['application_stage']
            and report.get('proof_binary_sha256') == binary_sha256
            and report.get('package_digest') == packet['package_digest']
            and report.get('setup_manifest_sha256') == packet['setup_manifest_sha256']
            and report.get('application_verified') is False
            and report.get('setup_executed') is False
            and report.get('private_cache_persisted') is False,
            'single unchanged-root Full proof report or setup identity differs')
    return True



def stage_transaction_specs(plan, stage, request, program):
    """Reconstruct normal request setup instructions from the pinned plan."""
    b58 = capacity.execute.base.b58
    key = capacity.execute.base.key
    nonce, issuer, recipient, creator = (bytes(plan[name]) for name in
                                        ('nonce', 'issuer_hash', 'recipient', 'creator'))
    payload = bytes(plan['payload'])
    deadline = plan['deadline']
    require(all(len(value) == 32 for value in (nonce, issuer, recipient, creator))
            and type(deadline) is int and 0 < deadline < 1 << 63
            and len(payload) <= 1024, 'bounded exact capacity request plan required')
    signer = b58(creator)
    create_accounts = [(signer, True, True), (stage['config'], False, False),
                       (stage['issuer'], False, False), (request, False, True),
                       ('11111111111111111111111111111111', False, False)]
    edit_accounts = [(signer, True, False), (stage['config'], False, False),
                     (request, False, True)]
    create = (b'\x51\x04' + nonce + issuer + recipient + (1).to_bytes(2, 'big')
              + deadline.to_bytes(8, 'big') + len(payload).to_bytes(2, 'big') + b'\x02')
    specs = [('create', create, create_accounts)]
    for offset in range(0, len(payload), 512):
        chunk = payload[offset:offset + 512]
        data = b'\x51\x06' + offset.to_bytes(2, 'big') + len(chunk).to_bytes(2, 'big') + chunk
        specs.append(('upload', data, edit_accounts))
    metas = b'\x51\x08\x00\x02'
    for address in (request, stage['queue']):
        metas += key(address) + b'\x02' + key(program)
    specs.extend([('upload-metas', metas, edit_accounts),
                  ('finalize', b'\x51\x05', edit_accounts)])
    return specs


def _new_dir(path):
    path = Path(path)
    require(path.is_absolute() and path.parent.resolve(strict=True) == path.parent
            and not path.exists() and not path.is_symlink(), 'fresh canonical capacity directory required')
    path.mkdir(mode=0o700)
    return path


def _raw_write(path, raw):
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def signed_validity(config, deadline):
    """Derive the only permitted expiry from pinned signed certificate bytes."""
    source = config['credential_source']
    raw = read(source['credential'], 952)
    modulus = read(source['issuer_modulus'], 256)
    require(len(modulus) == 256, 'exact RSA2048 issuer modulus required')
    parsed = admit_certificate(raw, int.from_bytes(modulus, 'big'))
    not_after = parsed['not_after']
    if 'cohort_manifest' in config:
        cohort = doc(config['cohort_manifest'])
        issuer, policy = public_bindings(parsed, int.from_bytes(modulus, 'big'))
        matches = [row for row in cohort.get('certificates', [])
                   if row.get('credential_sha256') == hashlib.sha256(raw).hexdigest()]
        require(cohort.get('schema') == 'credential-v3-heldout-issuance-cohort-v1'
                and len(matches) == 1
                and all(matches[0].get(key) == value for key, value in {
                    'variant': parsed['variant'], 'not_before_unix': parsed['not_before'],
                    'not_after_unix': not_after, 'issuer_hash': str(issuer),
                    'policy_hash': str(policy)}.items()),
                'signed credential must match exact pinned cohort receipt')
    require(type(deadline) is int and deadline <= not_after,
            'request deadline exceeds signed credential validity')
    return not_after


def prepare_proofs(config, config_pin):
    """65 serial genuine single-Full proofs; never keeps a validator running."""
    from tools.part5.finalize_v3_queue_capacity_negative import check_monitor
    prepared = doc(config['preparation_report'])
    require(prepared.get('schema') == PREPARATION_SCHEMA and prepared.get('passed') is True
            and prepared.get('request_count') == 65 and prepared.get('queue_empty') is True
            and len(prepared.get('inputs', [])) == 65, '65 normally finalized prepared requests required')
    require(prepared.get('credential_not_after') == signed_validity(config, prepared['request_deadline']),
            'offline proofs must bind pinned signed credential validity')
    stage_config = doc(config['stage_config'])
    status = doc(config['stage_status'])
    require(status.get('status') == 'candidate_verified_pending_external_finalization'
            and status.get('candidate') == config['preparation_report']
            and status.get('config_ref') == config['stage_config'], 'stopped verified preparation owner required')
    check_monitor(doc(config['stage_monitor']), doc(config['stage_invocation']),
                  config['stage_config'], Path(__file__), stage_config, staging=True)
    limit = config['proof_owner_limit_seconds']
    require(type(limit) is int and 1 <= limit <= 43200
            and limit == prepared['proof_owner_limit_seconds'], 'predeclared proof owner budget required')
    require(time.time()+limit+3600 < prepared['request_deadline'] <= prepared['credential_not_after'],
            'request/credential validity cannot cover declared offline and fill owners')
    baseline = doc(config['baseline_stage_report'])
    stage_root = Path(config['baseline_stage_report']['path']).parent
    config_bytes = read({'path':str(stage_root/'config.bin'), 'sha256':baseline['account_sha256'][0]},4096)
    template = doc(config['template'])
    product = proof._check_product_inputs(
        config['freeze']['path'],config['freeze']['sha256'],config['template']['path'],config['template']['sha256'],
        template['setup_manifest_path'],str(Path(template['setup_manifest_path']).parent/'ordinary.vk'),
        config['proof_runner']['path'],config['adapter']['path'],config['witness_js']['path'],
        config['relation_checker']['path'],config['node']['path'],config['node']['sha256'],
        config['bounded_supervisor']['path'],config['bounded_supervisor']['sha256'])
    for name in ('proof_runner','adapter','exporter','node','witness_js','relation_checker','bounded_supervisor'):
        read(config[name], 128*1024**2 if name in ('proof_runner','adapter','node') else 64*1024**2,
             private=False)
    require(config['proof_runner']['sha256'] == product['proof_runner_sha256']
            and config['adapter']['sha256'] == product['adapter_sha256'], 'same frozen proof/adapter binaries required')
    require(product['proof_source_identity'] == template.get('proof_source_identity',product['proof_source_identity']),
            'current/frozen proof source identity mismatch')
    material = {name:read(reference,65536) for name,reference in config['credential_source'].items()}
    require(set(material) == {'credential','holder','issuer_modulus','membership'}, 'exact credential source pins required')
    output = _new_dir(config['output_dir'])
    supervision = output/'supervision'
    supervision.mkdir(mode=0o700)
    helper = source.load_preparer()
    receipts, inputs = [], []
    proof_count = config.get('proof_count', 65)
    require(type(proof_count) is int and proof_count in (1, 65),
            'only bounded one-proof pilot or complete 65-proof run allowed')
    started = time.monotonic()
    for index,row in enumerate(prepared['inputs'][:proof_count]):
        require(time.monotonic()-started < limit, 'capacity offline proof deadline')
        require(time.time()+3600 < prepared['request_deadline'], 'capacity requests approaching fill deadline')
        work = output/f'proof-{index:02}'
        work.mkdir(mode=0o700)
        src, training = work/'source', work/'training'
        src.mkdir(mode=0o700)
        training.mkdir(mode=0o700)
        plan = doc(row['plan'],8192)
        params = {name:bytes(plan[key]).hex() for name,key in
                  [('program_id','program'),('genesis','genesis'),('creator','creator'),
                   ('nonce','nonce'),('recipient','recipient')]}
        params.update(payload=bytes(plan['payload']).hex(),request_type=1,deadline=plan['deadline'],
                      now=row['finalization']['block_time'],exporter_sha256=config['exporter']['sha256'])
        require(params['deadline'] == prepared['request_deadline'], 'common predeclared request deadline required')
        for name,raw in {'credential.der':material['credential'],'holder.pem':material['holder'],
                         'issuer-modulus.bin':material['issuer_modulus'],'membership.json':material['membership'],
                         'config.bin':config_bytes,'parameters.json':proof.encoded(params)}.items():
            _raw_write(src/name,raw)
        helper.prepare(src,training,Path(config['exporter']['path']))
        public = capacity.execute.base.decode_json((training/'public.json').read_bytes())
        require(type(public) is list and len(public)==6
                and f'{int(public[4]):064x}' == row['action_sha256']
                and int(public[3]) == prepared['credential_not_after'], 'training source action/validity differs')
        bounded = {}
        commands = {
            'witness':([product['node'],product['witness_js'],training],proof.WITNESS_LIMITS),
            'relation':([sys.executable,'-B',product['relation_checker'],'check',training],proof.RELATION_LIMITS)}
        for label,(command,bounds) in commands.items():
            bounded[label]=proof._run_bounded(product['supervisor'],output,supervision,f'{index:02}-{label}',command,limits=bounds)
        require((training/'preflight.bin').read_bytes() == b'V3R1'+(784796).to_bytes(4,'little')
                +(793681).to_bytes(4,'little')+(4257583).to_bytes(4,'little'), 'complete witness relation preflight required')
        final = {'root_version':0,'issuer_version':1,'policy_version':1,'allocation_epoch':1}
        for kind,name in [('wtns','output.wtns'),('input','input.json'),('public','public.json')]:
            pin = ref(training/name)
            final.update({kind+'_path':pin['path'],kind+'_sha256':pin['sha256']})
        app = {'program_id':prepared['program'],'genesis_hash':prepared['genesis'],
               'loaded_elf_sha256':prepared['loaded_program']['elf_sha256'],
               'base_stage_report_sha256':config['preparation_report']['sha256'],
               'base_config_sha256':baseline['account_sha256'][0],
               'finalized_request_sha256':row['request_sha256'],'request_address':row['request_address'],
               'base_finalized_slot':row['finalized_account_slot'],
               'near_state_report_sha256':config['preparation_report']['sha256'],
               'near_config_sha256':baseline['account_sha256'][0],
               'near_finalized_slot':row['finalized_account_slot'],
               'base_root':public[0],'near_root':public[0],'action_hash':public[4]}
        packet = single_full_packet(template,final,app,config['freeze']['sha256'],
                                   config['preparation_report']['sha256'],hashlib.sha256(proof.encoded([public[0]])).hexdigest())
        packet_pin = write(work/'packet.json',packet)
        proofs = work/'full-proof'
        bounded['proof']=proof._run_bounded(product['supervisor'],output,supervision,f'{index:02}-full',
            [product['proof_runner'],MODE,packet_pin['path'],packet_pin['sha256'],proofs],limits=proof.FULL_LIMITS)
        proof_pin = ref(proofs/'proof-report.json')
        proof_report = doc(proof_pin)
        check_single_full_report(proof_report,packet_pin,packet,product['proof_runner_sha256'])
        bounded['adapter']=proof._run_bounded(product['supervisor'],output,supervision,f'{index:02}-adapter',
            [product['adapter'],'private_campaign_final_wire_passes_adapter_and_program_host','--exact','--ignored','--test-threads=1'],
            env={'M2_V3_CAMPAIGN_MODE':MODE,'M2_V3_CAMPAIGN_FINAL_FIXTURE':str(training),
                 'M2_V3_CAMPAIGN_PACKET':packet_pin['path'],'M2_V3_CAMPAIGN_PACKET_SHA256':packet_pin['sha256'],
                 'M2_V3_CAMPAIGN_PROOFS':str(proofs),
                 'M2_V3_CAMPAIGN_FINAL_RECEIPT_SHA256':ref(training/'training-receipt.json')['sha256'],
                 'M2_V3_CAMPAIGN_REPORT_SHA256':proof_pin['sha256']},limits=proof.ADAPTER_LIMITS)
        wire_pin=ref(training/(MODE+'-solana-wire.bin'))
        receipt={'schema':PROOF_SCHEMA,'mode':MODE,'request_address':row['request_address'],
                 'request_sha256':row['request_sha256'],'action_sha256':row['action_sha256'],
                 'wire':wire_pin,'witness':ref(training/'output.wtns'),'input':ref(training/'input.json'),
                 'public':ref(training/'public.json'),'packet':packet_pin,'proof_report':proof_pin,
                 'training_receipt':ref(training/'training-receipt.json'),
                 'full_wire_verified':True,'complete_relation_checked':True,'bounded':bounded,
                 'tools':{name:config[name] for name in ('proof_runner','adapter','node','witness_js','relation_checker')},
                 'freeze':config['freeze'],'preparation_report':config['preparation_report']}
        check_proof_receipt(receipt,row,read(wire_pin,448))
        receipt_pin=write(work/'proof-receipt.json',receipt)
        receipts.append(receipt_pin)
        inputs.append({name:row[name] for name in ('request_address','action_sha256','request_account','request_sha256')}
                      | {'proof_receipt':receipt_pin['path'],'proof_receipt_sha256':receipt_pin['sha256'],
                         'full_wire':wire_pin['path'],'full_wire_sha256':wire_pin['sha256']})
    if proof_count == 1:
        receipt = {'schema': 'part5-v3-queue-capacity-one-proof-pilot-v1',
                   'config_ref': config_pin, 'preparation_report': config['preparation_report'],
                   'proof_receipts': receipts, 'proof_wall_seconds': time.monotonic()-started,
                   'application_effect': False}
        write(output/'pilot-receipt.json', receipt)
        return receipt
    return publish_full_fixture(output, config, config_pin, prepared, stage_config,
                                baseline, receipts, inputs, started, limit)


def publish_full_fixture(output, config, config_pin, prepared, stage_config, baseline,
                         receipts, inputs, started, limit):
    """Publish a full fixture only after every requested Full proof exists."""
    require(len(prepared['inputs']) == len(receipts) == len(inputs) == 65,
            '65 complete proofs required to publish capacity fixture')
    require(all(type(pin) is dict and set(pin) == REFERENCE_FIELDS for pin in receipts)
            and len({(pin['path'], pin['sha256']) for pin in receipts}) == 65
            and len({row['request_address'] for row in inputs}) == 65
            and all(row['proof_receipt'] == pin['path']
                    and row['proof_receipt_sha256'] == pin['sha256']
                    for row, pin in zip(inputs, receipts)),
            '65 distinct proofs bound to distinct requests required')
    fixture={'schema':FIXTURE_SCHEMA,'program':prepared['program'],'genesis':prepared['genesis'],
             'genesis_sha256':config['genesis_sha256'],'elf_sha256':prepared['loaded_program']['elf_sha256'],
             'stage_report':config['baseline_stage_report'],'signers':config['signers'],'inputs':inputs,
             'request_finalizations':[{'request_address':row['request_address'],
                 'signature':row['finalization']['signature'],'slot':row['finalization']['slot']} for row in prepared['inputs']]}
    fixture_pin=write(output/'fixture-manifest.json',fixture)
    receipt={'schema':'part5-v3-queue-capacity-prepared-fixture-v1','config_ref':config_pin,
             'fixture_manifest':fixture_pin,'preparation_report':config['preparation_report'],
             'stage_config':config['stage_config'],'stage_status':config['stage_status'],
             'stage_monitor':config['stage_monitor'],'stage_invocation':config['stage_invocation'],
             'prepared_ledger':stage_config['ledger'],'freeze':config['freeze'],
             'proof_receipts':receipts,'proof_wall_seconds':time.monotonic()-started,
             'stage_wall_seconds':doc(config['stage_monitor'])['duration_seconds'],
             'proof_owner_limit_seconds':limit,'request_deadline':prepared['request_deadline']}
    write(output/'preparation-receipt.json',receipt)
    return receipt


def verify_stage(rpc, report, config, output, loaded, runner_pid):
    """Bind the Rust preparation candidate before its owner is stopped."""
    from harness.tests import queue_v3_capacity_runtime as runtime
    require(report.get('schema') == PREPARATION_SCHEMA and report.get('passed') is True
            and report.get('config_ref') == {'path': config['rust_config_path'],
                                              'sha256': config['rust_config_sha256']}
            and report.get('request_count') == 65 and report.get('queue_empty') is True
            and report.get('request_preparation_effect') is True
            and report.get('application_effect') is False
            and report.get('request_deadline') == config['request_deadline']
            and report.get('credential_not_after') == config['credential_not_after']
            and report.get('stage_report_sha256') == config['baseline_stage_report']['sha256']
            and report.get('program') == config['expected_program']
            and report.get('genesis') == config['expected_genesis'],
            'exact normal capacity preparation candidate required')
    runtime.check_rust_loaded_observation(report.get('loaded_program'), loaded,
                                          config['expected_program'], config['expected_genesis'],
                                          config['expected_elf_sha256'])
    rows = report.get('inputs')
    require(type(rows) is list and len(rows) == 65, '65 prepared requests required')
    rust = doc({'path': config['rust_config_path'], 'sha256': config['rust_config_sha256']})
    stage = doc(config['baseline_stage_report'])
    baseline = doc(rust['plan'], 8192)
    require(rust.get('schema') == 'part5-v3-queue-capacity-stage-config-v1'
            and rust.get('scope') == 'part5-v3-queue-capacity-stage'
            and rust.get('stage_report') == config['baseline_stage_report']
            and rust.get('program') == config['expected_program']
            and rust.get('genesis') == config['expected_genesis']
            and capacity.execute.base.b58(bytes(baseline['program'])) == report['program']
            and capacity.execute.base.b58(bytes(baseline['genesis'])) == report['genesis']
            and capacity.execute.base.b58(bytes(baseline['creator'])) == rust['creator']['public_key'],
            'pinned stage plan and normal capacity signer required')
    seed_hex = rust.get('nonce_seed')
    require(type(seed_hex) is str and len(seed_hex) == 64
            and all(char in '0123456789abcdef' for char in seed_hex),
            'canonical capacity nonce seed required')
    seed = bytes.fromhex(seed_hex)
    addresses = set()
    signatures = set()
    replayed = []
    (Path(output) / 'rpc').mkdir(mode=0o700)
    for index, row in enumerate(rows):
        require(type(row) is dict and row.get('request_address') not in addresses
                and type(row.get('finalization')) is dict
                and type(row['finalization'].get('slot')) is int
                and type(row['finalization'].get('block_time')) is int,
                'distinct finalized request preparation required')
        addresses.add(row['request_address'])
        plan = doc(row['plan'], 8192)
        nonce = hashlib.sha256(b'part5-v3-capacity-nonce-v1' + seed
                               + index.to_bytes(8, 'big')).digest()
        require(plan == {**baseline, 'nonce': list(nonce),
                         'deadline': config['request_deadline']},
                'prepared request plan differs from pinned baseline and nonce schedule')
        raw = read({'path': row['request_account'], 'sha256': row['request_sha256']}, 2249)
        require(len(raw) == 2249 and raw[:8] == b'DYNREQ03'
                and int.from_bytes(raw[170:178], 'big') == config['request_deadline']
                and raw[183] == 1 and raw[8:40] == capacity.execute.base.key(stage['config'])
                and raw[40:72] == bytes(plan['creator']) and raw[72:104] == nonce
                and raw[104:136] == bytes(plan['issuer_hash'])
                and raw[136:168] == bytes(plan['recipient'])
                and raw[168:170] == (1).to_bytes(2, 'big')
                and raw[178:182] == len(plan['payload']).to_bytes(2, 'big') * 2
                and raw[182:185] == b'\x02\x01\x02'
                and raw[1225:1225 + len(plan['payload'])] == bytes(plan['payload']),
                'exact finalized live request and pinned plan required')
        specs = stage_transaction_specs(plan, stage, row['request_address'], report['program'])
        transactions = row.get('transactions')
        require(type(transactions) is list and len(transactions) == len(specs)
                and row['finalization'] == transactions[-1]
                and type(row.get('finalized_account_slot')) is int
                and row['finalized_account_slot'] >= transactions[-1]['slot'],
                'complete normal Create/Upload/Finalize transaction sequence required')
        for transaction, (name, data, accounts) in zip(transactions, specs):
            require(type(transaction) is dict
                    and set(transaction) == {'signature', 'slot', 'finalized', 'rpc_error', 'block_time'}
                    and type(transaction['signature']) is str
                    and transaction['signature'] not in signatures
                    and type(transaction['slot']) is int and transaction['slot'] > 0
                    and type(transaction['block_time']) is int
                    and transaction['finalized'] is True and transaction['rpc_error'] is None,
                    'distinct successful normal request transaction required')
            signatures.add(transaction['signature'])
            checked = runtime.rpc_transaction(rpc, transaction, report['program'], data,
                                              accounts, output, len(replayed))
            require(all(checked[field] == transaction[field] for field in transaction)
                    and checked['finalized'] is True,
                    f'independent finalized {name} RPC transaction differs')
            replayed.append(checked)
    require(report.get('finalized_slot') == rows[-1]['finalized_account_slot'],
            'complete normal request finalization slot differs')
    receipt = {'schema': 'part5-v3-queue-capacity-stage-rpc-replay-v1',
               'request_count': 65, 'transaction_count': len(replayed),
               'transactions': replayed}
    pin = write(Path(output) / 'stage-rpc-replay.json', receipt)
    return {'request_count': 65, 'transaction_count': len(replayed),
            'candidate_checked': True, 'replay_receipt': pin}


def clone_prepared(config, config_pin):
    """Copy only a stopped, pinned, normally prepared ledger to a fresh branch."""
    from tools.part5.finalize_v3_queue_capacity_negative import check_monitor
    stage_config, status = doc(config['stage_config']), doc(config['stage_status'])
    prepared = doc(config['preparation_report'])
    require(status.get('status') == 'candidate_verified_pending_external_finalization'
            and status.get('candidate') == config['preparation_report']
            and status.get('config_ref') == config['stage_config']
            and prepared.get('schema') == PREPARATION_SCHEMA
            and prepared.get('request_count') == 65 and prepared.get('queue_empty') is True,
            'stopped verified 65-request preparation required')
    check_monitor(doc(config['stage_monitor']), doc(config['stage_invocation']),
                  config['stage_config'], Path(__file__), stage_config, staging=True)
    proof_receipt = doc(config['preparation_receipt'])
    require(proof_receipt.get('schema') == 'part5-v3-queue-capacity-prepared-fixture-v1'
            and type(proof_receipt.get('fixture_manifest')) is dict
            and set(proof_receipt['fixture_manifest']) == REFERENCE_FIELDS
            and proof_receipt.get('preparation_report') == config['preparation_report']
            and len(proof_receipt.get('proof_receipts', [])) == 65,
            'completed offline proof owner required')
    check_monitor(doc(config['proof_monitor']), doc(config['proof_invocation']),
                  proof_receipt['config_ref'], Path(__file__), doc(proof_receipt['config_ref']))
    source = Path(stage_config['ledger'])
    destination = Path(config['ledger'])
    require(source.name == destination.name == 'ledger' and source.is_absolute()
            and source.resolve(strict=True) == source and destination.is_absolute()
            and destination.parent.resolve(strict=True) == destination.parent
            and not destination.exists() and not destination.is_symlink()
            and source not in destination.parents and destination not in source.parents,
            'fresh separate canonical capacity clone required')
    report_path = destination.parent / 'clone-report.json'
    require(config.get('output_dir') == str(destination.parent)
            and not report_path.exists() and not report_path.is_symlink(),
            'fresh rooted clone report required')
    require(type(config_pin) is dict and set(config_pin) == REFERENCE_FIELDS
            and config.get('phase') == 'clone', 'exact clone owner config required')
    capacity._hash(config_pin['sha256'], 'clone owner config')
    before = inventory(source)
    encoded = json.dumps(before, separators=(',', ':')).encode()
    tree_sha256 = hashlib.sha256(encoded).hexdigest()
    require(config.get('source_tree_sha256') == tree_sha256,
            'pinned prepared source tree required')
    exclude = stale_admin_socket(source)
    shutil.copytree(source, destination, symlinks=True, copy_function=shutil.copy2,
                    ignore=lambda directory, names: {'admin.rpc'}
                    if exclude and Path(directory) == source else set())
    require(before == inventory(source) == inventory(destination),
            'prepared source changed or clone differs')
    # This is a candidate: session_runner writes its completed monitor only
    # after this process exits. Acceptance must bind that monitor and its exact
    # invocation to config_ref and include the external owner's complete cost.
    receipt = {'schema': 'part5-v3-queue-capacity-prepared-ledger-clone-v1',
               'config_ref': config_pin, 'clone_owner_required': True,
               'cost_included': False,
               'owner_limits': {'runtime_seconds': 3600,
                                'owned_tree_rss_bytes': 4294967296,
                                'storage_growth_bytes': 17179869184,
                                'poll_seconds': .25},
               'source': str(source), 'destination': str(destination),
               'entry_count': len(before), 'tree_sha256': tree_sha256,
               'source_stable': True, 'copy_identical': True,
               'excluded_stale_admin_socket': exclude,
               'loaded_identity_rechecked_after_restart': False,
               'application_effect': False,
               'stage_report_sha256': config['baseline_stage_report']['sha256'],
               'stage_status_sha256': config['stage_status']['sha256'],
               'preparation_receipt_sha256': config['preparation_receipt']['sha256'],
               'fixture_manifest_sha256': proof_receipt['fixture_manifest']['sha256']}
    write(report_path, receipt)
    return receipt


def run(config, config_pin):
    """One phase per invocation, with external ownership of staging/proofs/clone."""
    phase = config.get('phase')
    require(phase in ('stage', 'proofs', 'clone'), 'explicit capacity phase required')
    if phase == 'stage':
        from harness.tests import queue_v3_capacity_runtime as runtime
        require(type(config.get('cohort_manifest')) is dict
                and set(config['cohort_manifest']) == REFERENCE_FIELDS,
                'pinned heldout cohort receipt required before stage launch')
        rust = doc({'path': config['rust_config_path'], 'sha256': config['rust_config_sha256']})
        require(type(config.get('baseline_stage_report')) is dict
                and set(config['baseline_stage_report']) == REFERENCE_FIELDS
                and type(rust.get('plan')) is dict
                and set(rust['plan']) == REFERENCE_FIELDS,
                'pinned baseline stage context and plan required')
        baseline = doc(config['baseline_stage_report'])
        doc(rust['plan'], 8192)
        require(baseline.get('schema') == 'part5-v3-local-stage-v1'
                and baseline.get('passed') is True
                and baseline.get('plan_sha256') == rust['plan']['sha256']
                and baseline.get('program') == config['expected_program']
                and baseline.get('genesis') == config['expected_genesis'],
                'baseline plan must bind accepted stage context')
        validity = signed_validity(config, config['request_deadline'])
        require(config['credential_not_after'] == validity
                and rust.get('credential_not_after') == validity
                and rust.get('request_deadline') == config['request_deadline']
                and rust.get('stage_report') == config['baseline_stage_report']
                and rust.get('proof_owner_limit_seconds') == config['proof_owner_limit_seconds']
                and time.time() + 3600 + config['proof_owner_limit_seconds'] + 3600
                    < config['request_deadline'] <= validity,
                'signed validity cannot cover declared stage, proof and fill owners')
        return runtime.supervise(config, config_pin, 'capacity-preparation-report.json',
                                 verify_stage, staging=True)
    if phase == 'proofs':
        prepare_proofs(config, config_pin)
        return 0
    clone_prepared(config, config_pin)
    return 0

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--config-sha256', required=True)
    args = parser.parse_args()
    config = doc({'path': str(args.config), 'sha256': args.config_sha256})
    require(config.get('schema') == SCHEMA, 'explicit capacity producer config required')
    return run(config, {'path': str(args.config), 'sha256': args.config_sha256})


if __name__ == '__main__':
    sys.exit(main())
