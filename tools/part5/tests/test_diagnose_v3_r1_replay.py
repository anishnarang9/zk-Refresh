import importlib.util
from pathlib import Path
import pytest

PATH = Path(__file__).resolve().parents[1] / 'diagnose_v3_r1_replay.py'

def module():
    spec = importlib.util.spec_from_file_location('diagnostic', PATH)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

def test_external_owner_and_limits_are_required(monkeypatch):
    d = module()
    monkeypatch.delenv('P5_R1_DIAGNOSTIC_OWNER', raising=False)
    with pytest.raises(ValueError, match='external owner'):
        d.require_owner()

def test_limits_cannot_be_weakened(monkeypatch):
    d = module()
    monkeypatch.setenv('P5_R1_DIAGNOSTIC_OWNER', d.OWNER)
    monkeypatch.setenv('P5_R1_DIAGNOSTIC_LIMITS', '{}')
    with pytest.raises(ValueError, match='limits'):
        d.require_owner()

def test_readiness_uses_transition_floor(monkeypatch):
    d = module()
    seen = {}
    def wait(*args, **kwargs):
        seen.update(kwargs)
        return 82, [b'a'] * 5
    monkeypatch.setattr(d.execute, 'wait_staged_finality', wait)
    d.observe_accounts(None, {'finalized_slot': 45}, 'program',
                       {'finalized_slot': 81, 'account_sha256': ['x'] * 5}, [1] * 5)
    assert seen == {'minimum_slot': 81}

def test_destination_cannot_be_preserved_case(tmp_path):
    d = module()
    with pytest.raises(ValueError, match='fresh diagnostic'):
        d.fresh_root(d.CASE / 'new-diagnostic')

def test_owner_requires_lock_attestation(monkeypatch):
    import json
    d = module()
    monkeypatch.setenv('P5_R1_DIAGNOSTIC_OWNER', d.OWNER)
    monkeypatch.setenv('P5_R1_DIAGNOSTIC_LIMITS', json.dumps(d.LIMITS))
    monkeypatch.delenv('P5_R1_DIAGNOSTIC_GLOBAL_LOCK', raising=False)
    with pytest.raises(ValueError, match='global lock'):
        d.require_owner()

def test_existing_destination_rejected(monkeypatch, tmp_path):
    d = module()
    monkeypatch.setattr(d, 'PART5', tmp_path)
    target = tmp_path / 'v3-r1-replay-diagnostic-existing'
    target.mkdir()
    with pytest.raises(ValueError, match='fresh diagnostic'):
        d.fresh_root(target)

def test_minimum_slot_reaches_rpc_and_rejects_wrong_account():
    import base64
    d = module()
    seen = []
    def rpc(method, params):
        seen.append((method, params))
        return {'context': {'slot': 82}, 'value': [
            {'owner': 'program', 'executable': False,
             'data': [base64.b64encode(b'wrong').decode(), 'base64']}] * 5}
    staged = dict(zip(d.execute.ACCOUNT_NAMES, ['key'] * 5))
    staged['finalized_slot'] = 45
    with pytest.raises(ValueError, match='exact account bytes mismatch'):
        d.observe_accounts(rpc, staged, 'program',
            {'finalized_slot': 81, 'account_sha256': ['0' * 64] * 5}, [5] * 5)
    assert seen[0][1][1]['minContextSlot'] == 81
