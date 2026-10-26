"""Prepare NEW independent public synthetic publisher vectors; NOT RUN yet.

This recipe uses a separate known public TEST seed, independent compact JSON
encoding and cryptography Ed25519. It does not authenticate a chain adapter.
Its output must be materialized/pinned under a separate ROOT grant before RED.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat

ROOT=Path(__file__).resolve().parents[2]
SOURCE_VECTOR=ROOT/'crates/credential-registry/tests/vectors/v3-source-auth-v1.json'
SOURCE_SHA='8b4044523fccc19e5834db290c7fe9c810c1b32328ac24f3aef909ffd18e5afd'
PUB_TAG=b'DYNARK-V3-PUBLISHER-BINDING-v1\0'
SOURCE_TAG=b'DYNARK-V3-SOURCE-STATUS-v1\0'
SOURCE_WIRE=b'DYNARK-V3-SOURCE-WIRE-v1\0'
SCOPE=['network','program','config','registry','profile','circuit','schema','package','ordinary_vk',
       'policy_hash','policy_version','config_eligibility_epoch','leaf_domain','depth']
ISSUER=['issuer_account','issuer_hash','source_key','issuer_eligibility_epoch',
        'enrollment_evidence_version','evidence_digest']

def canonical(value):return json.dumps(value,separators=(',',':'),ensure_ascii=True).encode('ascii')
def digest(label):return list(hashlib.sha256(label.encode('ascii')).digest())
def ordered(fields,value):return {key:copy.deepcopy(value[key]) for key in fields}

def build():
    raw=SOURCE_VECTOR.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SOURCE_SHA:raise ValueError('frozen source-vector identity')
    original=json.loads(raw);base=original['issuers'][0]
    scope=ordered(SCOPE,base['signed_source']['observation']['scope'])
    issuer=ordered(ISSUER,base['signed_source']['observation']['issuer'])
    seed=bytes(digest('PUBLIC TEST ONLY distinct v3 publisher seed 2026-10-15 v1'))
    key=Ed25519PrivateKey.from_private_bytes(seed)
    public=list(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))
    other=Ed25519PrivateKey.from_private_bytes(bytes(digest('PUBLIC TEST ONLY second v3 publisher seed v1')))
    other_public=list(other.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))
    assert public!=other_public and all(public!=r['enrolled_source']['issuer']['source_key'] for r in original['issuers'])
    head=dict(sequence=base['signed_source']['observation']['sequence'],digest=list(bytes.fromhex(base['source_wire_sha256'])))
    previous=dict(sequence=4,digest=digest('public previous v3 publisher checkpoint'))
    body=dict(scope=scope,issuer=issuer,source_head=head,root=[15]*32,root_version=0,
        publisher_key=public,publication_sequence=5,previous_publication_digest=previous['digest'])
    current=dict(scope=scope,issuer=issuer,source_head=head,root=[15]*32,root_version=0,
        publisher_key=public,config_enabled=True,issuer_enabled=True,status_valid=True,
        observed_config_epoch=scope['config_eligibility_epoch'],observed_issuer_epoch=issuer['issuer_eligibility_epoch'],
        clock_unix=150,valid_until=160)
    rows=[]
    def add(name,expect,change_binding=None,change_current=None,signer=key,source=None,checkpoint=None,now=150):
        b=copy.deepcopy(body);h=copy.deepcopy(current)
        if change_binding:change_binding(b)
        if change_current:change_current(h)
        src=source or base
        message=PUB_TAG+canonical(b);signature=signer.sign(message)
        signer.public_key().verify(signature,message)
        rows.append(dict(name=name,expect=expect,binding=dict(b,signature=list(signature)),
            signing_bytes_hex=message.hex(),signed_source=src['signed_source'],
            enrolled_source=src['enrolled_source'],previous_source_head=src['previous_head'],
            current_head=h,previous_publication_head=checkpoint or previous,source_verified_at=150,now=now))
    add('initialized_root_zero','accept')
    add('later_current_root_version','accept',lambda b:b.update(root_version=9),lambda h:h.update(root_version=9))
    add('wrong_root','reject',lambda b:b.update(root=[18]*32))
    add('wrong_root_version','reject',lambda b:b.update(root_version=1))
    for field in ['config_eligibility_epoch','policy_version','package','policy_hash']:
        def change(b,field=field):
            if isinstance(b['scope'][field],list):b['scope'][field][0]^=1
            else:b['scope'][field]+=1
        add('wrong_'+field,'reject',change)
    for field in ['issuer_eligibility_epoch','enrollment_evidence_version']:
        add('wrong_'+field,'reject',lambda b,field=field:b['issuer'].__setitem__(field,b['issuer'][field]+1))
    add('wrong_publisher_key','reject',lambda b:b.update(publisher_key=other_public),signer=other)
    add('wrong_source_sequence','reject',lambda b:b['source_head'].update(sequence=head['sequence']+1))
    add('wrong_source_digest','reject',lambda b:b['source_head']['digest'].__setitem__(0,b['source_head']['digest'][0]^1))
    add('unobserved_source_sequence','reject',lambda b:b['source_head'].update(sequence=0),lambda h:h['source_head'].update(sequence=0))
    add('replayed_publication','reject',lambda b:b.update(publication_sequence=4))
    add('gapped_publication','reject',lambda b:b.update(publication_sequence=6))
    add('wrong_publication_predecessor','reject',lambda b:b['previous_publication_digest'].__setitem__(0,b['previous_publication_digest'][0]^1))
    add('stale_current_head','reject',change_current=lambda h:h.update(valid_until=149))
    add('future_clock','reject',change_current=lambda h:h.update(clock_unix=151))
    add('source_expired_after_verification','reject',
        change_current=lambda h:h.update(clock_unix=201,valid_until=211),now=201)
    for field in ['config_enabled','issuer_enabled','status_valid']:
        add('disabled_'+field,'reject',change_current=lambda h,field=field:h.update({field:False}))
    for field in ['observed_config_epoch','observed_issuer_epoch']:
        add('stale_'+field,'reject',change_current=lambda h,field=field:h.update({field:h[field]-1}))
    modulus=list(bytes.fromhex('30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001'))
    add('noncanonical_root','reject',lambda b:b.update(root=modulus),lambda h:h.update(root=modulus))
    inactive=copy.deepcopy(base);old=base['signed_source']['observation']
    observation=dict(scope=scope,issuer=issuer,sequence=old['sequence'],previous_digest=old['previous_digest'],
        observed_at=old['observed_at'],valid_until=old['valid_until'],issuer_status_active=False,
        changes=[{'Revoke':dict(tbs_digest=old['changes'][0]['Issue']['tbs_digest'])}])
    source_key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(base['public_test_seed_hex']))
    source_signature=source_key.sign(SOURCE_TAG+canonical(observation))
    source_key.public_key().verify(source_signature,SOURCE_TAG+canonical(observation))
    inactive['signed_source']=dict(observation=observation,signature=list(source_signature))
    inactive_head=dict(sequence=observation['sequence'],digest=list(hashlib.sha256(SOURCE_WIRE+canonical(inactive['signed_source'])).digest()))
    add('inactive_source','reject',lambda b:b.update(source_head=inactive_head),
        lambda h:h.update(source_head=inactive_head),source=inactive)
    add('source_key_used_as_publisher','reject',lambda b:b.update(publisher_key=issuer['source_key']),signer=source_key)
    return dict(schema='credential-v3-public-publisher-auth-vectors-v1',synthetic_only=True,
        source_fixture_sha256=SOURCE_SHA,generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        public_test_seed_hex=seed.hex(),public_test_keys_not_authorities=True,
        caller_json_is_not_authenticated_current_head=True,cases=rows)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();value=build();encoded=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    if len(encoded)>2*1024*1024:raise ValueError('public publisher-vector bound')
    with args.output.open('xb') as target:target.write(encoded)
    print(json.dumps({'public_publisher_vectors':len(value['cases']),
        'sha256':hashlib.sha256(encoded).hexdigest(),'chain_adapter_authenticated':False}))

if __name__=='__main__':main()
