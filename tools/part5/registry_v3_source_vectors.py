"""Public synthetic v3 source-authentication vectors, independent of Rust codec.

Known deterministic Ed25519 seeds are public TEST DATA, never development
authority keys. cryptography signs independently encoded JSON; Rust tests first
cross-check the fixture using OpenSSL before the deliberate production RED stub.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat

SIGN_TAG=b'DYNARK-V3-SOURCE-STATUS-v1\0'
WIRE_TAG=b'DYNARK-V3-SOURCE-WIRE-v1\0'


def word(n):return [n]*32
def digest(label):return list(hashlib.sha256(label.encode('ascii')).digest())
def canonical(value):return json.dumps(value,separators=(',',':'),ensure_ascii=True).encode('ascii')


def build():
    scope=dict(network=word(1),program=word(2),config=word(3),registry=word(4),
        profile=word(5),circuit=word(6),schema=word(7),package=word(8),ordinary_vk=word(9),
        policy_hash=word(10),policy_version=1,config_eligibility_epoch=2,leaf_domain=2026101504,depth=10)
    rows=[];keys=[]
    for i,sequence in [(0,3),(1,8)]:
        seed=bytes(digest(f'PUBLIC TEST ONLY v3 source seed {i}'))
        key=Ed25519PrivateKey.from_private_bytes(seed)
        keys.append(key)
        public=list(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))
        issuer=dict(issuer_account=word(11+i),issuer_hash=word(13+i),source_key=public,
            issuer_eligibility_epoch=5+i,enrollment_evidence_version=7+i,
            evidence_digest=digest(f'public enrollment evidence {i}'))
        previous=dict(sequence=sequence-1,digest=digest(f'public previous source {i}'))
        observation=dict(scope=scope,issuer=issuer,sequence=sequence,previous_digest=previous['digest'],
            observed_at=140,valid_until=200,issuer_status_active=True,
            changes=[{'Issue':dict(tbs_digest=digest(f'public synthetic signed TBS {i}'),slot=17+i,allocation_epoch=1)}])
        preimage=SIGN_TAG+canonical(observation)
        signature=key.sign(preimage)
        key.public_key().verify(signature,preimage)
        signed=dict(observation=observation,signature=list(signature))
        wire=WIRE_TAG+canonical(signed)
        rows.append(dict(public_test_seed_hex=seed.hex(),
            enrolled_source=dict(scope=scope,issuer=issuer,config_enabled=True,issuer_enabled=True,max_age_seconds=300),
            previous_head=previous,now=150,signed_source=signed,signing_bytes_hex=preimage.hex(),
            source_wire_sha256=hashlib.sha256(wire).hexdigest()))
    a=rows[0]
    negatives=[]
    def resigned(name,observation,key=keys[0],tag=SIGN_TAG):
        message=tag+canonical(observation)
        signature=key.sign(message)
        key.public_key().verify(signature,message)
        negatives.append(dict(name=name,signing_bytes_hex=message.hex(),
            signed_source=dict(observation=observation,signature=list(signature))))
    for field in ['network','program','config','registry','profile','circuit','schema','package','ordinary_vk','policy_hash']:
        observation=copy.deepcopy(a['signed_source']['observation'])
        observation['scope'][field][0]^=1
        resigned('wrong_'+field,observation)
    for field in ['config_eligibility_epoch','policy_version','leaf_domain','depth']:
        observation=copy.deepcopy(a['signed_source']['observation'])
        observation['scope'][field]+=1
        resigned('wrong_'+field,observation)
    for field in ['issuer_eligibility_epoch','enrollment_evidence_version']:
        observation=copy.deepcopy(a['signed_source']['observation'])
        observation['issuer'][field]+=1
        resigned('wrong_'+field,observation)
    for field in ['issuer_account','issuer_hash','evidence_digest']:
        observation=copy.deepcopy(a['signed_source']['observation'])
        observation['issuer'][field][0]^=1
        resigned('wrong_'+field,observation)
    for name,sequence in [('unobserved_sequence',0),('replayed_sequence',2),('gapped_sequence',4)]:
        observation=copy.deepcopy(a['signed_source']['observation']);observation['sequence']=sequence
        resigned(name,observation)
    observation=copy.deepcopy(a['signed_source']['observation']);observation['previous_digest'][0]^=1
    resigned('wrong_predecessor_digest',observation)
    observation=copy.deepcopy(a['signed_source']['observation'])
    observation['issuer']['source_key']=rows[1]['enrolled_source']['issuer']['source_key']
    resigned('self_chosen_other_issuer_key',observation,keys[1])
    resigned('v2_signing_domain',copy.deepcopy(a['signed_source']['observation']),tag=b'DYNARK-SOURCE-STATUS-v1\0')
    binding=dict(scope=scope,issuer=a['enrolled_source']['issuer'],
        source_head=dict(sequence=3,digest=list(bytes.fromhex(a['source_wire_sha256']))),
        root=word(15),root_version=0,publisher_key=word(16),publication_sequence=1,
        previous_publication_digest=word(0),signature=[0]*64)
    current=dict(scope=scope,issuer=a['enrolled_source']['issuer'],source_head=binding['source_head'],
        root=word(15),root_version=0,publisher_key=word(16),config_enabled=True,issuer_enabled=True,
        status_valid=True,observed_config_epoch=2,observed_issuer_epoch=5,
        clock_unix=150,valid_until=160)
    return dict(schema='credential-v3-public-source-auth-vectors-v1',synthetic_only=True,
        public_test_keys_not_authorities=True,
        generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        signing_tag_hex=SIGN_TAG.hex(),wire_tag_hex=WIRE_TAG.hex(),issuers=rows,resigned_negatives=negatives,
        publisher_binding=binding,current_head=current,
        publisher_signature_is_placeholder=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();value=build()
    with args.output.open('x') as target:json.dump(value,target,sort_keys=True,indent=2);target.write('\n')
    print(json.dumps({'public_synthetic_source_vectors':2,'publisher_qualified':False,
        'sha256':hashlib.sha256(args.output.read_bytes()).hexdigest()}))


if __name__=='__main__':main()
