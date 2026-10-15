"""Independent public synthetic v3 membership vectors; no credential generation.

Rebuild complete levels from 1024 leaves; never import Rust tree/profile/corpus
logic. The scalar permutation is the pinned Python circomlib evaluator, which
is independent of the Rust light-poseidon implementation under test.
"""
import argparse
from functools import lru_cache
import hashlib
import json
from pathlib import Path
from tools.part5.poseidon import EXPECTED_CONSTANTS_SHA, poseidon

ROOT = Path(__file__).resolve().parents[2]
CONSTANTS = ROOT / 'node_modules/circomlib/circuits/poseidon_constants.circom'
DOMAIN = 2026101504
SLOTS = [0, 1, 17, 511, 512, 1023]


@lru_cache(maxsize=4096)
def h(values):
    return poseidon(list(values), CONSTANTS)


def leaf(digest, slot, active, domain=DOMAIN):
    return h((domain, int.from_bytes(digest[:16], 'big'),
              int.from_bytes(digest[16:], 'big'), slot, int(active)))


def encoded(value):
    return value.to_bytes(32, 'big').hex()


def digest(label):
    return hashlib.sha256(label.encode('ascii')).digest()


def rebuild(records):
    level = [0] * 1024
    for slot, d, active in records:
        level[slot] = leaf(d, slot, active)
    levels = [level]
    for _ in range(10):
        previous = levels[-1]
        levels.append([h((previous[i], previous[i+1])) for i in range(0,len(previous),2)])
    return levels


def siblings(levels, slot):
    return [encoded(levels[i][(slot >> i) ^ 1]) for i in range(10)]


def build():
    leaf_vectors = []
    for slot in SLOTS:
        d = digest(f'public synthetic v3 leaf {slot}')
        for active in [True, False]:
            leaf_vectors.append(dict(digest=d.hex(), slot=slot, active=active,
                leaf=encoded(leaf(d,slot,active)), v2_leaf=encoded(leaf(d,slot,active,20261015))))
    records = [(slot,digest(f'public synthetic v3 tree {slot}'),True) for slot in SLOTS]
    tree = rebuild(records)
    own, other = digest('public synthetic v3 own'), digest('public synthetic v3 unrelated')
    before = rebuild([(17,own,True),(18,other,True)])
    near = rebuild([(17,own,True),(18,other,False)])
    revoked = rebuild([(17,own,False),(18,other,False)])
    sources = {
        'generator': Path(__file__), 'python_evaluator': ROOT/'tools/part5/poseidon.py',
        'circom_constants': CONSTANTS,
        'circuit': ROOT/'circuits/credential-v3-bounded/credential.circom',
        'profile': ROOT/'circuits/credential-v3-bounded/profile.json',
    }
    return dict(schema='credential-v3-public-membership-vectors-v1', synthetic_only=True,
        encoding='canonical BE32 hex; digest is raw SHA256 bytes, split into unsigned BE128 halves',
        depth=10, leaf_domain=DOMAIN, parent='circomlib Poseidon(2)(left,right)',
        provenance={name:dict(path=str(path.relative_to(ROOT)),sha256=hashlib.sha256(path.read_bytes()).hexdigest())
                    for name,path in sources.items()},
        expected_constants_sha256=EXPECTED_CONSTANTS_SHA,
        empty_root=encoded(rebuild([])[-1][0]), leaf_vectors=leaf_vectors,
        sparse_tree=dict(root=encoded(tree[-1][0]),
            records=[dict(slot=slot,digest=d.hex(),active=active) for slot,d,active in records],
            paths=[dict(slot=slot,digest=d.hex(),siblings=siblings(tree,slot),
                        path_indices=[(slot>>i)&1 for i in range(10)]) for slot,d,_ in records]),
        revocation=dict(own_digest=own.hex(),other_digest=other.hex(),
            before_root=encoded(before[-1][0]),before_path=siblings(before,17),
            unrelated_root=encoded(near[-1][0]),unrelated_path=siblings(near,17),
            own_revoked_root=encoded(revoked[-1][0]),own_revoked_path=siblings(revoked,17)))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    value=build()
    with args.output.open('x') as target:
        json.dump(value,target,sort_keys=True,indent=2)
        target.write('\n')
    print(json.dumps({'public_synthetic_vectors':True,'leaf_cases':len(value['leaf_vectors']),
                      'sha256':hashlib.sha256(args.output.read_bytes()).hexdigest()}))


if __name__=='__main__':
    main()
