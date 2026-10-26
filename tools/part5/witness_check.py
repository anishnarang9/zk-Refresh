"""Streaming complete v3 R1CS checker; CLI pins the frozen compiled relation.

The checker evaluates all rows independently of the WASM witness generator.
The Python API accepts small toy relations for binary-format regression tests;
production CLI additionally enforces the exact accepted v3 R1CS SHA256.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617
R1CS_SHA256 = '976e9a76356ad015f0e4c587ccd79bba601b5caf80817b561aa4ca5442656888'
def _exact(stream, count):
    result = stream.read(count)
    if len(result) != count:
        raise ValueError("truncated binary artifact")
    return result


def _sections(stream, magic, version, limit):
    if _exact(stream, 4) != magic or int.from_bytes(_exact(stream, 4), "little") != version:
        raise ValueError("binary magic/version")
    count = int.from_bytes(_exact(stream, 4), "little")
    if not 2 <= count <= 3:
        raise ValueError("section count")
    file_size = os.fstat(stream.fileno()).st_size
    if file_size > limit:
        raise ValueError("binary size")
    result = {}
    for _ in range(count):
        kind, size = struct.unpack("<IQ", _exact(stream, 12))
        position = stream.tell()
        if kind in result or kind not in (1, 2, 3) or position + size > file_size:
            raise ValueError("binary sections")
        result[kind] = (position, size)
        stream.seek(size, 1)
    if stream.tell() != file_size or 1 not in result or 2 not in result:
        raise ValueError("binary final size/required sections")
    return result


def check_witness(r1cs_path, witness_path, expected_public):
    """Independent streaming complete R1CS satisfaction with canonical field bounds."""
    with open(witness_path, "rb") as witness:
        sections = _sections(witness, b"wtns", 2, 32 * 1024 * 1024)
        witness.seek(sections[1][0])
        if sections[1][1] != 40 or int.from_bytes(_exact(witness, 4), "little") != 32:
            raise ValueError("WTNS header")
        prime = int.from_bytes(_exact(witness, 32), "little")
        count = int.from_bytes(_exact(witness, 4), "little")
        if prime != FR or not 7 <= count <= 784796 or sections[2][1] != 32 * count:
            raise ValueError("WTNS field/count")
        witness.seek(sections[2][0])
        values = [int.from_bytes(_exact(witness, 32), "little") for _ in range(count)]
        if values[0] != 1 or any(value >= FR for value in values):
            raise ValueError("WTNS constant/canonical field")
        if len(expected_public) != 6 or values[1:7] != expected_public:
            raise ValueError("WTNS public statement")
    with open(r1cs_path, "rb", buffering=1024 * 1024) as relation:
        sections = _sections(relation, b"r1cs", 1, 192 * 1024 * 1024)
        relation.seek(sections[1][0])
        if sections[1][1] != 64 or int.from_bytes(_exact(relation, 4), "little") != 32:
            raise ValueError("R1CS header")
        if int.from_bytes(_exact(relation, 32), "little") != FR:
            raise ValueError("R1CS field")
        wires, outputs, public, private, labels, constraints = struct.unpack("<IIIIQI", _exact(relation, 28))
        if wires != count or outputs != 0 or public != 6 or not 1 <= constraints <= 793681:
            raise ValueError("R1CS counts")
        relation.seek(sections[2][0])
        end = sections[2][0] + sections[2][1]
        entries = 0
        max_row_terms = 0
        for row in range(constraints):
            result = []
            for _ in range(3):
                terms = int.from_bytes(_exact(relation, 4), "little")
                entries += terms
                max_row_terms = max(max_row_terms, terms)
                if terms > 4096 or entries > 5000000 or relation.tell() + terms * 36 > end:
                    raise ValueError("R1CS term bounds")
                value = 0
                for _ in range(terms):
                    index = int.from_bytes(_exact(relation, 4), "little")
                    coefficient = int.from_bytes(_exact(relation, 32), "little")
                    if index >= count or coefficient >= FR:
                        raise ValueError("R1CS term encoding")
                    value += coefficient * values[index]
                result.append(value % FR)
            if (result[0] * result[1] - result[2]) % FR:
                raise ValueError("unsatisfied relation row " + str(row))
        if relation.tell() != end:
            raise ValueError("R1CS constraint trailing bytes")
    return {"constraints_checked": constraints, "matrix_entries": entries,
            "max_row_terms": max_row_terms, "assignment_fields": count, "satisfied": True}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-witness',type=Path,required=True)
    parser.add_argument('--r1cs',type=Path,required=True)
    parser.add_argument('--expected-public',type=Path,required=True)
    args=parser.parse_args()
    with args.r1cs.open('rb') as source:
        if hashlib.file_digest(source,'sha256').hexdigest()!=R1CS_SHA256:
            raise ValueError('frozen R1CS identity mismatch')
    raw=json.loads(args.expected_public.read_text())
    if (type(raw) is not list or len(raw)!=6 or any(type(x) is not str or not x.isascii()
        or not x.isdecimal() or str(int(x))!=x or not 0<=int(x)<FR for x in raw)):
        raise ValueError('canonical six-field public statement required')
    print(json.dumps(check_witness(args.r1cs,args.check_witness,[int(x) for x in raw]),sort_keys=True))

if __name__=='__main__': main()
