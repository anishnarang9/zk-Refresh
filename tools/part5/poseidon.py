"""Pinned circomlib Poseidon evaluator; supports v3 issuer/policy binding arities.

Adapted from the independently checked v2 witness evaluator, without profile data.
"""
import ast
import functools
import hashlib
from pathlib import Path
import re
FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617
EXPECTED_CONSTANTS_SHA = "94c9e4b5ea891ab4d1ba626f1d719f8c661014d9b628f6096c803f75f39e3eee"
@functools.lru_cache(maxsize=16)
def _parameters(constants_path, t):
    raw = Path(constants_path).read_bytes()
    if len(raw) > 3 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != EXPECTED_CONSTANTS_SHA:
        raise ValueError("Poseidon constants identity/size")
    text = raw.decode("ascii")
    arrays = []
    for name in ("C", "S", "M", "P"):
        function = re.search(r"function POSEIDON_" + name + r"\(t\)\s*\{", text)
        if function is None:
            raise ValueError("Poseidon function missing")
        rest = text[function.end():]
        branch = re.search(r"if\s*\(t\s*==\s*" + str(t) + r"\)\s*\{\s*return\s*", rest)
        if branch is None:
            raise ValueError("Poseidon arity missing")
        tail = rest[branch.end():]
        value = ast.literal_eval(tail[:tail.index(";")])
        arrays.append(value)
    return arrays


def poseidon(values, constants_path):
    """Evaluate the pinned circomlib optimized permutation; initial state is zero."""
    if len(values) not in (2, 3, 4, 5, 8, 9) or any(type(x) is not int or not 0 <= x < FR for x in values):
        raise ValueError("unsupported Poseidon input shape/field")
    t = len(values) + 1
    rounds = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68][t - 2]
    c, sparse, m, p = _parameters(str(Path(constants_path).resolve()), t)
    if len(c) != 8 * t + rounds or len(sparse) != rounds * (2 * t - 1):
        raise ValueError("Poseidon parameter length")
    state = [(x + c[i]) % FR for i, x in enumerate([0] + list(values))]

    def mix(vector, matrix):
        return [sum(matrix[j][i] * vector[j] for j in range(t)) % FR for i in range(t)]

    for round_index in range(3):
        state = mix([(pow(x, 5, FR) + c[(round_index + 1) * t + j]) % FR
                     for j, x in enumerate(state)], m)
    state = mix([(pow(x, 5, FR) + c[4 * t + j]) % FR for j, x in enumerate(state)], p)
    for round_index in range(rounds):
        state[0] = (pow(state[0], 5, FR) + c[5 * t + round_index]) % FR
        offset = round_index * (2 * t - 1)
        first = sum(sparse[offset + j] * state[j] for j in range(t)) % FR
        state = [first] + [(state[j] + state[0] * sparse[offset + t + j - 1]) % FR for j in range(1, t)]
    for round_index in range(3):
        state = mix([(pow(x, 5, FR) + c[5 * t + rounds + round_index * t + j]) % FR
                     for j, x in enumerate(state)], m)
    return sum(m[j][0] * pow(state[j], 5, FR) for j in range(t)) % FR
