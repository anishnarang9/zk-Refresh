"""Fixed-artifact, exact-fixture experimental evaluator; no production validation API.

FixturePins must come from a parent-reviewed trusted execution receipt. Matching
caller-selected hashes alone does not establish R1CS satisfaction or provenance.
This module never runs WASM/proofs and never substitutes for full relation checks.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import struct
from types import MappingProxyType

PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617
COUNT = 643563
WTNS_BYTES = 76 + COUNT*32
INPUT_BYTES = 65536
ROOT = Path(__file__).resolve().parents[4]
RESULTS = ROOT/'results/dynark/phase-3/witness-dependency'
PUBLIC_KEYS = ('root','issuerHash','notBefore','notAfter','actionHash')
ARRAY_SIZES = dict(tbs=439,issuerModulus=17,issuerSignature=17,holderSignature=17,siblings=10,pathIndices=10)
INPUT_KEYS = frozenset((*PUBLIC_KEYS,'slot',*ARRAY_SIZES))
PATCH_SCOPE = frozenset((1,363,*range(643044,643562)))
PINS = {
 'poseidon-t3-fixed-constants-001.json':(29928,'2fcc1830e353733e9c0e537722f8ffcf9a27c4b6cfe1c42241b78ad4f8742d20'),
 'far-source-symbols-001.json':(116878,'34d7f76d12df860080ebf609493086764add87eeb3ca6b9e07a19aad37b664c7'),
 'compiled-far-aliases-001.json':(49021,'1d3abc482f5bdc985be6a86f80e712c7055ac1241e875bcf2ac9c1f426ae8b0f'),
}


class EvaluatorError(ValueError):pass
class SchemaError(EvaluatorError):pass
class ScopeError(EvaluatorError):pass
class RootMismatch(EvaluatorError):pass
class AliasMismatch(EvaluatorError):pass
class FixtureIdentityError(EvaluatorError):pass


def _unique(pairs):
    out={}
    for key,value in pairs:
        if key in out:raise SchemaError('duplicate_json_key')
        out[key]=value
    return out


def _no_float(_):raise SchemaError('float_or_nonfinite_json')


def _json(raw,cap):
    if type(raw) is not bytes or not 0<len(raw)<=cap:raise SchemaError('json_size_or_type')
    try:return json.loads(raw,object_pairs_hook=_unique,parse_float=_no_float,parse_constant=_no_float)
    except (ValueError,UnicodeError,RecursionError) as error:
        if isinstance(error,SchemaError):raise
        raise SchemaError('invalid_json') from None


def _number(value,upper=PRIME):
    if type(value) is int:number=value
    elif type(value) is str and len(value)<=78:
        if re.fullmatch(r'0|[1-9][0-9]*',value):number=int(value,10)
        elif re.fullmatch(r'0x[0-9a-fA-F]{1,64}',value):number=int(value,16)
        else:raise SchemaError('invalid_scalar_encoding')
    else:raise SchemaError('invalid_scalar_type')
    if not 0<=number<upper:raise SchemaError('noncanonical_or_out_of_range_scalar')
    return number


def parse_inputs(raw):
    obj=_json(raw,INPUT_BYTES)
    if type(obj) is not dict or set(obj)!=INPUT_KEYS:raise SchemaError('exact_input_keys')
    out={key:_number(obj[key]) for key in PUBLIC_KEYS}
    out['slot']=_number(obj['slot'],1024)
    for key,size in ARRAY_SIZES.items():
        values=obj[key]
        if type(values) is not list or len(values)!=size:raise SchemaError('exact_array_shape')
        upper=256 if key=='tbs' else 2 if key=='pathIndices' else (1<<121) if key in ('issuerModulus','issuerSignature','holderSignature') else PRIME
        out[key]=tuple(_number(value,upper) for value in values)
    if out['pathIndices']!=tuple((out['slot']>>level)&1 for level in range(10)):
        raise SchemaError('slot_selector_correspondence')
    return MappingProxyType(out)


def validate_scope(before,target):
    if set(before)!=INPUT_KEYS or set(target)!=INPUT_KEYS:raise SchemaError('exact_scope_keys')
    for key in INPUT_KEYS-{'root','siblings'}:
        if before[key]!=target[key]:raise ScopeError('unsupported_input_change')
    if before['siblings'][:9]!=target['siblings'][:9]:raise ScopeError('earlier_sibling_changed')


@dataclass(frozen=True)
class CanonicalWitness:
    words: bytes

    def field(self,index):
        if type(index) is not int or not 0<=index<COUNT:raise SchemaError('witness_index')
        return int.from_bytes(self.words[index*32:(index+1)*32],'little')


def encode_wtns(words):
    if type(words) is not bytes or len(words)!=COUNT*32:raise SchemaError('witness_word_bytes')
    return (b'wtns'+struct.pack('<II',2,2)+struct.pack('<IQI',1,40,32)
            +PRIME.to_bytes(32,'little')+struct.pack('<I',COUNT)
            +struct.pack('<IQ',2,len(words))+words)


def parse_wtns(raw):
    if type(raw) is not bytes or len(raw)!=WTNS_BYTES:raise SchemaError('exact_wtns_size')
    if raw[:4]!=b'wtns' or struct.unpack_from('<II',raw,4)!=(2,2):raise SchemaError('wtns_version_sections')
    if struct.unpack_from('<IQI',raw,12)!=(1,40,32):raise SchemaError('wtns_header')
    if int.from_bytes(raw[28:60],'little')!=PRIME or struct.unpack_from('<I',raw,60)[0]!=COUNT:
        raise SchemaError('wtns_field_or_count')
    if struct.unpack_from('<IQ',raw,64)!=(2,COUNT*32):raise SchemaError('wtns_body_section')
    words=raw[76:]
    for offset in range(0,len(words),32):
        if int.from_bytes(words[offset:offset+32],'little')>=PRIME:raise SchemaError('noncanonical_witness_field')
    if int.from_bytes(words[:32],'little')!=1:raise SchemaError('constant_one')
    return CanonicalWitness(words)


@dataclass(frozen=True)
class SignalRow:
    name: str
    original_label: int
    witness_index: int


@dataclass(frozen=True)
class Trace:
    root: int
    values: object


@dataclass(frozen=True)
class FrozenProgram:
    c: tuple
    s: tuple
    m: tuple
    p: tuple
    retained: tuple
    aliases: object
    required_names: frozenset

    @classmethod
    def load(cls):
        loaded={}
        for name,(size,digest) in PINS.items():
            path=RESULTS/name
            for ancestor in (path,*path.parents):
                if ancestor.is_symlink():raise FixtureIdentityError('program_symlink')
            if path.stat().st_size!=size:raise FixtureIdentityError('program_size')
            raw=path.read_bytes()
            if hashlib.sha256(raw).hexdigest()!=digest:raise FixtureIdentityError('program_digest')
            loaded[name]=_json(raw,131072)
        tables=loaded['poseidon-t3-fixed-constants-001.json']['tables']
        c=tuple(_number(v) for v in tables['C']);s=tuple(_number(v) for v in tables['S'])
        m=tuple(tuple(_number(v) for v in row) for row in tables['M'])
        p=tuple(tuple(_number(v) for v in row) for row in tables['P'])
        if len(c)!=81 or len(s)!=285 or tuple(map(len,m))!=(3,3,3) or tuple(map(len,p))!=(3,3,3):
            raise FixtureIdentityError('fixed_table_shape')
        rows=tuple(SignalRow(row['name'],row['original_label'],row['witness_index'])
                   for row in loaded['far-source-symbols-001.json']['rows'])
        retained=tuple(row for row in rows if row.witness_index>=0)
        if len(rows)!=767 or sorted(row.witness_index for row in retained)!=list(range(643044,643562)):
            raise FixtureIdentityError('fixed_retained_mapping')
        resolved=loaded['compiled-far-aliases-001.json']['resolved']
        aliases=MappingProxyType({entry['name']:tuple((int(index),_number(value))
                                  for index,value in entry['canonical_expression'].items())
                                  for entry in resolved.values()})
        if len(aliases)!=251:raise FixtureIdentityError('fixed_alias_count')
        required=frozenset([*(row.name for row in rows),'main.nodes[10]','main.slotBits.out[9]'])
        return cls(c,s,m,p,retained,aliases,required)

    def trace(self,node,sibling,bit,expected_root):
        node,sibling,expected_root=(_number(value) for value in (node,sibling,expected_root))
        bit=_number(bit,2)
        values={};prefix='main.path[9].pEx.'
        def put(name,value):
            if name in values:raise SchemaError('duplicate_computed_signal')
            values[name]=value%PRIME
            return values[name]
        def vector(name,kind,data):
            return [put(prefix+f'{name}.{kind}[{j}]',value) for j,value in enumerate(data)]
        def sigma(name,value):
            put(prefix+name+'.in',value)
            v2=put(prefix+name+'.in2',value*value)
            v4=put(prefix+name+'.in4',v2*v2)
            return put(prefix+name+'.out',v4*value)
        def ark(r,data,start):
            vector(f'ark[{r}]','in',data)
            return vector(f'ark[{r}]','out',[(data[j]+self.c[start+j])%PRIME for j in range(3)])
        def mix(r,data,matrix):
            vector(f'mix[{r}]','in',data)
            return vector(f'mix[{r}]','out',[sum(matrix[j][i]*data[j] for j in range(3))%PRIME for i in range(3)])
        u0=(node+bit*(sibling-node))%PRIME;u1=(sibling+bit*(node-sibling))%PRIME
        put('main.path[9].inputs[0]',u0);put('main.path[9].inputs[1]',u1)
        put(prefix+'inputs[0]',u0);put(prefix+'inputs[1]',u1);put(prefix+'initialState',0)
        state=ark(0,[0,u0,u1],0)
        for r in range(3):
            state=[sigma(f'sigmaF[{r}][{j}]',value) for j,value in enumerate(state)]
            state=mix(r,ark(r+1,state,3*(r+1)),self.m)
        state=[sigma(f'sigmaF[3][{j}]',value) for j,value in enumerate(state)]
        state=mix(3,ark(4,state,12),self.p)
        for r in range(57):
            nonlinear=sigma(f'sigmaP[{r}]',state[0])
            inputs=[(nonlinear+self.c[15+r])%PRIME,state[1],state[2]]
            vector(f'mixS[{r}]','in',inputs)
            state=vector(f'mixS[{r}]','out',[
                sum(self.s[5*r+j]*inputs[j] for j in range(3))%PRIME,
                (inputs[1]+inputs[0]*self.s[5*r+3])%PRIME,
                (inputs[2]+inputs[0]*self.s[5*r+4])%PRIME])
        for r in range(3):
            state=[sigma(f'sigmaF[{4+r}][{j}]',value) for j,value in enumerate(state)]
            state=mix(4+r,ark(5+r,state,72+3*r),self.m)
        state=[sigma(f'sigmaF[7][{j}]',value) for j,value in enumerate(state)]
        vector('mixLast[0]','in',state)
        root=put(prefix+'mixLast[0].out',sum(self.m[j][0]*state[j] for j in range(3)))
        put(prefix+'out[0]',root);put('main.path[9].out',root)
        put('main.nodes[10]',root);put('main.slotBits.out[9]',bit)
        if set(values)!=self.required_names:raise SchemaError('complete_named_signal_coverage')
        if root!=expected_root:raise RootMismatch('supplied_public_root_mismatch')
        return Trace(root,MappingProxyType(values))

    def check_aliases(self,values,witness):
        if set(values)!=self.required_names:raise AliasMismatch('complete_named_alias_coverage')
        for name,expression in self.aliases.items():
            expected=sum(coefficient*witness.field(index) for index,coefficient in expression)%PRIME
            if values[name]!=expected:raise AliasMismatch('compiled_affine_alias_mismatch')
        return len(self.aliases)


@dataclass(frozen=True)
class FixturePins:
    before_input_sha256: str
    before_wtns_sha256: str


@dataclass(frozen=True)
class Delta:
    index: int
    addend: int


@dataclass(frozen=True)
class RefreshResult:
    wtns: bytes
    deltas: tuple
    named_values: object
    aliases_checked: int


def refresh_bound_fixture(program,before_input,target_input,before_wtns,pins):
    """Exact identity comparator, requiring externally trusted fixture pins.

    No validation boolean is accepted. Identity matches do not prove R1CS validity;
    the real trial driver additionally binds parent-reviewed validation evidence.
    """
    if type(pins) is not FixturePins or any(not re.fullmatch(r'[0-9a-f]{64}',value)
        for value in (pins.before_input_sha256,pins.before_wtns_sha256)):
        raise FixtureIdentityError('exact_fixture_pins')
    if type(before_input) is not bytes or type(before_wtns) is not bytes:
        raise FixtureIdentityError('fixture_bytes')
    if len(before_input)>INPUT_BYTES or len(before_wtns)!=WTNS_BYTES:
        raise FixtureIdentityError('fixture_size')
    if hashlib.sha256(before_input).hexdigest()!=pins.before_input_sha256 or hashlib.sha256(before_wtns).hexdigest()!=pins.before_wtns_sha256:
        raise FixtureIdentityError('fixture_digest')
    before,target=parse_inputs(before_input),parse_inputs(target_input)
    validate_scope(before,target)
    baseline=parse_wtns(before_wtns)
    for index,key in enumerate(PUBLIC_KEYS,1):
        if baseline.field(index)!=before[key]:raise FixtureIdentityError('baseline_public_correspondence')
    if baseline.field(353)!=before['slot']:raise FixtureIdentityError('baseline_slot_correspondence')
    for start,key in [(354,'siblings'),(364,'pathIndices')]:
        for offset,value in enumerate(before[key]):
            if baseline.field(start+offset)!=value:raise FixtureIdentityError('baseline_path_correspondence')
    node,bit=baseline.field(400),baseline.field(373)
    trace=program.trace(node,target['siblings'][9],bit,target['root'])
    patches={row.witness_index:trace.values[row.name] for row in program.retained}
    patches.update({1:target['root'],363:target['siblings'][9]})
    if set(patches)!=PATCH_SCOPE:raise SchemaError('exact_patch_scope')
    words=bytearray(baseline.words);deltas=[]
    for index,value in sorted(patches.items()):
        words[index*32:(index+1)*32]=value.to_bytes(32,'little')
        change=(value-baseline.field(index))%PRIME
        if change:deltas.append(Delta(index,change))
    candidate=CanonicalWitness(bytes(words))
    for index in range(COUNT):
        if index not in PATCH_SCOPE and baseline.words[index*32:(index+1)*32]!=candidate.words[index*32:(index+1)*32]:
            raise ScopeError('unaffected_coordinate_mutation')
    if candidate.field(0)!=1 or candidate.field(643562)!=baseline.field(643562):
        raise ScopeError('constant_or_final_coordinate_mutation')
    aliases=program.check_aliases(trace.values,candidate)
    for index,key in enumerate(PUBLIC_KEYS,1):
        if candidate.field(index)!=target[key]:raise RootMismatch('target_public_correspondence')
    return RefreshResult(encode_wtns(candidate.words),tuple(deltas),trace.values,aliases)


@dataclass(frozen=True)
class Comparison:
    equal: bool
    coordinates_checked: int
    mismatches: int


def compare_all_fields(candidate_wtns,oracle_wtns):
    candidate,oracle=parse_wtns(candidate_wtns),parse_wtns(oracle_wtns)
    mismatches=sum(candidate.words[offset:offset+32]!=oracle.words[offset:offset+32]
                   for offset in range(0,COUNT*32,32))
    return Comparison(mismatches==0,COUNT,mismatches)
