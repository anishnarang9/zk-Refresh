"""Exact fixed-circuit single-sibling suffix experiment, not a validation API.

Only a separately authenticated parent fixture receipt establishes trusted R1CS
baseline provenance. Caller-selected hashes alone do not establish satisfaction.
"""
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from types import MappingProxyType

from far_evaluator import (AliasMismatch, CanonicalWitness, COUNT, Delta,
    FixtureIdentityError, FixturePins, FrozenProgram, INPUT_BYTES, INPUT_KEYS,
    PRIME, PUBLIC_KEYS, RESULTS, RootMismatch, SchemaError, ScopeError, SignalRow,
    WTNS_BYTES, _json, _number, encode_wtns, parse_inputs, parse_wtns)
from trace_component import _trace

MAPPING=RESULTS/'path-suffix-mapping-output-002/mapping.json'
MAPPING_BYTES=2063440
MAPPING_SHA='b842dd6bbcce1765629dad6af9e2b7e1d318df73a356887922316a40ed92ad67'


def level_number(k):
    if type(k) is not int or not 0<=k<10:raise SchemaError('fixed_depth_level')
    return k


def expression(value):
    if type(value) is not dict or len(value)>1:raise FixtureIdentityError('fixed_alias_expression')
    terms=[]
    for index,coefficient in value.items():
        if type(index) is not str or re.fullmatch(r'0|[1-9][0-9]*',index) is None:
            raise FixtureIdentityError('canonical_alias_index')
        number=int(index)
        if not 0<=number<COUNT:raise FixtureIdentityError('alias_index_bound')
        if type(coefficient) is not int or coefficient!=1:raise FixtureIdentityError('fixed_alias_unit_coefficient')
        terms.append((number,coefficient))
    return tuple(terms)


@dataclass(frozen=True)
class Component:
    retained: tuple
    names: frozenset
    aliases: object
    output_name: str
    output_coordinate: int


@dataclass(frozen=True)
class SuffixProgram:
    core: object
    components: tuple
    node_indices: tuple
    sibling_indices: tuple
    selector_indices: tuple
    outer_aliases: object
    slot_index: int

    @classmethod
    def load(cls):
        for ancestor in (MAPPING,*MAPPING.parents):
            if ancestor.is_symlink():raise FixtureIdentityError('mapping_symlink')
        if MAPPING.stat().st_size!=MAPPING_BYTES:raise FixtureIdentityError('mapping_size')
        raw=MAPPING.read_bytes()
        if len(raw)!=MAPPING_BYTES or hashlib.sha256(raw).hexdigest()!=MAPPING_SHA:
            raise FixtureIdentityError('mapping_digest')
        document=_json(raw,3*1024*1024);core=FrozenProgram.load()
        if (document['status']!='complete_fixed_path_compiler_mapping'
            or document['assignment_coordinates']!=COUNT or document['all_resolved_aliases']!=2502
            or document['selected_aliases']!=2501 or document['auxiliary_stable_aliases']!=1
            or document['alias_exceptions'] or len(document['components'])!=10):
            raise FixtureIdentityError('accepted_mapping_dimensions')
        components=[];all_retained=set()
        for k,entry in enumerate(document['components']):
            if entry['level']!=k:raise FixtureIdentityError('component_order')
            rows=tuple(SignalRow(row['name'],row['original_label'],row['witness_index']) for row in entry['signals'])
            names=frozenset(row.name for row in rows)
            expected=frozenset(name.replace('main.path[9].',f'main.path[{k}].')
                for name in core.required_names if name.startswith('main.path[9].'))
            retained=tuple(row for row in rows if row.witness_index>=0)
            indices={row.witness_index for row in retained}
            if (len(rows)!=767 or names!=expected or len(retained)!=518 or len(indices)!=518
                or indices!=set(entry['retained_coordinates']) or indices&all_retained
                or any(type(index) is not int or not 1<=index<COUNT for index in indices)):
                raise FixtureIdentityError('component_retained_name_coverage')
            all_retained.update(indices)
            aliases={entry['name']:expression(entry['canonical_expression']) for entry in entry['aliases']}
            if len(entry['aliases'])!=249 or set(aliases)!={row.name for row in rows if row.witness_index<0}:
                raise FixtureIdentityError('component_eliminated_coverage')
            output=entry['output_node_coordinate'];output_name=entry['output_node_name']
            if output!=(392+k if k<9 else 1) or output_name!=f'main.nodes[{k+1}]':
                raise FixtureIdentityError('own_level_output')
            for name,value in aliases.items():
                if any(index not in indices|{0,output} for index,coefficient in value):
                    raise FixtureIdentityError('component_alias_scope')
            for name in (f'main.path[{k}].out',f'main.path[{k}].pEx.out[0]',f'main.path[{k}].pEx.mixLast[0].out'):
                if aliases[name]!=((output,1),):raise FixtureIdentityError('compiled_output_binding')
            components.append(Component(retained,names,MappingProxyType(aliases),output_name,output))
        outer={row['name']:row['witness_index'] for row in document['outer_signals']}
        nodes=tuple(outer[f'main.nodes[{k}]'] for k in range(10))
        siblings=tuple(outer[f'main.siblings[{k}]'] for k in range(10))
        selectors=tuple(outer[f'main.pathIndices[{k}]'] for k in range(10))
        if nodes!=tuple(range(391,401)) or siblings!=tuple(range(354,364)) or selectors!=tuple(range(364,374)) or outer['main.slot']!=353:
            raise FixtureIdentityError('fixed_outer_retained_binding')
        outer_aliases={entry['name']:expression(entry['canonical_expression']) for entry in document['outer_aliases']}
        expected_outer={**{f'main.slotBits.out[{k}]':((selectors[k],1),) for k in range(10)},
            'main.nodes[10]':((1,1),),'main.slotBits.in':((353,1),)}
        if len(document['outer_aliases'])!=12 or outer_aliases!=expected_outer:
            raise FixtureIdentityError('all_selected_and_auxiliary_outer_aliases')
        return cls(core,tuple(components),nodes,siblings,selectors,MappingProxyType(outer_aliases),353)

    def trace(self,k,node,sibling,bit):
        k=level_number(k);trace=_trace(self.core,k,node,sibling,bit)
        if set(trace.values)!=self.components[k].names|{f'main.nodes[{k+1}]',f'main.slotBits.out[{k}]'}:
            raise SchemaError('complete_component_named_coverage')
        return trace

    def scope(self,k):
        k=level_number(k)
        scope={1,self.sibling_indices[k]}
        for component in self.components[k:]:
            scope.update(row.witness_index for row in component.retained)
            scope.add(component.output_coordinate)
        if len(scope)!=519*(10-k)+1 or scope&{0,643562,self.node_indices[k]}:
            raise SchemaError('exact_compiler_suffix_scope')
        return frozenset(scope)

    def check_aliases(self,values,witness,k,slot):
        k=level_number(k);slot=_number(slot,1024)
        required=set()
        for level in range(k,10):
            required.update(self.components[level].names)
            required.update((f'main.nodes[{level+1}]',f'main.slotBits.out[{level}]'))
        if set(values)!=required:raise AliasMismatch('complete_suffix_named_coverage')
        checked=0
        def check(name,terms):
            expected=sum(coefficient*witness.field(index) for index,coefficient in terms)%PRIME
            if values[name]!=expected:raise AliasMismatch('compiled_suffix_affine_alias_mismatch')
        for level in range(k,10):
            component=self.components[level]
            for row in component.retained:check(row.name,((row.witness_index,1),))
            for name,terms in component.aliases.items():check(name,terms);checked+=1
            check(component.output_name,((component.output_coordinate,1),))
            name=f'main.slotBits.out[{level}]';check(name,self.outer_aliases[name]);checked+=1
        check('main.nodes[10]',self.outer_aliases['main.nodes[10]']);checked+=1
        auxiliary=sum(coefficient*witness.field(index) for index,coefficient in self.outer_aliases['main.slotBits.in'])%PRIME
        if auxiliary!=slot:raise AliasMismatch('compiled_auxiliary_slot_alias_mismatch')
        if checked!=250*(10-k)+1:raise AliasMismatch('suffix_alias_count')
        return checked,1


def validate_suffix_scope(before,target):
    if set(before)!=INPUT_KEYS or set(target)!=INPUT_KEYS:raise SchemaError('exact_scope_keys')
    for key in INPUT_KEYS-{'root','siblings'}:
        if before[key]!=target[key]:raise ScopeError('unsupported_input_change')
    changed=[level for level in range(10) if before['siblings'][level]!=target['siblings'][level]]
    if len(changed)!=1:raise ScopeError('exactly_one_changed_sibling')
    return changed[0]


@dataclass(frozen=True)
class SuffixResult:
    wtns: bytes
    deltas: tuple
    named_values: object
    aliases_checked: int
    auxiliary_aliases_checked: int
    changed_level: int
    scope: frozenset


def refresh_suffix(program,before_input,target_input,before_wtns,pins):
    """Identity-bound experiment; baseline R1CS trust is external to this helper."""
    if type(pins) is not FixturePins or any(type(value) is not str or re.fullmatch(r'[0-9a-f]{64}',value) is None
        for value in (pins.before_input_sha256,pins.before_wtns_sha256)):
        raise FixtureIdentityError('exact_fixture_pins')
    if type(before_input) is not bytes or type(before_wtns) is not bytes:
        raise FixtureIdentityError('fixture_bytes')
    if len(before_input)>INPUT_BYTES or len(before_wtns)!=WTNS_BYTES:raise FixtureIdentityError('fixture_size')
    if hashlib.sha256(before_input).hexdigest()!=pins.before_input_sha256 or hashlib.sha256(before_wtns).hexdigest()!=pins.before_wtns_sha256:
        raise FixtureIdentityError('fixture_digest')
    before,target=parse_inputs(before_input),parse_inputs(target_input);k=validate_suffix_scope(before,target)
    baseline=parse_wtns(before_wtns)
    for index,key in enumerate(PUBLIC_KEYS,1):
        if baseline.field(index)!=before[key]:raise FixtureIdentityError('baseline_public_correspondence')
    if baseline.field(program.slot_index)!=before['slot']:raise FixtureIdentityError('baseline_slot_correspondence')
    for indices,key in ((program.sibling_indices,'siblings'),(program.selector_indices,'pathIndices')):
        for index,value in zip(indices,before[key]):
            if baseline.field(index)!=value:raise FixtureIdentityError('baseline_path_correspondence')
    node=baseline.field(program.node_indices[k]);patches={};values={}
    for level in range(k,10):
        bit=baseline.field(program.selector_indices[level])
        trace=program.trace(level,node,target['siblings'][level],bit)
        if values.keys()&trace.values.keys():raise SchemaError('duplicate_suffix_named_signal')
        values.update(trace.values);component=program.components[level]
        for row in component.retained:patches[row.witness_index]=trace.values[row.name]
        patches[component.output_coordinate]=trace.root;node=trace.root
    if node!=target['root']:raise RootMismatch('supplied_public_root_mismatch')
    patches[program.sibling_indices[k]]=target['siblings'][k]
    scope=program.scope(k)
    if set(patches)!=scope:raise SchemaError('exact_suffix_patch_scope')
    words=bytearray(baseline.words);deltas=[]
    for index,value in sorted(patches.items()):
        words[index*32:(index+1)*32]=value.to_bytes(32,'little')
        change=(value-baseline.field(index))%PRIME
        if change:deltas.append(Delta(index,change))
    candidate=CanonicalWitness(bytes(words))
    for index in range(COUNT):
        if index not in scope and baseline.words[index*32:(index+1)*32]!=candidate.words[index*32:(index+1)*32]:
            raise ScopeError('unaffected_coordinate_mutation')
    if candidate.field(0)!=1 or candidate.field(643562)!=baseline.field(643562):
        raise ScopeError('constant_or_final_coordinate_mutation')
    selected,auxiliary=program.check_aliases(values,candidate,k,before['slot'])
    for index,key in enumerate(PUBLIC_KEYS,1):
        if candidate.field(index)!=target[key]:raise RootMismatch('target_public_correspondence')
    return SuffixResult(encode_wtns(candidate.words),tuple(deltas),MappingProxyType(values),selected,auxiliary,k,scope)
