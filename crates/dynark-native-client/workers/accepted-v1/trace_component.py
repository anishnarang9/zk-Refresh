"""Accepted t3 optimized arithmetic; only signal labels/output assertion moved."""
from types import MappingProxyType
from far_evaluator import PRIME, SchemaError, Trace, _number

def _trace(core,level,node,sibling,bit):
    node,sibling=(_number(value) for value in (node,sibling))
    bit=_number(bit,2)
    values={};prefix=f'main.path[{level}].pEx.'
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
        return vector(f'ark[{r}]','out',[(data[j]+core.c[start+j])%PRIME for j in range(3)])
    def mix(r,data,matrix):
        vector(f'mix[{r}]','in',data)
        return vector(f'mix[{r}]','out',[sum(matrix[j][i]*data[j] for j in range(3))%PRIME for i in range(3)])
    u0=(node+bit*(sibling-node))%PRIME;u1=(sibling+bit*(node-sibling))%PRIME
    put(f'main.path[{level}].inputs[0]',u0);put(f'main.path[{level}].inputs[1]',u1)
    put(prefix+'inputs[0]',u0);put(prefix+'inputs[1]',u1);put(prefix+'initialState',0)
    state=ark(0,[0,u0,u1],0)
    for r in range(3):
        state=[sigma(f'sigmaF[{r}][{j}]',value) for j,value in enumerate(state)]
        state=mix(r,ark(r+1,state,3*(r+1)),core.m)
    state=[sigma(f'sigmaF[3][{j}]',value) for j,value in enumerate(state)]
    state=mix(3,ark(4,state,12),core.p)
    for r in range(57):
        nonlinear=sigma(f'sigmaP[{r}]',state[0])
        inputs=[(nonlinear+core.c[15+r])%PRIME,state[1],state[2]]
        vector(f'mixS[{r}]','in',inputs)
        state=vector(f'mixS[{r}]','out',[
            sum(core.s[5*r+j]*inputs[j] for j in range(3))%PRIME,
            (inputs[1]+inputs[0]*core.s[5*r+3])%PRIME,
            (inputs[2]+inputs[0]*core.s[5*r+4])%PRIME])
    for r in range(3):
        state=[sigma(f'sigmaF[{4+r}][{j}]',value) for j,value in enumerate(state)]
        state=mix(4+r,ark(5+r,state,72+3*r),core.m)
    state=[sigma(f'sigmaF[7][{j}]',value) for j,value in enumerate(state)]
    vector('mixLast[0]','in',state)
    root=put(prefix+'mixLast[0].out',sum(core.m[j][0]*state[j] for j in range(3)))
    put(prefix+'out[0]',root);put(f'main.path[{level}].out',root)
    put(f'main.nodes[{level+1}]',root);put(f'main.slotBits.out[{level}]',bit)
    return Trace(root,MappingProxyType(values))
