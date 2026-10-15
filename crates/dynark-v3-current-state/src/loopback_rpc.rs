//! Private JSON-RPC RESPONSE parser contract; no HTTP or authority factory.
//!
//! The decoders enforce the following before returning raw records:
//! * body <=1KiB genesis /8MiB accounts, one complete JSON object, duplicate
//!   object keys rejected at every depth (Value alone loses duplicates);
//! * exactly jsonrpc="2.0", expected unsigned integer id and result; reject
//!   error, missing/unknown envelope fields, notifications and batch envelopes;
//! * genesis/owners canonical base58 decoding to exactly32 bytes;
//! * account result {context:{slot:u64,apiVersion?:string<=64},value:[...]};
//!   positive slot >= request minimum, exactly4 or8 distinct requested keys;
//! * account fields owner:string,executable:bool,data:[string,"base64"],
//!   lamports:u64,rentEpoch:u64,space?:u64; reject unknown/duplicate fields,
//!   null entries and noncanonical padded base64; space, if given, equals bytes;
//! * before base64 allocation bound encoded length by the position's maximum,
//!   then bound decoded length. Maxima: Program36, ProgramData45+4MiB,
//!   Config381, Clock40, Issuer374, PublisherHead280, Request2249, Queue2090.
//!
//! RPC account values do NOT include public keys. Assign requested keys by exact
//! index only; the configured server supplies that association. These parsers
//! cannot independently prove response ordering, finality, owner legitimacy,
//! deployment, codecs, PDAs, signatures or application authority. They return
//! private raw records for later verifier checks, never a capability.
#![allow(dead_code)]
use super::{Account, Error, FinalizedBatch, FinalizedRequest, Pubkey};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::de::{DeserializeSeed, Error as DeError, MapAccess, SeqAccess, Visitor};
use std::{borrow::Cow, collections::BTreeMap, fmt};

const GENESIS_BODY_LIMIT: usize = 1024;
const ACCOUNTS_BODY_LIMIT: usize = 8 * 1024 * 1024;
const ROLE_LIMITS: [usize;8] = [36,45+4*1024*1024,381,40,374,280,2249,2090];
const MAX_ENCODED: usize = (ROLE_LIMITS[1]+2)/3*4;

type Object<'de> = BTreeMap<Cow<'de,str>,Node<'de>>;
enum Node<'de> {
    Object(Object<'de>), Array(Vec<Node<'de>>), String(Cow<'de,str>),
    Uint(u64), Bool(bool), Other,
}
impl<'de> Node<'de> {
    fn object(&self)->Result<&Object<'de>,Error> {match self {Self::Object(v)=>Ok(v),_=>Err(Error::Transport)}}
    fn array(&self)->Result<&[Self],Error> {match self {Self::Array(v)=>Ok(v),_=>Err(Error::Transport)}}
    fn string(&self)->Result<&str,Error> {match self {Self::String(v)=>Ok(v),_=>Err(Error::Transport)}}
    fn uint(&self)->Result<u64,Error> {match self {Self::Uint(v)=>Ok(*v),_=>Err(Error::Transport)}}
    fn boolean(&self)->Result<bool,Error> {match self {Self::Bool(v)=>Ok(*v),_=>Err(Error::Transport)}}
}

// From-slice JSON borrows unescaped strings. Escaped strings may use serde's
// bounded-by-body scratch, then copy only after this explicit string bound.
struct StringSeed { max:usize }
impl<'de> DeserializeSeed<'de> for StringSeed {
    type Value=Cow<'de,str>;
    fn deserialize<D:serde::Deserializer<'de>>(self,d:D)->Result<Self::Value,D::Error> {
        struct Strings {max:usize}
        impl<'de> Visitor<'de> for Strings {
            type Value=Cow<'de,str>;
            fn expecting(&self,f:&mut fmt::Formatter)->fmt::Result {f.write_str("bounded string")}
            fn visit_borrowed_str<E:DeError>(self,v:&'de str)->Result<Self::Value,E> {
                if v.len()>self.max {return Err(E::custom("string bound"));} Ok(Cow::Borrowed(v))
            }
            fn visit_str<E:DeError>(self,v:&str)->Result<Self::Value,E> {
                if v.len()>self.max {return Err(E::custom("string bound"));} Ok(Cow::Owned(v.to_owned()))
            }
        }
        d.deserialize_str(Strings {max:self.max})
    }
}
struct Budget {nodes:usize}
struct NodeSeed<'a> {budget:&'a mut Budget,depth:usize}
impl<'de> DeserializeSeed<'de> for NodeSeed<'_> {
    type Value=Node<'de>;
    fn deserialize<D:serde::Deserializer<'de>>(self,d:D)->Result<Self::Value,D::Error> {
        if self.depth>12 || self.budget.nodes>=512 {return Err(D::Error::custom("JSON traversal bound"));}
        self.budget.nodes+=1;
        d.deserialize_any(NodeVisitor {budget:self.budget,depth:self.depth})
    }
}
struct NodeVisitor<'a> {budget:&'a mut Budget,depth:usize}
impl<'de> Visitor<'de> for NodeVisitor<'_> {
    type Value=Node<'de>;
    fn expecting(&self,f:&mut fmt::Formatter)->fmt::Result {f.write_str("bounded duplicate-free JSON")}
    fn visit_map<M:MapAccess<'de>>(self,mut map:M)->Result<Self::Value,M::Error> {
        let mut out=BTreeMap::new();
        while let Some(key)=map.next_key_seed(StringSeed {max:64})? {
            if out.len()>=16 || out.contains_key(&key) {return Err(M::Error::custom("object bound/duplicate key"));}
            let value=map.next_value_seed(NodeSeed {budget:&mut *self.budget,depth:self.depth+1})?;
            out.insert(key,value);
        }
        Ok(Node::Object(out))
    }
    fn visit_seq<S:SeqAccess<'de>>(self,mut seq:S)->Result<Self::Value,S::Error> {
        let mut out=Vec::new();
        while let Some(value)=seq.next_element_seed(NodeSeed {budget:&mut *self.budget,depth:self.depth+1})? {
            if out.len()>=8 {return Err(S::Error::custom("array bound"));} out.push(value);
        }
        Ok(Node::Array(out))
    }
    fn visit_borrowed_str<E:DeError>(self,v:&'de str)->Result<Self::Value,E> {
        if v.len()>MAX_ENCODED {return Err(E::custom("string bound"));} Ok(Node::String(Cow::Borrowed(v)))
    }
    fn visit_str<E:DeError>(self,v:&str)->Result<Self::Value,E> {
        if v.len()>MAX_ENCODED {return Err(E::custom("string bound"));} Ok(Node::String(Cow::Owned(v.to_owned())))
    }
    fn visit_u64<E:DeError>(self,v:u64)->Result<Self::Value,E> {Ok(Node::Uint(v))}
    fn visit_i64<E:DeError>(self,_v:i64)->Result<Self::Value,E> {Ok(Node::Other)}
    fn visit_f64<E:DeError>(self,_v:f64)->Result<Self::Value,E> {Ok(Node::Other)}
    fn visit_bool<E:DeError>(self,v:bool)->Result<Self::Value,E> {Ok(Node::Bool(v))}
    fn visit_unit<E:DeError>(self)->Result<Self::Value,E> {Ok(Node::Other)}
    fn visit_none<E:DeError>(self)->Result<Self::Value,E> {Ok(Node::Other)}
}

fn parse(body:&[u8],limit:usize)->Result<Node<'_>,Error> {
    if body.len()>limit {return Err(Error::Transport);}
    let mut decoder=serde_json::Deserializer::from_slice(body);
    let mut budget=Budget {nodes:0};
    let node=NodeSeed {budget:&mut budget,depth:0}.deserialize(&mut decoder).map_err(|_|Error::Transport)?;
    decoder.end().map_err(|_|Error::Transport)?;
    Ok(node)
}
fn fields(object:&Object<'_>,required:&[&str],optional:&[&str])->Result<(),Error> {
    if required.iter().any(|key|!object.contains_key(*key))
        || object.keys().any(|key|!required.contains(&key.as_ref()) && !optional.contains(&key.as_ref()))
    {return Err(Error::Transport);} Ok(())
}
fn get<'a,'de>(object:&'a Object<'de>,key:&str)->Result<&'a Node<'de>,Error> {
    object.get(key).ok_or(Error::Transport)
}
fn envelope<'a,'de>(root:&'a Node<'de>,id:u64)->Result<&'a Node<'de>,Error> {
    let object=root.object()?;
    fields(object,&["jsonrpc","id","result"],&[])?;
    if get(object,"jsonrpc")?.string()?!="2.0" || get(object,"id")?.uint()!=Ok(id) {return Err(Error::Transport);}
    get(object,"result")
}
fn base58_word(value:&str)->Result<[u8;32],Error> {
    if value.is_empty() || value.len()>44 {return Err(Error::Transport);}
    let mut out=[0;32];
    if bs58::decode(value).onto(&mut out[..]).map_err(|_|Error::Transport)?!=32
        || bs58::encode(out).into_string()!=value {return Err(Error::Transport);}
    Ok(out)
}

// Validate every character, required padding and unused bits before allocating
// decoded bytes. This also supplies the exact output bound to decode_slice.
fn base64_length(value:&str,limit:usize)->Result<usize,Error> {
    let bytes=value.as_bytes();
    if bytes.len()>(limit+2)/3*4 || bytes.len()%4!=0 {return Err(Error::Account);}
    let padding=if bytes.ends_with(b"==") {2} else if bytes.ends_with(b"=") {1} else {0};
    let data_len=bytes.len().checked_sub(padding).ok_or(Error::Account)?;
    let mut last=0;
    for &byte in &bytes[..data_len] {
        last=match byte {
            b'A'..=b'Z'=>byte-b'A', b'a'..=b'z'=>byte-b'a'+26,
            b'0'..=b'9'=>byte-b'0'+52, b'+'=>62, b'/'=>63, _=>return Err(Error::Account),
        };
    }
    if (padding==1 && last&3!=0) || (padding==2 && last&15!=0) {return Err(Error::Account);}
    let length=(bytes.len()/4*3).checked_sub(padding).ok_or(Error::Account)?;
    if length>limit {return Err(Error::Account);} Ok(length)
}

fn decode_genesis_response(body: &[u8], expected_id: u64) -> Result<[u8;32],Error> {
    let root=parse(body,GENESIS_BODY_LIMIT)?;
    base58_word(envelope(&root,expected_id)?.string()?)
}

fn decode_accounts_response(body: &[u8], expected_id: u64, request: &FinalizedRequest)
    -> Result<FinalizedBatch,Error>
{
    if !matches!(request.keys.len(),4|8)
        || request.keys.iter().enumerate().any(|(i,k)|request.keys[..i].contains(k))
    {return Err(Error::Transport);}
    let root=parse(body,ACCOUNTS_BODY_LIMIT)?;
    let result=envelope(&root,expected_id)?.object()?;
    fields(result,&["context","value"],&[])?;
    let context=get(result,"context")?.object()?;
    fields(context,&["slot"],&["apiVersion"])?;
    let slot=get(context,"slot")?.uint()?;
    if slot==0 || slot<request.minimum_context_slot {return Err(Error::Finality);}
    if let Some(version)=context.get("apiVersion") {if version.string()?.len()>64 {return Err(Error::Transport);}}
    let values=get(result,"value")?.array()?;
    if values.len()!=request.keys.len() {return Err(Error::Account);}
    // Validate all account shapes/canonical strings and sizes first. The second
    // pass allocates only bounded, already validated decoded byte buffers.
    let mut prepared=Vec::with_capacity(values.len());
    for (i,value) in values.iter().enumerate() {
        let object=value.object()?;
        fields(object,&["owner","executable","data","lamports","rentEpoch"],&["space"])?;
        let owner=Pubkey::new_from_array(base58_word(get(object,"owner")?.string()?)?);
        let executable=get(object,"executable")?.boolean()?;
        get(object,"lamports")?.uint()?;get(object,"rentEpoch")?.uint()?;
        let data=get(object,"data")?.array()?;
        if data.len()!=2 || data[1].string()?!="base64" {return Err(Error::Transport);}
        let encoded=data[0].string()?;
        let length=base64_length(encoded,ROLE_LIMITS[i])?;
        if let Some(space)=object.get("space") {if space.uint()?!=length as u64 {return Err(Error::Account);}}
        prepared.push((owner,executable,encoded,length));
    }
    let mut accounts=Vec::with_capacity(prepared.len());
    for (i,(owner,executable,encoded,length)) in prepared.into_iter().enumerate() {
        let mut bytes=vec![0;length];
        if STANDARD.decode_slice(encoded,&mut bytes).map_err(|_|Error::Account)?!=length {return Err(Error::Account);}
        accounts.push(Account {key:request.keys[i],owner,executable,bytes});
    }
    Ok(FinalizedBatch {context_slot:slot,accounts})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Commitment, Pubkey};
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde_json::{json, Value};
    use solana_program::clock::Clock;
    use zk_fresh_program::{application_v3::Config, generated_vk_v3 as identity};

    const ID:u64=42;
    fn key(n:u8)->Pubkey { Pubkey::new_from_array([n;32]) }
    fn field(n:u8)->[u8;32] { let mut b=[0;32]; b[31]=n; b }
    fn wire(v:&Value)->Vec<u8> { serde_json::to_vec(v).unwrap() }
    fn request(count:usize)->FinalizedRequest {
        FinalizedRequest { keys:(0..count).map(|n|key(n as u8+1)).collect(),
            commitment:Commitment::Finalized,minimum_context_slot:90 }
    }
    fn role_limits()->[usize;8] { [36,45+4*1024*1024,381,40,374,280,2249,2090] }
    fn account_bytes(count:usize)->Vec<Vec<u8>> {
        let config=Config {admin:key(12),seed:[13;32],publisher:key(14),genesis:[15;32],
            policy_id:field(16),policy_version:1,circuit_id:identity::CIRCUIT_ID,
            package_id:identity::PACKAGE_ID,schema_id:identity::SEMANTIC_SCHEMA_ID,
            profile_id:identity::PROFILE_ID,ordinary_vk_digest:identity::ORDINARY_VK_DIGEST,
            root:field(17),root_version:0,eligibility_epoch:2,enabled:true};
        assert_eq!(Config::decode(&config.encode()).unwrap(),config);
        let clock=Clock {slot:100,epoch_start_timestamp:800,epoch:3,
            leader_schedule_epoch:4,unix_timestamp:1000};
        // Other positions intentionally contain uninterpreted bounded bytes.
        // Parser success is NOT owning-program codec/deployment admission.
        let mut bytes=vec![vec![1;36],vec![2;49],config.encode(),bincode::serialize(&clock).unwrap()];
        if count==8 { bytes.extend([vec![5;374],vec![6;280],vec![7;2249],vec![8;2090]]); }
        bytes
    }
    fn response(count:usize)->Value {
        json!({"jsonrpc":"2.0","id":ID,"result":{"context":{"slot":100,"apiVersion":"2.3.0"},
            "value":account_bytes(count).into_iter().enumerate().map(|(i,b)|json!({
                "owner":key(80+i as u8).to_string(),"executable":i==0,
                "data":[STANDARD.encode(&b),"base64"],"lamports":1,"rentEpoch":0,"space":b.len()
            })).collect::<Vec<_>>()}})
    }
    fn rejected(body:&[u8],req:&FinalizedRequest,name:&str) {
        let error=decode_accounts_response(body,ID,req).err();
        assert!(matches!(error,Some(Error::Transport|Error::Account|Error::Finality)),
            "{name}: reject by validation, not Unavailable: {error:?}");
    }
    fn rejected_genesis(body:&[u8],name:&str) {
        assert!(matches!(decode_genesis_response(body,ID).err(),Some(Error::Transport|Error::Account)),
            "{name}: reject by validation, not Unavailable");
    }

    #[test]
    fn finalized_four_account_response_gate() {
        let req=request(4);
        let value=response(4);
        let expected=account_bytes(4);
        // The final assertion is the one intended RED: stub Unavailable vs
        // expected parsed context/count. No input-dependent panic in decoder.
        let result=decode_accounts_response(&wire(&value),ID,&req);
        assert_eq!(result.as_ref().map(|b|(b.context_slot,b.accounts.len())),Ok((100,4)),
            "intentional RED: bounded RPC account decoder is Unavailable");
        let parsed=result.unwrap();
        for (i,account) in parsed.accounts.iter().enumerate() {
            assert_eq!(account.key,req.keys[i]); assert_eq!(account.owner,key(80+i as u8));
            assert_eq!(account.bytes,expected[i]); assert_eq!(account.executable,i==0);
        }
    }

    #[test]
    fn genesis_and_eight_account_responses_are_raw_records_only() {
        let genesis=[9;32];
        let body=wire(&json!({"jsonrpc":"2.0","id":ID,"result":bs58::encode(genesis).into_string()}));
        assert_eq!(decode_genesis_response(&body,ID),Ok(genesis));
        let req=request(8);
        let parsed=decode_accounts_response(&wire(&response(8)),ID,&req).unwrap();
        assert_eq!(parsed.context_slot,100); assert_eq!(parsed.accounts.len(),8);
        for (i,a) in parsed.accounts.iter().enumerate() { assert_eq!(a.key,req.keys[i]); }
        let mut at_floor=response(4);at_floor["result"]["context"]["slot"]=json!(90);
        assert_eq!(decode_accounts_response(&wire(&at_floor),ID,&request(4)).unwrap().context_slot,90);
    }

    #[test]
    fn rejects_envelope_errors_duplicates_and_malformed_json() {
        let req=request(4);
        for (name,body) in [
            ("truncated",b"{".to_vec()),("array envelope",b"[]".to_vec()),
            ("null envelope",b"null".to_vec()),("trailing",[wire(&response(4)),b"{}".to_vec()].concat()),
            ("error",wire(&json!({"jsonrpc":"2.0","id":ID,"error":{"code":-32016,"message":"floor"}}))),
            ("duplicate envelope",wire(&response(4)).into_iter().collect::<Vec<_>>()),
        ] {
            if name=="duplicate envelope" {
                let mut duplicate=b"{\"id\":42,".to_vec(); duplicate.extend(&body[1..]);
                rejected(&duplicate,&req,name);
            } else { rejected(&body,&req,name); }
        }
        for (name,mutate) in [
            ("wrong version",( |v:&mut Value|v["jsonrpc"]=json!("1.0")) as fn(&mut Value)),
            ("wrong id",|v|v["id"]=json!(43)),("string id",|v|v["id"]=json!("42")),
            ("float id",|v|v["id"]=json!(42.0)),("null id",|v|v["id"]=Value::Null),
            ("missing result",|v|{v.as_object_mut().unwrap().remove("result");}),
            ("extra envelope key",|v|v["extra"]=json!(1)),
            ("result and error",|v|v["error"]=Value::Null),
            ("zero slot",|v|v["result"]["context"]["slot"]=json!(0)),
            ("below floor",|v|v["result"]["context"]["slot"]=json!(89)),
            ("float slot",|v|v["result"]["context"]["slot"]=json!(100.0)),
            ("negative slot",|v|v["result"]["context"]["slot"]=json!(-1)),
            ("missing context",|v|{v["result"].as_object_mut().unwrap().remove("context");}),
            ("long api version",|v|v["result"]["context"]["apiVersion"]=json!("x".repeat(65))),
        ] {let mut v=response(4);mutate(&mut v);rejected(&wire(&v),&req,name);}
        for (name,needle,replacement) in [
            ("duplicate result","\"result\":","\"result\":null,\"result\":"),
            ("duplicate context slot","\"slot\":100","\"slot\":100,\"slot\":100"),
            ("duplicate owner","\"owner\":","\"owner\":\"11111111111111111111111111111111\",\"owner\":"),
            ("duplicate unknown","\"slot\":100","\"x\":1,\"x\":2,\"slot\":100"),
        ] {
            let s=String::from_utf8(wire(&response(4))).unwrap(); assert!(s.contains(needle));
            rejected(s.replacen(needle,replacement,1).as_bytes(),&req,name);
        }
    }

    #[test]
    fn rejects_invalid_account_shapes_and_canonical_encodings() {
        let req=request(4);
        for (name,mutate) in [
            ("null account",(|v:&mut Value|v["result"]["value"][0]=Value::Null) as fn(&mut Value)),
            ("missing account",|v|{v["result"]["value"].as_array_mut().unwrap().pop();}),
            ("extra account",|v|{let a=v["result"]["value"][0].clone();v["result"]["value"].as_array_mut().unwrap().push(a);}),
            ("owner base58",|v|v["result"]["value"][0]["owner"]=json!("0bad")),
            ("owner short",|v|v["result"]["value"][0]["owner"]=json!("1")),
            ("owner too long",|v|v["result"]["value"][0]["owner"]=json!("1".repeat(45))),
            ("executable integer",|v|v["result"]["value"][0]["executable"]=json!(1)),
            ("wrong encoding",|v|v["result"]["value"][0]["data"][1]=json!("base64+zstd")),
            ("tuple too long",|v|v["result"]["value"][0]["data"]=json!(["AA==","base64",0])),
            ("tuple missing tag",|v|v["result"]["value"][0]["data"]=json!(["AA=="])),
            ("data string",|v|v["result"]["value"][0]["data"]=json!("AA==")),
            ("bad base64",|v|v["result"]["value"][0]["data"][0]=json!("%")),
            ("base64 whitespace",|v|v["result"]["value"][0]["data"][0]=json!("AA==\n")),
            ("base64 missing padding",|v|v["result"]["value"][0]["data"][0]=json!("AA")),
            ("base64 trailing bits",|v|v["result"]["value"][0]["data"][0]=json!("/x==")),
            ("wrong space",|v|v["result"]["value"][0]["space"]=json!(999)),
            ("negative lamports",|v|v["result"]["value"][0]["lamports"]=json!(-1)),
            ("float rent epoch",|v|v["result"]["value"][0]["rentEpoch"]=json!(0.0)),
            ("unknown field",|v|v["result"]["value"][0]["pubkey"]=json!(key(1).to_string())),
        ] {let mut v=response(4);mutate(&mut v);rejected(&wire(&v),&req,name);}
    }

    #[test]
    fn rejects_role_bounds_body_caps_and_invalid_request_shapes() {
        for (i,limit) in role_limits().into_iter().enumerate() {
            let mut v=response(8);
            v["result"]["value"][i]["data"][0]=json!(STANDARD.encode(vec![0;limit+1]));
            v["result"]["value"][i]["space"]=json!(limit+1);
            rejected(&wire(&v),&request(8),"decoded role overflow");
        }
        rejected(&vec![b' ';ACCOUNTS_BODY_LIMIT+1],&request(4),"body overflow");
        for count in [0,3,5,9] {rejected(&wire(&response(4)),&request(count),"invalid key count");}
        let mut req=request(4);req.keys[1]=req.keys[0];
        rejected(&wire(&response(4)),&req,"duplicate requested keys");
        let deep=format!("{}0{}","[".repeat(200),"]".repeat(200));
        rejected(deep.as_bytes(),&request(4),"excess nesting");
    }

    #[test]
    fn rejects_genesis_wire_errors_and_noncanonical_lengths() {
        for result in [json!("0bad"),json!("1"),json!("1".repeat(33)),json!([1,2,3]),Value::Null] {
            rejected_genesis(&wire(&json!({"jsonrpc":"2.0","id":ID,"result":result})),"genesis value");
        }
        rejected_genesis(&vec![b' ';GENESIS_BODY_LIMIT+1],"genesis body overflow");
        rejected_genesis(b"{\"jsonrpc\":\"2.0\",\"id\":42,\"id\":42,\"result\":\"11111111111111111111111111111111\"}","duplicate id");
        rejected_genesis(&wire(&json!({"jsonrpc":"2.0","id":43,"result":bs58::encode([9;32]).into_string()})),"wrong id");
        rejected_genesis(&wire(&json!({"jsonrpc":"2.0","id":ID,"error":{"code":-1}})),"RPC error");
    }

    #[test]
    fn rejects_escaped_duplicate_keys_and_unknown_nested_fields() {
        // A Value-only parser would silently overwrite these identical known
        // keys and pass shape checks: distinguish duplicate detection itself.
        for (needle,replacement) in [
            ("\"id\":42","\"id\":42,\"i\\u0064\":42"),
            ("\"slot\":100","\"slot\":100,\"sl\\u006ft\":100"),
        ] {
            let source=String::from_utf8(wire(&response(4))).unwrap();assert!(source.contains(needle));
            rejected(source.replacen(needle,replacement,1).as_bytes(),&request(4),"escaped duplicate");
        }
        for parent in ["result","context"] {
            let mut value=response(4);
            if parent=="result" {value["result"]["unknown"]=json!(1);}
            else {value["result"]["context"]["unknown"]=json!(1);}
            rejected(&wire(&value),&request(4),"unknown nested field");
        }
    }
}
