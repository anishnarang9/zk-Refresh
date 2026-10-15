//! Private JSON-RPC RESPONSE parser contract; no HTTP or authority factory.
//!
//! Both decoders deliberately return Unavailable until the focused RED is
//! accepted. GREEN must enforce the following BEFORE returning raw records:
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
use super::{Error, FinalizedBatch, FinalizedRequest};

const GENESIS_BODY_LIMIT: usize = 1024;
const ACCOUNTS_BODY_LIMIT: usize = 8 * 1024 * 1024;

fn decode_genesis_response(_body: &[u8], _expected_id: u64) -> Result<[u8;32],Error> {
    Err(Error::Unavailable)
}

fn decode_accounts_response(_body: &[u8], _expected_id: u64, _request: &FinalizedRequest)
    -> Result<FinalizedBatch,Error>
{
    Err(Error::Unavailable)
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
}
