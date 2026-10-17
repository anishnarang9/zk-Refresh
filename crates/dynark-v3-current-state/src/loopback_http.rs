//! Private loopback-only HTTP transport. No public transport injection and no
//! authority minting. The public constructor selects only this private factory.
//! This uses the committed duplicate-aware parser, exact request IDs/ordered keys,
//! and a fresh
//! getGenesisHash + finalized getMultipleAccounts(minContextSlot) sequence.
//!
//! Endpoint contract: exactly http://127.0.0.1:PORT/, decimal port1..65535 with
//! no leading zero. No DNS, alternate IP spellings, userinfo, query or fragment.
//! reqwest policy: blocking-only HTTP1, no_proxy, redirects none, retry never,
//! no compression, no idle pooled connections;250ms connect/2s total per call.
//! No application retry, including429/RPC errors. Reject non200, wrong content
//! type/encoding, excessive Content-Length and streamed limit+1 overflow.
//! Response limits1KiB genesis/8MiB accounts; request<=4KiB. IDs strictly positive
//! monotone with checked overflow. Only4/8 distinct ordered requested keys.
#![allow(dead_code)]
use super::{Error, FinalizedBatch, FinalizedRequest, Transport};
use std::{io::Read,sync::atomic::{AtomicU64,Ordering},time::{Duration,Instant}};

const CONNECT_TIMEOUT:Duration=Duration::from_millis(250);
const REQUEST_TIMEOUT:Duration=Duration::from_secs(2);
const REQUEST_LIMIT:usize=4096;
const GENESIS_LIMIT:usize=1024;
const ACCOUNTS_LIMIT:usize=8*1024*1024;

/// The parent can select this implementation but cannot inject raw RPC records.
pub(super) fn configured_transport(endpoint:&str)->Result<Box<dyn Transport>,Error> {
    Ok(Box::new(LoopbackRpc::new(endpoint)?))
}

struct LoopbackRpc {
    endpoint:String,
    client:reqwest::blocking::Client,
    next_id:AtomicU64,
}
impl LoopbackRpc {
    fn new(endpoint:&str)->Result<Self,Error> {
        // Validate the original spelling before reqwest URL normalization can
        // turn shorthand/numeric/userinfo hosts into an apparently allowed URL.
        let text=endpoint.strip_prefix("http://127.0.0.1:")
            .and_then(|v|v.strip_suffix('/')).ok_or(Error::Transport)?;
        let port=text.parse::<u16>().map_err(|_|Error::Transport)?;
        if port==0 || text!=port.to_string() {return Err(Error::Transport);}
        let client=reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .http1_only()
            .no_gzip().no_brotli().no_zstd().no_deflate()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .pool_max_idle_per_host(0)
            .build().map_err(|_|Error::Transport)?;
        Ok(Self {endpoint:endpoint.into(),client,next_id:AtomicU64::new(1)})
    }

    fn call(&self,method:&str,params:serde_json::Value,limit:usize)->Result<(u64,Vec<u8>),Error> {
        let started=Instant::now();
        let id=self.next_id.fetch_update(Ordering::Relaxed,Ordering::Relaxed,|id|id.checked_add(1))
            .map_err(|_|Error::Transport)?;
        let body=serde_json::to_vec(&serde_json::json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
            .map_err(|_|Error::Transport)?;
        if body.len()>REQUEST_LIMIT {return Err(Error::Transport);}
        let remaining=REQUEST_TIMEOUT.checked_sub(started.elapsed()).filter(|v|!v.is_zero()).ok_or(Error::Transport)?;
        let mut response=self.client.post(&self.endpoint)
            .header(reqwest::header::CONTENT_TYPE,"application/json")
            .header(reqwest::header::ACCEPT,"application/json")
            .header(reqwest::header::ACCEPT_ENCODING,"identity")
            .header(reqwest::header::CONNECTION,"close")
            // Request-level timeout also sets reqwest's async total-body timer;
            // the blocking Client timeout alone can reset between Read calls.
            .timeout(remaining).body(body).send().map_err(|_|Error::Transport)?;
        if response.status()!=reqwest::StatusCode::OK {return Err(Error::Transport);}
        let headers=response.headers();
        let content_types=headers.get_all(reqwest::header::CONTENT_TYPE);
        if content_types.iter().count()!=1 {return Err(Error::Transport);}
        let content_type=content_types.iter().next().ok_or(Error::Transport)?;
        if content_type.as_bytes().len()>128
            || !content_type.to_str().map_err(|_|Error::Transport)?.split(';').next()
                .ok_or(Error::Transport)?.trim().eq_ignore_ascii_case("application/json")
        {return Err(Error::Transport);}
        let encodings=headers.get_all(reqwest::header::CONTENT_ENCODING);
        if encodings.iter().count()>1 {return Err(Error::Transport);}
        if let Some(encoding)=encodings.iter().next() {
            if !encoding.as_bytes().eq_ignore_ascii_case(b"identity") {return Err(Error::Transport);}
        }
        if response.content_length().is_some_and(|length|length>limit as u64) {return Err(Error::Transport);}
        let mut bytes=Vec::with_capacity(limit.min(8192));
        let mut buffer=[0u8;8192];
        loop {
            if started.elapsed()>=REQUEST_TIMEOUT {return Err(Error::Transport);}
            let available=(limit+1).checked_sub(bytes.len()).ok_or(Error::Transport)?.min(buffer.len());
            if available==0 {return Err(Error::Transport);}
            let count=response.read(&mut buffer[..available]).map_err(|_|Error::Transport)?;
            if started.elapsed()>=REQUEST_TIMEOUT {return Err(Error::Transport);}
            if count==0 {break;}
            if count>limit-bytes.len() {return Err(Error::Transport);}
            bytes.extend_from_slice(&buffer[..count]);
        }
        Ok((id,bytes))
    }
}
impl Transport for LoopbackRpc {
    fn genesis(&self)->Result<[u8;32],Error> {
        let (id,body)=self.call("getGenesisHash",serde_json::json!([]),GENESIS_LIMIT)?;
        super::loopback_rpc::decode_genesis_response(&body,id)
    }
    fn finalized_accounts(&self,request:&FinalizedRequest)->Result<FinalizedBatch,Error> {
        if !matches!(request.keys.len(),4|8) || request.commitment!=super::Commitment::Finalized
            || request.keys.iter().enumerate().any(|(i,k)|request.keys[..i].contains(k))
        {return Err(Error::Transport);}
        let keys=request.keys.iter().map(|key|key.to_string()).collect::<Vec<_>>();
        let (id,body)=self.call("getMultipleAccounts",serde_json::json!([keys,{
            "encoding":"base64","commitment":"finalized","minContextSlot":request.minimum_context_slot
        }]),ACCOUNTS_LIMIT)?;
        super::loopback_rpc::decode_accounts_response(&body,id,request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Commitment,Pubkey};
    use base64::{engine::general_purpose::STANDARD,Engine as _};
    use serde_json::{json,Value};
    use std::{io::{Read,Write},net::{TcpListener,TcpStream},sync::{Arc,Mutex,atomic::{AtomicBool,Ordering}},thread,time::Instant};

    #[derive(Clone)]
    struct Captured {first_line:String,headers:String,json:Value}
    #[derive(Clone)]
    enum Reply {
        Genesis, Accounts, Status(u16), Redirect(String), RpcError, WrongId,
        Oversize(bool), AccountsOversize, SlowHeaders, SlowBody, Encoding, Malformed,
    }
    struct Server {
        endpoint:String,stop:Arc<AtomicBool>,join:Option<thread::JoinHandle<()>>,
        captured:Arc<Mutex<Vec<Captured>>>,
    }
    impl Server {
        fn start(replies:Vec<Reply>)->Self {
            let listener=TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let endpoint=format!("http://127.0.0.1:{}/",listener.local_addr().unwrap().port());
            let stop=Arc::new(AtomicBool::new(false));let halted=stop.clone();
            let captured=Arc::new(Mutex::new(Vec::new()));let observed=captured.clone();
            let join=thread::spawn(move||{
                let deadline=Instant::now()+Duration::from_secs(8);
                while !halted.load(Ordering::Relaxed) && Instant::now()<deadline {
                    match listener.accept() {
                        Ok((mut stream,_))=>{
                            let _=stream.set_read_timeout(Some(Duration::from_millis(100)));
                            let _=stream.set_write_timeout(Some(Duration::from_millis(100)));
                            if let Some(request)=read_request(&mut stream,&halted) {
                                let id=request.json["id"].clone();
                                let index={let mut all=observed.lock().unwrap();let n=all.len();all.push(request);n};
                                if let Some(reply)=replies.get(index) {respond(&mut stream,reply,&id,&halted);}
                            }
                        },
                        Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>thread::sleep(Duration::from_millis(5)),
                        Err(_)=>break,
                    }
                }
            });
            Self {endpoint,stop,join:Some(join),captured}
        }
        fn requests(&self)->Vec<Captured> {self.captured.lock().unwrap().clone()}
    }
    impl Drop for Server {
        fn drop(&mut self) {
            self.stop.store(true,Ordering::Relaxed);
            if let Some(join)=self.join.take() {let _=join.join();}
        }
    }
    fn read_request(stream:&mut TcpStream,stop:&AtomicBool)->Option<Captured> {
        let deadline=Instant::now()+Duration::from_secs(3);
        let mut bytes=Vec::new();let mut buffer=[0;1024];
        while !stop.load(Ordering::Relaxed) && Instant::now()<deadline && bytes.len()<=16384 {
            match stream.read(&mut buffer) {
                Ok(0)=>return None,
                Ok(n)=>bytes.extend_from_slice(&buffer[..n]),
                Err(e) if matches!(e.kind(),std::io::ErrorKind::WouldBlock|std::io::ErrorKind::TimedOut)=>continue,
                Err(_)=>return None,
            }
            if let Some(at)=bytes.windows(4).position(|b|b==b"\r\n\r\n") {
                let headers=std::str::from_utf8(&bytes[..at]).ok()?;
                let length=headers.lines().find_map(|l|l.split_once(':').filter(|(k,_)|k.eq_ignore_ascii_case("content-length")).and_then(|(_,v)|v.trim().parse::<usize>().ok()))?;
                if length>REQUEST_LIMIT {return None;}
                if bytes.len()>=at+4+length {
                    let json=serde_json::from_slice(&bytes[at+4..at+4+length]).ok()?;
                    return Some(Captured {first_line:headers.lines().next()?.into(),headers:headers.into(),json});
                }
            }
        }
        None
    }
    fn pause(stop:&AtomicBool,duration:Duration) {
        let end=Instant::now()+duration;
        while Instant::now()<end && !stop.load(Ordering::Relaxed) {thread::sleep(Duration::from_millis(5));}
    }
    fn raw_accounts(id:&Value)->Value {
        let lengths=[36,49,381,40,374,280,2249,2090];
        json!({"jsonrpc":"2.0","id":id,"result":{"context":{"slot":100},"value":
            lengths.into_iter().enumerate().map(|(i,n)|json!({"owner":Pubkey::new_from_array([80+i as u8;32]).to_string(),
                "executable":i==0,"data":[STANDARD.encode(vec![i as u8;n]),"base64"],"lamports":1,"rentEpoch":0,"space":n})).collect::<Vec<_>>()}})
    }
    fn respond(stream:&mut TcpStream,reply:&Reply,id:&Value,stop:&AtomicBool) {
        let mut status=200;let mut extra=String::new();let mut chunked=false;
        let body=match reply {
            Reply::Genesis|Reply::SlowHeaders|Reply::SlowBody=>serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"result":bs58::encode([9;32]).into_string()})).unwrap(),
            Reply::Accounts=>serde_json::to_vec(&raw_accounts(id)).unwrap(),
            Reply::Status(code)=>{status=*code;b"{}".to_vec()},
            Reply::Redirect(target)=>{status=302;extra=format!("Location: {target}\r\n");b"{}".to_vec()},
            Reply::RpcError=>serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"error":{"code":429,"message":"no retry"}})).unwrap(),
            Reply::WrongId=>serde_json::to_vec(&json!({"jsonrpc":"2.0","id":999,"result":bs58::encode([9;32]).into_string()})).unwrap(),
            Reply::Oversize(chunks)=>{chunked=*chunks;vec![b' ';GENESIS_LIMIT+1]},
            Reply::AccountsOversize=>{chunked=true;vec![b' ';ACCOUNTS_LIMIT+1]},
            Reply::Encoding=>{extra="Content-Encoding: gzip\r\n".into();b"{}".to_vec()},
            Reply::Malformed=>b"{".to_vec(),
        };
        if matches!(reply,Reply::SlowHeaders) {pause(stop,Duration::from_millis(2300));}
        if stop.load(Ordering::Relaxed) {return;}
        let framing=if chunked {"Transfer-Encoding: chunked\r\n".into()} else {format!("Content-Length: {}\r\n",body.len())};
        let head=format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nConnection: close\r\n{extra}{framing}\r\n");
        if stream.write_all(head.as_bytes()).is_err() {return;}
        if matches!(reply,Reply::SlowBody) {pause(stop,Duration::from_millis(2300));}
        if stop.load(Ordering::Relaxed) {return;}
        if chunked {let _=write!(stream,"{:x}\r\n",body.len());let _=stream.write_all(&body);let _=stream.write_all(b"\r\n0\r\n\r\n");}
        else {let _=stream.write_all(&body);}
    }
    fn request()->FinalizedRequest {
        FinalizedRequest {keys:(1..=8).map(|n|Pubkey::new_from_array([n;32])).collect(),
            commitment:Commitment::Finalized,minimum_context_slot:90}
    }

    #[test]
    fn loopback_genesis_and_finalized_batch_gate() {
        let server=Server::start(vec![Reply::Genesis,Reply::Accounts]);
        let rpc=LoopbackRpc::new(&server.endpoint);
        let result=rpc.as_ref().map_err(|e|*e).and_then(|client|client.genesis());
        assert_eq!(result,Ok([9;32]),"intentional RED: private HTTP transport is Unavailable");
        let rpc=rpc.unwrap();let req=request();let batch=rpc.finalized_accounts(&req).unwrap();
        assert_eq!((batch.context_slot,batch.accounts.len()),(100,8));
        for (i,a) in batch.accounts.iter().enumerate() {assert_eq!(a.key,req.keys[i]);}
        let captured=server.requests();assert_eq!(captured.len(),2);
        for call in &captured {assert_eq!(call.first_line,"POST / HTTP/1.1");assert!(call.headers.to_ascii_lowercase().contains("content-type: application/json"));}
        assert_eq!(captured[0].json,json!({"jsonrpc":"2.0","id":1,"method":"getGenesisHash","params":[]}));
        assert_eq!(captured[1].json,json!({"jsonrpc":"2.0","id":2,"method":"getMultipleAccounts","params":[req.keys.iter().map(|k|k.to_string()).collect::<Vec<_>>(),
            {"encoding":"base64","commitment":"finalized","minContextSlot":90}]}));
    }

    #[test]
    fn public_constructor_routes_genesis_through_the_fixed_private_transport() {
        use crate::{ConfiguredVerifier, DeploymentPins};
        let server = Server::start(vec![Reply::Genesis]);
        let program = Pubkey::new_from_array([31;32]);
        let admin = Pubkey::new_from_array([32;32]);
        let seed = [33;32];
        let pins = DeploymentPins {
            endpoint:server.endpoint.clone(), genesis:[9;32], program,
            programdata:Pubkey::find_program_address(&[program.as_ref()],
                &solana_program::bpf_loader_upgradeable::id()).0,
            config:zk_fresh_program::application_runtime_v3::config_address(&program,&admin,&seed).0,
            admin, seed, elf_sha256:[34;32], elf_length:4,
            upgrade_authority:None, minimum_finalized_slot:90, maximum_clock_age_seconds:5,
        };
        // Constructor/transport evidence only: the synthetic image pin is not
        // loaded or admitted, and no current-state capability is requested.
        let configured = ConfiguredVerifier::new(pins).expect("fixed loopback constructor");
        assert_eq!(configured.transport.genesis(), Ok([9;32]));
        let calls = server.requests();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].json, json!({"jsonrpc":"2.0","id":1,"method":"getGenesisHash","params":[]}));
    }

    #[test]
    fn rejects_every_noncanonical_or_nonloopback_endpoint() {
        for endpoint in ["https://127.0.0.1:8899/","http://localhost:8899/","http://[::1]:8899/",
            "http://127.0.0.2:8899/","http://127.1:8899/","http://2130706433:8899/",
            "http://127.0.0.1:08899/","http://127.0.0.1:0/","http://127.0.0.1:65536/",
            "http://127.0.0.1/","http://127.0.0.1:8899","http://127.0.0.1:8899/rpc",
            "http://user@127.0.0.1:8899/","http://127.0.0.1:8899/?x=1","http://127.0.0.1:8899/#x"] {
            assert!(matches!(LoopbackRpc::new(endpoint).err(),Some(Error::Transport)),"{endpoint}");
        }
    }

    #[test]
    fn rejects_http_rpc_identity_encoding_and_body_failures_without_retry() {
        for reply in [Reply::Status(429),Reply::Status(500),Reply::RpcError,Reply::WrongId,
            Reply::Oversize(false),Reply::Oversize(true),Reply::Encoding,Reply::Malformed] {
            let server=Server::start(vec![reply]);let rpc=LoopbackRpc::new(&server.endpoint).unwrap();
            assert!(matches!(rpc.genesis().err(),Some(Error::Transport|Error::Account|Error::Finality)));
            assert_eq!(server.requests().len(),1,"transport retried");
        }
    }

    #[test]
    fn rejects_redirect_without_contacting_target() {
        let target=Server::start(vec![Reply::Genesis]);
        let server=Server::start(vec![Reply::Redirect(target.endpoint.clone())]);
        let rpc=LoopbackRpc::new(&server.endpoint).unwrap();
        assert_eq!(rpc.genesis().err(),Some(Error::Transport));
        assert_eq!(server.requests().len(),1);assert!(target.requests().is_empty());
    }

    #[test]
    fn total_timeout_covers_headers_and_streamed_body() {
        for reply in [Reply::SlowHeaders,Reply::SlowBody] {
            let server=Server::start(vec![reply]);let rpc=LoopbackRpc::new(&server.endpoint).unwrap();
            let start=Instant::now();assert_eq!(rpc.genesis().err(),Some(Error::Transport));
            assert!(start.elapsed()<Duration::from_secs(3),"2s total timeout was not applied");
            assert_eq!(server.requests().len(),1);
        }
    }

    #[test]
    fn rejects_streamed_account_batch_overflow() {
        let server=Server::start(vec![Reply::Genesis,Reply::AccountsOversize]);
        let rpc=LoopbackRpc::new(&server.endpoint).unwrap();assert_eq!(rpc.genesis(),Ok([9;32]));
        assert_eq!(rpc.finalized_accounts(&request()).err(),Some(Error::Transport));
        assert_eq!(server.requests().len(),2);
    }

    #[test]
    fn ignores_proxy_environment_without_contacting_proxy() {
        // ROOT runs this gate with one test thread. Restore every touched key
        // on unwind. Even a faulty implementation can only reach loopback here.
        struct Restore(Vec<(&'static str,Option<std::ffi::OsString>)>);
        impl Drop for Restore {
            fn drop(&mut self) {for (key,value) in &self.0 {match value {Some(v)=>std::env::set_var(key,v),None=>std::env::remove_var(key)}}}
        }
        let proxy=Server::start(vec![Reply::Status(502)]);
        let server=Server::start(vec![Reply::Genesis]);
        let keys=["HTTP_PROXY","http_proxy","ALL_PROXY","all_proxy","NO_PROXY","no_proxy"];
        let _restore=Restore(keys.iter().map(|key|(*key,std::env::var_os(key))).collect());
        for key in &keys[..4] {std::env::set_var(key,&proxy.endpoint);}
        for key in &keys[4..] {std::env::remove_var(key);}
        let rpc=LoopbackRpc::new(&server.endpoint).unwrap();assert_eq!(rpc.genesis(),Ok([9;32]));
        assert_eq!(server.requests().len(),1);assert!(proxy.requests().is_empty());
    }
}
