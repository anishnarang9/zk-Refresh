//! Private loopback-only HTTP RED scaffold. No public transport injection and no
//! authority minting. ConfiguredVerifier::new remains closed. GREEN must use the
//! committed duplicate-aware parser, exact request IDs/ordered keys, and a fresh
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
use std::{sync::atomic::AtomicU64,time::Duration};

const CONNECT_TIMEOUT:Duration=Duration::from_millis(250);
const REQUEST_TIMEOUT:Duration=Duration::from_secs(2);
const REQUEST_LIMIT:usize=4096;
const GENESIS_LIMIT:usize=1024;
const ACCOUNTS_LIMIT:usize=8*1024*1024;

struct LoopbackRpc {
    endpoint:String,
    client:reqwest::blocking::Client,
    next_id:AtomicU64,
}
impl LoopbackRpc {
    fn new(_endpoint:&str)->Result<Self,Error> {Err(Error::Unavailable)}
}
impl Transport for LoopbackRpc {
    fn genesis(&self)->Result<[u8;32],Error> {Err(Error::Unavailable)}
    fn finalized_accounts(&self,_request:&FinalizedRequest)->Result<FinalizedBatch,Error> {Err(Error::Unavailable)}
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
