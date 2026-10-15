//! Private atomic-effect mechanics only. Synthetic program-owned bytes are not
//! authenticated deployment/current state, a holder proof, or authorization.
//! Execute dispatch must remain closed until a real request-bound Full gate.
use super::*;

const NOW:i64=100;
fn key(n:u8)->Pubkey {Pubkey::new_from_array([n;32])}
fn account(key:Pubkey,owner:Pubkey,bytes:Vec<u8>)->AccountInfo<'static> {
    AccountInfo::new(Box::leak(Box::new(key)),false,true,
        Box::leak(Box::new(100)),Box::leak(bytes.into_boxed_slice()),
        Box::leak(Box::new(owner)),false,0)
}
struct Fixture {request:AccountInfo<'static>,queue:AccountInfo<'static>}
impl Fixture {
    fn new()->Self {
        let program=key(12);let config=key(13);let creator=key(14);let nonce=[15;32];
        let request_key=request_address(&program,&config,&creator,&nonce).0;
        let queue_key=queue_address(&program,&config).0;
        let mut issuer_hash=[0;32];issuer_hash[31]=8;
        let request=Request {config,creator,nonce,issuer_hash,recipient:key(16),request_type:1,
            deadline:200,payload_len:4,uploaded:4,metas_uploaded:2,state:RequestState::Finalized,
            metas:vec![RelevantMeta {key:request_key,owner:program,flags:2},
                RelevantMeta {key:queue_key,owner:program,flags:2}],payload:b"work".to_vec()};
        let queue=Queue {config,entries:vec![key(70),key(71)]};
        assert_eq!(Request::decode(&request.encode()).unwrap(),request);
        assert_eq!(Queue::decode(&queue.encode()).unwrap(),queue);
        Self {request:account(request_key,program,request.encode()),queue:account(queue_key,program,queue.encode())}
    }
}
type Snapshot=(Pubkey,Pubkey,u64,bool,bool,bool,Vec<u8>);
fn snapshot(f:&Fixture)->Vec<Snapshot> {
    [&f.request,&f.queue].into_iter().map(|a|(*a.key,*a.owner,a.lamports(),
        a.is_signer,a.is_writable,a.executable,a.try_borrow_data().unwrap().to_vec())).collect()
}

#[test]
fn appends_request_once_and_consumes() {
    let f=Fixture::new();let before=snapshot(&f);
    let mut expected_request=Request::decode(&before[0].6).unwrap();
    let mut expected_queue=Queue::decode(&before[1].6).unwrap();
    expected_request.state=RequestState::Consumed;
    expected_queue.entries.push(*f.request.key);
    let result=apply_execute_effect(&f.request,&f.queue,NOW);
    assert_eq!(result,Ok(()),"intentional RED: private atomic effect remains Unavailable");
    let mut expected=before;
    expected[0].6=expected_request.encode();expected[1].6=expected_queue.encode();
    // Exact encoding equality retains every immutable request field, previous
    // queue entry, owner, key, lamport balance and account privilege bit.
    assert_eq!(snapshot(&f),expected);
    assert_eq!(Queue::decode(&f.queue.try_borrow_data().unwrap()).unwrap().entries
        .iter().filter(|key|**key==*f.request.key).count(),1);
}

#[test]
fn held_immutable_request_borrow_prevents_partial_queue_append() {
    let f=Fixture::new();let before=snapshot(&f);
    let held=f.request.try_borrow_data().unwrap();
    // Request shared reads (decoding/preparation) and queue mutable borrowing
    // remain possible. Only the eventual request destination borrow must fail.
    assert!(f.queue.try_borrow_mut_data().is_ok());
    let result=apply_execute_effect(&f.request,&f.queue,NOW);
    assert_eq!(snapshot(&f),before,"second destination borrow failure partially wrote state");
    assert_eq!(result,Err(ProgramError::AccountBorrowFailed));
    drop(held);
}
