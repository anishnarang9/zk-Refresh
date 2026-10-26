//! Real signed-history tests against explicit expected heads. The expected
//! records are synthetic; only the production caller derives them from RPC.
use super::*;
use credential_registry::v3::protocol::{Change, IssuerScope, Observation, Scope, SOURCE_SIGN_TAG, SOURCE_WIRE_TAG};
use openssl::{pkey::{Id, PKey, Private}, sign::Signer};
use std::time::{Duration, Instant};

fn field(n:u8)->Digest {let mut b=[0;32];b[31]=n;b}
fn key(seed:u8)->PKey<Private> {PKey::private_key_from_raw_bytes(&[seed;32],Id::ED25519).unwrap()}
fn public(seed:u8)->Digest {key(seed).raw_public_key().unwrap().try_into().unwrap()}
fn source_sign(s:&mut SignedSource) {
    let mut message=SOURCE_SIGN_TAG.to_vec();message.extend(serde_json::to_vec(&s.observation).unwrap());
    s.signature=Signer::new_without_digest(&key(61)).unwrap().sign_oneshot_to_vec(&message).unwrap();
}
fn source_hash(s:&SignedSource)->Digest {
    let mut b=SOURCE_WIRE_TAG.to_vec();b.extend(serde_json::to_vec(s).unwrap());Sha256::digest(b).into()
}
#[derive(serde::Serialize)]
struct PublisherBody<'a> {
    scope:&'a Scope,issuer:&'a IssuerScope,source_head:&'a credential_registry::v3::protocol::SourceHead,
    root:Digest,root_version:u64,publisher_key:Digest,publication_sequence:u64,previous_publication_digest:Digest,
}
fn publisher_sign(p:&mut PublisherBinding) {
    let mut b=b"DYNARK-V3-PUBLISHER-BINDING-v1\0".to_vec();
    b.extend(serde_json::to_vec(&PublisherBody {scope:&p.scope,issuer:&p.issuer,source_head:&p.source_head,
        root:p.root,root_version:p.root_version,publisher_key:p.publisher_key,
        publication_sequence:p.publication_sequence,previous_publication_digest:p.previous_publication_digest}).unwrap());
    p.signature=Signer::new_without_digest(&key(62)).unwrap().sign_oneshot_to_vec(&b).unwrap();
}
fn publisher_hash(p:&PublisherBinding)->Digest {
    let mut b=b"DYNARK-V3-PUBLISHER-WIRE-v1\0".to_vec();b.extend(serde_json::to_vec(p).unwrap());Sha256::digest(b).into()
}
fn fixture()->(EnrolledSource,Vec<SignedSource>,Vec<PublisherBinding>,ReplayHead) {
    let manifest=crate::V3FullManifest::frozen_development().unwrap();
    let enrolled=EnrolledSource {
        scope:Scope {network:[1;32],program:[2;32],config:[3;32],registry:[4;32],profile:manifest.admission.profile,
            circuit:manifest.package.circuit_digest,schema:manifest.admission.semantic_schema,
            package:manifest.package.package_digest,ordinary_vk:crate::decode_digest("2f9b770ff51ac399619a3127ddb32efad67697402f10c4549441a3578e4f9a4e").unwrap(),
            policy_hash:field(10),policy_version:1,config_eligibility_epoch:1,
            leaf_domain:credential_registry::v3::LEAF_DOMAIN,depth:10},
        issuer:IssuerScope {issuer_account:[5;32],issuer_hash:field(9),source_key:public(61),
            issuer_eligibility_epoch:1,enrollment_evidence_version:1,evidence_digest:[6;32]},
        config_enabled:true,issuer_enabled:true,max_age_seconds:300,
    };
    let mut source=SignedSource {observation:Observation {scope:enrolled.scope.clone(),issuer:enrolled.issuer.clone(),
        sequence:1,previous_digest:[0;32],observed_at:100,valid_until:200,issuer_status_active:true,
        changes:vec![Change::Issue{tbs_digest:[11;32],slot:7,allocation_epoch:1}]},signature:vec![]};
    source_sign(&mut source);
    let mut tree=credential_registry::v3::Tree::new().unwrap();tree.set(7,[11;32],true).unwrap();
    let mut publisher=PublisherBinding {scope:enrolled.scope.clone(),issuer:enrolled.issuer.clone(),
        source_head:credential_registry::v3::protocol::SourceHead{sequence:1,digest:source_hash(&source)},
        root:tree.root(),root_version:0,publisher_key:public(62),publication_sequence:1,
        previous_publication_digest:[0;32],signature:vec![]};publisher_sign(&mut publisher);
    let head=ReplayHead{root:publisher.root,root_version:0,source_sequence:1,source_digest:source_hash(&source),
        publication_sequence:1,publication_digest:publisher_hash(&publisher)};
    (enrolled,vec![source],vec![publisher],head)
}
fn checkpoints<'a>(s:&'a [SignedSource],p:&'a [PublisherBinding])->Vec<V3SignedHistoryCheckpoint<'a>> {
    s.iter().zip(p).enumerate().map(|(n,(source,publisher))|V3SignedHistoryCheckpoint{source,publisher,checked_at:150+n as i64}).collect()
}
fn control()->OperationControl {OperationControl::new(Instant::now()+Duration::from_secs(10))}

#[test]
fn signed_history_joins_exact_head_and_attested_allocation() {
    let (enrolled,s,p,head)=fixture();let cp=checkpoints(&s,&p);
    let membership=replay_current_membership(enrolled,public(62),&cp,&head,[11;32],7,1,&control()).unwrap();
    assert_eq!((membership.tbs_digest(),membership.slot(),membership.allocation_epoch()),([11;32],7,1));
    assert_eq!((membership.root(),membership.root_version()),(head.root,0));
}
#[test]
fn resigned_same_root_with_different_epoch_cannot_replace_current_history() {
    let (enrolled,mut s,mut p,head)=fixture();
    if let Change::Issue{allocation_epoch,..}=&mut s[0].observation.changes[0]{*allocation_epoch=99;}else{panic!("Issue fixture")}
    source_sign(&mut s[0]);p[0].source_head.digest=source_hash(&s[0]);publisher_sign(&mut p[0]);
    assert_eq!(p[0].root,head.root,"allocation epoch is not in the tree leaf");
    let cp=checkpoints(&s,&p);
    assert!(matches!(replay_current_membership(enrolled,public(62),&cp,&head,[11;32],7,99,&control()),Err(ClientError::Superseded)));
}
#[test]
fn history_head_substitution_and_cancelled_work_fail() {
    let (enrolled,s,p,head)=fixture();let cp=checkpoints(&s,&p);
    for field in 0..4 {let mut wrong=head.clone();match field {0=>wrong.source_digest[0]^=1,1=>wrong.publication_digest[0]^=1,
        2=>wrong.root_version+=1,_=>wrong.publication_sequence+=1}
        assert!(matches!(replay_current_membership(enrolled.clone(),public(62),&cp,&wrong,[11;32],7,1,&control()),Err(ClientError::Superseded)));}
    let stopped=control();stopped.cancel();
    assert!(matches!(replay_current_membership(enrolled,public(62),&cp,&head,[11;32],7,1,&stopped),Err(ClientError::Cancelled)));
}
#[test]
fn own_revocation_never_produces_current_active_membership() {
    let (enrolled,mut s,mut p,mut head)=fixture();
    let mut next=s[0].clone();next.observation.sequence=2;next.observation.previous_digest=head.source_digest;
    next.observation.observed_at=101;next.observation.changes=vec![Change::Revoke{tbs_digest:[11;32]}];source_sign(&mut next);
    let mut tree=credential_registry::v3::Tree::new().unwrap();tree.set(7,[11;32],false).unwrap();
    let mut next_p=p[0].clone();next_p.source_head.sequence=2;next_p.source_head.digest=source_hash(&next);
    next_p.root=tree.root();next_p.root_version=1;next_p.publication_sequence=2;
    next_p.previous_publication_digest=head.publication_digest;publisher_sign(&mut next_p);
    head=ReplayHead{root:next_p.root,root_version:1,source_sequence:2,source_digest:source_hash(&next),
        publication_sequence:2,publication_digest:publisher_hash(&next_p)};
    s.push(next);p.push(next_p);let cp=checkpoints(&s,&p);
    assert!(matches!(replay_current_membership(enrolled,public(62),&cp,&head,[11;32],7,1,&control()),Err(ClientError::Revoked)));
}

#[test]
fn final_time_guard_rejects_expiry_crossed_during_rpc_and_witness_work() {
    assert_eq!(final_timestamp_guard(100, 101, 120, 130, 140), Ok(()));
    assert_eq!(final_timestamp_guard(100, 99, 120, 130, 140), Err(ClientError::Deadline));
    assert_eq!(final_timestamp_guard(100, 120, 120, 130, 140), Err(ClientError::StaleIssuer));
    assert_eq!(final_timestamp_guard(100, 130, 140, 130, 150), Err(ClientError::Expired));
    assert_eq!(final_timestamp_guard(100, 140, 150, 160, 140), Err(ClientError::Expired));
}

#[test]
fn history_check_time_cannot_exceed_current_verified_batch_time() {
    let (_, s, p, _) = fixture();
    let cp = checkpoints(&s, &p);
    assert_eq!(reject_future_history(&cp, 150), Ok(()));
    assert_eq!(reject_future_history(&cp, 149), Err(ClientError::Deadline));
}
