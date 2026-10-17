//! Real deterministic Ed25519 envelopes over synthetic finalized account batches.
//! This establishes the join contract only, not an actual deployment or allocation.
use super::*;
use credential_registry::v3::protocol::{
    IssuerScope, Observation, PublisherBinding, Scope, SignedSource,
    SourceHead, SOURCE_SIGN_TAG, SOURCE_WIRE_TAG,
};
use openssl::{pkey::{Id, PKey, Private}, sign::Signer};

const SOURCE_SEED: [u8;32] = [51;32];
const PUBLISHER_SEED: [u8;32] = [52;32];

fn signing_key(seed:&[u8;32])->PKey<Private> {
    PKey::private_key_from_raw_bytes(seed,Id::ED25519).unwrap()
}
fn public_key(seed:&[u8;32])->[u8;32] {
    signing_key(seed).raw_public_key().unwrap().try_into().unwrap()
}
fn sign_source(source:&mut SignedSource) {
    let mut message=SOURCE_SIGN_TAG.to_vec();
    message.extend(serde_json::to_vec(&source.observation).unwrap());
    source.signature=Signer::new_without_digest(&signing_key(&SOURCE_SEED)).unwrap()
        .sign_oneshot_to_vec(&message).unwrap();
}
fn source_digest(source:&SignedSource)->[u8;32] {
    let mut wire=SOURCE_WIRE_TAG.to_vec();
    wire.extend(serde_json::to_vec(source).unwrap());
    Sha256::digest(wire).into()
}
#[derive(serde::Serialize)]
struct PublisherBody<'a> {
    scope:&'a Scope,issuer:&'a IssuerScope,source_head:&'a SourceHead,
    root:[u8;32],root_version:u64,publisher_key:[u8;32],publication_sequence:u64,
    previous_publication_digest:[u8;32],
}
fn sign_publisher(binding:&mut PublisherBinding) {
    let mut message=b"DYNARK-V3-PUBLISHER-BINDING-v1\0".to_vec();
    message.extend(serde_json::to_vec(&PublisherBody {
        scope:&binding.scope,issuer:&binding.issuer,source_head:&binding.source_head,
        root:binding.root,root_version:binding.root_version,publisher_key:binding.publisher_key,
        publication_sequence:binding.publication_sequence,
        previous_publication_digest:binding.previous_publication_digest,
    }).unwrap());
    binding.signature=Signer::new_without_digest(&signing_key(&PUBLISHER_SEED)).unwrap()
        .sign_oneshot_to_vec(&message).unwrap();
}
fn publisher_digest(binding:&PublisherBinding)->[u8;32] {
    let mut wire=b"DYNARK-V3-PUBLISHER-WIRE-v1\0".to_vec();
    wire.extend(serde_json::to_vec(binding).unwrap());
    Sha256::digest(wire).into()
}
fn envelope_fixture()->(CurrentFixture,SignedSource,PublisherBinding) {
    let mut f=current_fixture();
    let mut c=Config::decode(&f.deployment.batch.accounts[2].bytes).unwrap();
    let mut i=Issuer::decode(&f.deployment.batch.accounts[4].bytes).unwrap();
    let mut h=PublisherHead::decode(&f.deployment.batch.accounts[5].bytes).unwrap();
    c.publisher=Pubkey::new_from_array(public_key(&PUBLISHER_SEED));
    i.source=Pubkey::new_from_array(public_key(&SOURCE_SEED));
    f.selection.publisher=c.publisher;
    let scope=Scope {
        network:c.genesis,program:f.deployment.pins.program.to_bytes(),
        config:f.deployment.pins.config.to_bytes(),registry:f.deployment.batch.accounts[7].key.to_bytes(),
        profile:c.profile_id,circuit:c.circuit_id,schema:c.schema_id,package:c.package_id,
        ordinary_vk:c.ordinary_vk_digest,policy_hash:c.policy_id,policy_version:c.policy_version,
        config_eligibility_epoch:c.eligibility_epoch,
        leaf_domain:credential_registry::v3::LEAF_DOMAIN,depth:credential_registry::v3::DEPTH as u8,
    };
    let issuer=IssuerScope {
        issuer_account:f.deployment.batch.accounts[4].key.to_bytes(),issuer_hash:i.issuer_hash,
        source_key:i.source.to_bytes(),issuer_eligibility_epoch:i.eligibility_epoch,
        enrollment_evidence_version:i.enrollment_version,evidence_digest:i.evidence_digest,
    };
    let mut source=SignedSource {
        observation:Observation {
            scope:scope.clone(),issuer:issuer.clone(),sequence:i.sequence,previous_digest:[53;32],
            observed_at:i.observed_at,valid_until:i.expires_at,issuer_status_active:true,changes:vec![],
        },signature:vec![],
    };
    sign_source(&mut source);
    i.digest=source_digest(&source);
    i.bound_source_digest=i.digest;
    h.publisher=c.publisher;
    h.source_digest=i.digest;
    let mut publisher=PublisherBinding {
        scope,issuer,source_head:SourceHead {sequence:i.sequence,digest:i.digest},root:c.root,
        root_version:c.root_version,publisher_key:c.publisher.to_bytes(),
        publication_sequence:h.publication_sequence,previous_publication_digest:h.previous_publication_digest,
        signature:vec![],
    };
    sign_publisher(&mut publisher);
    h.envelope_digest=publisher_digest(&publisher);
    f.deployment.batch.accounts[2].bytes=c.encode();
    f.deployment.batch.accounts[4].bytes=i.encode();
    f.deployment.batch.accounts[5].key=runtime::publisher_head_address(
        &f.deployment.pins.program,&f.deployment.pins.config,&f.deployment.batch.accounts[4].key,&c.publisher).0;
    f.deployment.batch.accounts[5].bytes=h.encode();
    (f,source,publisher)
}

#[test]
fn detached_envelopes_join_exact_same_batch_at_root_version_zero() {
    let (f,source,publisher)=envelope_fixture();
    let current=run_current(f,1002).0.unwrap();
    assert_eq!(current.config().root_version,0);
    let joined=current.authenticate_detached_envelopes(&source,&publisher)
        .expect("matching real signatures and same-batch commitments");
    assert!(std::ptr::eq(joined.current(),&current));
    assert_eq!(joined.current().validated_at(),1002);
}

#[test]
fn detached_envelopes_reject_resigned_source_substitutions() {
    let (f,source,publisher)=envelope_fixture();
    let current=run_current(f,1002).0.unwrap();
    for mutate in [
        (|s:&mut SignedSource|s.observation.sequence+=1) as fn(&mut SignedSource),
        |s|s.observation.previous_digest[0]^=1,
        |s|s.observation.scope.registry[0]^=1,
        |s|s.observation.scope.config_eligibility_epoch+=1,
        |s|s.observation.issuer.source_key[0]^=1,
        |s|s.observation.issuer.issuer_eligibility_epoch+=1,
        |s|s.observation.issuer.enrollment_evidence_version+=1,
        |s|s.observation.issuer.evidence_digest[0]^=1,
        |s|s.observation.issuer_status_active=false,
        |s|s.observation.observed_at+=1,
        |s|s.observation.valid_until-=1,
    ] {
        let mut changed=source.clone();mutate(&mut changed);sign_source(&mut changed);
        assert_eq!(current.authenticate_detached_envelopes(&changed,&publisher).err(),Some(Error::Account));
    }
}

#[test]
fn detached_envelopes_reject_resigned_publisher_substitutions() {
    let (f,source,publisher)=envelope_fixture();
    let current=run_current(f,1002).0.unwrap();
    for mutate in [
        (|p:&mut PublisherBinding|p.root[31]^=1) as fn(&mut PublisherBinding),
        |p|p.root_version+=1,
        |p|p.publisher_key[0]^=1,
        |p|p.source_head.sequence+=1,
        |p|p.source_head.digest[0]^=1,
        |p|p.publication_sequence+=1,
        |p|p.previous_publication_digest[0]^=1,
        |p|p.scope.config_eligibility_epoch+=1,
        |p|p.issuer.issuer_eligibility_epoch+=1,
        |p|p.issuer.evidence_digest[0]^=1,
    ] {
        let mut changed=publisher.clone();mutate(&mut changed);sign_publisher(&mut changed);
        assert_eq!(current.authenticate_detached_envelopes(&source,&changed).err(),Some(Error::Account));
    }
    // Matching the hash of a new signature is still insufficient if its signed
    // root differs from the independently authenticated account root.
    let (mut f,source,mut changed)=envelope_fixture();
    changed.root[31]^=1;sign_publisher(&mut changed);
    let mut head=PublisherHead::decode(&f.deployment.batch.accounts[5].bytes).unwrap();
    head.envelope_digest=publisher_digest(&changed);
    f.deployment.batch.accounts[5].bytes=head.encode();
    let current=run_current(f,1002).0.unwrap();
    assert_eq!(current.authenticate_detached_envelopes(&source,&changed).err(),Some(Error::Account));
}

#[test]
fn detached_envelopes_reject_new_batch_evidence_and_changed_signatures() {
    let (mut f,source,publisher)=envelope_fixture();
    issuer_mutate(&mut f,|i|i.evidence_digest[0]^=1);
    let current=run_current(f,1002).0.unwrap();
    assert_eq!(current.authenticate_detached_envelopes(&source,&publisher).err(),Some(Error::Account));
    let (f,mut source,publisher)=envelope_fixture();
    let current=run_current(f,1002).0.unwrap();
    source.signature[0]^=1;
    assert_eq!(current.authenticate_detached_envelopes(&source,&publisher).err(),Some(Error::Account));
    let (f,source,mut publisher)=envelope_fixture();
    let current=run_current(f,1002).0.unwrap();
    publisher.signature[0]^=1;
    assert_eq!(current.authenticate_detached_envelopes(&source,&publisher).err(),Some(Error::Account));
}

#[test]
fn detached_envelope_context_rejects_expired_or_backward_batch_clock() {
    for now in [999,1100] {
        let (mut f,_,_)=envelope_fixture();
        if now==1100 {
            clock_mutate(&mut f.deployment,|clock|clock.unix_timestamp=1100);
        }
        assert_eq!(run_current(f,now).0.err(),Some(Error::Clock));
    }
    let (mut f,source,publisher)=envelope_fixture();
    issuer_mutate(&mut f,|i|i.expires_at+=1);
    let current=run_current(f,1002).0.unwrap();
    assert_eq!(current.authenticate_detached_envelopes(&source,&publisher).err(),Some(Error::Account));
}
