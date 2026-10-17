//! Independent v3 local transaction encodings for the bounded queue demo.
//! Constructing an instruction or PDA does not authenticate current chain state.
use super::*;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V3QueuePlan {
    pub program: [u8; 32],
    pub genesis: [u8; 32],
    pub admin: [u8; 32],
    pub publisher: [u8; 32],
    pub source: [u8; 32],
    pub creator: [u8; 32],
    pub seed: [u8; 32],
    pub nonce: [u8; 32],
    pub recipient: [u8; 32],
    pub issuer_hash: [u8; 32],
    pub aki: [u8; 32],
    pub root: [u8; 32],
    pub policy_id: [u8; 32],
    pub deadline: i64,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V3Addresses {
    pub config: Pubkey,
    pub issuer: Pubkey,
    pub head: Pubkey,
    pub request: Pubkey,
    pub queue: Pubkey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V3HeadBinding {
    pub expected_config_epoch: u64,
    pub expected_issuer_epoch: u64,
    pub expected_root: [u8; 32],
    pub expected_root_version: u64,
    pub expected_source_sequence: u64,
    pub expected_source_digest: [u8; 32],
    pub expected_publication_sequence: u64,
    pub expected_publication_digest: [u8; 32],
    pub next_publication_sequence: u64,
    pub envelope_digest: [u8; 32],
}

impl V3QueuePlan {
    pub fn addresses(&self) -> V3Addresses {
        let program = Pubkey::new_from_array(self.program);
        let config =
            Pubkey::find_program_address(&[b"dyn-config-v3", &self.admin, &self.seed], &program).0;
        let issuer = Pubkey::find_program_address(
            &[b"dyn-issuer-v3", config.as_ref(), &self.issuer_hash],
            &program,
        )
        .0;
        let head = Pubkey::find_program_address(
            &[
                b"dyn-pubhead-v3",
                config.as_ref(),
                issuer.as_ref(),
                &self.publisher,
            ],
            &program,
        )
        .0;
        let request = Pubkey::find_program_address(
            &[
                b"dyn-request-v3",
                config.as_ref(),
                &self.creator,
                &self.nonce,
            ],
            &program,
        )
        .0;
        let queue = Pubkey::find_program_address(&[b"dyn-queue-v3", config.as_ref()], &program).0;
        V3Addresses {
            config,
            issuer,
            head,
            request,
            queue,
        }
    }

    fn instruction(&self, opcode: u8, body: Vec<u8>, accounts: Vec<AccountMeta>) -> Instruction {
        let mut data = vec![0x51, opcode];
        data.extend(body);
        Instruction {
            program_id: Pubkey::new_from_array(self.program),
            accounts,
            data,
        }
    }

    pub fn initialize(&self) -> Instruction {
        let a = self.addresses();
        let mut body = Vec::with_capacity(324);
        for value in [self.seed, self.publisher, self.genesis, self.policy_id] {
            body.extend(value);
        }
        body.extend(1u32.to_be_bytes());
        for value in [
            "eae99530daf7331037f2d1c6dc93ccc582603bd448f38d06e6469c734e8252fe",
            "61d941890d823433468048dd1bd91da80c1bf7e1b3d2b6f5d509077a47ed06c8",
            "eabfaa2d95e4abc9126b87a04e94397091c103891e92dbaefaafba79cf3b26d4",
            "2e5d26564fb055e70cff924c4cb6e296509030b8c0062130f86ad5af783f7918",
            "2f9b770ff51ac399619a3127ddb32efad67697402f10c4549441a3578e4f9a4e",
        ] {
            body.extend(hex::decode(value).expect("frozen reviewed v3 identity"));
        }
        body.extend(self.root);
        self.instruction(
            0,
            body,
            vec![
                AccountMeta::new(Pubkey::new_from_array(self.admin), true),
                AccountMeta::new(a.config, false),
                AccountMeta::new(a.queue, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
        )
    }

    pub fn enroll(&self, enrollment_version: u64, evidence_digest: [u8; 32]) -> Instruction {
        let a = self.addresses();
        let mut body = Vec::with_capacity(136);
        body.extend(self.issuer_hash);
        body.extend(self.aki);
        body.extend(self.source);
        body.extend(enrollment_version.to_be_bytes());
        body.extend(evidence_digest);
        self.instruction(
            1,
            body,
            vec![
                AccountMeta::new(Pubkey::new_from_array(self.admin), true),
                AccountMeta::new_readonly(a.config, false),
                AccountMeta::new(a.issuer, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
        )
    }

    pub fn observe(
        &self,
        config_epoch: u64,
        issuer_epoch: u64,
        expected_sequence: u64,
        next_sequence: u64,
        digest: [u8; 32],
        active: bool,
        observed: i64,
        expires: i64,
    ) -> Instruction {
        let a = self.addresses();
        let mut body = Vec::with_capacity(81);
        for value in [config_epoch, issuer_epoch, expected_sequence, next_sequence] {
            body.extend(value.to_be_bytes());
        }
        body.extend(digest);
        body.push(u8::from(active));
        body.extend(observed.to_be_bytes());
        body.extend(expires.to_be_bytes());
        self.instruction(
            3,
            body,
            vec![
                AccountMeta::new_readonly(Pubkey::new_from_array(self.source), true),
                AccountMeta::new_readonly(a.config, false),
                AccountMeta::new(a.issuer, false),
            ],
        )
    }

    pub fn bind_with_head(&self, binding: &V3HeadBinding) -> Instruction {
        let a = self.addresses();
        let mut body = vec![1];
        body.extend(binding.expected_config_epoch.to_be_bytes());
        body.extend(binding.expected_issuer_epoch.to_be_bytes());
        body.extend(binding.expected_root);
        body.extend(binding.expected_root_version.to_be_bytes());
        body.extend(binding.expected_source_sequence.to_be_bytes());
        body.extend(binding.expected_source_digest);
        body.extend(binding.expected_publication_sequence.to_be_bytes());
        body.extend(binding.expected_publication_digest);
        body.extend(binding.next_publication_sequence.to_be_bytes());
        body.extend(binding.envelope_digest);
        self.instruction(
            13,
            body,
            vec![
                AccountMeta::new(Pubkey::new_from_array(self.publisher), true),
                AccountMeta::new_readonly(a.config, false),
                AccountMeta::new(a.issuer, false),
                AccountMeta::new(a.head, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
        )
    }

    pub fn create(&self) -> Result<Instruction> {
        ensure!(
            self.payload.len() <= 1024 && self.deadline > 0,
            "bounded request required"
        );
        let a = self.addresses();
        let mut body = Vec::with_capacity(109);
        body.extend(self.nonce);
        body.extend(self.issuer_hash);
        body.extend(self.recipient);
        body.extend(1u16.to_be_bytes());
        body.extend(self.deadline.to_be_bytes());
        body.extend((self.payload.len() as u16).to_be_bytes());
        body.push(2);
        Ok(self.instruction(
            4,
            body,
            vec![
                AccountMeta::new(Pubkey::new_from_array(self.creator), true),
                AccountMeta::new_readonly(a.config, false),
                AccountMeta::new_readonly(a.issuer, false),
                AccountMeta::new(a.request, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
        ))
    }

    fn edit_accounts(&self) -> Vec<AccountMeta> {
        let a = self.addresses();
        vec![
            AccountMeta::new_readonly(Pubkey::new_from_array(self.creator), true),
            AccountMeta::new_readonly(a.config, false),
            AccountMeta::new(a.request, false),
        ]
    }

    pub fn upload_payload(&self, offset: usize, chunk: &[u8]) -> Result<Instruction> {
        ensure!(
            offset <= 1024
                && !chunk.is_empty()
                && chunk.len() <= 512
                && offset + chunk.len() <= self.payload.len()
                && chunk == &self.payload[offset..offset + chunk.len()],
            "bounded upload chunk required"
        );
        let mut body = Vec::with_capacity(4 + chunk.len());
        body.extend((offset as u16).to_be_bytes());
        body.extend((chunk.len() as u16).to_be_bytes());
        body.extend(chunk);
        Ok(self.instruction(6, body, self.edit_accounts()))
    }

    pub fn upload_metas(&self) -> Instruction {
        let a = self.addresses();
        let mut body = vec![0, 2];
        for key in [a.request, a.queue] {
            body.extend(key.to_bytes());
            body.push(2);
            body.extend(self.program);
        }
        self.instruction(8, body, self.edit_accounts())
    }

    pub fn finalize(&self) -> Instruction {
        self.instruction(5, Vec::new(), self.edit_accounts())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zk_fresh_program::{application_runtime_v3 as runtime, application_v3::AppInstruction};

    fn plan() -> V3QueuePlan {
        V3QueuePlan {
            program: [12; 32],
            genesis: [1; 32],
            admin: [18; 32],
            publisher: [19; 32],
            source: [20; 32],
            creator: [21; 32],
            seed: [7; 32],
            nonce: [16; 32],
            recipient: [17; 32],
            issuer_hash: {
                let mut b = [0; 32];
                b[31] = 8;
                b
            },
            aki: {
                let mut b = [0; 32];
                b[..20].fill(8);
                b
            },
            root: {
                let mut b = [0; 32];
                b[31] = 6;
                b
            },
            policy_id: {
                let mut b = [0; 32];
                b[31] = 5;
                b
            },
            deadline: 500,
            payload: vec![0, 1, 2, 3],
        }
    }
    #[test]
    fn independent_pd_as_and_admin_instructions_match_v3_parser() {
        let p = plan();
        let a = p.addresses();
        let program = Pubkey::new_from_array(p.program);
        assert_eq!(
            a.config,
            runtime::config_address(&program, &Pubkey::new_from_array(p.admin), &p.seed).0
        );
        assert_eq!(
            a.issuer,
            runtime::issuer_address(&program, &a.config, &p.issuer_hash).0
        );
        assert_eq!(
            a.head,
            runtime::publisher_head_address(
                &program,
                &a.config,
                &a.issuer,
                &Pubkey::new_from_array(p.publisher)
            )
            .0
        );
        assert_eq!(
            a.request,
            runtime::request_address(
                &program,
                &a.config,
                &Pubkey::new_from_array(p.creator),
                &p.nonce
            )
            .0
        );
        assert_eq!(a.queue, runtime::queue_address(&program, &a.config).0);
        assert!(matches!(
            AppInstruction::parse(&p.initialize().data),
            Ok(AppInstruction::Initialize { .. })
        ));
        assert!(matches!(
            AppInstruction::parse(&p.enroll(1, [9; 32]).data),
            Ok(AppInstruction::Enroll { .. })
        ));
        assert!(matches!(
            AppInstruction::parse(&p.create().unwrap().data),
            Ok(AppInstruction::Create { .. })
        ));
    }
    #[test]
    fn request_chunks_and_exact_relevant_metas_match_v3_parser() {
        let p = plan();
        let a = p.addresses();
        let upload = p.upload_payload(0, &p.payload).unwrap();
        assert!(
            matches!(AppInstruction::parse(&upload.data), Ok(AppInstruction::Upload { offset:0, bytes }) if bytes == p.payload)
        );
        let metas = p.upload_metas();
        assert!(
            matches!(AppInstruction::parse(&metas.data), Ok(AppInstruction::UploadMetas { offset:0, metas }) if metas.len()==2 && metas[0].key==a.request && metas[1].key==a.queue && metas.iter().all(|m| m.flags==2 && m.owner==Pubkey::new_from_array(p.program)))
        );
        assert_eq!(
            AppInstruction::parse(&p.finalize().data),
            Ok(AppInstruction::Finalize)
        );
        assert!(p.upload_payload(0, &[]).is_err());
        assert!(p.upload_payload(0, &[0; 513]).is_err());
        assert!(p.upload_payload(3, &p.payload).is_err());
        assert!(p.upload_payload(0, &[9, 1, 2, 3]).is_err());
    }
    #[test]
    fn signed_source_observation_and_head_binding_match_v3_parser() {
        use zk_fresh_program::application_v3::PublisherHeadBinding;
        let p = plan();
        let observed = p.observe(0, 0, 0, 1, [41; 32], true, 100, 340);
        assert_eq!(observed.accounts.len(), 3);
        assert!(
            matches!(AppInstruction::parse(&observed.data), Ok(AppInstruction::Observe { expected_config_epoch:0, expected_issuer_epoch:0, expected:0, sequence:1, digest, active:true, observed:100, expires:340 }) if digest == [41;32])
        );
        let binding = V3HeadBinding {
            expected_config_epoch: 0,
            expected_issuer_epoch: 0,
            expected_root: p.root,
            expected_root_version: 0,
            expected_source_sequence: 1,
            expected_source_digest: [41; 32],
            expected_publication_sequence: 0,
            expected_publication_digest: [0; 32],
            next_publication_sequence: 1,
            envelope_digest: [91; 32],
        };
        let ix = p.bind_with_head(&binding);
        assert_eq!(ix.accounts.len(), 5);
        assert_eq!(
            AppInstruction::parse(&ix.data),
            Ok(AppInstruction::BindWithHead(PublisherHeadBinding {
                expected_config_epoch: binding.expected_config_epoch,
                expected_issuer_epoch: binding.expected_issuer_epoch,
                expected_root: binding.expected_root,
                expected_root_version: binding.expected_root_version,
                expected_source_sequence: binding.expected_source_sequence,
                expected_source_digest: binding.expected_source_digest,
                expected_publication_sequence: binding.expected_publication_sequence,
                expected_publication_digest: binding.expected_publication_digest,
                next_publication_sequence: binding.next_publication_sequence,
                envelope_digest: binding.envelope_digest,
            }))
        );
    }
}
