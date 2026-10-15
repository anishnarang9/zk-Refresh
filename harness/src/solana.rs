#![allow(deprecated)]

fn deployment_bytes_match(local: &[u8], remote: &[u8]) -> bool {
    !local.is_empty()
        && remote.starts_with(local)
        && remote[local.len()..].iter().all(|byte| *byte == 0)
}

struct Session<'a> {
    rpc: &'a Rpc,
    payer: &'a Keypair,
    program: Pubkey,
    output: PathBuf,
    evidence: Value,
    receipt_rent: u64,
}
impl Session<'_> {
    fn save(&self) -> Result<()> {
        write_json(self.output.join("evidence.json"), &self.evidence, true)
    }
    fn send(
        &mut self,
        name: &str,
        instruction: Instruction,
        expected: Option<u64>,
        signer: Option<&Keypair>,
    ) -> Result<Value> {
        let mut result = self.rpc.transaction(self.payer, instruction, signer)?;
        result["name"] = name.into();
        self.evidence["transactions"]
            .as_array_mut()
            .unwrap()
            .push(result.clone());
        self.save()?;
        match expected {
            None => ensure!(result["err"].is_null(), "{name} failed: {}", result["err"]),
            Some(code) => ensure!(
                result["customError"].as_u64() == Some(code),
                "{name}: expected program error {code}, received {}",
                result["err"]
            ),
        }
        Ok(result)
    }
    fn record_proof(&mut self, name: &str, result: &ProofResult) -> Result<()> {
        self.evidence["proofs"].as_array_mut().unwrap().push(json!({"name":name,"publicSignals":result.public_signals,"verified":result.verified,
            "timings":{"witnessMs":result.timings.witness_ms,"provingMs":result.timings.proving_ms,
                "verificationMs":result.timings.verification_ms,"peakRssBytes":result.timings.peak_rss_bytes},
            "provingStartedUnixMs":result.proving_started_unix_ms,"provingFinishedUnixMs":result.proving_finished_unix_ms}));
        self.save()?;
        ensure!(result.verified, "{name}: local verification failed");
        Ok(())
    }
    fn no_receipt(&mut self, name: &str, registry: &Pubkey, action: &Field) -> Result<()> {
        let address = receipt_address(&self.program, registry, action);
        ensure!(
            self.rpc.account(&address)?.is_none(),
            "{name}: rejected action allocated a receipt"
        );
        self.evidence["scenarios"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name":name,"receiptAddress":address.to_string(),"receiptCreated":false}));
        self.save()
    }
    fn receipt(
        &self,
        registry: &Pubkey,
        action: &Field,
        recipient: &Pubkey,
        root: &Field,
        version: u64,
    ) -> Result<Value> {
        let address = receipt_address(&self.program, registry, action);
        let (info, bytes) = self
            .rpc
            .account(&address)?
            .context("Successful transaction has no receipt account")?;
        ensure!(
            info["owner"] == self.program.to_string(),
            "Receipt has wrong owner"
        );
        ensure!(
            info["lamports"].as_u64().unwrap_or(0) >= self.receipt_rent,
            "Receipt is not rent exempt"
        );
        let mut receipt = decode_receipt(&bytes)?;
        ensure!(
            receipt["registry"] == registry.to_string()
                && receipt["recipient"] == recipient.to_string()
                && receipt["actionId"] == hex::encode(action)
                && receipt["root"] == field_decimal(root)
                && receipt["rootVersion"].as_u64() == Some(version),
            "Receipt contents differ from the authorized statement"
        );
        receipt["address"] = address.to_string().into();
        receipt["owner"] = info["owner"].clone();
        receipt["lamports"] = info["lamports"].clone();
        Ok(receipt)
    }
    fn scenario(&mut self, value: Value) -> Result<()> {
        self.evidence["scenarios"]
            .as_array_mut()
            .unwrap()
            .push(value);
        self.save()
    }
}

fn benchmark(rpc: &Rpc, payer: &Keypair, program: Pubkey, output: &Path) -> Result<()> {
    let fixtures = load_fixtures()?;
    ensure!(
        fixtures.credentials.len() >= 2,
        "Solana scenarios require Alice and Bob fixtures"
    );
    let mut registry = Registry::new(fixtures.clone())?;
    registry.snapshot(now())?;
    let root0 = registry.root();
    let issuer = registry.issuer;
    let strict_seed = random_bytes();
    let historical_seed = random_bytes();
    let strict = registry_address(&program, &payer.pubkey(), &strict_seed);
    let historical = registry_address(&program, &payer.pubkey(), &historical_seed);
    let recipient = payer.pubkey();
    let mut session = Session {
        rpc,
        payer,
        program,
        output: output.to_owned(),
        receipt_rent: rpc.rent(152)?,
        evidence: json!({"cluster":rpc.endpoint,"programId":program.to_string(),"payer":payer.pubkey().to_string(),"startedAtUnix":now(),
            "strictRegistry":strict.to_string(),"historicalRegistry":historical.to_string(),"transactions":[],"proofs":[],"scenarios":[],
            "status":"running","historicalRootWindowSeconds":300,"proofJobCount":5,
            "trustAssumptions":["Trusted issuer and root-publishing authority.","Witnesses constructed locally; a future witness service may learn queried credential slots."]}),
    };
    session.save()?;
    let result = (|| -> Result<()> {
        let baseline_action = random_bytes();
        let stale_action = random_bytes();
        let historical_action = random_bytes();
        let baseline = prove(
            &registry.input(
                0,
                action_digest(&program, &strict, &recipient, &baseline_action),
            )?,
            "solana-strict-valid",
            None,
        )?;
        session.record_proof("solana-strict-valid", &baseline)?;
        let stale = prove(
            &registry.input(
                0,
                action_digest(&program, &strict, &recipient, &stale_action),
            )?,
            "solana-strict-stale-alice",
            None,
        )?;
        session.record_proof("solana-strict-stale-alice", &stale)?;
        session.send(
            "initialize-strict",
            initialize_instruction(&program, &payer.pubkey(), &strict_seed, &issuer, &root0, 0)?,
            None,
            None,
        )?;
        let baseline_ix = authorize_instruction(
            &program,
            &payer.pubkey(),
            &strict,
            &baseline_action,
            &recipient,
            &baseline.public_signals,
            &baseline.proof,
        )?;
        let mut bad_proof = baseline_ix.clone();
        bad_proof.data[416] ^= 1;
        session.send("invalid-proof", bad_proof, Some(19), None)?;
        session.no_receipt("invalid-proof", &strict, &baseline_action)?;
        let changed_action = random_bytes();
        session.send(
            "wrong-action",
            authorize_instruction(
                &program,
                &payer.pubkey(),
                &strict,
                &changed_action,
                &recipient,
                &baseline.public_signals,
                &baseline.proof,
            )?,
            Some(18),
            None,
        )?;
        session.no_receipt("wrong-action", &strict, &changed_action)?;
        let wrong_recipient = Keypair::new().pubkey();
        session.send(
            "wrong-recipient",
            authorize_instruction(
                &program,
                &payer.pubkey(),
                &strict,
                &baseline_action,
                &wrong_recipient,
                &baseline.public_signals,
                &baseline.proof,
            )?,
            Some(18),
            None,
        )?;
        session.no_receipt("wrong-recipient", &strict, &baseline_action)?;
        let accepted_tx = session.send("strict-valid", baseline_ix.clone(), None, None)?;
        let baseline_receipt = session.receipt(&strict, &baseline_action, &recipient, &root0, 0)?;
        session.scenario(
            json!({"name":"strict-valid","receipt":baseline_receipt,"proofHolder":"Alice"}),
        )?;
        let before_replay = rpc
            .account(&receipt_address(&program, &strict, &baseline_action))?
            .unwrap();
        let replay_tx = session.send("replay", baseline_ix, Some(10), None)?;
        ensure!(
            accepted_tx["signature"] != replay_tx["signature"],
            "Replay did not execute as a distinct transaction"
        );
        let after_replay = rpc
            .account(&receipt_address(&program, &strict, &baseline_action))?
            .unwrap();
        ensure!(
            before_replay == after_replay,
            "Replay altered the permanent receipt"
        );
        session.scenario(
            json!({"name":"replay","receiptUnchanged":true,"newTransactionExecuted":true}),
        )?;
        let attacker = project_keypair(&output.join("unauthorized-authority.json"))?;
        session.send(
            "unauthorized-update",
            update_instruction(&program, &attacker.pubkey(), &strict, &root0, 0),
            Some(16),
            Some(&attacker),
        )?;
        let before_update = decode_registry(&rpc.account(&strict)?.unwrap().1)?;
        ensure!(
            before_update["currentVersion"] == 0,
            "Unauthorized update changed registry version"
        );
        registry.revoke(1, now())?;
        let root1 = registry.root();
        session.send(
            "revoke-bob-update-strict",
            update_instruction(&program, &payer.pubkey(), &strict, &root1, 0),
            None,
            None,
        )?;
        session.send(
            "alice-stale-after-bob-revocation",
            authorize_instruction(
                &program,
                &payer.pubkey(),
                &strict,
                &stale_action,
                &recipient,
                &stale.public_signals,
                &stale.proof,
            )?,
            Some(7),
            None,
        )?;
        session.no_receipt("alice-stale-after-bob-revocation", &strict, &stale_action)?;
        let fresh = prove(
            &registry.input(
                0,
                action_digest(&program, &strict, &recipient, &stale_action),
            )?,
            "solana-strict-regenerated-alice",
            None,
        )?;
        session.record_proof("solana-strict-regenerated-alice", &fresh)?;
        session.send(
            "alice-regenerated-same-action",
            authorize_instruction(
                &program,
                &payer.pubkey(),
                &strict,
                &stale_action,
                &recipient,
                &fresh.public_signals,
                &fresh.proof,
            )?,
            None,
            None,
        )?;
        let fresh_receipt = session.receipt(&strict, &stale_action, &recipient, &root1, 1)?;
        session.scenario(json!({"name":"alice-regenerated-same-action","receipt":fresh_receipt,"revokedCredential":"Bob","proofHolder":"Alice",
            "oldProofLocallyVerified":stale.verified,"oldActionId":hex::encode(stale_action),"newActionId":hex::encode(stale_action)}))?;

        let original = Registry::new(fixtures.clone())?;
        let historical_input = original.input(
            1,
            action_digest(&program, &historical, &recipient, &historical_action),
        )?;
        let mut publication_timing = None;
        let mut publish_during_proving = || -> Result<()> {
            let initialized = session.send(
                "initialize-historical",
                initialize_instruction(
                    &program,
                    &payer.pubkey(),
                    &historical_seed,
                    &issuer,
                    &root0,
                    1,
                )?,
                None,
                None,
            )?;
            let updated = session.send(
                "revoke-bob-update-historical",
                update_instruction(&program, &payer.pubkey(), &historical, &root1, 0),
                None,
                None,
            )?;
            publication_timing = Some((
                initialized["confirmedAtUnixMs"]
                    .as_u64()
                    .context("Initialization confirmation time missing")? as u128,
                updated["confirmedAtUnixMs"]
                    .as_u64()
                    .context("Root-update confirmation time missing")? as u128,
                unix_ms(),
            ));
            Ok(())
        };
        let historical_proof = prove(
            &historical_input,
            "solana-historical-revoked-bob",
            Some(&mut publish_during_proving),
        )?;
        session.record_proof("solana-historical-revoked-bob", &historical_proof)?;
        let (initialized_at, updated_at, callback_completed_at) =
            publication_timing.context("Historical publication callback did not complete")?;
        let overlap = historical_overlap(
            historical_proof.proving_started_unix_ms,
            historical_proof.proving_finished_unix_ms,
            initialized_at,
            updated_at,
            callback_completed_at,
        );
        session.evidence["historicalProvingOverlap"] = json!({
            "provingStartedUnixMs":historical_proof.proving_started_unix_ms,
            "initializeConfirmedAtUnixMs":initialized_at,"updateConfirmedAtUnixMs":updated_at,
            "callbackCompletedAtUnixMs":callback_completed_at,
            "provingFinishedUnixMs":historical_proof.proving_finished_unix_ms,"overlapVerified":overlap,
            "method":"Both transaction confirmations and callback completion fall inside the independently observed proving-process interval"
        });
        session.save()?;
        if !overlap {
            session.scenario(json!({"name":"historical-revoked-bob","outcome":"missed-overlap","authorizationAttempted":false,
                "reason":"Root publication confirmations did not finish before the real proving process ended","rerunRequired":true}))?;
            bail!("Historical root-publication overlap was missed; rerun with fresh registries to measure this scenario");
        }
        let historical_tx = rpc.transaction(
            payer,
            authorize_instruction(
                &program,
                &payer.pubkey(),
                &historical,
                &historical_action,
                &recipient,
                &historical_proof.public_signals,
                &historical_proof.proof,
            )?,
            None,
        )?;
        let mut named_tx = historical_tx.clone();
        named_tx["name"] = "historical-revoked-bob".into();
        session.evidence["transactions"]
            .as_array_mut()
            .unwrap()
            .push(named_tx);
        session.save()?;
        let history = decode_registry(
            &rpc.account(&historical)?
                .context("Historical registry missing")?
                .1,
        )?;
        let activated_at = history["entries"][0]["activatedAt"]
            .as_i64()
            .context("Historical activation time missing")?;
        if historical_tx["err"].is_null() {
            let receipt =
                session.receipt(&historical, &historical_action, &recipient, &root0, 0)?;
            let elapsed = receipt["executedAt"].as_i64().unwrap() - activated_at;
            ensure!(
                (0..=300).contains(&elapsed),
                "Historical receipt exceeded actual chain root window"
            );
            session.scenario(json!({"name":"historical-revoked-bob","outcome":"accepted-within-window","ownCredentialRevoked":true,"elapsedSeconds":elapsed,"receipt":receipt}))?;
        } else if historical_tx["customError"] == 6 {
            session.no_receipt(
                "historical-revoked-bob-expired",
                &historical,
                &historical_action,
            )?;
            let elapsed = historical_tx["blockTime"]
                .as_i64()
                .map(|time| time - activated_at);
            if let Some(elapsed) = elapsed {
                ensure!(
                    elapsed > 300,
                    "RootExpired transaction is not beyond historical window"
                );
            }
            session.scenario(json!({"name":"historical-revoked-bob","outcome":"root-expired-during-proving","ownCredentialRevoked":true,"elapsedSeconds":elapsed,"rootWindowSeconds":300}))?;
        } else {
            bail!(
                "Historical revoked proof returned unexpected error {}",
                historical_tx["err"]
            );
        }
        let expired_fixtures = create_fixtures(2, now() - 7200, now() - 3600)?;
        let expired_registry = Registry::new(expired_fixtures)?;
        let expired_seed = random_bytes();
        let expired_action = random_bytes();
        let expired_address = registry_address(&program, &payer.pubkey(), &expired_seed);
        session.send(
            "initialize-expired-credential-registry",
            initialize_instruction(
                &program,
                &payer.pubkey(),
                &expired_seed,
                &expired_registry.issuer,
                &expired_registry.root(),
                0,
            )?,
            None,
            None,
        )?;
        let expired_proof = prove(
            &expired_registry.input(
                0,
                action_digest(&program, &expired_address, &recipient, &expired_action),
            )?,
            "solana-real-expired-credential",
            None,
        )?;
        session.record_proof("solana-real-expired-credential", &expired_proof)?;
        session.send(
            "real-signed-expired-credential",
            authorize_instruction(
                &program,
                &payer.pubkey(),
                &expired_address,
                &expired_action,
                &recipient,
                &expired_proof.public_signals,
                &expired_proof.proof,
            )?,
            Some(5),
            None,
        )?;
        session.no_receipt(
            "real-signed-expired-credential",
            &expired_address,
            &expired_action,
        )?;
        session.evidence["expiryScenario"] = json!({"status":"verified-on-chain","locallyVerifiedRealProof":expired_proof.verified,"customError":5,"receiptCreated":false,"registry":expired_address.to_string(),"notAfter":expired_proof.public_signals[3]});
        session.evidence["strictState"] =
            decode_registry(&rpc.account(&strict)?.context("Strict registry missing")?.1)?;
        session.evidence["historicalState"] = history;
        session.evidence["completedAtUnix"] = now().into();
        session.evidence["status"] = "complete".into();
        session.save()
    })();
    if let Err(error) = &result {
        session.evidence["status"] = "failed".into();
        session.evidence["error"] = error.to_string().into();
        session.save()?;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_rpc(responses: Vec<(u16, &'static str)>) -> (Rpc, thread::JoinHandle<()>) {
        use std::io::{BufRead, BufReader, Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let rpc = Rpc::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let server = thread::spawn(move || {
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = BufReader::new(stream.try_clone().unwrap());
                let mut length = 0;
                loop {
                    let mut header = String::new();
                    request.read_line(&mut header).unwrap();
                    if header == "\r\n" {
                        break;
                    }
                    if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:")
                    {
                        length = value.trim().parse().unwrap();
                    }
                }
                request.read_exact(&mut vec![0; length]).unwrap();
                write!(stream, "HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        (rpc, server)
    }

    #[test]
    fn rpc_retries_http_and_json_rate_limits_before_returning_the_result() {
        let (rpc, server) = mock_rpc(vec![
            (429, "{}"),
            (
                200,
                r#"{"error":{"code":429,"message":"Connection rate limits exceeded"}}"#,
            ),
            (200, r#"{"result":42}"#),
        ]);
        assert_eq!(rpc.call("getSlot", json!([])).unwrap(), json!(42));
        server.join().unwrap();
    }

    #[test]
    fn rpc_does_not_retry_an_application_error() {
        let (rpc, server) = mock_rpc(vec![(
            200,
            r#"{"error":{"code":-32602,"message":"Invalid params"}}"#,
        )]);
        assert!(rpc
            .call("getSlot", json!([]))
            .unwrap_err()
            .to_string()
            .contains("Invalid params"));
        server.join().unwrap();
    }

    fn sample_proof() -> Value {
        json!({"pi_a":["1","2","1"],"pi_b":[["3","4"],["5","6"],["1","0"]],"pi_c":["7","8","1"]})
    }

    #[test]
    fn proof_packing_negates_a_and_swaps_extension_components() {
        let bytes = proof_bytes(&sample_proof()).unwrap();
        assert_eq!(BigUint::from_bytes_be(&bytes[..32]), BigUint::from(1u8));
        assert_eq!(
            BigUint::from_bytes_be(&bytes[32..64]),
            BigUint::parse_bytes(BASE_FIELD.as_bytes(), 10).unwrap() - BigUint::from(2u8)
        );
        for (offset, expected) in [(64, 4u8), (96, 3), (128, 6), (160, 5), (192, 7), (224, 8)] {
            assert_eq!(
                BigUint::from_bytes_be(&bytes[offset..offset + 32]),
                BigUint::from(expected)
            );
        }
        let mut zero = sample_proof();
        zero["pi_a"][1] = "0".into();
        assert_eq!(&proof_bytes(&zero).unwrap()[32..64], &[0; 32]);
    }

    #[test]
    fn proof_coordinates_reject_base_modulus_and_negative_values() {
        let mut proof = sample_proof();
        proof["pi_a"][0] = BASE_FIELD.into();
        assert!(proof_bytes(&proof).is_err());
        proof["pi_a"][0] = "-1".into();
        assert!(proof_bytes(&proof).is_err());
        proof["pi_a"][0] = "+1".into();
        assert!(proof_bytes(&proof).is_err());
        assert!(proof_bytes(&json!({})).is_err());
    }

    #[test]
    fn action_digest_matches_program_domain_and_binds_every_account() {
        let program = Pubkey::new_from_array([1; 32]);
        let registry = Pubkey::new_from_array([2; 32]);
        let recipient = Pubkey::new_from_array([3; 32]);
        let digest = action_digest(&program, &registry, &recipient, &[4; 32]);
        assert_eq!(
            field_decimal(&digest),
            "8601621792788052251120873132529569660356582910828730470328860304051872447240"
        );
        assert_ne!(
            digest,
            action_digest(&Pubkey::new_unique(), &registry, &recipient, &[4; 32])
        );
        assert_ne!(
            digest,
            action_digest(&program, &Pubkey::new_unique(), &recipient, &[4; 32])
        );
        assert_ne!(
            digest,
            action_digest(&program, &registry, &Pubkey::new_unique(), &[4; 32])
        );
        assert_ne!(
            digest,
            action_digest(&program, &registry, &recipient, &[5; 32])
        );
    }

    #[test]
    fn instructions_match_exact_abi_lengths_accounts_and_offsets() {
        let program = Pubkey::new_unique();
        let payer = Pubkey::new_unique();
        let seed = [1; 32];
        let issuer = [0; 32];
        let root = [2; 32];
        let init = initialize_instruction(&program, &payer, &seed, &issuer, &root, 1).unwrap();
        assert_eq!(init.data.len(), 106);
        assert_eq!(init.data[0], 0);
        assert_eq!(init.data[97], 1);
        assert_eq!(u64_at(&init.data, 98), 300);
        assert_eq!(
            init.accounts[1].pubkey,
            registry_address(&program, &payer, &seed)
        );
        assert!(init.accounts[0].is_signer && init.accounts[0].is_writable);
        assert_eq!(init.accounts[2].pubkey, system_program::id());
        assert!(initialize_instruction(&program, &payer, &seed, &issuer, &root, 2).is_err());
        let registry = init.accounts[1].pubkey;
        let action = [9; 32];
        let recipient = Pubkey::new_unique();
        let update = update_instruction(&program, &payer, &registry, &root, 42);
        assert_eq!(update.data.len(), 41);
        assert_eq!(u64_at(&update.data, 33), 42);
        assert_eq!(update.accounts[1].pubkey, registry);
        let signals: Vec<String> = (1..=5).map(|v| v.to_string()).collect();
        let authorize = authorize_instruction(
            &program,
            &payer,
            &registry,
            &action,
            &recipient,
            &signals,
            &sample_proof(),
        )
        .unwrap();
        assert_eq!(authorize.data.len(), 481);
        assert_eq!(authorize.data[0], 2);
        assert_eq!(field_decimal(&field_at(&authorize.data, 129)), "5");
        assert_eq!(&authorize.data[417..449], &action);
        assert_eq!(&authorize.data[449..481], recipient.as_ref());
        assert_eq!(
            authorize.accounts[2].pubkey,
            receipt_address(&program, &registry, &action)
        );
        assert!(!authorize.accounts[1].is_writable);
        assert!(authorize_instruction(
            &program,
            &payer,
            &registry,
            &action,
            &recipient,
            &signals[..4],
            &sample_proof()
        )
        .is_err());
        let mut noncanonical = signals;
        noncanonical[0] = SCALAR_FIELD.into();
        assert!(authorize_instruction(
            &program,
            &payer,
            &registry,
            &action,
            &recipient,
            &noncanonical,
            &sample_proof()
        )
        .is_err());
    }

    #[test]
    fn account_decoding_rejects_malformed_ring_and_preserves_times() {
        let mut registry = vec![0; 6272];
        registry[..8].copy_from_slice(b"ZKFREG01");
        registry[106..114].copy_from_slice(&300u64.to_le_bytes());
        registry[122..124].copy_from_slice(&1u16.to_le_bytes());
        registry[124..126].copy_from_slice(&1u16.to_le_bytes());
        registry[168..176].copy_from_slice(&1234567890i64.to_le_bytes());
        assert_eq!(
            decode_registry(&registry).unwrap()["entries"][0]["activatedAt"],
            1234567890
        );
        registry[124..126].copy_from_slice(&0u16.to_le_bytes());
        assert!(decode_registry(&registry).is_err());
        assert!(decode_registry(&[]).is_err());
        assert!(decode_receipt(&[]).is_err());
        let mut receipt = vec![0; 152];
        receipt[..8].copy_from_slice(b"ZKFREC01");
        receipt[136..144].copy_from_slice(&42u64.to_le_bytes());
        receipt[144..152].copy_from_slice(&(-1i64).to_le_bytes());
        let parsed = decode_receipt(&receipt).unwrap();
        assert_eq!(parsed["rootVersion"], 42);
        assert_eq!(parsed["executedAt"], -1);
        receipt.push(0);
        assert!(decode_receipt(&receipt).is_err());
    }

    #[test]
    fn wallets_cannot_escape_project_artifacts() {
        let outside = tempfile::tempdir().unwrap();
        assert!(project_keypair(&outside.path().join("wallet.json")).is_err());
        assert!(!outside.path().join("wallet.json").exists());
    }

    #[test]
    fn explicitly_selected_devnet_key_is_loaded_without_rewriting_it() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("existing-devnet.json");
        let key = Keypair::new();
        let original = serde_json::to_vec(&key.to_bytes().to_vec()).unwrap();
        fs::write(&path, &original).unwrap();
        let loaded = existing_devnet_keypair(&path).unwrap();
        assert_eq!(loaded.pubkey(), key.pubkey());
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(existing_devnet_keypair(&directory.path().join("missing.json")).is_err());
    }
    #[test]
    fn deployment_evidence_can_record_an_external_selected_payer_path() {
        let external = Path::new("/tmp/selected-devnet-key.json");
        assert_eq!(
            payer_path_label(external).unwrap(),
            external.display().to_string()
        );
    }

    #[test]
    fn starting_a_run_clears_previous_success_and_failure_status() {
        let output = tempfile::tempdir().unwrap();
        fs::write(
            output.path().join("deployment.json"),
            br#"{"status":"verified"}"#,
        )
        .unwrap();
        fs::write(
            output.path().join("evidence.json"),
            br#"{"status":"complete"}"#,
        )
        .unwrap();
        fs::write(
            output.path().join("failure.json"),
            br#"{"error":"old failure"}"#,
        )
        .unwrap();
        prepare_run(output.path(), "test").unwrap();
        let deployment: Value =
            serde_json::from_slice(&fs::read(output.path().join("deployment.json")).unwrap())
                .unwrap();
        let evidence: Value =
            serde_json::from_slice(&fs::read(output.path().join("evidence.json")).unwrap())
                .unwrap();
        assert_eq!(deployment["status"], "preparing");
        assert_eq!(evidence["status"], "not-started");
        assert!(!output.path().join("failure.json").exists());
    }

    #[test]
    fn validator_faucet_port_does_not_overlap_rpc_websocket() {
        assert_eq!(
            validator_ports(18899).unwrap(),
            [18899, 18900, 18901, 18801]
        );
        assert!(validator_ports(65534).is_err());
        assert!(validator_ports(18800).is_err());
        assert!(validator_ports(18827).is_err());
    }

    #[test]
    fn oversized_transactions_are_rejected_before_encoding_or_submission() {
        assert_eq!(transaction_packet_size(&vec![0; 1232]).unwrap(), 1232);
        assert!(transaction_packet_size(&vec![0; 1233]).is_err());
        let payer = Keypair::new();
        let program = Pubkey::new_unique();
        let registry = Pubkey::new_unique();
        let signals: Vec<_> = (1..=5).map(|value| value.to_string()).collect();
        let authorize = authorize_instruction(
            &program,
            &payer.pubkey(),
            &registry,
            &[9; 32],
            &payer.pubkey(),
            &signals,
            &sample_proof(),
        )
        .unwrap();
        let transaction = Transaction::new_signed_with_payer(
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
                authorize,
            ],
            Some(&payer.pubkey()),
            &[&payer],
            Hash::new_unique(),
        );
        let bytes = bincode::serialize(&transaction).unwrap();
        assert!(transaction_packet_size(&bytes).unwrap() <= 1232);
    }

    #[test]
    fn historical_overlap_requires_both_confirmations_before_real_proving_finishes() {
        assert!(historical_overlap(100, 500, 150, 200, 210));
        assert!(!historical_overlap(100, 200, 150, 190, 210));
        assert!(!historical_overlap(100, 500, 99, 200, 210));
        assert!(!historical_overlap(100, 500, 200, 150, 210));
        assert!(!historical_overlap(100, 500, 150, 200, 190));
    }

    #[test]
    fn deployment_check_accepts_only_identical_bytes_and_zero_padding() {
        assert!(deployment_bytes_match(&[1, 2, 3], &[1, 2, 3]));
        assert!(deployment_bytes_match(&[1, 2, 3], &[1, 2, 3, 0, 0]));
        assert!(!deployment_bytes_match(&[1, 2, 3], &[1, 2]));
        assert!(!deployment_bytes_match(&[1, 2, 3], &[1, 2, 4]));
        assert!(!deployment_bytes_match(&[1, 2, 3], &[1, 2, 3, 1]));
        assert!(!deployment_bytes_match(&[], &[]));
    }
}
use crate::fixtures::{
    create_fixtures, field_decimal, field_from_decimal, load_fixtures, write_json, Field,
};
use crate::prover::{prove, ProofResult};
use crate::registry::Registry;
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use num_bigint::BigUint;
use rand::RngCore;
use reqwest::blocking::Client;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_program,
    transaction::Transaction,
};
use std::{
    fs::{self, File, OpenOptions},
    net::TcpListener,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    str::FromStr,
    sync::atomic::{AtomicU32, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const BASE_FIELD: &str =
    "21888242871839275222246405745257275088696311157297823662689037894645226208583";
const SCALAR_FIELD: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";
static TX_SEQUENCE: AtomicU32 = AtomicU32::new(0);

fn transaction_packet_size(bytes: &[u8]) -> Result<usize> {
    ensure!(
        bytes.len() <= 1232,
        "Serialized Solana transaction is {} bytes; packet limit is 1232",
        bytes.len()
    );
    Ok(bytes.len())
}
fn historical_overlap(
    start: u128,
    finish: u128,
    initialize: u128,
    update: u128,
    callback: u128,
) -> bool {
    start <= initialize && initialize <= update && update <= callback && callback <= finish
}

fn root_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_owned()
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}
fn random_bytes() -> Field {
    let mut value = [0; 32];
    rand::thread_rng().fill_bytes(&mut value);
    value
}
fn padded(value: &BigUint) -> Field {
    let bytes = value.to_bytes_be();
    let mut result = [0; 32];
    result[32 - bytes.len()..].copy_from_slice(&bytes);
    result
}
pub fn proof_bytes(proof: &Value) -> Result<[u8; 256]> {
    let modulus = BigUint::parse_bytes(BASE_FIELD.as_bytes(), 10).unwrap();
    let coordinate = |path: &[usize], group: &str| -> Result<BigUint> {
        let mut value = &proof[group];
        for index in path {
            value = &value[*index];
        }
        let text = value
            .as_str()
            .context("Proof coordinate is not a decimal string")?;
        ensure!(
            !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()),
            "Invalid proof coordinate"
        );
        let number =
            BigUint::parse_bytes(text.as_bytes(), 10).context("Invalid proof coordinate")?;
        ensure!(
            number < modulus,
            "Proof coordinate is outside the BN254 base field"
        );
        Ok(number)
    };
    let ay = coordinate(&[1], "pi_a")?;
    let negated_ay = (&modulus - &ay) % &modulus;
    let values = [
        coordinate(&[0], "pi_a")?,
        negated_ay,
        coordinate(&[0, 1], "pi_b")?,
        coordinate(&[0, 0], "pi_b")?,
        coordinate(&[1, 1], "pi_b")?,
        coordinate(&[1, 0], "pi_b")?,
        coordinate(&[0], "pi_c")?,
        coordinate(&[1], "pi_c")?,
    ];
    let mut bytes = [0; 256];
    for (index, value) in values.iter().enumerate() {
        bytes[index * 32..(index + 1) * 32].copy_from_slice(&padded(value));
    }
    Ok(bytes)
}
pub fn action_digest(
    program: &Pubkey,
    registry: &Pubkey,
    recipient: &Pubkey,
    action: &Field,
) -> Field {
    let mut hasher = Sha256::new();
    hasher.update(b"zk-fresh-action-v1");
    hasher.update(program.as_ref());
    hasher.update(registry.as_ref());
    hasher.update(1u64.to_le_bytes());
    hasher.update(recipient.as_ref());
    hasher.update(action);
    let modulus = BigUint::parse_bytes(SCALAR_FIELD.as_bytes(), 10).unwrap();
    padded(&(BigUint::from_bytes_be(&hasher.finalize()) % modulus))
}
pub fn registry_address(program: &Pubkey, authority: &Pubkey, seed: &Field) -> Pubkey {
    Pubkey::find_program_address(&[b"registry", authority.as_ref(), seed], program).0
}
pub fn receipt_address(program: &Pubkey, registry: &Pubkey, action: &Field) -> Pubkey {
    Pubkey::find_program_address(&[b"receipt", registry.as_ref(), action], program).0
}
pub fn initialize_instruction(
    program: &Pubkey,
    authority: &Pubkey,
    seed: &Field,
    issuer: &Field,
    root: &Field,
    policy: u8,
) -> Result<Instruction> {
    ensure!(policy <= 1, "Invalid registry policy");
    let mut data = vec![0];
    data.extend_from_slice(seed);
    data.extend_from_slice(issuer);
    data.extend_from_slice(root);
    data.push(policy);
    data.extend_from_slice(&300u64.to_le_bytes());
    Ok(Instruction {
        program_id: *program,
        accounts: vec![
            AccountMeta::new(*authority, true),
            AccountMeta::new(registry_address(program, authority, seed), false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data,
    })
}
pub fn update_instruction(
    program: &Pubkey,
    authority: &Pubkey,
    registry: &Pubkey,
    root: &Field,
    version: u64,
) -> Instruction {
    let mut data = vec![1];
    data.extend_from_slice(root);
    data.extend_from_slice(&version.to_le_bytes());
    Instruction {
        program_id: *program,
        accounts: vec![
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new(*registry, false),
        ],
        data,
    }
}
pub fn authorize_instruction(
    program: &Pubkey,
    payer: &Pubkey,
    registry: &Pubkey,
    action: &Field,
    recipient: &Pubkey,
    signals: &[String],
    proof: &Value,
) -> Result<Instruction> {
    ensure!(signals.len() == 5, "Expected exactly five public signals");
    let mut data = vec![2];
    for signal in signals {
        data.extend_from_slice(&field_from_decimal(signal)?);
    }
    data.extend_from_slice(&proof_bytes(proof)?);
    data.extend_from_slice(action);
    data.extend_from_slice(recipient.as_ref());
    Ok(Instruction {
        program_id: *program,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(*registry, false),
            AccountMeta::new(receipt_address(program, registry, action), false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data,
    })
}
fn field_at(data: &[u8], offset: usize) -> Field {
    data[offset..offset + 32].try_into().unwrap()
}
fn u64_at(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}
fn i64_at(data: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}
pub fn decode_receipt(data: &[u8]) -> Result<Value> {
    ensure!(
        data.len() == 152 && &data[..8] == b"ZKFREC01",
        "Invalid receipt account layout"
    );
    Ok(
        json!({"registry":Pubkey::new_from_array(field_at(data,8)).to_string(), "recipient":Pubkey::new_from_array(field_at(data,40)).to_string(),
        "actionId":hex::encode(field_at(data,72)), "root":field_decimal(&field_at(data,104)), "rootVersion":u64_at(data,136), "executedAt":i64_at(data,144)}),
    )
}
pub fn decode_registry(data: &[u8]) -> Result<Value> {
    ensure!(
        data.len() == 6272 && &data[..8] == b"ZKFREG01",
        "Invalid registry account layout"
    );
    let length = u16::from_le_bytes(data[122..124].try_into().unwrap()) as usize;
    let next = u16::from_le_bytes(data[124..126].try_into().unwrap()) as usize;
    let age = u64_at(data, 106);
    ensure!(
        (1..=128).contains(&length)
            && next < 128
            && (length == 128 || next == length)
            && data[104] <= 1
            && (1..=300).contains(&age),
        "Invalid registry ring or policy"
    );
    let entries: Vec<_> = (0..length).map(|index| { let offset = 128 + index * 48;
        json!({"root":field_decimal(&field_at(data,offset)), "version":u64_at(data,offset+32), "activatedAt":i64_at(data,offset+40)}) }).collect();
    Ok(
        json!({"authority":Pubkey::new_from_array(field_at(data,8)).to_string(), "seed":hex::encode(field_at(data,40)),
        "issuer":field_decimal(&field_at(data,72)), "policy":data[104], "bump":data[105], "maxAge":age,
        "currentVersion":u64_at(data,114), "nextSlot":next, "entries":entries}),
    )
}

struct Rpc {
    endpoint: String,
    client: Client,
}
impl Rpc {
    fn new(endpoint: &str) -> Result<Self> {
        Ok(Self {
            endpoint: endpoint.to_owned(),
            client: Client::builder().timeout(Duration::from_secs(30)).build()?,
        })
    }
    fn call(&self, method: &str, params: Value) -> Result<Value> {
        for attempt in 0..6 {
            let response = self
                .client
                .post(&self.endpoint)
                .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
                .send()
                .with_context(|| format!("RPC {method} transport failed"))?;
            let http_limited = response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS;
            let response: Value = if http_limited {
                json!({"error":{"code":429}})
            } else {
                response.error_for_status()?.json()?
            };
            if response["error"]["code"].as_i64() == Some(429) {
                ensure!(
                    attempt < 5,
                    "RPC {method} rate limit persisted after six attempts"
                );
                thread::sleep(Duration::from_secs(1 << attempt));
                continue;
            }
            if let Some(error) = response.get("error") {
                bail!("RPC {method}: {error}");
            }
            return response
                .get("result")
                .cloned()
                .with_context(|| format!("RPC {method} has no result"));
        }
        unreachable!("Rate-limit attempts return a result or error")
    }
    fn account(&self, address: &Pubkey) -> Result<Option<(Value, Vec<u8>)>> {
        let result = self.call(
            "getAccountInfo",
            json!([address.to_string(),{"encoding":"base64","commitment":"confirmed"}]),
        )?;
        let info = &result["value"];
        if info.is_null() {
            return Ok(None);
        }
        let encoded = info["data"][0]
            .as_str()
            .context("RPC account data missing")?;
        Ok(Some((info.clone(), STANDARD.decode(encoded)?)))
    }
    fn balance(&self, address: &Pubkey) -> Result<u64> {
        self.call(
            "getBalance",
            json!([address.to_string(),{"commitment":"confirmed"}]),
        )?["value"]
            .as_u64()
            .context("Invalid balance response")
    }
    fn rent(&self, bytes: usize) -> Result<u64> {
        self.call(
            "getMinimumBalanceForRentExemption",
            json!([bytes,{"commitment":"confirmed"}]),
        )?
        .as_u64()
        .context("Invalid rent response")
    }
    fn confirmed_transaction(&self, signature: &str) -> Result<Value> {
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let status = self.call(
                "getSignatureStatuses",
                json!([[signature],{"searchTransactionHistory":true}]),
            )?;
            let status = &status["value"][0];
            if !status.is_null()
                && (status["confirmationStatus"] == "confirmed"
                    || status["confirmationStatus"] == "finalized")
            {
                let recorded = self.call("getTransaction",json!([signature,{"commitment":"confirmed","maxSupportedTransactionVersion":0,"encoding":"json"}]))?;
                if !recorded.is_null() && !recorded["meta"].is_null() {
                    ensure!(
                        status["err"] == recorded["meta"]["err"],
                        "Confirmation disagrees with recorded transaction error"
                    );
                    return Ok(recorded);
                }
            }
            ensure!(
                Instant::now() < deadline,
                "Transaction {signature} was not retrievable at confirmed commitment"
            );
            thread::sleep(Duration::from_millis(500));
        }
    }
    fn transaction(
        &self,
        payer: &Keypair,
        instruction: Instruction,
        extra_signer: Option<&Keypair>,
    ) -> Result<Value> {
        let latest = self.call("getLatestBlockhash", json!([{"commitment":"confirmed"}]))?;
        let blockhash = Hash::from_str(
            latest["value"]["blockhash"]
                .as_str()
                .context("Missing latest blockhash")?,
        )?;
        let sequence = TX_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        // A distinct message forces replay attempts to execute even inside one blockhash interval.
        let compute =
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000 - sequence % 10_000);
        let mut signers: Vec<&dyn Signer> = vec![payer];
        if let Some(signer) = extra_signer {
            signers.push(signer);
        }
        let transaction = Transaction::new_signed_with_payer(
            &[compute, instruction],
            Some(&payer.pubkey()),
            &signers,
            blockhash,
        );
        let serialized = bincode::serialize(&transaction)?;
        let transaction_bytes = transaction_packet_size(&serialized)?;
        let encoded = STANDARD.encode(serialized);
        let start = Instant::now();
        let submitted_at = unix_ms();
        let signature = self
            .call(
                "sendTransaction",
                json!([encoded,{"encoding":"base64","skipPreflight":true,"maxRetries":3}]),
            )?
            .as_str()
            .context("Missing sent transaction signature")?
            .to_owned();
        let submitted_ms = start.elapsed().as_secs_f64() * 1000.;
        let recorded = self.confirmed_transaction(&signature)?;
        let confirmed_at = unix_ms();
        let error = &recorded["meta"]["err"];
        let custom = error
            .get("InstructionError")
            .and_then(|v| v.get(1))
            .and_then(|v| v.get("Custom"))
            .cloned()
            .unwrap_or(Value::Null);
        Ok(
            json!({"signature":signature,"slot":recorded["slot"],"blockTime":recorded["blockTime"],"err":error,"customError":custom,
            "feeLamports":recorded["meta"]["fee"],"computeUnits":recorded["meta"]["computeUnitsConsumed"],
            "transactionBytes":transaction_bytes,"submittedAtUnixMs":submitted_at,"confirmedAtUnixMs":confirmed_at,
            "submittedMs":submitted_ms,"confirmationMs":start.elapsed().as_secs_f64()*1000.,"logs":recorded["meta"]["logMessages"]}),
        )
    }
}

fn private_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(file)
}
fn project_keypair(path: &Path) -> Result<Keypair> {
    let allowed = root_dir().join("artifacts/solana");
    ensure!(
        path.starts_with(&allowed),
        "Wallet must remain inside project artifacts/solana"
    );
    fs::create_dir_all(path.parent().context("Wallet path has no parent")?)?;
    ensure!(
        fs::canonicalize(path.parent().unwrap())?.starts_with(fs::canonicalize(&allowed)?),
        "Wallet directory escapes project artifacts through a symlink"
    );
    if path.exists() {
        ensure!(
            !fs::symlink_metadata(path)?.file_type().is_symlink(),
            "Wallet path is a symlink"
        );
        let bytes: Vec<u8> = serde_json::from_slice(&fs::read(path)?)?;
        let keypair = Keypair::from_bytes(&bytes)
            .map_err(|_| anyhow::anyhow!("Invalid project keypair file"))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        return Ok(keypair);
    }
    let keypair = Keypair::new();
    write_json(path, &keypair.to_bytes().to_vec(), true)?;
    Ok(keypair)
}
fn existing_devnet_keypair(path: &Path) -> Result<Keypair> {
    let bytes: Vec<u8> =
        serde_json::from_slice(&fs::read(path).context("Could not read selected devnet keypair")?)?;
    Keypair::from_bytes(&bytes).map_err(|_| anyhow::anyhow!("Invalid selected devnet keypair file"))
}
fn payer_path_label(path: &Path) -> Result<String> {
    Ok(path
        .strip_prefix(root_dir())
        .unwrap_or(path)
        .display()
        .to_string())
}
fn command_logged(mut command: Command, path: &Path) -> Result<()> {
    let log = private_file(path)?;
    let status = command
        .current_dir(root_dir())
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .status()?;
    ensure!(
        status.success(),
        "Command failed ({status}); see {}",
        path.display()
    );
    Ok(())
}
fn check_verifier() -> Result<()> {
    let source = fs::read_to_string(root_dir().join("program/src/generated_vk.rs"))?;
    let compact: String = source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    ensure!(
        compact.contains("VK_ENABLED:bool=true"),
        "Verifier key disabled; finish setup before building or deploying"
    );
    for path in [
        "artifacts/setup/credential_final.zkey",
        "artifacts/setup/verification_key.json",
        "artifacts/circuit/credential_js/credential.wasm",
    ] {
        ensure!(
            root_dir().join(path).is_file(),
            "Missing prover artifact {path}"
        );
    }
    Ok(())
}
fn build_program(output: &Path) -> Result<PathBuf> {
    check_verifier()?;
    let mut command = Command::new("cargo-build-sbf");
    command.args([
        "--manifest-path",
        "program/Cargo.toml",
        "--sbf-out-dir",
        "program/target/deploy",
    ]);
    command_logged(command, &output.join("build.log"))?;
    let binary = root_dir().join("program/target/deploy/zk_fresh_program.so");
    ensure!(binary.is_file(), "SBF build produced no program binary");
    Ok(binary)
}
fn source_hashes(binary: &Path) -> Result<Value> {
    let mut values = serde_json::Map::new();
    for path in [
        binary.to_owned(),
        root_dir().join("program/src/generated_vk.rs"),
        root_dir().join("artifacts/setup/verification_key.json"),
    ] {
        values.insert(
            path.strip_prefix(root_dir())?.display().to_string(),
            hex::encode(Sha256::digest(fs::read(path)?)).into(),
        );
    }
    Ok(Value::Object(values))
}
fn verify_deployment(
    rpc: &Rpc,
    payer_path: &Path,
    program: &Pubkey,
    binary: &Path,
    output: &Path,
    cluster: &str,
) -> Result<()> {
    let (account, _) = rpc
        .account(program)?
        .context("Deployed program account missing")?;
    ensure!(
        account["executable"] == true,
        "Deployed account is not executable"
    );
    let dump = output.join("deployed-program.so");
    let mut command = Command::new("solana");
    command
        .args(["program", "dump", "--url", &rpc.endpoint, "--keypair"])
        .arg(payer_path)
        .arg(program.to_string())
        .arg(&dump);
    command_logged(command, &output.join("dump.log"))?;
    fs::set_permissions(&dump, fs::Permissions::from_mode(0o600))?;
    let local = fs::read(binary)?;
    let remote = fs::read(&dump)?;
    ensure!(
        deployment_bytes_match(&local, &remote),
        "Deployed program bytes differ from current local SBF binary"
    );
    write_json(
        output.join("deployment.json"),
        &json!({"cluster":cluster,"rpc":rpc.endpoint,"programId":program.to_string(),
        "payerPath":payer_path_label(payer_path)?,"executable":true,"owner":account["owner"],
        "localBinaryBytes":local.len(),"remoteBinaryBytes":remote.len(),"remoteTrailingZeroBytes":remote.len()-local.len(),
        "binaryMatchVerified":true,"sourceHashes":source_hashes(binary)?,"status":"verified","checkedAtUnix":now()}),
        true,
    )
}
struct ValidatorGuard {
    child: Child,
}
impl Drop for ValidatorGuard {
    fn drop(&mut self) {
        unsafe {
            libc::kill(self.child.id() as i32, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn wait_rpc(rpc: &Rpc, validator: &mut ValidatorGuard) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        ensure!(
            validator.child.try_wait()?.is_none(),
            "Validator exited; inspect validator.log"
        );
        if rpc.call("getVersion", json!([])).is_ok() {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "Validator RPC did not become ready"
        );
        thread::sleep(Duration::from_millis(500));
    }
}
fn save_failure(output: &Path, result: Result<()>) -> Result<()> {
    if let Err(error) = &result {
        write_json(
            output.join("failure.json"),
            &json!({"failedAtUnix":now(),"error":format!("{error:#}")}),
            true,
        )?;
        let mut evidence: Value = serde_json::from_slice(&fs::read(output.join("evidence.json"))?)?;
        evidence["status"] = "failed".into();
        evidence["error"] = format!("{error:#}").into();
        write_json(output.join("evidence.json"), &evidence, true)?;
        let mut deployment: Value =
            serde_json::from_slice(&fs::read(output.join("deployment.json"))?)?;
        if deployment["status"] != "verified" {
            deployment["status"] = "failed".into();
            deployment["error"] = format!("{error:#}").into();
            write_json(output.join("deployment.json"), &deployment, true)?;
        }
    }
    result
}
fn prepare_run(output: &Path, cluster: &str) -> Result<()> {
    fs::create_dir_all(output)?;
    let failure = output.join("failure.json");
    if failure.exists() {
        fs::remove_file(failure)?;
    }
    write_json(
        output.join("deployment.json"),
        &json!({"cluster":cluster,"status":"preparing","startedAtUnix":now()}),
        true,
    )?;
    write_json(
        output.join("evidence.json"),
        &json!({"cluster":cluster,"status":"not-started","startedAtUnix":now(),"transactions":[],"proofs":[],"scenarios":[]}),
        true,
    )?;
    write_json(output.join("funding.json"), &json!([]), true)
}
fn validator_ports(port: u16) -> Result<[u16; 4]> {
    ensure!((1024..=65533).contains(&port), "Invalid validator RPC port");
    let ports = [port, port + 1, port + 2, 18801];
    ensure!(
        !ports[..3]
            .iter()
            .any(|value| (18801..=18828).contains(value)),
        "RPC or faucet port overlaps validator gossip or dynamic port range"
    );
    Ok(ports)
}
pub fn run_local() -> Result<()> {
    let output = root_dir().join("artifacts/solana/local");
    prepare_run(&output, "local")?;
    let result = (|| -> Result<()> {
        let payer_path = output.join("payer.json");
        let payer = project_keypair(&payer_path)?;
        let program = project_keypair(&output.join("program.json"))?;
        let port: u16 = std::env::var("SOLANA_LOCAL_RPC_PORT")
            .unwrap_or_else(|_| "18899".to_owned())
            .parse()?;
        let ports = validator_ports(port)?;
        for probe_port in ports {
            drop(
                TcpListener::bind(("127.0.0.1", probe_port))
                    .with_context(|| format!("Local validator port {probe_port} is in use"))?,
            );
        }
        let binary = build_program(&output)?;
        write_json(
            output.join("deployment.json"),
            &json!({"cluster":"local","programId":program.pubkey().to_string(),"payer":payer.pubkey().to_string(),
            "rpcPort":port,"sourceHashes":source_hashes(&binary)?,"status":"prepared","method":"solana-test-validator genesis --bpf-program","preparedAtUnix":now()}),
            true,
        )?;
        let log = private_file(&output.join("validator.log"))?;
        let mut command = Command::new("solana-test-validator");
        command
            .args(["--reset", "--ledger"])
            .arg(output.join("ledger"))
            .args([
                "--bind-address",
                "127.0.0.1",
                "--rpc-port",
                &port.to_string(),
                "--gossip-port",
                "18801",
                "--faucet-port",
                &ports[2].to_string(),
                "--dynamic-port-range",
                "18802-18828",
                "--bpf-program",
            ])
            .arg(program.pubkey().to_string())
            .arg(&binary)
            .arg("--quiet")
            .current_dir(root_dir())
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log));
        let mut validator = ValidatorGuard {
            child: command.spawn()?,
        };
        let rpc = Rpc::new(&format!("http://127.0.0.1:{port}"))?;
        wait_rpc(&rpc, &mut validator)?;
        verify_deployment(
            &rpc,
            &payer_path,
            &program.pubkey(),
            &binary,
            &output,
            "local",
        )?;
        let signature = rpc
            .call(
                "requestAirdrop",
                json!([payer.pubkey().to_string(), 10_000_000_000u64]),
            )?
            .as_str()
            .context("Faucet signature missing")?
            .to_owned();
        let funding = rpc.confirmed_transaction(&signature)?;
        write_json(
            output.join("funding.json"),
            &json!([{"signature":signature,"err":funding["meta"]["err"],"lamports":10_000_000_000u64}]),
            true,
        )?;
        ensure!(
            funding["meta"]["err"].is_null(),
            "Local faucet transaction failed"
        );
        benchmark(&rpc, &payer, program.pubkey(), &output)?;
        println!(
            "Local Solana scenarios complete. Evidence: {}",
            output.join("evidence.json").display()
        );
        Ok(())
    })();
    save_failure(&output, result)
}
pub fn run_devnet(force_deploy: bool) -> Result<()> {
    let output = root_dir().join("artifacts/solana/devnet");
    prepare_run(&output, "devnet")?;
    let result = (|| -> Result<()> {
        let payer_path = std::env::var_os("SOLANA_DEVNET_KEYPAIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| output.join("payer.json"));
        let program_path = output.join("program.json");
        let payer = if std::env::var_os("SOLANA_DEVNET_KEYPAIR").is_some() {
            existing_devnet_keypair(&payer_path)?
        } else {
            project_keypair(&payer_path)?
        };
        let program = project_keypair(&program_path)?;
        let rpc = Rpc::new("https://api.devnet.solana.com")?;
        let binary = build_program(&output)?;
        let existing = rpc.account(&program.pubkey())?;
        let deploy = force_deploy
            || !existing
                .as_ref()
                .is_some_and(|(value, _)| value["executable"] == true);
        let size = fs::metadata(&binary)?.len() as usize;
        let minimum = if deploy {
            2 * rpc.rent(size + 45)? + 250_000_000
        } else {
            250_000_000
        };
        let mut funding = Vec::<Value>::new();
        for attempt in 0..8 {
            if rpc.balance(&payer.pubkey())? >= minimum {
                break;
            }
            let request = rpc.call(
                "requestAirdrop",
                json!([payer.pubkey().to_string(),1_000_000_000u64,{"commitment":"confirmed"}]),
            );
            let signature = match request {
                Ok(value) => value
                    .as_str()
                    .context("Devnet faucet signature missing")?
                    .to_owned(),
                Err(error) => {
                    funding.push(json!({"attempt":attempt+1,"status":"failed","error":format!("{error:#}"),"projectWallet":payer.pubkey().to_string()}));
                    write_json(output.join("funding.json"), &funding, true)?;
                    bail!("Devnet faucet could not fund project wallet {}: {error:#}. No other wallet funds were used.",payer.pubkey());
                }
            };
            let confirmed = rpc.confirmed_transaction(&signature)?;
            funding.push(json!({"attempt":attempt+1,"signature":signature,"err":confirmed["meta"]["err"],"lamports":1_000_000_000u64}));
            write_json(output.join("funding.json"), &funding, true)?;
            ensure!(
                confirmed["meta"]["err"].is_null(),
                "Devnet faucet transaction failed"
            );
        }
        let balance = rpc.balance(&payer.pubkey())?;
        ensure!(
            balance >= minimum,
            "Devnet project wallet budget exhausted: needs {minimum} lamports, has {balance}"
        );
        if deploy {
            let buffer_path = output.join("buffer.json");
            let _buffer = project_keypair(&buffer_path)?;
            write_json(
                output.join("deployment.json"),
                &json!({"cluster":"devnet","programId":program.pubkey().to_string(),"payer":payer.pubkey().to_string(),
                "sourceHashes":source_hashes(&binary)?,"status":"deploying","preparedAtUnix":now()}),
                true,
            )?;
            let mut command = Command::new("solana");
            command
                .args(["program", "deploy"])
                .arg(&binary)
                .args(["--url", &rpc.endpoint, "--keypair"])
                .arg(&payer_path)
                .arg("--program-id")
                .arg(&program_path)
                .arg("--upgrade-authority")
                .arg(&payer_path)
                .arg("--buffer")
                .arg(&buffer_path)
                .args(["--output", "json", "--use-tpu-client"]);
            command_logged(command, &output.join("deploy.log"))?;
        }
        verify_deployment(
            &rpc,
            &payer_path,
            &program.pubkey(),
            &binary,
            &output,
            "devnet",
        )?;
        benchmark(&rpc, &payer, program.pubkey(), &output)?;
        println!(
            "Devnet Solana scenarios complete. Evidence: {}",
            output.join("evidence.json").display()
        );
        Ok(())
    })();
    save_failure(&output, result)
}

/// Focused actual-ELF queue integration. ROOT owns the loopback validator lifecycle.
pub mod queue_v2 {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct QueuePlan {
        pub genesis: [u8; 32],
        pub program: [u8; 32],
        pub config: [u8; 32],
        pub queue: [u8; 32],
        pub request: [u8; 32],
        pub issuer_account: [u8; 32],
        pub admin: [u8; 32],
        pub publisher: [u8; 32],
        pub source: [u8; 32],
        pub seed: [u8; 32],
        pub nonce: [u8; 32],
        pub recipient: [u8; 32],
        pub policy_id: [u8; 32],
        pub deadline: i64,
        pub payload: Vec<u8>,
        pub expected_inputs: [[u8; 32]; 5],
    }
    const CIRCUIT: &str = "da0ad2e5e92f3879951ac3e56e077967eb5fcf6a9814839d680037d620ae9146";
    const PACKAGE: &str = "04d5ad5776bea03ee014790f54c2572adde796f4d8caeacb88f8a54b0e98b6eb";
    const SCHEMA: &str = "de111be59b7a21f5e9aa757506a9ec679d892d6342c88729b6b7997c8b472611";
    const PROFILE: &str = "eb77028b2bd1e324c6ee74c40b43739ec2ce519014f6d04aebe2ca7f82aa1f68";
    fn unhex(s: &str) -> Result<[u8; 32]> {
        ensure!(
            s.len() == 64
                && s.bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "canonical digest required"
        );
        Ok(hex::decode(s)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("digest width"))?)
    }
    fn pk(b: [u8; 32]) -> Pubkey {
        Pubkey::new_from_array(b)
    }
    fn field(s: &str) -> Result<[u8; 32]> {
        ensure!(
            !s.is_empty()
                && s.bytes().all(|c| c.is_ascii_digit())
                && (s == "0" || !s.starts_with('0')),
            "canonical decimal field required"
        );
        let x = field_from_decimal(s)?;
        ensure!(
            BigUint::from_bytes_be(&x) < BigUint::parse_bytes(SCALAR_FIELD.as_bytes(), 10).unwrap(),
            "noncanonical Fr"
        );
        Ok(x)
    }
    fn epoch(s: &str) -> Result<[u8; 32]> {
        let x = field(s)?;
        ensure!(x[..24] == [0; 24], "epoch exceeds u64");
        Ok(x)
    }
    fn ix(p: &QueuePlan, op: u8, body: Vec<u8>, accounts: Vec<AccountMeta>) -> Instruction {
        let mut data = vec![0x50, op];
        data.extend(body);
        Instruction {
            program_id: pk(p.program),
            accounts,
            data,
        }
    }
    fn shape(p: &QueuePlan) -> Result<()> {
        ensure!(p.deadline > 0 && p.payload.len() <= 1024, "request bounds");
        Ok(())
    }
    impl QueuePlan {
        pub fn action_preimage(&self) -> Result<Vec<u8>> {
            shape(self)?;
            let mut b = b"DYNARK-WORK-REQUEST".to_vec();
            b.push(2);
            for x in [self.genesis, self.program, self.config, self.policy_id] {
                b.extend(x)
            }
            b.extend(1u32.to_be_bytes());
            b.extend(unhex(CIRCUIT)?);
            b.extend(self.nonce);
            b.extend(self.recipient);
            b.extend(1u16.to_be_bytes());
            b.extend((self.payload.len() as u32).to_be_bytes());
            b.extend(Sha256::digest(&self.payload));
            b.push(2);
            b.extend(self.request);
            b.push(2);
            b.extend(self.queue);
            b.push(2);
            b.extend(self.deadline.to_be_bytes());
            Ok(b)
        }
        pub fn action_hash(&self) -> Result<[u8; 32]> {
            let hash = Sha256::digest(self.action_preimage()?);
            let x = BigUint::from_bytes_be(&hash)
                % BigUint::parse_bytes(SCALAR_FIELD.as_bytes(), 10).unwrap();
            let b = x.to_bytes_be();
            let mut out = [0; 32];
            out[32 - b.len()..].copy_from_slice(&b);
            Ok(out)
        }
        pub fn finalized_request(&self) -> Result<Vec<u8>> {
            shape(self)?;
            let mut b = b"DYNREQ02".to_vec();
            for x in [
                self.config,
                self.admin,
                self.nonce,
                self.expected_inputs[1],
                self.recipient,
            ] {
                b.extend(x)
            }
            b.extend(1u16.to_be_bytes());
            b.extend(self.deadline.to_be_bytes());
            b.extend((self.payload.len() as u16).to_be_bytes());
            b.extend((self.payload.len() as u16).to_be_bytes());
            b.extend([2, 1, 2]);
            for k in [self.request, self.queue] {
                b.extend(k);
                b.push(2);
                b.extend(self.program)
            }
            b.resize(1225, 0);
            b.extend(&self.payload);
            b.resize(2249, 0);
            Ok(b)
        }
        pub fn check_wire(&self, wire: &[u8]) -> Result<()> {
            ensure!(wire.len() == 416, "exact416-byte native wire required");
            ensure!(
                self.expected_inputs[4] == self.action_hash()?,
                "plan action mismatch"
            );
            for (actual, expected) in wire[..160].chunks_exact(32).zip(self.expected_inputs) {
                ensure!(
                    actual == expected,
                    "proof public fields differ from finalized request"
                );
            }
            Ok(())
        }
        pub fn execute_instruction(&self, wire: &[u8]) -> Result<Instruction> {
            self.check_wire(wire)?;
            Ok(ix(
                self,
                7,
                wire.to_vec(),
                vec![
                    AccountMeta::new_readonly(pk(self.config), false),
                    AccountMeta::new_readonly(pk(self.issuer_account), false),
                    AccountMeta::new(pk(self.request), false),
                    AccountMeta::new(pk(self.queue), false),
                ],
            ))
        }
        fn validate_addresses(&self) -> Result<()> {
            shape(self)?;
            let program = pk(self.program);
            ensure!(
                self.config
                    == Pubkey::find_program_address(
                        &[b"dyn-config-v2", &self.admin, &self.seed],
                        &program
                    )
                    .0
                    .to_bytes(),
                "config PDA"
            );
            ensure!(
                self.issuer_account
                    == Pubkey::find_program_address(
                        &[b"dyn-issuer-v2", &self.config, &self.expected_inputs[1]],
                        &program
                    )
                    .0
                    .to_bytes(),
                "issuer PDA"
            );
            ensure!(
                self.request
                    == Pubkey::find_program_address(
                        &[b"dyn-request-v2", &self.config, &self.admin, &self.nonce],
                        &program
                    )
                    .0
                    .to_bytes(),
                "request PDA"
            );
            ensure!(
                self.queue
                    == Pubkey::find_program_address(&[b"dyn-queue-v2", &self.config], &program)
                        .0
                        .to_bytes(),
                "queue PDA"
            );
            ensure!(
                self.expected_inputs[4] == self.action_hash()?,
                "action field"
            );
            Ok(())
        }
    }
    pub fn check_loopback(endpoint: &str) -> Result<()> {
        let u = reqwest::Url::parse(endpoint)?;
        ensure!(
            u.scheme() == "http"
                && u.host_str() == Some("127.0.0.1")
                && u.port().is_some_and(|p| p >= 1024)
                && u.username().is_empty()
                && u.password().is_none()
                && u.path() == "/"
                && u.query().is_none()
                && u.fragment().is_none(),
            "explicit plain HTTP loopback RPC only"
        );
        Ok(())
    }
    fn env(name: &str) -> Result<String> {
        std::env::var(name).with_context(|| format!("ROOT pin {name} required"))
    }
    fn pinned(path: &Path, digest: &str, cap: u64) -> Result<Vec<u8>> {
        use std::io::Read;
        use std::os::unix::fs::MetadataExt;
        unhex(digest)?;
        let m = fs::symlink_metadata(path)?;
        ensure!(
            m.is_file() && !m.file_type().is_symlink() && m.len() <= cap,
            "artifact type/size"
        );
        let f = File::open(path)?;
        let n = f.metadata()?;
        ensure!(
            (m.dev(), m.ino(), m.len()) == (n.dev(), n.ino(), n.len()),
            "artifact changed while opening"
        );
        let mut b = Vec::new();
        f.take(cap + 1).read_to_end(&mut b)?;
        ensure!(
            b.len() as u64 == m.len() && hex::encode(Sha256::digest(&b)) == digest,
            "artifact digest mismatch"
        );
        Ok(b)
    }
    fn output() -> Result<PathBuf> {
        let p = PathBuf::from(env("P5_QUEUE_OUTPUT")?);
        ensure!(p.is_absolute(), "absolute output required");
        let m = fs::symlink_metadata(&p)?;
        ensure!(
            m.is_dir() && !m.file_type().is_symlink() && m.permissions().mode() & 0o777 == 0o700,
            "private0700 output required"
        );
        Ok(p)
    }
    fn new_file(path: &Path, b: &[u8]) -> Result<()> {
        use std::io::Write;
        let mut f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(b)?;
        f.sync_all()?;
        Ok(())
    }
    fn new_json(path: &Path, v: &impl serde::Serialize) -> Result<()> {
        new_file(path, &serde_json::to_vec_pretty(v)?)
    }
    fn keys(out: &Path, name: &str) -> Result<Keypair> {
        let k = Keypair::new();
        new_json(&out.join(name), &k.to_bytes().to_vec())?;
        Ok(k)
    }
    fn load_key(out: &Path, name: &str, expected: [u8; 32]) -> Result<Keypair> {
        let p = out.join(name);
        let m = fs::symlink_metadata(&p)?;
        ensure!(
            m.is_file()
                && !m.file_type().is_symlink()
                && m.len() < 1024
                && m.permissions().mode() & 0o777 == 0o600,
            "private key file required"
        );
        let b: Vec<u8> = serde_json::from_slice(&fs::read(&p)?)?;
        let k = Keypair::from_bytes(&b)?;
        ensure!(
            k.pubkey().to_bytes() == expected,
            "development key mismatch"
        );
        Ok(k)
    }
    fn local_rpc() -> Result<Rpc> {
        let endpoint = env("P5_QUEUE_RPC")?;
        check_loopback(&endpoint)?;
        Ok(Rpc {
            endpoint,
            client: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(2))
                .build()?,
        })
    }
    fn loaded(rpc: &Rpc, program: Pubkey) -> Result<Value> {
        use solana_sdk::bpf_loader_upgradeable::{self, UpgradeableLoaderState};
        let local = pinned(
            Path::new(&env("P5_QUEUE_ELF")?),
            &env("P5_QUEUE_ELF_SHA256")?,
            4 * 1024 * 1024,
        )?;
        ensure!(local.starts_with(b"\x7fELF"), "ELF required");
        let (a, b) = rpc
            .account(&program)?
            .context("actual application missing")?;
        ensure!(a["executable"] == true, "actual application not executable");
        let owner = Pubkey::from_str(a["owner"].as_str().context("program owner")?)?;
        let remote = if owner == bpf_loader_upgradeable::id() {
            let state: UpgradeableLoaderState = bincode::deserialize(&b)?;
            let key = match state {
                UpgradeableLoaderState::Program {
                    programdata_address,
                } => programdata_address,
                _ => bail!("wrong program account type"),
            };
            let (a, pd) = rpc.account(&key)?.context("programdata missing")?;
            ensure!(a["owner"] == owner.to_string(), "programdata owner");
            let n = UpgradeableLoaderState::size_of_programdata_metadata();
            ensure!(pd.len() >= n, "short programdata");
            pd[n..].to_vec()
        } else {
            ensure!(
                owner == solana_sdk::bpf_loader::id()
                    || owner == solana_sdk::bpf_loader_deprecated::id(),
                "unexpected program loader"
            );
            b
        };
        ensure!(
            deployment_bytes_match(&local, &remote),
            "loaded application differs from reviewed ELF"
        );
        Ok(
            json!({"elf_match":true,"elf_sha256":env("P5_QUEUE_ELF_SHA256")?,"local_bytes":local.len(),"remote_bytes":remote.len(),"loader":owner.to_string()}),
        )
    }
    fn domain(rpc: &Rpc) -> Result<([u8; 32], [u8; 32], Value)> {
        let program = Pubkey::from_str(&env("P5_QUEUE_PROGRAM")?)?;
        let genesis = rpc.call("getGenesisHash", json!([]))?;
        ensure!(
            genesis.as_str() == Some(env("P5_QUEUE_GENESIS")?.as_str()),
            "local genesis mismatch"
        );
        let g = Hash::from_str(genesis.as_str().context("genesis")?)?.to_bytes();
        Ok((program.to_bytes(), g, loaded(rpc, program)?))
    }
    fn clock(rpc: &Rpc) -> Result<i64> {
        let slot = rpc
            .call("getSlot", json!([{"commitment":"confirmed"}]))?
            .as_u64()
            .context("slot")?;
        rpc.call("getBlockTime", json!([slot]))?
            .as_i64()
            .context("execution clock unavailable")
    }
    fn state(rpc: &Rpc, key: [u8; 32], program: [u8; 32], len: usize) -> Result<Vec<u8>> {
        let (a, b) = rpc.account(&pk(key))?.context("program state missing")?;
        ensure!(
            a["owner"] == pk(program).to_string() && a["executable"] == false && b.len() == len,
            "program state identity"
        );
        Ok(b)
    }
    fn finalized_effect(rpc: &Rpc, p: &QueuePlan, request: &[u8], queue: &[u8]) -> Result<u64> {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let mut matches = true;
            for (key, expected) in [(p.request, request), (p.queue, queue)] {
                let result = rpc.call(
                    "getAccountInfo",
                    json!([pk(key).to_string(),{"encoding":"base64","commitment":"finalized"}]),
                )?;
                let info = &result["value"];
                ensure!(
                    info["owner"] == pk(p.program).to_string()
                        && info["executable"] == false
                        && info["data"][1] == "base64",
                    "finalized effect account identity"
                );
                let encoded = info["data"][0]
                    .as_str()
                    .context("finalized account bytes missing")?;
                ensure!(encoded.len() <= 4096, "finalized account size cap");
                matches &= STANDARD.decode(encoded)? == expected;
            }
            if matches {
                return rpc
                    .call("getSlot", json!([{"commitment":"finalized"}]))?
                    .as_u64()
                    .context("finalized reconciliation slot missing");
            }
            ensure!(
                Instant::now() < deadline,
                "exact finalized effect reconciliation deadline"
            );
            thread::sleep(Duration::from_millis(250));
        }
    }
    fn send(
        rpc: &Rpc,
        payer: &Keypair,
        extra: Option<&Keypair>,
        instruction: Instruction,
        name: &str,
        expected: Option<u64>,
        events: &mut Vec<Value>,
    ) -> Result<()> {
        // Persist each observed result before assertions, retaining failed gate evidence.
        use std::io::Write;
        let mut r = rpc.transaction(payer, instruction, extra)?;
        r["scenario"] = name.into();
        let path = output()?.join("transactions.jsonl");
        if path.exists() {
            let m = fs::symlink_metadata(&path)?;
            ensure!(
                m.is_file()
                    && !m.file_type().is_symlink()
                    && m.len() < 1024 * 1024
                    && m.permissions().mode() & 0o777 == 0o600,
                "private bounded transaction journal required"
            );
        }
        let mut journal = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        serde_json::to_writer(&mut journal, &r)?;
        journal.write_all(b"\n")?;
        journal.sync_all()?;
        events.push(r.clone());
        if let Some(e) = expected {
            ensure!(
                r["customError"].as_u64() == Some(e),
                "{name}: expected{e}, received{}",
                r["err"]
            )
        } else {
            ensure!(r["err"].is_null(), "{name}: {}", r["err"])
        }
        ensure!(
            r["computeUnits"].as_u64().unwrap_or(0) > 0
                && r["transactionBytes"].as_u64().unwrap_or(u64::MAX) <= 1232,
            "missing CU/packet evidence"
        );
        Ok(())
    }
    // The persistent-ledger supervisor may stop the validator immediately after return.
    // Wait for the last observed transaction slot to become rooted before reporting success.
    fn wait_finalized(rpc: &Rpc, events: &[Value]) -> Result<u64> {
        let slot = events
            .last()
            .and_then(|e| e["slot"].as_u64())
            .context("last transaction slot missing")?;
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let rooted = rpc
                .call("getSlot", json!([{"commitment":"finalized"}]))?
                .as_u64()
                .context("finalized slot missing")?;
            if rooted >= slot {
                return Ok(rooted);
            }
            ensure!(
                Instant::now() < deadline,
                "persistent-ledger finalization deadline"
            );
            thread::sleep(Duration::from_millis(250));
        }
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PublicContext {
        schema: String,
        synthetic_only: bool,
        circuit_id: String,
        package_id: String,
        semantic_schema: String,
        profile_id: String,
        issuer_hash: String,
        root: String,
        not_before: String,
        not_after: String,
    }
    fn context() -> Result<[[u8; 32]; 5]> {
        let b = pinned(
            Path::new(&env("P5_QUEUE_CONTEXT")?),
            &env("P5_QUEUE_CONTEXT_SHA256")?,
            16384,
        )?;
        let c: PublicContext = serde_json::from_slice(&b)?;
        ensure!(
            c.schema == "dynark-part5-v2-public-context-v1"
                && c.synthetic_only
                && c.circuit_id == CIRCUIT
                && c.package_id == PACKAGE
                && c.semantic_schema == SCHEMA
                && c.profile_id == PROFILE,
            "public context identity"
        );
        let inputs = [
            field(&c.root)?,
            field(&c.issuer_hash)?,
            epoch(&c.not_before)?,
            epoch(&c.not_after)?,
            [0; 32],
        ];
        ensure!(
            inputs[2] <= inputs[3] && inputs[1] != [0; 32],
            "context interval/issuer"
        );
        Ok(inputs)
    }
    pub fn prepare_from_env() -> Result<()> {
        ensure!(
            env("P5_QUEUE_SCOPE")? == "part5-v2-queue-local-prepare",
            "prepare scope"
        );
        let out = output()?;
        ensure!(
            fs::read_dir(&out)?.next().is_none(),
            "fresh empty output required"
        );
        let rpc = local_rpc()?;
        let (program, genesis, loaded) = domain(&rpc)?;
        let inputs = context()?;
        let admin = keys(&out, "admin.json")?;
        let publisher = keys(&out, "publisher.json")?;
        let source = keys(&out, "source.json")?;
        let seed = random_bytes();
        let nonce = random_bytes();
        let config = Pubkey::find_program_address(
            &[b"dyn-config-v2", admin.pubkey().as_ref(), &seed],
            &pk(program),
        )
        .0
        .to_bytes();
        let issuer_account =
            Pubkey::find_program_address(&[b"dyn-issuer-v2", &config, &inputs[1]], &pk(program))
                .0
                .to_bytes();
        let request = Pubkey::find_program_address(
            &[b"dyn-request-v2", &config, admin.pubkey().as_ref(), &nonce],
            &pk(program),
        )
        .0
        .to_bytes();
        let queue = Pubkey::find_program_address(&[b"dyn-queue-v2", &config], &pk(program))
            .0
            .to_bytes();
        let now = clock(&rpc)?;
        ensure!(
            now >= 0 && epoch_seconds(inputs[2])? <= now && now <= epoch_seconds(inputs[3])?,
            "credential currently valid"
        );
        let mut p = QueuePlan {
            genesis,
            program,
            config,
            queue,
            request,
            issuer_account,
            admin: admin.pubkey().to_bytes(),
            publisher: publisher.pubkey().to_bytes(),
            source: source.pubkey().to_bytes(),
            seed,
            nonce,
            recipient: source.pubkey().to_bytes(),
            policy_id: Sha256::digest(b"dynark-part5/development-queue-policy/v2").into(),
            deadline: (now + 86400).min(epoch_seconds(inputs[3])?),
            payload: vec![0x5a; 1024],
            expected_inputs: inputs,
        };
        p.expected_inputs[4] = p.action_hash()?;
        p.validate_addresses()?;
        let sig = rpc.call(
            "requestAirdrop",
            json!([admin.pubkey().to_string(), 1_000_000_000u64]),
        )?;
        let funding = rpc.confirmed_transaction(sig.as_str().context("airdrop signature")?)?;
        ensure!(funding["meta"]["err"].is_null(), "local funding failure");
        let mut events = vec![];
        let mut init = vec![];
        init.extend(p.seed);
        init.extend(p.publisher);
        init.extend(p.genesis);
        init.extend(p.policy_id);
        init.extend(1u32.to_be_bytes());
        init.extend(unhex(CIRCUIT)?);
        init.extend(unhex(PACKAGE)?);
        init.extend(unhex(SCHEMA)?);
        init.extend(inputs[0]);
        send(
            &rpc,
            &admin,
            None,
            ix(
                &p,
                0,
                init,
                vec![
                    AccountMeta::new(admin.pubkey(), true),
                    AccountMeta::new(pk(config), false),
                    AccountMeta::new(pk(queue), false),
                    AccountMeta::new_readonly(system_program::id(), false),
                ],
            ),
            "initialize",
            None,
            &mut events,
        )?;
        let mut enroll = inputs[1].to_vec();
        enroll.extend(unhex(PROFILE)?);
        enroll.extend(2u32.to_be_bytes());
        enroll.extend(0xa0..=0xb3);
        enroll.extend([0; 12]);
        enroll.extend(p.source);
        send(
            &rpc,
            &admin,
            None,
            ix(
                &p,
                1,
                enroll,
                vec![
                    AccountMeta::new(admin.pubkey(), true),
                    AccountMeta::new_readonly(pk(config), false),
                    AccountMeta::new(pk(issuer_account), false),
                    AccountMeta::new_readonly(system_program::id(), false),
                ],
            ),
            "enroll",
            None,
            &mut events,
        )?;
        let mut create = p.nonce.to_vec();
        create.extend(inputs[1]);
        create.extend(p.recipient);
        create.extend(1u16.to_be_bytes());
        create.extend(p.deadline.to_be_bytes());
        create.extend(1024u16.to_be_bytes());
        create.push(2);
        send(
            &rpc,
            &admin,
            None,
            ix(
                &p,
                4,
                create,
                vec![
                    AccountMeta::new(admin.pubkey(), true),
                    AccountMeta::new_readonly(pk(config), false),
                    AccountMeta::new_readonly(pk(issuer_account), false),
                    AccountMeta::new(pk(request), false),
                    AccountMeta::new_readonly(system_program::id(), false),
                ],
            ),
            "create",
            None,
            &mut events,
        )?;
        let edit = vec![
            AccountMeta::new_readonly(admin.pubkey(), true),
            AccountMeta::new_readonly(pk(config), false),
            AccountMeta::new(pk(request), false),
        ];
        for (j, chunk) in p.payload.chunks(512).enumerate() {
            let mut upload = ((j * 512) as u16).to_be_bytes().to_vec();
            upload.extend((chunk.len() as u16).to_be_bytes());
            upload.extend(chunk);
            send(
                &rpc,
                &admin,
                None,
                ix(&p, 6, upload, edit.clone()),
                "upload-payload",
                None,
                &mut events,
            )?
        }
        let mut metas = vec![0, 2];
        for key in [request, queue] {
            metas.extend(key);
            metas.push(2);
            metas.extend(program)
        }
        send(
            &rpc,
            &admin,
            None,
            ix(&p, 8, metas, edit.clone()),
            "upload-metas",
            None,
            &mut events,
        )?;
        send(
            &rpc,
            &admin,
            None,
            ix(&p, 5, vec![], edit),
            "finalize",
            None,
            &mut events,
        )?;
        let req = state(&rpc, request, program, 2249)?;
        ensure!(
            req == p.finalized_request()?,
            "finalized request differs from independent encoding"
        );
        let q = state(&rpc, queue, program, 2090)?;
        ensure!(q == empty_queue(&p), "queue not initially empty");
        let issuer_state = state(&rpc, p.issuer_account, p.program, 309)?;
        ensure!(
            &issuer_state[..8] == b"DYNIS2B1"
                && issuer_state[140..172] == p.source
                && issuer_state[229..].iter().all(|x| *x == 0),
            "revised issuer enrollment/binding layout"
        );
        let finalized_slot = wait_finalized(&rpc, &events)?;
        new_json(&out.join("plan.json"), &p)?;
        new_file(&out.join("action-preimage.bin"), &p.action_preimage()?)?;
        new_file(&out.join("action-hash.be"), &p.expected_inputs[4])?;
        new_file(&out.join("request-before.bin"), &req)?;
        new_file(&out.join("queue-before.bin"), &q)?;
        new_json(
            &out.join("prepare-report.json"),
            &json!({"scope":"local Full application preparation only","passed":true,"finalized_slot":finalized_slot,"program":pk(program).to_string(),"genesis":Hash::new_from_array(genesis).to_string(),"context_sha256":env("P5_QUEUE_CONTEXT_SHA256")?,"loaded_program":loaded,"plan_sha256":hex::encode(Sha256::digest(fs::read(out.join("plan.json"))?)),"action_hash_be":hex::encode(p.expected_inputs[4]),"transactions":events,"full_proof_created":false,"validator_lifecycle":"ROOT-owned persistent ledger"}),
        )?;
        Ok(())
    }
    fn epoch_seconds(b: [u8; 32]) -> Result<i64> {
        ensure!(b[..24] == [0; 24], "epoch width");
        Ok(i64::try_from(u64::from_be_bytes(b[24..].try_into()?))?)
    }
    fn empty_queue(p: &QueuePlan) -> Vec<u8> {
        let mut q = b"DYNQUE02".to_vec();
        q.extend(p.config);
        q.extend(0u16.to_be_bytes());
        q.resize(2090, 0);
        q
    }
    pub fn execute_from_env() -> Result<()> {
        ensure!(
            env("P5_QUEUE_SCOPE")? == "part5-v2-queue-local-execute",
            "execute scope"
        );
        let out = output()?;
        let rpc = local_rpc()?;
        let (program, genesis, loaded) = domain(&rpc)?;
        let plan = pinned(&out.join("plan.json"), &env("P5_QUEUE_PLAN_SHA256")?, 16384)?;
        let p: QueuePlan = serde_json::from_slice(&plan)?;
        p.validate_addresses()?;
        ensure!(
            program == p.program && genesis == p.genesis,
            "prepared domain changed"
        );
        let admin = load_key(&out, "admin.json", p.admin)?;
        let source = load_key(&out, "source.json", p.source)?;
        let publisher = load_key(&out, "publisher.json", p.publisher)?;
        let wire = pinned(
            Path::new(&env("P5_QUEUE_FULL_WIRE")?),
            &env("P5_QUEUE_FULL_WIRE_SHA256")?,
            416,
        )?;
        p.check_wire(&wire)?;
        let mut expected_request = p.finalized_request()?;
        let empty = empty_queue(&p);
        let mut completed_queue = empty.clone();
        completed_queue[40..42].copy_from_slice(&1u16.to_be_bytes());
        completed_queue[42..74].copy_from_slice(&p.request);
        let current_request = state(&rpc, p.request, p.program, 2249)?;
        let current_queue = state(&rpc, p.queue, p.program, 2090)?;
        let mut consumed = expected_request.clone();
        consumed[183] = 2;
        if current_request == consumed && current_queue == completed_queue {
            // Chain state was rechecked above on every reconciliation attempt.
            // Preserve an earlier successful report when another uncertain retry arrives.
            let finalized_slot = finalized_effect(&rpc, &p, &consumed, &completed_queue)?;
            let report = out.join("reconciled-report.json");
            if !report.exists() {
                new_json(
                    &report,
                    &json!({"passed":true,"scope":"already confirmed exact queue effect","finalized_slot":finalized_slot,"effect_count":1,"new_execute_transactions":0,"loaded_program":loaded}),
                )?;
            }
            return Ok(());
        }
        // A consumed-state startup barrier may launch reconciliation only. If
        // state changed after that observation, fail before any transaction.
        ensure!(
            std::env::var("P5_QUEUE_RECONCILE_ONLY").as_deref() != Ok("1"),
            "reconciliation-only barrier no longer matches exact consumed effect"
        );
        ensure!(
            current_request == expected_request && current_queue == empty,
            "unexpected prepared request/queue state"
        );
        let mut events = vec![];
        let cb = state(&rpc, p.config, p.program, 309)?;
        let ib = state(&rpc, p.issuer_account, p.program, 309)?;
        let public_context = context()?;
        ensure!(
            public_context[..4] == p.expected_inputs[..4],
            "public context differs from prepared proof context"
        );
        ensure!(
            cb[268..300] == p.expected_inputs[0]
                && cb[308] == 1
                && ib[40..72] == p.expected_inputs[1]
                && ib[140..172] == p.source
                && ib[172] == 1,
            "synthetic observation scope differs from authoritative current config/issuer"
        );
        let context_digest = unhex(&env("P5_QUEUE_CONTEXT_SHA256")?)?;
        let seq = u64::from_be_bytes(ib[173..181].try_into()?);
        let now = clock(&rpc)?;
        let mut observe = seq.to_be_bytes().to_vec();
        observe.extend(
            seq.checked_add(1)
                .context("status sequence overflow")?
                .to_be_bytes(),
        );
        // Controlled synthetic source attests its local fixture observation.
        // This is not evidence of an upstream issuer-status check.
        let observation_digest = Sha256::digest(
            [
                b"part5-synthetic-signed-source-observation".as_slice(),
                &cb[268..300],
                &ib[40..72],
                &context_digest,
                &now.to_be_bytes(),
                &seq.to_be_bytes(),
            ]
            .concat(),
        );
        observe.extend_from_slice(&observation_digest);
        observe.extend(now.to_be_bytes());
        observe.extend((now + 300).to_be_bytes());
        send(
            &rpc,
            &admin,
            Some(&source),
            ix(
                &p,
                3,
                observe,
                vec![
                    AccountMeta::new_readonly(pk(p.source), true),
                    AccountMeta::new_readonly(pk(p.config), false),
                    AccountMeta::new(pk(p.issuer_account), false),
                ],
            ),
            "synthetic-signed-source-observation",
            None,
            &mut events,
        )?;
        let root_version = u64::from_be_bytes(cb[300..308].try_into()?);
        let source_sequence = seq.checked_add(1).context("source sequence overflow")?;
        let mut binding = root_version.to_be_bytes().to_vec();
        binding.extend(source_sequence.to_be_bytes());
        send(
            &rpc,
            &admin,
            Some(&publisher),
            ix(
                &p,
                11,
                binding,
                vec![
                    AccountMeta::new_readonly(pk(p.publisher), true),
                    AccountMeta::new_readonly(pk(p.config), false),
                    AccountMeta::new(pk(p.issuer_account), false),
                ],
            ),
            "publisher-bind-current-root-and-source",
            None,
            &mut events,
        )?;
        let bound = state(&rpc, p.issuer_account, p.program, 309)?;
        ensure!(
            &bound[..8] == b"DYNIS2B1"
                && bound[229..261] == p.expected_inputs[0]
                && bound[261..269] == root_version.to_be_bytes()
                && bound[269..277] == source_sequence.to_be_bytes()
                && bound[277..309] == observation_digest[..],
            "publisher binding differs from exact current root/source"
        );
        let good = p.execute_instruction(&wire)?;
        let mut bad_action = good.clone();
        bad_action.data[161] ^= 1;
        send(
            &rpc,
            &admin,
            None,
            bad_action,
            "wrong-action",
            Some(512),
            &mut events,
        )?;
        ensure!(
            state(&rpc, p.request, p.program, 2249)? == expected_request
                && state(&rpc, p.queue, p.program, 2090)? == empty,
            "wrong action changed effect state"
        );
        let mut bad_proof = good.clone();
        bad_proof.data[162..].fill(0);
        send(
            &rpc,
            &admin,
            None,
            bad_proof,
            "invalid-proof",
            Some(514),
            &mut events,
        )?;
        ensure!(
            state(&rpc, p.request, p.program, 2249)? == expected_request
                && state(&rpc, p.queue, p.program, 2090)? == empty,
            "invalid proof changed effect state"
        );
        send(
            &rpc,
            &admin,
            None,
            good.clone(),
            "valid-full-exact-queue-append",
            None,
            &mut events,
        )?;
        expected_request[183] = 2;
        ensure!(
            state(&rpc, p.request, p.program, 2249)? == expected_request
                && state(&rpc, p.queue, p.program, 2090)? == completed_queue,
            "protected effect differs from exact request"
        );
        send(
            &rpc,
            &admin,
            None,
            good,
            "replay-new-transaction",
            Some(507),
            &mut events,
        )?;
        ensure!(
            state(&rpc, p.request, p.program, 2249)? == expected_request
                && state(&rpc, p.queue, p.program, 2090)? == completed_queue,
            "replay changed exact completed state"
        );
        let finalized_slot = wait_finalized(&rpc, &events)?;
        new_json(
            &out.join("execute-report.json"),
            &json!({"passed":true,"scope":"actual local loaded application Full proof and exact protected queue effect","finalized_slot":finalized_slot,"full_only":true,"synthetic_signed_source_observation":true,"upstream_issuer_check":false,"source_observation_digest":hex::encode(observation_digest),"public_context_sha256":env("P5_QUEUE_CONTEXT_SHA256")?,"loaded_program":loaded,"plan_sha256":env("P5_QUEUE_PLAN_SHA256")?,"wire_sha256":env("P5_QUEUE_FULL_WIRE_SHA256")?,"request":pk(p.request).to_string(),"queue":pk(p.queue).to_string(),"effect_count":1,"request_consumed":true,"publisher_binding_current":true,"bound_root_version":root_version,"bound_source_sequence":source_sequence,"request_sha256":hex::encode(Sha256::digest(expected_request)),"queue_sha256":hex::encode(Sha256::digest(completed_queue)),"transactions":events,"devnet":false,"anchor_refresh":false}),
        )?;
        Ok(())
    }
}
