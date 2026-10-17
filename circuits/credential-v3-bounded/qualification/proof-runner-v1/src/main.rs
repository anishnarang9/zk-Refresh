//! Separate v3 Full/Anchor qualification. No setup or persistent private cache API.
#![forbid(unsafe_code)]
mod artifacts;
mod context;
#[path = "ordinary.rs"]
mod ordinary_checks;
use ark_bn254::Fr;
use ark_serialize::CanonicalSerialize;
use artifacts::*;
use context::*;
use dynark_bn254::{
    Anchor, AnchorBinding, PublicPackage, Transition, UpdatingMaterial, ValidatedAssignment,
};
use ordinary_checks::Counts;
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    os::unix::fs::MetadataExt,
    path::Path,
    time::Instant,
};

struct Case {
    values: Vec<Fr>,
    validated: ValidatedAssignment,
    public: Vec<Fr>,
    flat: BTreeMap<String, Fr>,
    context: RootOnlyContext,
}
fn read_case(
    spec: &Value,
    map: &BTreeMap<String, usize>,
    package: &PublicPackage,
    owner: u32,
    request_bound: bool,
) -> Result<Case> {
    let bytes = received_bytes(
        Path::new(text(spec, "wtns_path")?),
        text(spec, "wtns_sha256")?,
        32 * 1024 * 1024,
        true,
        owner,
    )?;
    let values = decode_witness(&bytes, ASSIGNMENT_FIELDS)?;
    drop(bytes);
    let public = expected_public(
        Path::new(text(spec, "public_path")?),
        text(spec, "public_sha256")?,
        owner,
    )?;
    match_public_values(&values, &public)?;
    let input = json_file(
        Path::new(text(spec, "input_path")?),
        text(spec, "input_sha256")?,
        owner,
    )?;
    let flat = match_inputs(&values, &input, map)?;
    let context = if request_bound {
        derive_context_mode(&flat, spec, true)?
    } else {
        derive_context(&flat, spec)?
    };
    let encoded = encoded(&values)?;
    let validated = package.validate_assignment(&encoded, &public)?;
    Ok(Case {
        values,
        validated,
        public,
        flat,
        context,
    })
}
fn delta_and_preflight(
    package: &PublicPackage,
    base: &Case,
    near: &Case,
    request_bound: bool,
) -> Result<(Vec<(usize, [u8; 32])>, Value)> {
    admit_pair(&base.context, &near.context, request_bound)?;
    root_only_inputs(&base.flat, &near.flat)?;
    required(
        base.public[1..] == near.public[1..] && base.public[0] != near.public[0],
        "same-action six-field root-only pair",
    )?;
    let mut delta = Vec::new();
    for (i, (a, b)) in base.values.iter().zip(&near.values).enumerate() {
        if a != b {
            let mut bytes = [0u8; 32];
            (*b - *a).serialize_compressed(&mut bytes[..])?;
            delta.push((i, bytes));
        }
    }
    required(
        delta.len() <= limits().max_delta_entries
            && delta.iter().filter(|(i, _)| *i < 7).count() == 1
            && delta.iter().any(|(i, _)| *i == 1),
        "bounded exact root-only public delta",
    )?;
    // Provisional binding is used only for mathematical support preflight. The
    // actual update is reconstructed from the created Anchor's private binding.
    let binding = AnchorBinding::new(
        package,
        base.context.credential,
        base.context.action,
        base.context.root_version,
    );
    let transition = Transition::new(
        package,
        binding,
        near.context.root_version,
        &delta,
        &near.public,
        limits(),
    )?;
    let prepared = transition.validate_target(package, &base.validated)?;
    let stats = prepared.stats();
    required(
        stats.full_validation_entries == ENTRIES
            && stats.quadratic_pair_visits <= limits().max_pair_work,
        "bounded complete transition work",
    )?;
    Ok((
        delta,
        json!({"delta_entries":transition.normalized_count(),"pair_visits":stats.quadratic_pair_visits,
        "a_rows":stats.a.nonzero_rows,"b_rows":stats.b.nonzero_rows,"c_rows":stats.c.nonzero_rows,
        "full_validation_entries":stats.full_validation_entries}),
    ))
}
fn cross_context_negatives(contexts: &[(RootOnlyContext, RootOnlyContext)]) -> Result<usize> {
    cross_context_negatives_mode(contexts, false)
}
fn cross_context_negatives_mode(
    contexts: &[(RootOnlyContext, RootOnlyContext)],
    request_bound: bool,
) -> Result<usize> {
    let mut checks = 0;
    for (i, (base, own_near)) in contexts.iter().enumerate() {
        let valid = *own_near;
        for field in 0..7 {
            let mut wrong = valid;
            match field {
                0 => wrong.credential[0] ^= 1,
                1 => wrong.action[0] ^= 1,
                2 => wrong.package[0] ^= 1,
                3 => wrong.policy_version ^= 1,
                4 => wrong.allocation_epoch ^= 1,
                5 => wrong.root_version = base.root_version,
                _ => wrong.root = base.root,
            }
            required(
                admit_pair(base, &wrong, request_bound).is_err(),
                "context mutation unexpectedly admitted",
            )?;
            checks += 1;
        }
        for (j, (_, other_near)) in contexts.iter().enumerate() {
            if i != j {
                let other = RootOnlyContext {
                    root: own_near.root,
                    root_version: own_near.root_version,
                    ..*other_near
                };
                required(
                    admit_pair(base, &other, request_bound).is_err(),
                    "cross-credential cache reuse admitted",
                )?;
                checks += 1;
            }
        }
    }
    Ok(checks)
}
fn engine_binding_negatives(
    package: &PublicPackage,
    material: &UpdatingMaterial,
    anchor: &Anchor,
    near: &Case,
    delta: &[(usize, [u8; 32])],
) -> Result<usize> {
    let original = anchor.binding();
    let mut count = 0;
    let mut rng = OsRng;
    for field in 0..6 {
        let mut wrong = original;
        match field {
            0 => wrong.credential[0] ^= 1,
            1 => wrong.action[0] ^= 1,
            2 => wrong.anchor_state[0] ^= 1,
            3 => {
                wrong.generation = if original.generation == 0 {
                    1
                } else {
                    original.generation - 1
                }
            }
            4 => wrong.package.package_digest[0] ^= 1,
            _ => wrong.domain_size += 1,
        }
        match Transition::new(
            package,
            wrong,
            near.context.root_version,
            delta,
            &near.public,
            limits(),
        ) {
            Err(dynark_bn254::Error::AnchorBinding) => {}
            Err(dynark_bn254::Error::Generation) if field == 3 && original.generation == 0 => {}
            Err(_) => return Err("unexpected binding-constructor rejection class".into()),
            Ok(transition) => {
                match anchor.update(package, material, &transition, limits(), &mut rng) {
                    Err(dynark_bn254::Error::AnchorBinding) => {}
                    _ => {
                        return Err(
                            "forged private Anchor binding was not rejected before refresh".into(),
                        )
                    }
                }
            }
        }
        required(
            anchor.binding() == original,
            "failed update mutated Anchor binding",
        )?;
        count += 1;
    }
    let replay = Transition::new(
        package,
        original,
        original.generation,
        delta,
        &near.public,
        limits(),
    );
    required(
        matches!(replay, Err(dynark_bn254::Error::Generation)),
        "replayed generation admitted",
    )?;
    Ok(count + 1)
}
fn proof_source_identity() -> String {
    let files: [(&str, &[u8]); 6] = [
        ("main.rs", include_bytes!("main.rs")),
        ("artifacts.rs", include_bytes!("artifacts.rs")),
        ("context.rs", include_bytes!("context.rs")),
        ("ordinary.rs", include_bytes!("ordinary.rs")),
        ("Cargo.lock", include_bytes!("../Cargo.lock")),
        ("Cargo.toml", include_bytes!("../Cargo.toml")),
    ];
    let mut h = Sha256::new();
    h.update(b"dynark-v3-proof/source-closure/v1");
    for (name, data) in files {
        h.update((name.len() as u32).to_be_bytes());
        h.update(name.as_bytes());
        h.update((data.len() as u64).to_be_bytes());
        h.update(data);
    }
    hex(&h.finalize())
}
fn heldout_boundary(packet: &Value, owner: u32) -> Result<()> {
    if text(packet, "cohort")? == "heldout-v1" {
        let frozen = json_file(
            Path::new(text(packet, "freeze_receipt_path")?),
            text(packet, "freeze_receipt_sha256")?,
            owner,
        )?;
        required(
            text(&frozen, "schema")? == "credential-v3-frozen-holdout-boundary-v1"
                && text(&frozen, "setup_manifest_sha256")? == SETUP_MANIFEST_SHA
                && text(&frozen, "package_digest")? == PACKAGE_SHA
                && text(&frozen, "proof_binary_sha256")? == binary_hash(owner)?
                && text(&frozen, "proof_source_identity")? == proof_source_identity()
                && text(&frozen, "input_preparer_sha256")?
                    == text(packet, "input_preparer_sha256")?,
            "heldout exact implementation/setup freeze",
        )?;
        let at = frozen["frozen_at_unix_ns"]
            .as_u64()
            .filter(|x| *x > 0)
            .ok_or("holdout freeze timestamp")?;
        for key in [
            "client_sha256",
            "adapter_sha256",
            "application_source_sha256",
            "application_elf_sha256",
        ] {
            unhex(text(&frozen, key)?)?;
        }
        for pair in packet_cases(packet)? {
            for role in ["base", "near"] {
                let path = Path::new(text(&pair[role], "input_path")?);
                let meta = fs::symlink_metadata(path)?;
                let changed_ns = (meta.ctime() as i128) * 1_000_000_000 + meta.ctime_nsec() as i128;
                required(
                    changed_ns > at as i128,
                    "heldout input must follow freeze receipt",
                )?;
            }
        }
    }
    Ok(())
}
fn validate_full_receipt(
    path: &Path,
    sha: &str,
    packet_sha: &str,
    n: usize,
    owner: u32,
) -> Result<()> {
    let r = json_file(path, sha, owner)?;
    required(
        text(&r, "schema")? == "credential-v3-bounded-proof-qualification-v1"
            && r["passed"] == true
            && text(&r, "mode")? == "full-corpus"
            && text(&r, "packet_sha256")? == packet_sha
            && text(&r, "package_digest")? == PACKAGE_SHA
            && r["counts"] == Counts::full(n as u64).json(),
        "accepted matching Full corpus receipt",
    )
}
fn execute(args: &[String]) -> Result<()> {
    let mode = args.get(1).map(String::as_str).ok_or("proof mode")?;
    required(
        matches!(
            mode,
            "full-corpus"
                | "full-request-bound"
                | "anchor-pilot"
                | "anchor-corpus"
                | "anchor-request-bound"
        ),
        "proof-only explicit mode",
    )?;
    let full_request_bound = mode == "full-request-bound";
    let request_bound = mode == "anchor-request-bound" || full_request_bound;
    required(
        args.len()
            == if mode == "full-corpus" || request_bound {
                5
            } else {
                7
            },
        "proof mode argument count",
    )?;
    let packet_path = Path::new(&args[2]);
    let owner = fs::symlink_metadata(packet_path)?.uid();
    let packet = json_file(packet_path, &args[3], owner)?;
    required(
        (packet["schema"] == "credential-v3-request-bound-anchor-v1") == request_bound,
        "packet schema matches explicit runner mode",
    )?;
    let cases = packet_cases(&packet)?;
    heldout_boundary(&packet, owner)?;
    let map = mapping(&json_file(
        Path::new(text(&packet, "input_map_path")?),
        text(&packet, "input_map_sha256")?,
        owner,
    )?)?;
    if mode != "full-corpus" && !request_bound {
        validate_full_receipt(Path::new(&args[4]), &args[5], &args[3], cases.len(), owner)?;
    }
    let out = Path::new(args.last().ok_or("fresh output")?);
    required(output(out)? == owner, "private output owner")?;
    let all = Instant::now();
    let package = load_package(&packet, owner, out)?;
    let id = package.identity();
    let mut contexts = Vec::new();
    let mut preflights = Vec::new();
    // All complete pairs and local cache guards are checked before expensive
    // public updating tables or any private Anchor preparation.
    for pair in cases {
        let t = Instant::now();
        let base = read_case(&pair["base"], &map, &package, owner, request_bound)?;
        let near = read_case(&pair["near"], &map, &package, owner, request_bound)?;
        let (_, stats) = delta_and_preflight(&package, &base, &near, request_bound)?;
        if request_bound {
            match_request_stage(&packet, &base.flat, &near.flat)?;
        }
        contexts.push((base.context, near.context));
        preflights.push(json!({"name":text(pair,"name")?,"support":stats}));
        event(out, "complete_pair_and_support_preflight", t)?;
    }
    let local_negatives = if request_bound {
        cross_context_negatives_mode(&contexts, true)?
    } else {
        cross_context_negatives(&contexts)?
    };
    let mut counts = Counts::default();
    let mut rows = Vec::new();
    let mut rng = OsRng;
    let mut binding_negatives = 0;
    let mut material_ms = 0.0;
    if mode == "full-corpus" || full_request_bound {
        for pair in cases {
            let t = Instant::now();
            let name = text(pair, "name")?;
            case_event(out, name, "full_credential_started", all)?;
            let base = read_case(&pair["base"], &map, &package, owner, request_bound)?;
            let near = read_case(&pair["near"], &map, &package, owner, request_bound)?;
            admit_pair(&base.context, &near.context, request_bound)?;
            root_only_inputs(&base.flat, &near.flat)?;
            let before = dynark_bn254::prove(
                &package,
                &base.validated,
                base.context.root_version,
                &mut rng,
            )?;
            ordinary_checks::verify_save(
                &package,
                &before,
                &base.public,
                base.context.root_version,
                out,
                &format!("{name}_full_base"),
                &mut counts,
            )?;
            let after = dynark_bn254::prove(
                &package,
                &near.validated,
                near.context.root_version,
                &mut rng,
            )?;
            let a = ordinary_checks::verify_save(
                &package,
                &after,
                &near.public,
                near.context.root_version,
                out,
                &format!("{name}_full_near"),
                &mut counts,
            )?;
            let randomized = dynark_bn254::prove(
                &package,
                &near.validated,
                near.context.root_version,
                &mut rng,
            )?;
            let b = ordinary_checks::verify_save(
                &package,
                &randomized,
                &near.public,
                near.context.root_version,
                out,
                &format!("{name}_full_near_randomized"),
                &mut counts,
            )?;
            required(a != b, "fresh Full randomization")?;
            ordinary_checks::reject_cross_root(&package, &before, &near.public, &mut counts)?;
            ordinary_checks::reject_cross_root(&package, &after, &base.public, &mut counts)?;
            rows.push(
                json!({"name":name,"full_proofs":3,"elapsed_ms":t.elapsed().as_secs_f64()*1000.0}),
            );
            case_event(out, name, "one_credential_full_complete", t)?;
        }
    } else {
        let pilot = if request_bound {
            "request_bound_training"
        } else {
            text(&packet, "pilot_pair")?
        };
        required(
            cases.iter().any(|c| c["name"] == pilot),
            "named pilot present",
        )?;
        if text(&packet, "cohort")? == "training-v1" {
            required(pilot == "credential_8", "independent OpenSSL pilot")?;
        }
        event(out, "public_updating_material_started", all)?;
        let t = Instant::now();
        let material = UpdatingMaterial::prepare(&package, limits())?;
        material_ms = t.elapsed().as_secs_f64() * 1000.0;
        event(out, "public_updating_material_prepared", t)?;
        for pair in cases {
            let name = text(pair, "name")?;
            if mode == "anchor-pilot" && name != pilot {
                continue;
            }
            let case_t = Instant::now();
            let base = read_case(&pair["base"], &map, &package, owner, request_bound)?;
            let near = read_case(&pair["near"], &map, &package, owner, request_bound)?;
            let (delta, _) = delta_and_preflight(&package, &base, &near, request_bound)?;
            let base_public = base.public.clone();
            if request_bound {
                let t = Instant::now();
                let old_full = dynark_bn254::prove(
                    &package,
                    &base.validated,
                    base.context.root_version,
                    &mut rng,
                )?;
                ordinary_checks::verify_save(
                    &package,
                    &old_full,
                    &base.public,
                    base.context.root_version,
                    out,
                    &format!("{name}_full_base"),
                    &mut counts,
                )?;
                ordinary_checks::reject_cross_root(&package, &old_full, &near.public, &mut counts)?;
                case_event(out, name, "old_base_full_verified_and_rejected_at_near", t)?;
            }
            let binding = AnchorBinding::new(
                &package,
                base.context.credential,
                base.context.action,
                base.context.root_version,
            );
            case_event(out, name, "private_anchor_started", all)?;
            let t = Instant::now();
            // A new private Anchor is created for every credential. Only public,
            // package-bound UpdatingMaterial is shared within this process.
            let anchor = Anchor::create(
                &package,
                &material,
                base.validated,
                binding,
                limits(),
                &mut rng,
            )?;
            let prepare_ms = t.elapsed().as_secs_f64() * 1000.0;
            case_event(out, name, "private_anchor_prepared", t)?;
            binding_negatives +=
                engine_binding_negatives(&package, &material, &anchor, &near, &delta)?;
            let before = anchor.binding();
            let transition = Transition::new(
                &package,
                before,
                near.context.root_version,
                &delta,
                &near.public,
                limits(),
            )?;
            case_event(out, name, "anchor_update_started", all)?;
            let t = Instant::now();
            let refreshed = anchor.update(&package, &material, &transition, limits(), &mut rng)?;
            required(anchor.binding() == before, "private Anchor mutated")?;
            ordinary_checks::verify_save(
                &package,
                &refreshed,
                &near.public,
                near.context.root_version,
                out,
                &format!("{name}_anchor_near"),
                &mut counts,
            )?;
            ordinary_checks::reject_cross_root(&package, &refreshed, &base_public, &mut counts)?;
            let refresh_ms = t.elapsed().as_secs_f64() * 1000.0;
            drop(anchor);
            rows.push(json!({"name":name,"private_anchor_prepare_ms":prepare_ms,"refresh_and_verify_ms":refresh_ms,
                "paid_credential_ms":case_t.elapsed().as_secs_f64()*1000.0,"anchor_binding_unchanged":true}));
            case_event(out, name, "one_private_anchor_credential_complete", case_t)?;
        }
    }
    let expected = if mode == "full-corpus" || full_request_bound {
        Counts::full(cases.len() as u64)
    } else if request_bound {
        Counts {
            proofs: 2,
            positives: 2,
            altered: 12,
            cross_root: 2,
        }
    } else {
        Counts::anchor(if mode == "anchor-pilot" {
            1
        } else {
            cases.len() as u64
        })
    };
    required(
        counts.json() == expected.json() && package.identity() == id,
        "executed proof/check counts and shared identity",
    )?;
    let mut report = json!({"schema":"credential-v3-bounded-proof-qualification-v1","passed":true,"mode":mode,
        "cohort":text(&packet,"cohort")?,"packet_sha256":args[3],"package_digest":PACKAGE_SHA,"identity":identity_json(id),
        "setup_manifest_sha256":SETUP_MANIFEST_SHA,"setup_binary_sha256":SETUP_BINARY_SHA,"setup_launcher_src_sha256":SETUP_SOURCE_SHA,
        "proof_binary_sha256":binary_hash(owner)?,"proof_source_identity":proof_source_identity(),
        "proof_package_lock_sha256":hex(&Sha256::digest(include_bytes!("../Cargo.lock"))),
        "ordinary_vk_file_sha256":ORDINARY_VK_FILE_SHA,"public_inputs":PUBLIC_FIELDS,"counts":counts.json(),
        "preflights":preflights,"cases":rows,"local_context_rejections":local_negatives,"engine_binding_rejections":binding_negatives,
        "public_package_loads":1,"public_material_preparations":usize::from(mode!="full-corpus" && !full_request_bound),"public_material_prepare_ms":material_ms,
        "total_paid_session_ms":all.elapsed().as_secs_f64()*1000.0,"setup_executed":false,"private_cache_persisted":false,
        "incremental_witness_enabled":false,"application_verified":false,"admitted":false});
    if request_bound {
        report["schema"] = json!(if full_request_bound {
            "credential-v3-request-bound-full-proof-v1"
        } else {
            "credential-v3-request-bound-anchor-proof-v1"
        });
        report["application_stage_pins"] = packet["application_stage"].clone();
        report["application_stage_pins_authority"] =
            json!("caller-supplied; external finalized-state verification required");
        report["old_base_full_rejected_at_near_publics"] = json!(true);
    }
    save_json(&out.join("proof-report.json"), &report)?;
    File::open(out)?.sync_all()?;
    println!(
        "{{\"proof_qualification_passed\":true,\"proofs\":{},\"ordinary_checks\":{}}}",
        counts.proofs,
        counts.checks()
    );
    Ok(())
}
fn run() -> Result<()> {
    rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .build_global()?;
    execute(&std::env::args().collect::<Vec<_>>())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("v3 proof qualification failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn same_credential_action_root_only_refresh_is_admitted() {
        assert_eq!(SETUP_MANIFEST_SHA.len(), 64);
        assert_eq!(PACKAGE_SHA.len(), 64);
        let base = RootOnlyContext {
            package: [1; 32],
            credential: [2; 32],
            action: [3; 32],
            root: [4; 32],
            root_version: 1,
            policy_version: 1,
            allocation_epoch: 1,
        };
        let target = RootOnlyContext {
            root: [5; 32],
            root_version: 2,
            ..base
        };
        admit_root_only(&base, &target)
            .expect("same credential and action with a newer root must be admitted");
    }
    #[test]
    fn cross_context_checks_do_not_overflow_max_versions() {
        let base = RootOnlyContext {
            package: [1; 32],
            credential: [2; 32],
            action: [3; 32],
            root: [4; 32],
            root_version: 1,
            policy_version: u32::MAX,
            allocation_epoch: u64::MAX,
        };
        let near = RootOnlyContext {
            root: [5; 32],
            root_version: 2,
            ..base
        };
        assert_eq!(cross_context_negatives(&[(base, near)]).unwrap(), 7);
    }
    #[test]
    fn request_zero_generation_context_negatives_and_proof_counts() {
        let base = RootOnlyContext {
            package: [1; 32],
            credential: [2; 32],
            action: [3; 32],
            root: [4; 32],
            root_version: 0,
            policy_version: 1,
            allocation_epoch: 1,
        };
        let near = RootOnlyContext {
            root: [5; 32],
            root_version: 1,
            ..base
        };
        admit_pair(&base, &near, true).unwrap();
        assert_eq!(
            cross_context_negatives_mode(&[(base, near)], true).unwrap(),
            7
        );
        let counts = Counts {
            proofs: 2,
            positives: 2,
            altered: 12,
            cross_root: 2,
        };
        assert_eq!(counts.checks(), 16);
        // The new mode accepts no legacy Full receipt positional arguments.
        assert!(execute(&[
            "runner".into(),
            "anchor-request-bound".into(),
            "packet".into(),
            "sha".into(),
            "receipt".into(),
            "sha".into(),
            "out".into()
        ])
        .is_err());
    }
    #[test]
    fn no_setup_or_unknown_runtime_mode() {
        assert!(execute(&["runner".into(), "setup".into()]).is_err());
        assert!(execute(&["runner".into(), "prove".into()]).is_err());
    }
}
