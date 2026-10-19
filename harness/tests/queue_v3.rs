#[test]
#[ignore = "requires ROOT-pinned actual v3 ELF and supervised loopback validator"]
fn root_pinned_queue_v3_stage() {
    zk_fresh_benchmark::solana::queue_v3::stage_from_env().unwrap();
}

#[test]
#[ignore = "requires frozen eleven-leaf context and supervised loaded v3 validator"]
fn root_pinned_queue_v3_campaign_stage() {
    zk_fresh_benchmark::solana::queue_v3::campaign_stage_from_env().unwrap();
}

#[test]
#[ignore = "requires pinned campaign R0 clone and supervised loaded v3 validator"]
fn root_pinned_queue_v3_campaign_transition() {
    zk_fresh_benchmark::solana::queue_v3::campaign_transition_from_env().unwrap();
}

#[test]
#[ignore = "requires pinned R0/Rk campaign clone, actual proof wire and supervised loaded validator"]
fn root_pinned_queue_v3_campaign_effect() {
    zk_fresh_benchmark::solana::queue_v3::campaign_effect_from_env().unwrap();
}

#[test]
#[ignore = "requires pinned staged ledger, exact Full proof, and supervised loopback validator"]
fn root_pinned_queue_v3_execute() {
    zk_fresh_benchmark::solana::queue_v3::execute_from_env().unwrap();
}

#[test]
#[ignore = "requires pinned unconsumed v3 request and supervised loaded validator"]
fn root_pinned_queue_v3_unrelated_transition() {
    zk_fresh_benchmark::solana::queue_v3::transition_from_env().unwrap();
}

#[test]
#[ignore = "requires reviewed R1 ledger branch, pinned proof wires and supervised loaded validator"]
fn root_pinned_queue_v3_branch() {
    zk_fresh_benchmark::solana::queue_v3::branch_from_env().unwrap();
}

#[test]
#[ignore = "requires separate heldout R0 clone, valid Full wire, and supervised loaded v3 validator"]
fn root_pinned_queue_v3_disabled_config_negative() {
    zk_fresh_benchmark::solana::queue_v3::disabled_config_negative_from_env().unwrap();
}

#[test]
#[ignore = "requires separate heldout R0 clone, pinned Full wire, and supervised loaded v3 validator"]
fn root_pinned_queue_v3_expired_status_negative() {
    zk_fresh_benchmark::solana::queue_v3::expired_status_negative_from_env().unwrap();
}
