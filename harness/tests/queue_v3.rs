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
