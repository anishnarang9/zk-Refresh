#[test]
#[ignore = "requires ROOT-pinned actual v3 ELF and supervised loopback validator"]
fn root_pinned_queue_v3_stage() {
    zk_fresh_benchmark::solana::queue_v3::stage_from_env().unwrap();
}
