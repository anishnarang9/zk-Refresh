# V3 ProgramData allocation compatibility gate

The locked Solana loader interface permits `DeployWithMaxDataLen` to allocate
more ProgramData space than the ELF occupies. The previous finalized-state
checker required `45 + pinned ELF length` account bytes, so a deployment with
zero-filled reserve was rejected before its reviewed ELF could be checked.

The checker now treats the first 45 bytes as loader metadata, hashes exactly
the independently pinned ELF length starting at byte 45, and admits only a
zero-filled allocation suffix. It caps the entire image allocation at 4 MiB.
It does not trim zeros from the ELF: genuine ending zero bytes remain part of
the pinned length and digest. The upgrade-authority, program linkage, finalized
slot, config identity, Clock and closed production constructor are unchanged.

The tests-first `accepts_zero_padded_programdata_allocation` case failed with
`Err(Deployment)` versus `Ok(100)` under the bounded runner. After the narrow
repair, all 29 crate tests passed, including nonzero-suffix and over-cap
rejections. The GREEN receipt records 8.97 seconds and sampled peak owned-tree
RSS of 292,765,696 bytes; neither run hit a cap.

Evidence: `results/dynark/part5/v3-deployment-padding-red-001.json` and
`v3-deployment-padding-green-001.json`. The test uses synthetic loader bytes.
Actual deployment provenance, independently trusted pins, RPC runtime Clock
semantics and loaded-program availability still need separate evidence before
the production constructor can open.
