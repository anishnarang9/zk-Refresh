# V3 program administrative runtime: tests-first gate

The frozen host integration target checks administrator enrollment and
configuration, publisher root updates, authenticated source observation and
current-root binding. It includes account owner/PDA, signer and writable
privilege, predecessor, policy and two eligibility-epoch adversarial cases.
Its CPI stub models fresh System CreateAccount only; the host test does not
establish loaded ELF allocation or transaction rollback.

The exact authorized Publish positive compiled and failed at the intended
unavailable dispatch: `Err(Custom(799))` versus `Ok(())`. One test failed,
six were filtered. Bounded duration was 2.797 seconds, with no cap, runner
error or residual process. Sampled peak owned RSS was 200,671,232 bytes and
positive storage growth was 8,986,176 bytes. The frozen test source SHA-256 is
`101e71a873b3c1773687c449265c824f98d8a4d9a8b55f0ddce17c5907eb4ac8`;
public receipt `results/dynark/part5/program-admin-red-bounded-001.json`
has SHA-256 `15b457138afd1b5ecff4aa295f33d4a9b5546914fc8ff48b30bcfbbac832f981`.

Request staging, the six-field proof verifier and queue effect remain closed
until their own implementation and loaded runtime gates.
