# V2 local application preparation

The pinned local validator loaded the actual versioned application ELF and
finalized a synthetic work request on October 15, 2026. RPC programdata bytes
matched the reviewed 186,984-byte ELF, SHA-256
`e20d0df801e49e211a5b791d2f1c284240568049656edf8991b7cc00dbe7e639`.
The fresh local genesis was
`DDeEBprS6FPndW11NfgMS3RjUoQh9BJoBBa2KgAt4znD` and the local program ID
was `FPixV9CAxXGFiHH6udUhyTPUzposTYEf1uxmQxYc8xha`. The validator ledger is
preserved under `artifacts/dynark/part5/application-v2-local-runtime-001/` for
the exact proof and execution phase; the process itself shut down cleanly.

The seven successful application transactions were initialize (14,667 CU,
572 bytes), enroll (10,255 CU, 444 bytes), create (13,322 CU, 453 bytes), two
payload uploads (14,240 CU, 795 bytes each), metadata upload (14,494 CU,
411 bytes) and finalize (19,032 CU, 278 bytes). The runner compared all
2,249 finalized request bytes and the 2,090-byte empty queue with independent
encodings and waited through finalized slot 8. The protected plan SHA-256 is
`783c1c8c9110e41e1cf3d1cd79d6bb10c07c79f81aa3d17774b60fb6f7bd4c4b`;
the exact action hash is
`204adc0e5bc8095de0e3d5d768f1ca596267148fd3ca130c0290e5976015cdb0`
as a canonical 32-byte big-endian field. The holder must sign that action and
produce a matching Full proof before Execute can be attempted.

The independent process-tree monitor reports exit zero, no stop or residual
owned process, 20.171 seconds, 527,040,512 bytes sampled peak workload RSS,
and 36,053,463 bytes sampled positive storage growth. Caps were 180 seconds,
4 GiB sampled RSS and 256 MiB positive storage growth. Its scrubbed receipt is
`results/dynark/part5/v2-prepare-bounded-001.json`; the protected supervisor
status and full transaction observations remain in the ignored runtime/control
directories. The synthetic source observation, publisher binding, proof
verification, queue append, replay and revocation gates have **not** run yet.
This fixture preparation does not establish real issuer enrollment or upstream
status checking for the bounded v3 product profile.
