# V3 signed inactive-status boundary: host GREEN gate

The v3 Observe parser now requires the canonical active byte at offset 66
in an exact 83-byte wire, after both signed eligibility epochs. The runtime
passes that bit to the issuer model. An inactive observation advances its
source sequence, digest, signed epochs and times while setting
`status_valid=false`. Freshness and current Bind reject it; a later active
observation still needs an explicit new publisher Bind. Old 82-byte and
epochless wires reject. V2 is unchanged.

The frozen six-test status target passed in the bounded run recorded at
`results/dynark/part5/v3-status-green-bounded-001.json` (SHA-256
`225f6c94c3ef3ed693f67e241bc20773bb86cfafea1ce32986a29e14cc743998`):
3.063 seconds, sampled peak owned-tree RSS 253,853,696 bytes, sampled
storage growth 5,791,534 bytes. The two prior v3 host targets (24 model
tests and seven admin-runtime tests) also passed with the explicit active
wire in `v3-status-regression-bounded-001.json` (SHA-256
`1f52f48ef4f81a1bffdf866fc435d21da3ad881806980e7dcc7d5a9e59ab1fd2`):
1.581 seconds, sampled peak RSS 312,197,120 bytes, storage growth
2,597,040 bytes. Both runs used one Cargo job, four Rayon threads, one test
thread, a 180-second runtime cap, 1 GiB owned-tree RSS cap and 256 MiB
target-growth cap. Neither hit a cap or left an owned process.

Reviewed source identities:

| File | SHA-256 |
| --- | --- |
| `program/src/application_v3.rs` | `3422a45c2463dc634152d0bd0b123f22385f64cc465f32470501c4e8412b607d` |
| `program/src/application_runtime_v3.rs` | `5bbd150e088a3dd38b3c493a0210ffa6a98cfc7cb294b178fbb817cbb9b4eccc` |
| `program/tests/application_v3.rs` | `ed305e7363931b960b1003fe56f5e174fbc2c47e7e09a3d51e3fa4b1d39eab7a` |
| `program/tests/application_runtime_v3.rs` | `7716527e6aba7488f837778c7e693aaa4571139d2006bd00304004d7a522e56f` |

This is host parser/model/admin evidence. It does not establish a real
source-envelope admission, loaded Solana ELF execution, six-field proof
verification, queue atomicity, or complete credential authorization.
