# One shared v3 development setup

The frozen `credential-v3-bounded` Original BN254 launcher completed **one**
OS-CSPRNG development setup for the reviewed six-field R1CS on October 15,
2026. The setup is shared by eligible credentials in this circuit/profile;
there is no per-certificate setup input. The accepted 52-case complete-witness
report, R1CS, WASM, profile and six-field schema were pinned before randomness.
The protected output is `artifacts/dynark/part5/v3-development-setup-001/`
with a 159,122,357-byte PK, 456-byte ordinary VK and manifest under owner-only
permissions. The PK and development artifacts stay out of Git.

| Identity | SHA-256 or engine digest |
| --- | --- |
| Setup manifest file | `d31f82e3f147e31b30074b3a570a9d7945c5e1f5d3f3dd74172801abbe984918` |
| Raw PK file | `879563839a95ab1a9e5a44b316ba86290918a5cf522863c1ddc58379365293bc` |
| Raw ordinary VK file | `87edb4608c2140f3c7fddc8503e49b68931cda973711ce2c831bd44f1b98a875` |
| Matrix | `da82ee7cfbe33f6780032bece071a4c2a11d84d4744ba230f4c5149ceb72a471` |
| Circuit | `eae99530daf7331037f2d1c6dc93ccc582603bd448f38d06e6469c734e8252fe` |
| Engine proving key | `14ddfd5773edda5cf02771ebfe2ac4e7af18437848d7822d6d28e2e0085bb671` |
| Engine extended VK | `2611d58c8c8d0b0c1f2c3f0facc4516e5c08e1fb3a7f14b16e32b948bc8f3c70` |
| Engine public package | `61d941890d823433468048dd1bd91da80c1bf7e1b3d2b6f5d509077a47ed06c8` |

These identities are separately named; in particular, the raw ordinary VK
file hash is not the engine extended-VK digest or the later application-tagged
ordinary VK digest. The ordinary VK has seven IC entries for the constant and
six ordered public inputs. The package manifest records the reviewed launcher
source/lock, exact profile and semantic-schema digests, Original reduction,
793,681 constraints, 784,796 assignment fields and 1,048,576 domain.

The independent bounded monitor reports exit zero, no stop or residual owned
process, 22.210 seconds, 990,855,168 bytes sampled peak workload RSS and
159,126,445 bytes sampled positive storage growth. Limits were 1,200 seconds,
4 GiB sampled RSS and 1 GiB new output with four Rayon workers. The scrubbed
receipt is `results/dynark/part5/v3-development-setup-bounded-001.json`; the
stage events and private files remain under protected artifacts. Setup alone
does not admit the package. Reload with the authenticated setup-manifest hash,
exact VK comparison and all 18 accepted complete assignments is the next gate.
No v3 proof or application execution has occurred. This is a trusted local
development setup, not a production ceremony or secure-erasure claim.
