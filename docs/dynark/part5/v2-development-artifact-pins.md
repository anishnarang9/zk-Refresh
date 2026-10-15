# V2 development package pins for the first Full application

October 15, 2026. ROOT rehashed the retained setup manifest, ordinary VK file and generated Solana VK source before the versioned application key transfer. These are development-only artifact identities, not an audit or production setup. `admitted:false` remains in the setup manifest.

| Identity | Exact value |
| --- | --- |
| Circuit digest | `da0ad2e5e92f3879951ac3e56e077967eb5fcf6a9814839d680037d620ae9146` |
| Package digest | `04d5ad5776bea03ee014790f54c2572adde796f4d8caeacb88f8a54b0e98b6eb` |
| Engine extended VK digest | `b2678dbd6c04cfb536826cf26156ac5a046c1cdfe3734ea936f79e5d5f2a3a06` |
| Tagged ordinary VK digest | `e677671299cae78e1a7a3015aaac5200d03c8b54d562c8362cb326721610b22a` |
| Raw ordinary VK file SHA-256 | `52b614e3a8560ae8b5dc246bc197944a95072b8784b5a2c9c84c740f119925e3` |
| Semantic schema digest | `de111be59b7a21f5e9aa757506a9ec679d892d6342c88729b6b7997c8b472611` |
| R1CS SHA-256 | `ae7d802e9d62d6475fbcc312472b66f583f761c0d74dec223c733f4348bfc009` |
| Setup manifest SHA-256 | `878503eb2e182f4cb53b481ef5f3961ec81725f7546d472c0fe14e5f94ee6f53` |
| Isolated generated VK source SHA-256 | `9383d7338279e60035b88478ace92bc39e8cda3e47d91e797f07162dd5f5f1b8` |

The package is BN254/Original with five ordered public inputs `[root, issuerHash, notBefore, notAfter, actionHash]` and six instance fields including one. The separate verifier-only ELF is not the Part 5 application ELF. A new successor profile with an organization/group policy binding has a different semantic schema and key; it cannot use this v2 verifier by matching five names or by copying the VK file. The complete package source remains in ignored local artifact storage. This document stores only public hashes and labels.
