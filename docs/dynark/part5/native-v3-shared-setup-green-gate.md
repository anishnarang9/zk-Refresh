# Native v3 shared setup admission

`V3SharedSetup::load` rejects caller hash assertions and an altered frozen
manifest before artifact I/O. It reads bounded, regular, owner-checked files
through the same handles it hashes. The R1CS import receives a private snapshot
of the verified public bytes because the engine accepts a path; the snapshot is
deleted after import. The proving key is decoded from retained verified bytes,
then `PublicPackage::new` checks dimensions, curve/subgroup validity and the
independently pinned circuit/key/package identity. The exact 456-byte ordinary
VK projection and reviewed receipt separately bind the ordinary adapter key.
The shareable package contains no credential, holder signer, witness or private
Anchor state.

Two early negative tests passed without key decode under the debug target. The
first real-package debug attempt hit its 600-second runtime cap during key
validation; its receipt and reviewed release-mode plan are in
`native-v3-shared-setup-debug-cap.md`. With identical frozen source and
artifacts, the exact ignored positive passed in **release mode**: one test,
26 filtered, 41.26 test seconds and 45.600 bounded seconds including compile.
The external monitor reported no cap, runner error or residual owned process.
Sampled peak owned RSS was 838,533,120 bytes and maximum positive setup-root
growth was 169,084,727 bytes. No transient R1CS snapshot remained afterward.

The public release receipt is
`results/dynark/part5/native-v3-shared-setup-release-green-bounded-001.json`
(SHA-256 `87fe7f0571f600735a1bbcbc13d938836724a1b2391cc59fe3b67acea75771f1`).
The reviewed loader source SHA-256 is
`c394698064d71301474463f0d910784bed4e8ec1192f871fdf68e80042db1125`.
This admits the one development setup for all eligible credentials in its
profile. It does not authenticate an issuer, current state, request or proof,
and it does not establish a production setup ceremony.
