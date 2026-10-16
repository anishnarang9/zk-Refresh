# Fresh independent v3 relation preflight

On October 15, a new `cryptography.x509` issuer and holder were generated in
memory by the test-only preparer, independently of the profile's DER
constructor and the retained nine-pair corpus. The preparer admitted its
bounded-profile certificate, constructed the 751-input worker request and
public statement, and wrote only private mode-`0600` files under a fresh
mode-`0700` directory. The keys were discarded with the generator process.

The pinned Circom WASM/calculator produced one complete 25,113,548-byte WTNS.
An independently pinned Python streaming checker compared the six public
values, required a canonical 784,796-field assignment and constant one, and
evaluated all 793,681 rows and 4,257,583 matrix entries of the frozen v3
R1CS. It reported satisfaction. The R1CS snapshot used for the check was
removed; the private witness and inputs remain outside Git. The public R1CS
SHA-256 is
`976e9a76356ad015f0e4c587ccd79bba601b5caf80817b561aa4ca5442656888`.

The three serialized bounded runs passed without cap stops or remaining owned
processes. Generation took 1.656 seconds and peaked at 49,332,224 bytes RSS;
WTNS generation took 4.887 seconds and peaked at 327,811,072 bytes; full
relation checking took 4.884 seconds and peaked at 31,981,568 bytes. These
are separate stage observations, not a complete refresh measurement. The
scrubbed receipts are `results/dynark/part5/v3-relation-generate-001.json`,
`v3-relation-wtns-001.json` and `v3-relation-check-001.json`. The reviewed
preparer and calculator launcher are
`crates/dynark-native-client/tests/support/prepare_v3_relation.py` and
`v3_relation_witness.cjs`, SHA-256 `ea5d1cf19cbe8840cea786dcda9738dccf9665b95480f9ab6c9a8ecad30e4d86`
and `61226e940c7380ce83dd7119f6d03ba4058aaf3c75f652e36f7539d07483c86b`.

This training witness uses a synthetic action and membership path. It has not
passed the native client's complete-assignment admission, Full proving or
application authorization. It is not the frozen unseen-credential acceptance
cohort and does not qualify Anchor refresh economics.

The release-mode native harness now repeats generation and independent full
relation checking from a fresh test-owned private root. Its fixed-output checks
require the 25,113,548-byte complete WTNS, 784,796 fields, 793,681 rows and
4,257,583 matrix entries. The bounded run passed in 17.614 seconds with
362,463,232 bytes peak sampled owned-tree RSS and 194,240,679 bytes peak
sampled storage growth. The private root was removed and the runner reported
no remaining owned processes. See the scrubbed
`results/dynark/part5/v3-relation-wtns-harness-green-001.json` receipt. This
harness still performs its relation check in the independent Python preflight;
native client candidate-to-coordinate and admitted-package validation remain
separate gates.
