# V3 complete-witness envelope: unit GREEN gate

The private client envelope check now requires Full mode and the exact v3
WTNS v2 header, BN254 scalar modulus, 784,796 coordinates, constant one,
canonical scalar encodings and six ordered public coordinates. It compares
all six fields with the expected local context and rejects a different
credential, holder key, action, signature, package, allocation, generation
or source sequence even when the six public fields match. It classifies
malformed encodings, context mismatches and unsupported modes separately.

The bounded `v3_binding` target passed seven tests in 6.101 seconds. Sampled
peak owned-tree RSS was 256,344,064 bytes and storage growth was 280,622
bytes. It hit no runtime, RSS or storage cap, and left no owned process. The
receipt is `results/dynark/part5/native-v3-binding-green-bounded-001.json`
(SHA-256 `6204fc18c72ec2ced99ff9130be2fa048309ada0d648b9fe42c7661e71cf0626`).
The source SHA-256 is
`4e1541f7a600d18b87cad1adab3c9522418e87dafdc84a40b3692de5032ad88a`.

This check only validates a synthetic envelope and local binding shape. It
does not authenticate a credential or source, map all declared private
inputs, validate the R1CS relation, generate a proof or authorize an
application action. `V3BoundWitness::open_full` deliberately remains
`Unsupported` until those separately reviewed dependencies are present.
