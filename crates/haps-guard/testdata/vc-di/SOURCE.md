# Source

W3C Data Integrity test vectors, copied unmodified:

- `eddsa-jcs-2022.*` from https://github.com/w3c/vc-di-eddsa, `TestVectors/eddsa-jcs-2022/`
  and `TestVectors/keyPair.json`, at commit `13e7070`.
- `ecdsa-jcs-2019-p256.*` from https://github.com/w3c/vc-di-ecdsa,
  `TestVectors/ecdsa-jcs-2019-p256/` and `TestVectors/p256KeyPair.json`, at commit `59df72c`.

The key pairs are the specifications' published example keys, not secrets. The tests verify the
published signed credentials with the published public keys and reproduce the published
combined hashes, so the guard's `vc+json` verifier is tied to the specifications rather than to
its own reading of them.
