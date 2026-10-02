# Source

Copied unmodified from `test_vectors/v0.4/` of https://github.com/iProov/HAPS-reference at
commit `fb15eac5773ae113bd62fdf1ac798217415a3f8f`, the same commit `haps-canon` and `haps-hash`
are pinned to in `Cargo.toml`. The intent and signing-view files are the normative VEC-01 inputs;
the tests check that hashing them reproduces the expected hashes beside them, so an edit to any of
them fails the suite rather than silently changing what the guard is tested against.
