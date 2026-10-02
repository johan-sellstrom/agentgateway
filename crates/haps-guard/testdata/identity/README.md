# Identity test fixtures

`google-test-key.pem` is a throwaway RSA key generated for these tests only; it stands in for
Google's ID-token signing key, and `google-test-jwks.json` is its public half. It signs nothing
outside the test suite and must never be trusted by a deployed guard.
