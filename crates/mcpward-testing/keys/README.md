# Test-only keys

These RSA key pairs are **public** and exist only to sign test tokens. They are committed on
purpose so tests don't need key generation at run time. Never trust them anywhere.

- `TEST-ONLY-key0.pem`, `TEST-ONLY-key1.pem`: the issuer's current and next key (rotation).
- `TEST-ONLY-key2.pem`: an untrusted key that never appears in the test JWKS.
