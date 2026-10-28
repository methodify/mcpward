# Contributing

Thanks for helping. Issues and pull requests are welcome.

## Before you open a pull request

Run the same checks CI runs:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test -p mcpward --no-default-features --features rust-crypto
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
scripts/denylist.sh
```

The conformance suite runs as part of `cargo test` against both examples and a probe server.
It must pass. If you change behavior the suite checks, update the suite in the same pull
request and say why.

Add an entry under `## Unreleased` in `CHANGELOG.md` for any user-facing change.

## Fixtures and examples

Use placeholders only:

- Domains: `example.com`, `api.example.com`, `mcp.example.com`.
- GUIDs: `00000000-0000-0000-0000-0000000000xx`.
- Email addresses: `@example.com`.

No real tenant IDs, client IDs, domains, names, or file-system paths. `scripts/denylist.sh`
enforces this in CI, on every tracked file and every commit message in a pull request. You can
add your own patterns, for example your employer's name, to an untracked
`denylist.local.txt`; the script reads it when present.

## Security-sensitive changes

Changes to token validation, the JWKS cache, the auth or policy layers, or token exchange need
a test that fails without the change. Report vulnerabilities privately; see
[SECURITY.md](SECURITY.md).
