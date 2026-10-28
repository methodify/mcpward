# Testing your server

`mcpward-testing` lets you test authorization without a real identity provider.

## The test issuer

```rust
let issuer = TestIssuer::entra(TENANT, API).start().await; // Entra-shaped tokens
let issuer = TestIssuer::start().await;                    // generic OIDC, with discovery
```

The issuer serves a JWKS on `127.0.0.1` and counts fetches. `issuer.auth_for(url)` returns
authentication that trusts it, with `required_scopes(["access_as_user"])` and
`allowed_clients(["test-client"])` to match the tokens it mints.

Mint tokens from valid defaults and change what the test is about:

```rust
issuer.token().mint();                                  // valid
issuer.token().roles(&["Orders.Writer"]).mint();
issuer.token().aud("api://other").mint();               // wrong audience
issuer.token().expired().mint();
issuer.token().alg_none().mint();
issuer.token().hs256_with_public_key().mint();          // key-confusion attempt
issuer.token().signed_by_untrusted_key().mint();        // bad signature
issuer.token().unknown_kid().mint();
issuer.token().claim("ver", "1.0").mint();              // Entra v1
```

`issuer.rotate()` switches the signing key and drops the old one from the JWKS.

The issuer signs with RSA keys committed under `crates/mcpward-testing/keys/`. They're public
test keys. Never trust them anywhere else.

## The test client

`TestClient` drives a built `McpServer` in-process, with no network:

```rust
let client = TestClient::new(build_server(&issuer).await); // async fn(&TestIssuer) -> McpServer
let token = issuer.token().roles(&["Orders.Reader"]).mint();

let tools = client.list_tools(&token).await;
assert!(!tools.names().contains(&"draft_order"));

let res = client.call_tool(&token, "draft_order", json!({"sku": "A1"})).await;
assert_eq!(res.status, 200);
assert!(res.is_tool_error());
```

By default requests use the `2025-11-25` protocol. To test the `2026-07-28` protocol, which sends
`MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, and per-request `_meta`, call
`.era(Era::V2026_07_28)`.

## The conformance suite

The suite checks the resource-server contract against your own server:

```rust
mcpward_testing::conformance! {
    issuer = TestIssuer::entra(TENANT, API).start(),
    server = build_server,   // async fn(&TestIssuer) -> McpServer
    config = Conformance::new("http://localhost/mcp", "whoami")
        .role_tool("draft_order", "Orders.Writer")
        .role_denial(RoleDenial::InBand),
}
```

It generates about 36 `#[tokio::test]`s in a module named `mcpward_conformance`, including:

- the exact `401` challenge, metadata at the right path, and no redirects;
- refusal of a wrong `iss`, `aud`, or `tid`, an expired token, a missing scope, an unlisted
  `azp`, a bad signature, `alg=none`, HS256 key confusion, a future `nbf`, a missing `kid`, a v1
  token, an app-only token, and a token in the query string;
- role-gated tools hidden from lists and denied on call, in the configured mode;
- exactly one JWKS refetch for 100 concurrent unknown `kid`s, rate limiting, and rotation;
- logs that contain the subject and client ID but no token or token segment;
- stateless behavior in both protocol eras.

`Conformance` options:

| Option | Use it when |
|---|---|
| `role_tool(tool, role)` | You have a role-gated tool |
| `scope_tool(tool, scope)` | You have a tool that needs a delegated scope |
| `role_denial(mode)` | You use `RoleDenial::HttpInsufficientScope` |
| `caller_roles(&[..])` | Even your open tool needs a role |
| `open_tool_args(json)` | Your open tool takes arguments |

## Downstream calls

`TestTokenEndpoint` is a mock Entra token endpoint and managed-identity endpoint:

```rust
let ep = TestTokenEndpoint::start().await;
let obo = ep.obo_builder(TENANT, API, ep.obo_credential()).build()?;
ep.fail_next(EntraError::codes(&[65001]));     // consent required, once
ep.mint_with(|req| downstream_issuer.token().sub(req.assertion_claims["oid"].as_str().unwrap()).mint());
```

`mint_with` makes the token endpoint return a real JWT from a second `TestIssuer`, so one test
can cover the whole chain: an MCP token, the On-Behalf-Of exchange, and a downstream API that
validates the result. [`examples/downstream`](../examples/downstream/src/tests.rs) does this.

## Checking logs

`LogCapture::start()` captures `tracing` output on the current thread until its guard drops.
Use it with the default current-thread `#[tokio::test]` runtime.
