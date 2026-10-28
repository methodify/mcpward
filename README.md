# mcpward

An auth-first toolkit for remote [Model Context Protocol](https://modelcontextprotocol.io)
servers in Rust, built on the official SDK, [`rmcp`](https://crates.io/crates/rmcp) 3.8.

mcpward turns an rmcp `ServerHandler` into an OAuth 2.1 **resource server**. It serves the
discovery document clients need, answers with the exact `401` and `403` challenges that start
sign-in, validates every JWT, enforces per-tool roles and scopes, and gives your tool handlers
a validated `Principal` instead of a raw token. When a tool needs to call another API as the
user, mcpward mints the downstream token with Microsoft Entra On-Behalf-Of.

It fails closed: a server won't start without a required scope, a client allowlist, and a
policy for every tool, unless you opt out of each by name.

## How it fits the resource-server pattern

Your identity provider (Microsoft Entra ID, Okta, Auth0, Keycloak) is the authorization
server. The MCP client (for example Claude) is a pre-registered OAuth client. Your server
issues no tokens; it checks them.

```text
 MCP client                 mcpward server                  Identity provider
     |  POST /mcp (no token)      |                                 |
     |--------------------------->|                                 |
     |  401 WWW-Authenticate:     |                                 |
     |  resource_metadata, scope  |                                 |
     |<---------------------------|                                 |
     |  GET /.well-known/oauth-protected-resource/mcp               |
     |--------------------------->|                                 |
     |  { resource, authorization_servers: [issuer], ... }          |
     |<---------------------------|                                 |
     |  sign-in, consent, code exchange (server not involved)       |
     |------------------------------------------------------------->|
     |  access token (JWT, aud = your API)                          |
     |<-------------------------------------------------------------|
     |  POST /mcp  Authorization: Bearer <jwt>                      |
     |--------------------------->|  validate signature, iss, aud, |
     |                            |  exp, tenant, azp, scopes;      |
     |                            |  check the tool's policy        |
     |  result                    |                                 |
     |<---------------------------|                                 |
```

mcpward owns the server's half of that exchange:

| Requirement | What mcpward does |
|---|---|
| Challenge unauthenticated requests | `401` with `resource_metadata` and `scope`, byte-for-byte stable |
| Publish Protected Resource Metadata (RFC 9728) | Served at the path-inserted well-known URL, derived only from your configured URL |
| Validate every token | `alg` allowlist, `kid` lookup with rate-limited refetch, signature, `iss`, `aud`, `exp`, `nbf`, tenant, version, subject, client (`azp`), base scopes |
| Authorize each tool | Declarative `Require` per tool, prompt, and resource prefix; deny by default; list filtering |
| Keep tokens away from handlers | The `Authorization` header is removed; handlers get `Principal` (a custom `TokenExchanger` on a `Downstream` still receives the user's token, by design) |
| Call downstream APIs as the user | Entra On-Behalf-Of with secrets or federated credentials, cached per user |
| Never log tokens | Logs carry subject, client, tool, and outcome only |

## Quick start

```toml
[dependencies]
mcpward = "0.1"
rmcp = { version = "~3.8", features = ["server", "macros", "schemars"] }
schemars = "1"
serde = { version = "1", features = ["derive"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }

[dev-dependencies]
mcpward-testing = "0.1"
```

Depend on `rmcp` directly with a compatible requirement (`"~3.8"`): rmcp's macros emit
`rmcp::` paths, and Cargo then unifies both crates on one copy.

```rust
use mcpward::prelude::*;
use rmcp::{ServerHandler, handler::server::router::tool::ToolRouter, model::ServerConfig, tool, tool_handler, tool_router};

#[derive(Clone)]
struct Notes { tool_router: ToolRouter<Self> }

#[tool_router]
impl Notes {
    /// Show who is calling.
    #[tool(annotations(read_only_hint = true))]
    async fn whoami(&self, me: Principal) -> String {
        me.subject.key().to_owned()
    }

    /// Add a note. Requires the Notes.Writer role.
    #[tool]
    async fn add_note(&self, me: Principal) -> String {
        format!("{} added a note", me.subject.key())
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Notes {
    fn get_info(&self) -> ServerConfig {
        mcpward::server_info("notes", env!("CARGO_PKG_VERSION"), "")
    }
}

#[tokio::main]
async fn main() -> Result<(), mcpward::Error> {
    McpServer::builder(Notes { tool_router: Notes::tool_router() })
        .resource_url("https://mcp.example.com/mcp")?
        .auth(
            Auth::entra(Entra::new("<tenant-id>", "<api-client-id>"))
                .required_scopes(["access_as_user"])
                .allowed_clients(["<client-app-id>"]),
        )
        .tools(&Notes::tool_router())
        .policies(
            Policies::new()
                .tool("whoami", Require::authenticated())
                .tool("add_note", Require::role("Notes.Writer")),
        )
        .build()
        .await?
        .serve()
        .await?;
    Ok(())
}
```

The complete version, configured from `MCPWARD_*` environment variables, is in
[`examples/minimal`](examples/minimal/src/main.rs). [`examples/downstream`](examples/downstream/src/main.rs)
calls a REST API as the user with On-Behalf-Of.

To test your authorization rules without a real identity provider, generate the conformance
suite against your own server:

```rust
mcpward_testing::conformance! {
    issuer = mcpward_testing::TestIssuer::entra(TENANT, API).start(),
    server = build_server, // async fn(&TestIssuer) -> McpServer
    config = mcpward_testing::conformance::Conformance::new("http://localhost/mcp", "whoami")
        .role_tool("add_note", "Notes.Writer"),
}
```

## Features

| Feature | Default | Enables |
|---|---|---|
| `server` | yes | Builder, auth and policy layers, extractors, serving |
| `exchange` | yes | `EntraObo`, `CachedExchanger`, `Downstream`, `Caller::client` |
| `aws-lc-rs` | yes | jsonwebtoken on aws-lc-rs |
| `rust-crypto` | no | jsonwebtoken on RustCrypto |
| `dev-auth` | **no** | `Auth::dev`, a local mode with no token checks |

`dev-auth` is off by default, so a production build has no bypass compiled in. Turn it on
through your own dev-only feature: `[features] dev = ["mcpward/dev-auth"]`.

For the validator alone, without rmcp or axum, use
`mcpward = { version = "0.1", default-features = false, features = ["aws-lc-rs"] }`.

## Providers

- **Microsoft Entra ID**: a first-class preset (`Entra`), single tenant, v2 tokens.
- **Any OIDC provider that issues JWT access tokens**: `Oidc`, with discovery. Recipes for
  Okta, Auth0, and Keycloak are in [docs/oidc.md](docs/oidc.md).
- **Anything else**: implement `TokenValidator`, for example for opaque tokens with
  introspection.

## Guides

- [Getting started](docs/getting-started.md)
- [Microsoft Entra ID setup](docs/entra-setup.md)
- [Generic OIDC providers](docs/oidc.md)
- [Testing your server](docs/testing.md)
- [Design](docs/design.md)

## What this is not

- Not an authorization server. mcpward issues no tokens and hosts no `/authorize`, `/token`,
  Dynamic Client Registration, or `/.well-known/oauth-authorization-server`.
- Not a gateway in front of other MCP servers.
- Not an MCP protocol implementation. rmcp owns JSON-RPC, version negotiation, and the
  transport, and you write ordinary rmcp `#[tool]` handlers.
- Not a session store. Every request is authenticated on its own.
- Not for stdio servers, which don't use OAuth.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Unless you explicitly state otherwise, any
contribution you intentionally submit for inclusion in this work, as defined in the Apache-2.0
license, is dual licensed as above, without any additional terms or conditions.
