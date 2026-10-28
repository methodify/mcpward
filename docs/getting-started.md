# Getting started

This guide takes you from an rmcp handler to a server that accepts real tokens. It assumes you
already know how to write rmcp `#[tool]` handlers.

## 1. Add the dependencies

```toml
[dependencies]
mcpward = "0.1"
rmcp = { version = "~3.8", features = ["server", "macros", "schemars"] }
schemars = "1"
serde = { version = "1", features = ["derive"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
tracing-subscriber = { version = "0.3", features = ["json"] }

[dev-dependencies]
mcpward-testing = "0.1"

[features]
dev = ["mcpward/dev-auth"]
```

## 2. Keep the router in the handler

mcpward clones your handler for every request, so build the `ToolRouter` once and store it:

```rust
#[derive(Clone)]
struct Notes {
    tool_router: ToolRouter<Self>,
}
```

Put shared state, such as a database pool, behind `Arc`.

## 3. Take the caller as a parameter

Any tool can take `Principal`, which is the validated caller:

```rust
#[tool(annotations(read_only_hint = true))]
async fn whoami(&self, me: Principal) -> Json<Me> {
    Json(Me { id: me.subject.key().to_owned(), name: me.name.clone() })
}
```

Use `me.subject.key()` for authorization, audit, and data ownership. For Entra it's
`"<tid>:<oid>"`. `name` and `username` are for display only, because they can change.

A tool that calls another API as the user takes `Caller` instead. See
[`examples/downstream`](../examples/downstream/src/main.rs).

## 4. Declare a policy for every tool

```rust
let policies = Policies::new()
    .tool("whoami", Require::authenticated())
    .tool("add_note", Require::role("Notes.Writer"));
```

Pass the router with `.tools(&Notes::tool_router())` so `build()` can check the table. It
fails when a tool has no policy, when a policy names a tool that doesn't exist, and when you
set policies without declaring the router. To apply one requirement to everything unlisted,
use `Policies::default(..)`.

Requirements combine with `and`: `Require::scope("Mail.Read").and(Require::role("Reader"))`.

| Unmet requirement | Result |
|---|---|
| Delegated scope | `403` with `error="insufficient_scope"` listing every scope the call needs. The client can step up. |
| Role | The tool is hidden from `tools/list`. A call returns an in-band tool error (`isError: true`), or `403 insufficient_scope` with `RoleDenial::HttpInsufficientScope`. |
| No policy | In-band error. |

The in-band default exists because an app role comes from assignment, not consent. A new
sign-in returns a token without the role, so a challenge can loop. Choose
`HttpInsufficientScope` when your organization's auth standard requires a `403`.

## 5. Configure authentication

From code:

```rust
let server = McpServer::builder(Notes::new())
    .resource_url("https://mcp.example.com/mcp")?
    .auth(
        Auth::entra(Entra::new("<tenant-id>", "<api-client-id>"))
            .required_scopes(["access_as_user"])
            .allowed_clients(["<client-app-id>"]),
    )
    .tools(&Notes::tool_router())
    .policies(policies)
    .build()
    .await?;
server.serve().await?;
```

Or from the environment, with `.from_env()?` before `.build()`:

| Variable | Example |
|---|---|
| `MCPWARD_RESOURCE_URL` | `https://mcp.example.com/mcp` |
| `MCPWARD_AUTH` | `entra`, `oidc`, or `dev` |
| `MCPWARD_ENTRA_TENANT_ID`, `MCPWARD_ENTRA_API_CLIENT_ID` | GUIDs |
| `MCPWARD_REQUIRED_SCOPES` | `access_as_user` (or `none` to opt out) |
| `MCPWARD_ALLOWED_CLIENTS` | Comma-separated client IDs (or `any` to opt out) |
| `MCPWARD_BIND` | `0.0.0.0:8080` (default) |

`from_env` reports every problem at once, each with its variable name. Settings you make in
code after `from_env` win. The full list of variables is in [design.md](design.md#configuration).

The resource URL is the exact URL users enter in their client. mcpward derives the MCP route,
the metadata path, and the challenge's `resource_metadata` from it, and never from request
headers. It must use `https` (or `http` on `localhost`), with no query, fragment, or trailing
slash.

## 6. Run locally without an identity provider

With your `dev` feature on:

```bash
MCPWARD_AUTH=dev \
MCPWARD_RESOURCE_URL=http://localhost:8080/mcp \
MCPWARD_BIND=127.0.0.1:8080 \
MCPWARD_DEV_ROLES=Notes.Writer \
cargo run --features dev
```

Every request is the dev identity. Policies still run. mcpward logs an error-level banner at
startup and every 5 minutes, adds `X-Mcpward-Dev-Auth: true` to every response, refuses a
non-loopback bind unless `MCPWARD_DEV_ALLOW_NON_LOOPBACK=i-understand-this-disables-auth`, and
refuses any resource host other than `localhost`, a loopback address, or a single-label name.

## 7. Test it

See [testing.md](testing.md).

## 8. Deploy

- Terminate TLS at your ingress. mcpward serves plain HTTP behind it.
- The ingress must preserve the original `Host` header; mcpward rejects other hosts. Add
  internal names with `extra_allowed_hosts`.
- The MCP URL must answer directly. Clients drop `Authorization` on cross-host redirects, and
  mcpward never redirects (`/mcp/` is `404`).
- Probe `/healthz` for liveness and `/readyz` for readiness. Readiness waits for the signing
  keys.
- On `SIGTERM`, mcpward stops accepting connections and drains requests for up to 25 seconds
  (`shutdown_timeout`), under the usual 30-second grace period.
