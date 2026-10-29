# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/) (breaking changes bump the minor version while 0.x).

## 0.2.0 (2026-10-29)

### Added

- `mcpward::server::schema`: opt-in portable tool schemas. `portable(router)` (or
  `Portable::new().router(router)`) rewrites the input schemas of an rmcp `ToolRouter`,
  including those the `#[tool]` macros generate, so they pass the MCP Inspector's schema
  portability checks: bare `true`/`false` and untyped schemas get an explicit spelling, an
  optional property's `type: [T, "null"]` becomes `type: T`, a required nullable becomes
  `anyOf: [{type: T}, {type: "null"}]`, and an optional property drops a `null` branch from
  `anyOf`/`oneOf`. `Portable::output_schemas(true)` covers output schemas too, and
  `AnyValue::Object` advertises free-form values as JSON objects. The integer formats
  schemars writes for Rust integer types (`uint32`, `uint`, `int8`, and the rest), which aren't
  JSON Schema formats, are removed. `Portable` also implements schemars' `Transform`.

## 0.1.0 (2026-10-28)

### Added

- `mcpward`: JWT validation with a JWKS cache (scheduled refresh, rate-limited single-flight
  refetch on an unknown `kid`, no key pinning), RFC 9728 Protected Resource Metadata, and
  `WWW-Authenticate` challenges.
- Microsoft Entra ID preset and generic OIDC discovery.
- `McpServer` builder on rmcp 3.8 with stateless Streamable HTTP, fail-closed configuration,
  per-tool, per-prompt, and per-resource policies, list filtering, and two role-denial modes.
- `Principal`, `Caller`, and `RequestMeta` extractors. The raw token is unreachable from
  handlers.
- Entra On-Behalf-Of with client secrets, managed identity, and assertion files; a per-user
  token cache; and `AuthorizedClient` for downstream calls.
- `ToolFailure`, `server_info`, `DocsResources`, environment configuration, health and
  readiness routes, graceful shutdown, and an opt-in development auth mode.
- `mcpward-testing`: `TestIssuer`, `TokenBuilder`, `TestTokenEndpoint`, `TestClient` for both
  protocol eras, `LogCapture`, and the `conformance!` suite.

### Security

- The policy layer fails closed: a body that isn't exactly one JSON object, or that repeats an
  object key at any depth, gets `400` instead of reaching rmcp.
- `completion/complete` and `resources/subscribe`/`unsubscribe` are checked against the prompt
  or resource policy. `tasks/*` is refused unless `Policies::allow_tasks(true)`.
- An Entra token without `scp` is treated as app-only even without `roles` or `idtyp`.
- A non-integer `iat` is still checked. Entra GUIDs (tenant, API, allowed clients) compare
  case-insensitively.
- `fetch_timeout` bounds every JWKS fetch, including with a custom HTTP client, and a failed
  lazy first load is retried within seconds.
- Dev auth mode refuses to serve on a non-loopback listener passed to `serve_listener`.
- The token cache keys on the requested scopes, and an expired user token isn't sent to
  On-Behalf-Of.
- Resource URLs with surrounding whitespace or non-ASCII characters are refused, and a
  normalized one is logged.
