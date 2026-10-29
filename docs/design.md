# Design

This document explains how mcpward works and why. It's for contributors and for anyone who
needs to know exactly what the server does before they deploy it.

## Goals

mcpward makes an rmcp server a correct OAuth 2.1 resource server with little code:

- Serve RFC 9728 Protected Resource Metadata and the `401`/`403` challenges MCP clients use.
- Validate every JWT with a hardened key cache.
- Enforce per-tool requirements declared in one table, deny by default.
- Give handlers a validated identity and no way to reach the raw token.
- Mint downstream tokens as the user (Entra On-Behalf-Of) without passing the incoming token
  through.
- Fail closed on ambiguous configuration.
- Ship test tools so consumers can prove their rules without a real identity provider.

Non-goals are listed at the end.

## Crates and modules

| Crate | Contents |
|---|---|
| `mcpward` | `auth` (always on, no rmcp or axum), `server` (feature `server`), `exchange` (feature `exchange`, needs `server`) |
| `mcpward-testing` | `TestIssuer`, `TokenBuilder`, `TestTokenEndpoint`, `TestClient`, `LogCapture`, `conformance!` |

mcpward depends on `rmcp = "~3.8"`. It relies on where rmcp puts the request's
`http::request::Parts` and on rmcp's stateless configuration, so each rmcp minor is adopted
deliberately: bump the requirement, run the conformance suite, and note it in the changelog.
rmcp's macros emit `rmcp::` paths, so consumers depend on rmcp directly.

`server::schema` rewrites tool schemas for portability after rmcp builds them. rmcp's
`#[tool]` macros generate schemas with fixed schemars settings and no hook, so the rewrite runs
on the `ToolRouter` (whose routes and `Tool` definitions are public) rather than in schemars or
in the policy layer. That keeps it opt-in, runs it once at startup, and leaves `tools/list`
bodies untouched by mcpward.

## Request pipeline

For `POST {mcp_path}`, outermost first:

1. **Request ID and timeout.** `x-request-id` is kept or generated (a ULID) and echoed. The
   request times out after 120 seconds by default.
2. **Trace layer.** Opens the `mcp.request` span and records its fields once, at the end.
3. **Auth layer.**
   1. A token in the query string or a form body is a `400 invalid_request`.
   2. More than one `Authorization` header is a `400`. None, or a non-Bearer scheme, is the
      bare `401` challenge.
   3. The `TokenValidator` runs. Failures map to the challenges below.
   4. Base scopes are checked again, so custom validators can't skip them.
   5. The `Authorization` header is removed. `Arc<Principal>` and a crate-private token slot
      are inserted into the request extensions.
4. **Policy layer.**
   1. The body is buffered (1 MiB limit) and parsed. A JSON array (a JSON-RPC batch) is a `400`.
   2. For `tools/call`, `prompts/get`, and `resources/read`, the requirement for the name or
      URI is looked up and enforced.
   3. After rmcp answers, `tools/list`, `prompts/list`, `resources/list`, and
      `resources/templates/list` results are filtered, and marked `cacheScope: "private"` when
      any policy uses roles.
5. **rmcp's `StreamableHttpService`**, stateless, with `json_response` on. It checks `Host`
   and `Origin`, validates protocol headers, and negotiates the version.
6. **Your handler**, unwrapped.

Metadata and health routes bypass layers 2 to 6.

### Why there is no handler wrapper

Authorization could live in a wrapper around your `ServerHandler`. mcpward doesn't do that.
rmcp's handler trait has many methods with default bodies, and a wrapper silently replaces
your override with the default whenever rmcp adds a method the wrapper doesn't forward.
Instead, the policy layer works on the HTTP exchange. That works because mcpward forces
`json_response`: every response is one JSON document the layer can read and rewrite. A list
response that arrives as a stream can't be filtered, so the layer replaces it with a JSON-RPC
internal error rather than send it unfiltered.

### Why the policy layer reads the body

The `2026-07-28` protocol sends the tool name in an `Mcp-Name` header, but older protocol
versions don't. mcpward always reads the name from the body, which is the name rmcp will
execute. If the header disagrees, rmcp rejects the request itself.

## Resource URL and metadata

You configure one canonical resource URL, for example `https://mcp.example.com/mcp`. mcpward
derives everything from it and never from `Host` or `X-Forwarded-*`:

| Value | Example |
|---|---|
| MCP route | `/mcp` (or `/` for an empty path) |
| Metadata path (RFC 9728 path insertion) | `/.well-known/oauth-protected-resource/mcp` |
| `resource_metadata` in challenges | `https://mcp.example.com/.well-known/oauth-protected-resource/mcp` |
| Accepted `Host` values | `mcp.example.com`, and `host:port` when a port is set |

The URL must use `https` (`http` only on loopback or in dev mode), with no query, fragment,
userinfo, or trailing slash. The scheme and host are lowercased; the path is kept as written.

The metadata document:

```json
{
  "resource": "https://mcp.example.com/mcp",
  "authorization_servers": ["https://login.microsoftonline.com/<tenant-id>/v2.0"],
  "scopes_supported": ["api://<api-client-id>/access_as_user"],
  "bearer_methods_supported": ["header"]
}
```

It lists exactly one authorization server, never advertises `offline_access`, and is served
with `Cache-Control: public, max-age=300` and `Access-Control-Allow-Origin: *`. The root path
`/.well-known/oauth-protected-resource` is served only for an empty URL path, or with
`serve_root_prm(true)`. That flag is off by default because RFC 9728 ties the document to the
path-inserted URL, and mcpward always sends `resource_metadata`. mcpward never serves
`/.well-known/oauth-authorization-server` or `/.well-known/openid-configuration`.

## Challenges

Parameters always appear in this order: `resource_metadata`, `scope`, `error`,
`error_description`. Descriptions are fixed phrases, never token content.

| Situation | Status | `WWW-Authenticate` |
|---|---|---|
| No token, or a non-Bearer scheme | `401` | `Bearer resource_metadata="..", scope=".."` |
| Invalid token (any validation failure) | `401` | the above plus `error="invalid_token", error_description=".."` |
| Missing a base scope | `403` | `scope` = base scopes, `error="insufficient_scope"` |
| Call needs a delegated scope the token lacks | `403` | `scope` = base and tool scopes, `error="insufficient_scope"` |
| Client not in the allowlist | `403` | none, body `{"error":"client_not_allowed"}` |
| Token in the query or body, several `Authorization` headers | `400` | `Bearer error="invalid_request"` |
| Keys not loaded | `503` | none |

Every `401` carries `resource_metadata` and `scope`, because clients start sign-in only from
a `401`. An unlisted client gets a terminal `403` without a challenge, because signing in again
can't change which client the user runs, so a challenge would loop.

## Validation

`JwtValidator` runs these checks in order and stops at the first failure:

| # | Check | Rule |
|---|---|---|
| 1 | Transport | One `Authorization: Bearer` header; at most 16 KiB |
| 2 | Shape | Three segments; the header is JSON |
| 3 | `alg` | In the allowlist (default `RS256`); `none` and `HS*` are never allowed |
| 4 | `typ` | Matches, if required (for example `at+jwt`) |
| 5 | `kid` | Present and found, after at most one rate-limited refetch; no fallback to "the only key" |
| 6 | Signature | Verified with the key for that `kid` |
| 7 | `iss` | Equals the configured issuer |
| 8 | `aud` | At least one value is accepted |
| 9 | `exp` | Required; leeway default 120 s, at most 300 s |
| 10 | `nbf` | Required when configured (Entra: yes) |
| 11 | `iat` | Not in the future beyond the leeway |
| 12 | Tenant | Equals the configured tenant (Entra `tid`) |
| 13 | Version | Equals the configured version (Entra `ver == "2.0"`) |
| 14 | Token use | Configured claims equal their values |
| 15 | Subject | Present and non-empty; app-only tokens refused unless allowed |
| 16 | Client | In the allowlist |
| 17 | Base scopes | All present |
| 18 | Custom | Your `ClaimCheck`s |

Every request verifies the signature. There's no validation-result cache: an RS256 verify
costs microseconds, and a cache is one more place a revoked result could linger.

## Key cache

- Validation reads an immutable key snapshot without locks. A fetched set replaces the old one
  entirely, so retired keys drop out. Keys are never pinned.
- Only signing keys of an allowed type are kept (`use` absent or `sig`, `alg` absent or
  allowed, `kid` present).
- A background task refreshes every 6 hours with ±10 % jitter. On failure it keeps the current
  keys and retries with backoff from 30 seconds.
- On an unknown `kid`, a request waits for the fetch lock, checks the snapshot again, and
  fetches only if no on-demand fetch happened in the last 60 seconds (10 seconds to 10
  minutes). Concurrent requests share one fetch, and a stream of junk `kid`s causes at most one
  fetch per interval. Scheduled refreshes don't count against the interval, so a key rotated
  just after startup is picked up immediately.
- Fetches follow no redirects, time out after 10 seconds, and are capped at 256 KiB.
- By default the server doesn't finish building until the first load succeeds (30-second
  limit). With the lazy policy, requests get `503` and `/readyz` reports not ready until it does.

## Principal

`Principal` carries `subject` (with a stable `key()`: `"<tid>:<oid>"` for Entra, `"<sub>"`
otherwise), `client_id`, `scopes`, `roles`, display fields, times, token ID, and kind (user,
application, or dev). Entra's `sub` is pairwise per application, so mcpward uses `oid` and
`tid`. `Debug` leaves out the claims map, which can hold personal data.

## Identity in handlers

rmcp puts the request's `http::request::Parts` into the handler context, and any handler can
read them with `Extension<Parts>`. So mcpward designs for that:

- The `Authorization` header is removed before rmcp sees the request.
- The raw token sits in extensions only inside a crate-private type. Code outside mcpward can't
  name it, so it can't look it up.
- Only `Caller` reads it, and only to pass it to a `TokenExchanger`.

The conformance suite proves this with a probe tool that inspects `Parts`.

## Authorization

Policies are declared on the builder, keyed by tool name, prompt name, and resource URI prefix
(the longest prefix wins). They're checked twice:

1. **At build time**, against the routers you pass with `.tools(..)` and `.prompts(..)`. A tool
   with no policy and no default, a policy for a tool that doesn't exist, or policies without a
   declared router all fail `build()`. rmcp can't list a handler's tools outside a live request,
   which is why the router is passed in.
2. **At call time**, for any name, including tools served outside the router.

A tool annotated `destructive_hint = true` with no role or scope requirement logs a warning at
startup.

| Failure | Result | Reason |
|---|---|---|
| Delegated scope missing | `403 insufficient_scope` with base and tool scopes | Consent can grant scopes, so step-up fixes it |
| Role missing | Hidden from lists; on call, in-band `isError` (default) or `403 insufficient_scope` | Roles come from assignment, and a new sign-in returns a token without the role, so an HTTP challenge can loop. Some auth standards require the `403`, so both are offered. |
| No policy | In-band error | A server bug, not a sign-in problem |

For `prompts/get` and `resources/read`, which have no `isError`, an in-band denial is the
JSON-RPC error `-32002` with the text in `data.message`. Tools with an unmet scope stay listed,
because calling them is the useful step-up path; `hide_on_missing_scope(true)` hides them too.
`scope_implies` and `role_implies` let a broader grant satisfy a narrower one.

In-band errors carry text only, never `structuredContent`, because a tool's output schema
describes success results and a client that validates against it could reject an
error-shaped object.

## Downstream calls

`TokenExchanger` turns `(principal, subject token, target)` into a downstream token.
`EntraObo` posts the subject token to Entra's token endpoint with
`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` and `requested_token_use=on_behalf_of`,
authenticating with a secret, a managed-identity federated assertion (read from
`IDENTITY_ENDPOINT` with `IDENTITY_HEADER` read on every fetch, cached until 5 minutes before
expiry), an assertion file read on every use, or your own `ClientAssertionSource`. It never
requests `offline_access`.

Failures map on Entra's numeric `error_codes`, not on the `error` string, because
`invalid_grant` covers both user-fixable and configuration faults. Unknown codes map to
"contact the administrator", so users aren't told to reconnect in a loop. Error codes and
correlation IDs are logged; tokens and claims content are not.

`CachedExchanger` wraps any exchanger. Entries are keyed by `(subject.key(), target)` and expire
at the earlier of the downstream token's expiry and the expiry of the user token that minted
it, minus a margin (default 3 minutes). An entry therefore never outlives the session that
created it. Concurrent requests for one key share one exchange, and errors aren't cached.

`Downstream` binds a base URL, scopes, and an exchanger. `Caller::client` returns an
`AuthorizedClient` that only builds requests under the base URL: absolute URLs, `//host`, and
paths that resolve outside the base panic in debug builds and fail to send in release builds.
The `Authorization` value is marked sensitive, redirects aren't followed, and the incoming
`x-request-id` and `traceparent` are forwarded when enabled, without overwriting values you
set. A downstream `401` or `403` becomes an in-band tool error, never an HTTP error from the
MCP server, because signing in to the MCP server again can't change the downstream decision.

There's no way to forward the incoming token.

## Observability

mcpward logs with `tracing` and never installs a subscriber.

| Field on `mcp.request` | Value |
|---|---|
| `request_id`, `http.method`, `http.status`, `latency_ms` | |
| `mcp.method`, `mcp.tool`, `mcp.protocol_version` | Truncated to 256 characters |
| `subject`, `tenant`, `client_id` | From the principal |
| `outcome` | `ok`, `tool_error`, `denied_role`, `insufficient_scope`, `invalid_token`, `unauthorized`, `client_not_allowed`, `bad_request`, or `error` |
| `reject_reason` | For example `wrong_audience` |
| `client_ip` | From the socket, or from `X-Forwarded-For` when `trust_forwarded_for` is set |

`mcp.exchange` records `target`, `outcome`, `entra.error_codes`, and `entra.correlation_id`, and
key refreshes log `jwks.refresh` with `outcome`, `keys`, and `trigger`. For rejected tokens, the
unverified `iss`, `aud`, and `kid` are logged at debug level only, truncated and escaped,
because an audience mismatch is the most common setup error.

Never logged: tokens, `Authorization` values, secrets, assertions, the claims map, and request
or response bodies. A consumer that wants an audit trail subscribes to these spans.

## Configuration

Programmatic configuration is the primary interface. `from_env` (prefix `MCPWARD_`, or your
own with `from_env_prefixed`) reads:

| Variable | Default | Meaning |
|---|---|---|
| `RESOURCE_URL` | required | Canonical MCP URL |
| `BIND` | `0.0.0.0:8080` | Listen address |
| `AUTH` | required | `entra`, `oidc`, or `dev` (`dev` needs the `dev-auth` feature) |
| `ENTRA_TENANT_ID`, `ENTRA_API_CLIENT_ID` | required for `entra` | GUIDs |
| `ENTRA_APP_ID_URIS` | none | Extra audiences, comma-separated |
| `OIDC_ISSUER`, `OIDC_AUDIENCES` | required for `oidc` | |
| `OIDC_JWKS_URI`, `OIDC_ROLES_CLAIM`, `OIDC_SCOPES_CLAIM` | discovered, `roles`, auto | |
| `REQUIRED_SCOPES` | required | Claim form, comma-separated, or `none` |
| `ALLOWED_CLIENTS` | required | Comma-separated, or `any` |
| `CLOCK_SKEW_SECS` | `120` | 0 to 300 |
| `JWKS_REFRESH_SECS`, `JWKS_MIN_REFETCH_SECS` | `21600`, `60` | |
| `EXTRA_ALLOWED_HOSTS`, `ALLOWED_ORIGINS` | none | Comma-separated |
| `SHUTDOWN_TIMEOUT_SECS` | `25` | |
| `TRUST_FORWARDED_FOR` | `0` | Hop count, for logs only |
| `SERVE_ROOT_PRM` | `false` | |
| `DEV_SUBJECT`, `DEV_NAME`, `DEV_SCOPES`, `DEV_ROLES`, `DEV_ALLOW_NON_LOOPBACK` | | Dev mode |

`EntraObo::from_env` reads `EXCHANGE` (`entra-obo` or `none`), `EXCHANGE_CLIENT_ID` (defaults to
`ENTRA_API_CLIENT_ID`), `EXCHANGE_CREDENTIAL` (`secret`, `managed-identity`, or
`assertion-file`), `EXCHANGE_CLIENT_SECRET`, `MANAGED_IDENTITY_CLIENT_ID` (falls back to
`AZURE_CLIENT_ID`), and `ASSERTION_FILE` (falls back to `AZURE_FEDERATED_TOKEN_FILE`).
`Downstream::from_env("ORDERS_API")` reads `MCPWARD_ORDERS_API_BASE_URL` and
`MCPWARD_ORDERS_API_SCOPES`.

Every reader collects all problems and reports them together, each with its variable name.
Startup logs one summary of the effective configuration, with no secret values.

**Fail closed.** `build()` fails unless a required scope (non-empty) or `no_required_scopes()`
was set, and unless a client allowlist (non-empty) or `allow_any_client()` was set. An empty
list is an error, not an opt-out. When both a list and its opt-out are set, the list wins.

## rmcp settings

| Setting | Value |
|---|---|
| Session manager | none (`NeverSessionManager`) |
| `legacy_session_mode` | `false` |
| `json_response` | `true` (required by the policy layer) |
| SSE keep-alive | off |
| `allowed_hosts` | from the resource URL, plus extras |
| Origin validation | on, with your `allowed_origins` |
| Request body limit | 1 MiB |

`rmcp_config(..)` can adjust the rest. mcpward re-applies `legacy_session_mode(false)` and
`json_response(true)` afterwards and refuses a session store, because sessions conflict with
per-request authentication. The handler's own `supported_protocol_versions` decides which
versions are negotiated; mcpward doesn't override it.

## Operations

- `serve()` binds, waits for `SIGTERM` or Ctrl-C, stops accepting connections, and drains
  in-flight requests for up to `shutdown_timeout` (default 25 seconds). Then it cancels
  rmcp's token and stops background tasks.
- `/healthz` returns `200` while the process runs. `/readyz` returns `200` when keys are loaded
  and every `ReadinessCheck` passes, and otherwise `503` with the failing names.
- No redirects and no trailing-slash normalization: `/mcp/` is `404`.

## Dev mode

`Auth::dev` (feature `dev-auth`, off by default) authenticates every request as one identity
and ignores any token. Policies still run. It refuses a non-loopback bind unless explicitly
acknowledged, refuses any resource host except `localhost`, loopback addresses, and
single-label names, logs a banner at error level at startup and at warn level every 5
minutes, and marks every response with `X-Mcpward-Dev-Auth: true`. It can't be combined with a
token exchanger; downstream calls in dev use `StaticToken` or `NoAuth`, which in turn refuse to
run outside dev mode.

## Choices that differ from common guidance

Some resource-server guides prescribe different behavior. mcpward's choices, and how to match
the guide when you must:

| Common guidance | mcpward | To match the guide |
|---|---|---|
| A missing role gets `403 insufficient_scope` | In-band tool error by default, because step-up can't grant a role | `role_denial(RoleDenial::HttpInsufficientScope)` |
| Unlisted client: often unspecified | Terminal `403` with no challenge | Nothing to change |
| Key cache behind a read-write lock | Lock-free snapshot plus a fetch lock | Same behavior |
| Metadata at the root well-known path | Path-inserted only | `serve_root_prm(true)` |

## Non-goals

- Authorization server features: `/authorize`, `/token`, Dynamic Client Registration, client
  metadata hosting, refresh tokens, consent screens.
- Sessions or per-connection authorization state.
- Token passthrough to downstream APIs.
- Claims challenges.
- Multi-tenant Entra (`common`, `organizations`), v1 tokens, and sovereign clouds in 0.1.
- More than one issuer per server in 0.1. Write a `TokenValidator` that chooses between two
  `JwtValidator`s if you need it.
- Built-in RFC 8693 token exchange, certificate credentials, and instance metadata identity in
  0.1. All are possible through the traits.
- Opaque-token introspection built in. It's possible through `TokenValidator`.
- Sender-constrained tokens (mTLS, DPoP).
- Rate limiting and WAF features. Use your ingress.
- stdio transport.

## Open questions

- Which protocol version each MCP client sends. mcpward supports both eras.
- Whether clients treat a `403` without `insufficient_scope` as terminal, and whether any loop
  on a role denial sent as `403 insufficient_scope`.
- Whether any client probes the root metadata path.
- Whether per-tool scopes belong in `scopes_supported` by default (`advertise_tool_scopes`).
- A metrics feature, after first deployments.
