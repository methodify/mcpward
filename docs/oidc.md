# Generic OIDC providers

Any provider that issues JWT access tokens works through `Oidc`:

```rust
Auth::oidc(Oidc::new("https://id.example.com/").audience("api://orders"))
    .required_scopes(["orders.read"])
    .allowed_clients(["<client-id>"])
```

At startup mcpward fetches `{issuer}/.well-known/openid-configuration` (falling back to the
RFC 8414 `/.well-known/oauth-authorization-server` path), requires the document's `issuer` to
equal yours byte-for-byte, and reads `jwks_uri`. To skip discovery, call `.jwks_uri(url)`.

At least one audience is required. The MCP specification requires servers to validate the
audience.

## Default claims

| What | Claims |
|---|---|
| Subject | `sub` |
| Client | `azp`, then `client_id`, then `cid` |
| Scopes | `scope`, then `scp`, each as a space-separated string or an array |
| Roles | `roles` |
| Display | `name`, `preferred_username`, `email` |

Change them with `roles_claim`, `scopes_claim`, `require_typ`, and `require_claim`, or edit
`Oidc::claims` directly. A role path is dotted (`realm_access.roles`); for a claim name that
contains a dot, use `ClaimPath::literal`.

## Recipes

These are configuration recipes. mcpward's tests cover them with tokens shaped like each
provider's, not against the live providers.

### Okta (custom authorization server)

```rust
Oidc::new("https://example.okta.com/oauth2/<server-id>")
    .audience("api://orders")
    .scopes_claim(ScopeClaim::Array("scp".into()))
    .roles_claim("groups")
```

Use a custom authorization server. Okta's org authorization server issues tokens that a
resource server can't validate. The client ID is in `cid`, which the defaults read.

### Auth0

```rust
Oidc::new("https://example.auth0.com/")
    .audience("https://api.example.com")
    .roles_claim("permissions")
    .require_typ("at+jwt")
```

Turn on RBAC and **Add Permissions in the Access Token** for the API so `permissions` is
present.

### Keycloak

```rust
Oidc::new("https://sso.example.com/realms/example")
    .audience("orders-api")
    .roles_claim("realm_access.roles")
```

Add an audience mapper to the client scope; otherwise `aud` is `account`. For client roles, use
`resource_access.<client>.roles`.

### Amazon Cognito

Not supported. Cognito access tokens carry no `aud`, so they can't meet the MCP requirement to
validate the audience.

## Providers that don't issue scopes or client claims

If your provider has no scope claim or no client claim, opt out explicitly with
`no_required_scopes()` or `allow_any_client()`. Both log a warning at startup, and both names
say what you give up.
