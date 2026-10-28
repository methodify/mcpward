# Microsoft Entra ID setup

This guide registers an MCP server and its clients in Microsoft Entra ID. It uses these
placeholders:

| Placeholder | Meaning |
|---|---|
| `<tenant-id>` | Your directory (tenant) ID |
| `<api-client-id>` | The API registration's application (client) ID |
| `<client-app-id>` | The MCP client registration's application ID |
| `https://mcp.example.com/mcp` | Your MCP server's URL, exactly as users enter it |

Entra supports neither Dynamic Client Registration nor Client ID Metadata Documents, so each
client product is pre-registered. The MCP specification lists pre-registered credentials first
in a client's order of preference.

## API registration (the MCP server)

- [ ] **Expose an API:** add a delegated scope named `access_as_user`, admin consent only.
- [ ] **Application ID URI:** add the exact MCP URL, `https://mcp.example.com/mcp`, with the
  path and no trailing slash. Keep the default `api://<api-client-id>` as well. The URL must
  be on a domain verified in your tenant; Entra rejects platform host names such as
  `*.azurewebsites.net`.
- [ ] **Manifest:** set `requestedAccessTokenVersion` to `2`. mcpward refuses v1 tokens.
- [ ] **App roles (optional):** define roles such as `Mcp.Reader` and `Mcp.Writer` for
  per-tool policies.
- [ ] **Enterprise application:** turn on **Assignment required** and assign the groups that
  may use the server, with their roles.
- [ ] **No client secret** on this registration unless the server makes On-Behalf-Of calls.
- [ ] **No claims mapping or custom signing key.** Those sign tokens with app-specific keys
  (`keys?appid=`), which mcpward doesn't support, and they also break On-Behalf-Of.

## Client registration (for example Claude)

- [ ] **Platform:** Web, with redirect URI `https://claude.ai/api/mcp/auth_callback`.
- [ ] **Client secret:** a Web redirect needs a confidential client. Use a 6 to 12 month
  lifetime and track the expiry.
- [ ] **API permissions:** add the `access_as_user` delegated scope (and `offline_access` for
  refresh tokens). Grant admin consent.
- [ ] **No application permissions** and no Microsoft Graph permissions. A leaked secret must
  not be able to mint app-only tokens for anything.
- [ ] Record `<client-app-id>`. mcpward checks it against the token's `azp` claim.

## Public client for a command-line tool (optional)

- [ ] Create a separate registration with a **Mobile and desktop** redirect of
  `http://localhost`. Entra accepts any port on localhost for this platform type.
- [ ] Turn on **Allow public client flows**. Give it no secret.
- [ ] Add the same `access_as_user` permission with admin consent, and add its client ID to the
  server's allowlist.

## Server configuration

```rust
Auth::entra(Entra::new("<tenant-id>", "<api-client-id>"))
    .required_scopes(["access_as_user"])
    .allowed_clients(["<client-app-id>", "<cli-client-app-id>"])
```

The preset accepts these audiences: `<api-client-id>`, `api://<api-client-id>`, the resource
URL, and any extra Application ID URIs you add with `Entra::app_id_uri`. Entra may put either
the GUID or a URI in `aud`, so all of them are accepted. The challenge and metadata advertise
the scope as `api://<api-client-id>/access_as_user`, while policies use the short form that
appears in `scp`.

## On-Behalf-Of (optional)

To call another API as the user:

- [ ] On the API registration, add the downstream API's delegated permission (for example
  `api://<downstream-id>/access_as_user` or Graph `User.Read`) and grant admin consent.
- [ ] Give the API registration a credential. Prefer a federated credential over a secret:
  - **Container platforms with a managed identity endpoint** (`IDENTITY_ENDPOINT`): create a
    user-assigned managed identity, attach it to the app, and add a federated credential on the
    API registration with issuer `https://login.microsoftonline.com/<tenant-id>/v2.0`, subject
    the identity's **principal (object) ID**, and audience `api://AzureADTokenExchange`. Use
    `ClientCredential::ManagedIdentity { client_id: "<identity-client-id>" }`. Entra accepts
    only user-assigned identities here.
  - **Kubernetes workload identity**: use `ClientCredential::AssertionFile` with the projected
    token file (`AZURE_FEDERATED_TOKEN_FILE`).
  - **Secret**: `ClientCredential::Secret`, injected from your platform's secret store.

```rust
let obo = EntraObo::builder("<tenant-id>", "<api-client-id>",
    ClientCredential::ManagedIdentity { client_id: "<identity-client-id>".into() })
    .build()?;
```

mcpward maps token endpoint failures by Entra error code:

| Codes | Error | Message shown to the user |
|---|---|---|
| 50076, 50079, 50158, `interaction_required` | `InteractionRequired` | Disconnect and reconnect, then try again |
| 65001, `consent_required` | `ConsentRequired` | An administrator needs to grant consent |
| 50173, 50132, 50133, 50089 | `SessionRevoked` | Disconnect and reconnect |
| 500131, 50013, 700016, 7000215, 700024, 70021, `invalid_client`, `unauthorized_client`, any other `invalid_grant` | `Misconfigured` | Contact the server's administrator |
| Network failure, `5xx`, `temporarily_unavailable` | `Unavailable` | Try again shortly |

## Known problems

| Symptom | Cause | Fix |
|---|---|---|
| Token request fails with `AADSTS9010010` or `invalid_target` | The client sends `resource` = the MCP URL, and it isn't an Application ID URI | Add the exact MCP URL under **Expose an API** |
| Entra refuses to save the Application ID URI | The domain isn't verified in the tenant | Serve from a verified custom domain |
| Users see a consent screen, or error 90095 | The client sends `prompt=consent` | Grant admin consent, and test with a non-admin account |
| Valid tokens rejected with "issued for another resource" | `aud` holds a value you didn't configure | Check the debug log's `unverified_aud`, then add it with `app_id_uri` |
| Connection works, then fails after about an hour | Conditional Access evaluates the refresh from the client's servers, not the user's device | Review Conditional Access policies for the client application |
| Every call fails with `403 client_not_allowed` | The client's ID isn't in `allowed_clients` | Add it |

## Manual checks before rollout

These checks need a real tenant, so the conformance suite can't run them:

- [ ] `curl -i -X POST https://mcp.example.com/mcp` from a public network returns `401` with the
  `WWW-Authenticate` header that the conformance suite expects.
- [ ] `curl -sI https://mcp.example.com/mcp` shows no redirect.
- [ ] A non-admin user in an assigned group can connect, sign in, and call a tool.
- [ ] A user outside the assigned groups is refused at sign-in.
- [ ] After you disable the client's service principal, calls stop at the next token refresh.
- [ ] The server logs show `subject` and `client_id` for each call, and no tokens.
