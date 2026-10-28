//! Tests of mcpward itself against a probe server: handler isolation, fail-closed builds,
//! metadata paths, policies for every kind of target, and dev mode.

mod common;

use common::*;
use mcpward::{Auth, ConfigError, Entra, McpServer, Policies, Require, RoleDenial};
use mcpward_testing::{Era, TestClient, TestIssuer};
use serde_json::{Value, json};

async fn entra() -> TestIssuer {
    TestIssuer::entra(TENANT, API).start().await
}

#[tokio::test]
async fn authorization_header_not_visible_to_handler() {
    let issuer = entra().await;
    let c = TestClient::new(server(&issuer).await);
    let token = issuer.token().mint();
    let r = c.call_tool(&token, "probe", json!({})).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let s = r.structured().expect("structured");
    assert_eq!(s["has_authorization"], false);
    assert!(!s["headers"].to_string().to_ascii_lowercase().contains("authorization"));
    assert!(!r.text().contains(&token));
}

#[tokio::test]
async fn subject_token_not_reachable_through_extension_parts() {
    let issuer = entra().await;
    let c = TestClient::new(server(&issuer).await);
    let token = issuer.token().mint();
    let r = c.call_tool(&token, "probe", json!({})).await;
    let s = r.structured().expect("structured");
    assert_eq!(s["subject_token_extension"], false);
    for k in ["parts_debug", "principal_debug"] {
        let d = s[k].as_str().unwrap();
        for seg in token.split('.') {
            assert!(!d.contains(seg), "{k} exposes the token");
        }
    }
}

#[tokio::test]
async fn build_fails_without_scopes_or_opt_out() {
    let issuer = entra().await;
    let auth = Auth::entra(Entra::new(TENANT, API)).allowed_clients(["c"]).jwks({
        let u = issuer.jwks_uri();
        move |mut j| {
            j.uri = u;
            j
        }
    });
    let err = builder().resource_url(URL).unwrap().auth(auth).build().await.unwrap_err();
    assert!(matches!(err, ConfigError::NoRequiredScopes), "{err}");
    let auth = Auth::entra(Entra::new(TENANT, API)).allowed_clients(["c"]).required_scopes(Vec::<String>::new());
    let err = builder().resource_url(URL).unwrap().auth(auth).build().await.unwrap_err();
    assert!(matches!(err, ConfigError::NoRequiredScopes), "an empty list is not an opt-out: {err}");
}

#[tokio::test]
async fn build_fails_without_client_allowlist_or_opt_out() {
    let auth = Auth::entra(Entra::new(TENANT, API)).required_scopes(["access_as_user"]);
    let err = builder().resource_url(URL).unwrap().auth(auth).build().await.unwrap_err();
    assert!(matches!(err, ConfigError::NoClientAllowlist), "{err}");
}

#[tokio::test]
async fn build_fails_on_unpoliced_router_tool() {
    let issuer = entra().await;
    let b = McpServer::builder(Probe::new())
        .tools(&Probe::tool_router())
        .policies(Policies::new().tool("whoami", Require::authenticated()));
    let err = b.resource_url(URL).unwrap().auth(issuer.auth_for(URL)).build().await.unwrap_err();
    assert!(matches!(err, ConfigError::UnpolicedTool { .. }), "{err}");
}

#[tokio::test]
async fn build_fails_on_unknown_policy_target_and_missing_routers() {
    let issuer = entra().await;
    let b = McpServer::builder(Probe::new())
        .tools(&Probe::tool_router())
        .prompts(&Probe::prompt_router())
        .policies(policies().tool("wirte", Require::role("Writer")));
    let err = b.resource_url(URL).unwrap().auth(issuer.auth_for(URL)).build().await.unwrap_err();
    assert!(matches!(err, ConfigError::UnknownPolicyTarget { ref name } if name == "wirte"), "{err}");
    let b = McpServer::builder(Probe::new()).policies(policies());
    let err = b.resource_url(URL).unwrap().auth(issuer.auth_for(URL)).build().await.unwrap_err();
    assert!(matches!(err, ConfigError::RoutersNotDeclared), "{err}");
}

#[tokio::test]
async fn default_policy_opts_out() {
    let issuer = entra().await;
    let s = McpServer::builder(Probe::new())
        .tools(&Probe::tool_router())
        .policies(Policies::new().default(Require::authenticated()))
        .resource_url(URL)
        .unwrap()
        .auth(issuer.auth_for(URL))
        .build()
        .await
        .unwrap();
    let r = TestClient::new(s).call_tool(&issuer.token().mint(), "write", json!({"text": "x"})).await;
    assert!(!r.is_tool_error(), "{}", r.text());
}

#[tokio::test]
async fn root_prm_404_unless_enabled() {
    let issuer = entra().await;
    let c = TestClient::new(server(&issuer).await);
    assert_eq!(c.get("/.well-known/oauth-protected-resource").await.status, 404);
    assert_eq!(c.get("/.well-known/oauth-authorization-server").await.status, 404);
    assert_eq!(c.get("/.well-known/openid-configuration").await.status, 404);
    let s = builder().resource_url(URL).unwrap().auth(issuer.auth_for(URL)).serve_root_prm(true).build().await.unwrap();
    let r = TestClient::new(s).get("/.well-known/oauth-protected-resource").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json.unwrap()["resource"], URL);
}

#[tokio::test]
async fn empty_path_resource_mounts_at_root() {
    let issuer = entra().await;
    let url = "http://localhost:8080";
    let s = builder().resource_url(url).unwrap().auth(issuer.auth_for(url)).build().await.unwrap();
    let c = TestClient::new(s);
    let r = c.get("/.well-known/oauth-protected-resource").await;
    assert_eq!(r.json.unwrap()["resource"], url);
    let r = c.list_tools(&issuer.token().mint()).await;
    assert_eq!(r.status, 200, "{}", r.text());
}

#[tokio::test]
async fn entra_prm_and_challenge_use_api_uri_scope() {
    let issuer = entra().await;
    let c = TestClient::new(server(&issuer).await);
    let r = c.get("/.well-known/oauth-protected-resource/mcp").await;
    let doc = r.json.unwrap();
    assert_eq!(doc["authorization_servers"][0], format!("https://login.microsoftonline.com/{TENANT}/v2.0"));
    assert_eq!(doc["scopes_supported"], json!([format!("api://{API}/access_as_user")]));
    let r = c.rpc(None, "tools/list", json!({})).await;
    assert_eq!(
        r.www_authenticate().unwrap(),
        format!(
            "Bearer resource_metadata=\"http://localhost/.well-known/oauth-protected-resource/mcp\", scope=\"api://{API}/access_as_user\""
        )
    );
}

#[tokio::test]
async fn audience_forms_accepted() {
    let issuer = entra().await;
    let c = TestClient::new(server(&issuer).await);
    for aud in [API.to_owned(), format!("api://{API}"), URL.to_owned()] {
        let r = c.list_tools(&issuer.token().aud(&aud).mint()).await;
        assert_eq!(r.status, 200, "aud {aud}: {}", r.text());
    }
    let r = c.list_tools(&issuer.token().claim("aud", [API, "x"]).mint()).await;
    assert_eq!(r.status, 200);
}

#[tokio::test]
async fn scope_tool_step_up_lists_base_and_tool_scopes() {
    let issuer = entra().await;
    let c = TestClient::new(server(&issuer).await);
    let r = c.call_tool(&issuer.token().mint(), "mail", json!({})).await;
    assert_eq!(r.status, 403);
    assert_eq!(
        r.www_authenticate().unwrap(),
        format!(
            "Bearer resource_metadata=\"http://localhost/.well-known/oauth-protected-resource/mcp\", scope=\"api://{API}/access_as_user api://{API}/Mail.Read\", error=\"insufficient_scope\", error_description=\"The token is missing a required scope\""
        )
    );
    let ok = c.call_tool(&issuer.token().scopes(&["access_as_user", "Mail.Read"]).mint(), "mail", json!({})).await;
    assert!(!ok.is_tool_error(), "{}", ok.text());
    // Scope-gated tools stay listed (calling them is the step-up path).
    assert!(c.list_tools(&issuer.token().mint()).await.names().contains(&"mail"));
}

#[tokio::test]
async fn http_insufficient_scope_role_denial() {
    let issuer = entra().await;
    let s = McpServer::builder(Probe::new())
        .tools(&Probe::tool_router())
        .prompts(&Probe::prompt_router())
        .policies(policies().role_denial(RoleDenial::HttpInsufficientScope))
        .resource_url(URL)
        .unwrap()
        .auth(issuer.auth_for(URL))
        .build()
        .await
        .unwrap();
    let c = TestClient::new(s);
    for era in [Era::Legacy2025_11_25, Era::V2026_07_28] {
        let r = c.clone().era(era).call_tool(&issuer.token().mint(), "write", json!({"text": "x"})).await;
        assert_eq!(r.status, 403, "{era:?}");
        assert!(
            r.www_authenticate()
                .unwrap()
                .contains(&format!("scope=\"api://{API}/access_as_user\", error=\"insufficient_scope\""))
        );
    }
}

#[tokio::test]
async fn in_band_denial_in_both_eras() {
    let issuer = entra().await;
    let c = TestClient::new(server(&issuer).await);
    for era in [Era::Legacy2025_11_25, Era::V2026_07_28] {
        let r = c.clone().era(era).call_tool(&issuer.token().mint(), "write", json!({"text": "x"})).await;
        assert_eq!(r.status, 200);
        assert!(r.is_tool_error());
        assert!(r.tool_text().unwrap().contains("`Writer` role"));
        assert!(r.structured().is_none());
        if era == Era::V2026_07_28 {
            assert_eq!(r.result().unwrap()["resultType"], "complete");
        }
        let ok = c
            .clone()
            .era(era)
            .call_tool(&issuer.token().roles(&["Writer"]).mint(), "write", json!({"text": "x"}))
            .await;
        assert_eq!(ok.structured().unwrap()["text"], "x", "{}", ok.text());
    }
}

#[tokio::test]
async fn tool_failure_is_text_only() {
    let issuer = entra().await;
    let c = TestClient::new(server(&issuer).await);
    let r = c.call_tool(&issuer.token().mint(), "fail", json!({})).await;
    assert!(r.is_tool_error());
    assert!(r.structured().is_none());
    let v: Value = serde_json::from_str(r.tool_text().unwrap()).unwrap();
    assert_eq!(v, json!({"error": "conflict", "message": "Already exists", "status": 409}));
    let r = c.call_tool(&issuer.token().mint(), "handler_check", json!({})).await;
    assert!(r.is_tool_error());
    let v: Value = serde_json::from_str(r.tool_text().unwrap()).unwrap();
    assert_eq!(v["error"], "forbidden");
}

#[tokio::test]
async fn prompts_and_resources_are_policed_and_filtered() {
    let issuer = entra().await;
    let c = TestClient::new(server(&issuer).await);
    let user = issuer.token().mint();
    let admin = issuer.token().roles(&["Admin"]).mint();

    let r = c.rpc(Some(&user), "prompts/list", json!({})).await;
    assert_eq!(r.names(), vec!["greet"], "{}", r.text());
    let r = c.rpc(Some(&admin), "prompts/list", json!({})).await;
    assert_eq!(r.names().len(), 2);
    let r = c.rpc(Some(&user), "prompts/get", json!({"name": "admin_prompt"})).await;
    assert_eq!(r.rpc_error().unwrap()["code"], -32002);
    assert!(r.rpc_error().unwrap()["data"]["message"].as_str().unwrap().contains("Admin"));
    let r = c.rpc(Some(&user), "prompts/get", json!({"name": "greet"})).await;
    assert!(r.result().is_some(), "{}", r.text());

    let r = c.rpc(Some(&user), "resources/list", json!({})).await;
    let uris: Vec<&str> =
        r.result().unwrap()["resources"].as_array().unwrap().iter().filter_map(|x| x["uri"].as_str()).collect();
    assert_eq!(uris, vec!["docs://guide"]);
    assert_eq!(r.result().unwrap()["cacheScope"], "private");
    let r = c.rpc(Some(&user), "resources/read", json!({"uri": "docs://admin/runbook"})).await;
    assert_eq!(r.rpc_error().unwrap()["code"], -32002);
    let r = c.rpc(Some(&admin), "resources/read", json!({"uri": "docs://admin/runbook"})).await;
    assert_eq!(r.result().unwrap()["contents"][0]["text"], "# Runbook");
    let r = c.rpc(Some(&user), "resources/read", json!({"uri": "other://x"})).await;
    assert_eq!(r.rpc_error().unwrap()["code"], -32002, "unpoliced URI is denied");
}

#[tokio::test]
async fn batches_and_bad_requests() {
    let issuer = entra().await;
    let c = TestClient::new(server(&issuer).await);
    let t = issuer.token().mint();
    let r = c
        .post_raw(
            Some(&t),
            json!([{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}]),
            &[("mcp-protocol-version", "2025-11-25")],
        )
        .await;
    assert_eq!(r.status, 400);
    let r = c
        .send(
            http::Request::post("/mcp")
                .header("authorization", format!("Bearer {t}"))
                .header("authorization", format!("Bearer {t}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from("{}"))
                .unwrap(),
        )
        .await;
    assert_eq!(r.status, 400, "two Authorization headers");
    let r = c
        .send(
            http::Request::post("/mcp")
                .header("authorization", "Basic dXNlcjpwYXNz")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(r.status, 401);
    assert!(!r.www_authenticate().unwrap().contains("error="), "non-Bearer gets the bare challenge");
    let r = c
        .send(
            http::Request::post("/mcp")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(format!("access_token={t}")))
                .unwrap(),
        )
        .await;
    assert_eq!(r.status, 400);
    assert_eq!(r.www_authenticate(), Some("Bearer error=\"invalid_request\""));
}

#[tokio::test]
async fn host_header_must_match_resource() {
    let issuer = entra().await;
    let c = TestClient::new(server(&issuer).await);
    let t = issuer.token().mint();
    let r = c
        .send(
            http::Request::post("/mcp")
                .header("host", "evil.example.com")
                .header("authorization", format!("Bearer {t}"))
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .body(axum::body::Body::from(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}).to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(r.status, 403);
}

#[tokio::test]
async fn request_id_generated_and_propagated() {
    let issuer = entra().await;
    let c = TestClient::new(server(&issuer).await);
    let r = c.list_tools(&issuer.token().mint()).await;
    assert_eq!(r.header("x-request-id").map(str::len), Some(26), "a ULID");
    let r = c
        .post_raw(
            Some(&issuer.token().mint()),
            json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
            &[("x-request-id", "abc-123")],
        )
        .await;
    assert_eq!(r.header("x-request-id"), Some("abc-123"));
}

#[tokio::test]
async fn health_and_readiness() {
    let issuer = entra().await;
    let c = TestClient::new(server(&issuer).await);
    assert_eq!(c.get("/healthz").await.status, 200);
    assert_eq!(c.get("/readyz").await.status, 200);
}

#[tokio::test]
async fn startup_fails_when_jwks_unreachable() {
    let auth = Auth::entra(Entra::new(TENANT, API)).required_scopes(["access_as_user"]).allowed_clients(["c"]).jwks(
        |mut j| {
            j.uri = "http://127.0.0.1:9/keys".parse().unwrap();
            j.startup = mcpward::auth::StartupPolicy::WaitUntilLoaded { timeout: std::time::Duration::from_secs(2) };
            j
        },
    );
    let err = builder().resource_url(URL).unwrap().auth(auth).build().await.unwrap_err();
    assert!(err.to_string().contains("127.0.0.1:9/keys"), "{err}");
}

#[tokio::test]
async fn graceful_shutdown_over_tcp() {
    let issuer = entra().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://127.0.0.1:{}/mcp", addr.port());
    let s = builder().resource_url(&url).unwrap().auth(issuer.auth_for(&url)).build().await.unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(s.serve_listener(listener, async move {
        let _ = rx.await;
    }));
    let r = reqwest::Client::new()
        .post(&url)
        .bearer_auth(issuer.token().mint())
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2025-11-25")
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), task).await.expect("shut down in time").unwrap().unwrap();
}

#[tokio::test]
async fn env_config_reports_every_problem() {
    let env = |k: &str| -> Option<String> {
        match k {
            "MCPWARD_AUTH" => Some("entra".into()),
            "MCPWARD_RESOURCE_URL" => Some("https://mcp.example.com/mcp/".into()),
            "MCPWARD_ALLOWED_CLIENTS" => Some("abc".into()),
            "MCPWARD_CLOCK_SKEW_SECS" => Some("900".into()),
            _ => None,
        }
    };
    let err = builder().from_env_with("MCPWARD_", env).unwrap_err().to_string();
    for needle in [
        "MCPWARD_RESOURCE_URL: ",
        "trailing slash",
        "MCPWARD_ENTRA_TENANT_ID: required",
        "MCPWARD_ALLOWED_CLIENTS: \"abc\" is not a GUID",
        "MCPWARD_REQUIRED_SCOPES",
        "MCPWARD_CLOCK_SKEW_SECS",
    ] {
        assert!(err.contains(needle), "missing {needle:?} in:\n{err}");
    }
    assert!(err.starts_with("mcpward configuration is invalid:"));
}

#[tokio::test]
async fn env_config_builds_oidc_server() {
    let issuer = TestIssuer::start().await;
    let iss = issuer.issuer().to_owned();
    let env = move |k: &str| -> Option<String> {
        match k.strip_prefix("APP_MCP_")? {
            "AUTH" => Some("oidc".into()),
            "RESOURCE_URL" => Some(URL.into()),
            "OIDC_ISSUER" => Some(iss.clone()),
            "OIDC_AUDIENCES" => Some(mcpward_testing::TEST_AUDIENCE.into()),
            "REQUIRED_SCOPES" => Some("access_as_user".into()),
            "ALLOWED_CLIENTS" => Some(mcpward_testing::TEST_CLIENT_ID.into()),
            "BIND" => Some("127.0.0.1:0".into()),
            _ => None,
        }
    };
    let s = builder().from_env_with("APP_MCP_", env).unwrap().build().await.unwrap();
    let r = TestClient::new(s).list_tools(&issuer.token().mint()).await;
    assert_eq!(r.status, 200, "{}", r.text());
}

#[tokio::test]
async fn unavailable_keys_return_503_without_challenge() {
    let issuer = entra().await;
    let s = builder()
        .resource_url(URL)
        .unwrap()
        .auth(issuer.auth_for(URL).jwks(|mut j| {
            j.uri = "http://127.0.0.1:9/keys".parse().unwrap();
            j.startup = mcpward::auth::StartupPolicy::Lazy;
            j
        }))
        .build()
        .await
        .unwrap();
    let c = TestClient::new(s);
    let r = c.list_tools(&issuer.token().mint()).await;
    assert_eq!(r.status, 503);
    assert!(r.www_authenticate().is_none());
    assert_eq!(c.get("/readyz").await.status, 503);
}

mod dev {
    use super::*;
    use mcpward::DevIdentity;

    #[tokio::test]
    async fn dev_identity_and_guards() {
        let id = DevIdentity { roles: vec!["Writer".into()], ..Default::default() };
        let s = builder()
            .resource_url("http://localhost:5100/mcp")
            .unwrap()
            .bind("127.0.0.1:0".parse().unwrap())
            .auth(Auth::dev(id.clone()))
            .build()
            .await
            .unwrap();
        let c = TestClient::new(s);
        let r = c.call_tool("ignored-token", "whoami", json!({})).await;
        assert_eq!(r.tool_text(), Some("dev-user"));
        assert_eq!(r.header("x-mcpward-dev-auth"), Some("true"));
        let r = c.call_tool("ignored", "write", json!({"text": "x"})).await;
        assert!(!r.is_tool_error(), "dev roles apply: {}", r.text());
        let r = c.call_tool("ignored", "handler_check", json!({})).await;
        assert!(r.is_tool_error(), "policies still run");
        assert_eq!(
            c.get("/.well-known/oauth-protected-resource/mcp").await.json.unwrap()["authorization_servers"][0],
            "http://localhost/dev"
        );

        let err = builder()
            .resource_url("http://localhost/mcp")
            .unwrap()
            .bind("0.0.0.0:8080".parse().unwrap())
            .auth(Auth::dev(id.clone()))
            .build()
            .await
            .unwrap_err();
        assert!(err.to_string().contains("refusing to bind"), "{err}");
        let ok = builder()
            .resource_url("http://mcp:8080/mcp")
            .unwrap()
            .bind("0.0.0.0:8080".parse().unwrap())
            .auth(Auth::dev(id.clone()).dev_allow_non_loopback("i-understand-this-disables-auth"))
            .build()
            .await;
        assert!(ok.is_ok(), "single-label host with the override");
        let err = builder()
            .resource_url("https://mcp.example.com/mcp")
            .unwrap()
            .bind("0.0.0.0:8080".parse().unwrap())
            .auth(Auth::dev(id).dev_allow_non_loopback("i-understand-this-disables-auth"))
            .build()
            .await
            .unwrap_err();
        assert!(err.to_string().contains("dev auth mode refuses"), "{err}");
    }
}
