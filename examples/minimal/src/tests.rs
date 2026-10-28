use mcpward_testing::{TestClient, TestIssuer, conformance::Conformance};
use serde_json::json;

use super::*;

const TENANT: &str = "00000000-0000-0000-0000-000000000001";
const API: &str = "00000000-0000-0000-0000-000000000002";
const URL: &str = "http://localhost/mcp";

async fn build(issuer: &TestIssuer) -> McpServer {
    server().resource_url(URL).unwrap().auth(issuer.auth_for(URL)).build().await.unwrap()
}

mcpward_testing::conformance! {
    issuer = TestIssuer::entra(TENANT, API).start(),
    server = build,
    config = Conformance::new(URL, "whoami").role_tool("add_note", "Notes.Writer"),
}

mod generic_oidc {
    use super::*;
    mcpward_testing::conformance! {
        issuer = TestIssuer::start(),
        server = build,
        config = Conformance::new(URL, "whoami").role_tool("add_note", "Notes.Writer"),
    }
}

#[tokio::test]
async fn writer_can_add_reader_cannot() {
    let issuer = TestIssuer::entra(TENANT, API).start().await;
    let client = TestClient::new(build(&issuer).await);

    let reader = issuer.token().mint();
    let denied = client.call_tool(&reader, "add_note", json!({"text": "hi"})).await;
    assert_eq!(denied.status, 200);
    assert!(denied.is_tool_error());
    assert!(denied.tool_text().unwrap().contains("Notes.Writer"));

    let writer = issuer.token().roles(&["Notes.Writer"]).mint();
    let ok = client.call_tool(&writer, "add_note", json!({"text": "hi"})).await;
    assert!(!ok.is_tool_error(), "{}", ok.text());
    assert!(ok.tool_text().unwrap().ends_with("added: hi"));

    let me = client.call_tool(&reader, "whoami", json!({})).await;
    assert_eq!(me.structured().unwrap()["id"], format!("{TENANT}:{}", mcpward_testing::TEST_OID));
}

/// The same suite with role denials as `403 insufficient_scope`.
mod http_role_denial {
    use super::*;
    use mcpward::RoleDenial;

    async fn build_http(issuer: &TestIssuer) -> McpServer {
        let policies = Policies::new()
            .tool("whoami", Require::authenticated())
            .tool("add_note", Require::role("Notes.Writer"))
            .role_denial(RoleDenial::HttpInsufficientScope);
        server().policies(policies).resource_url(URL).unwrap().auth(issuer.auth_for(URL)).build().await.unwrap()
    }

    mcpward_testing::conformance! {
        issuer = TestIssuer::entra(TENANT, API).start(),
        server = build_http,
        config = Conformance::new(URL, "whoami").role_tool("add_note", "Notes.Writer").role_denial(RoleDenial::HttpInsufficientScope),
    }
}
