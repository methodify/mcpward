#![allow(dead_code)]

use mcpward::{DocEntry, DocsResources, ToolFailure};
use mcpward::{
    McpServer, McpServerBuilder, Policies, Principal, Require,
    rmcp::{
        ErrorData, RoleServer, ServerHandler,
        handler::server::{
            common::Extension,
            router::{prompt::PromptRouter, tool::ToolRouter},
            wrapper::{Json, Parameters},
        },
        model::{
            GetPromptResult, ListResourcesResult, PaginatedRequestParams, PromptMessage, ReadResourceRequestParams,
            ReadResourceResponse, Role, ServerConfig,
        },
        service::RequestContext,
    },
};
use rmcp::{prompt, prompt_handler, prompt_router, tool, tool_handler, tool_router};
use serde_json::{Value, json};

pub const TENANT: &str = "00000000-0000-0000-0000-000000000001";
pub const API: &str = "00000000-0000-0000-0000-000000000002";
pub const URL: &str = "http://localhost/mcp";

#[derive(Clone)]
pub struct Probe {
    tool_router: ToolRouter<Self>,
    prompt_router: PromptRouter<Self>,
    docs: DocsResources,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct Echo {
    pub text: String,
}

#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct Out {
    pub text: String,
}

#[tool_router(vis = "pub")]
impl Probe {
    pub fn new() -> Self {
        let docs = DocsResources::from_entries(vec![
            DocEntry {
                uri: "docs://guide".into(),
                name: "guide".into(),
                title: Some("Guide".into()),
                description: None,
                mime: "text/markdown".into(),
                text: "# Guide".into(),
            },
            DocEntry {
                uri: "docs://admin/runbook".into(),
                name: "runbook".into(),
                title: None,
                description: None,
                mime: "text/markdown".into(),
                text: "# Runbook".into(),
            },
        ]);
        Probe { tool_router: Self::tool_router(), prompt_router: Self::prompt_router(), docs }
    }

    /// Reports what the handler can see of the request.
    #[tool]
    async fn probe(&self, Extension(parts): Extension<http::request::Parts>, me: Principal) -> Json<Value> {
        Json(json!({
            "has_authorization": parts.headers.contains_key(http::header::AUTHORIZATION),
            "subject_token_extension": parts.extensions.get::<mcpward::auth::SubjectToken>().is_some(),
            "parts_debug": format!("{parts:?}"),
            "principal_debug": format!("{me:?}"),
            "headers": parts.headers.iter().map(|(k, v)| format!("{k}: {}", v.to_str().unwrap_or(""))).collect::<Vec<_>>(),
        }))
    }

    /// Open to every caller.
    #[tool(annotations(read_only_hint = true))]
    async fn whoami(&self, me: Principal) -> String {
        me.subject.key().to_owned()
    }

    /// Needs Writer.
    #[tool]
    async fn write(&self, Parameters(e): Parameters<Echo>) -> Result<Json<Out>, ToolFailure> {
        Ok(Json(Out { text: e.text }))
    }

    /// Needs the Mail.Read delegated scope.
    #[tool]
    async fn mail(&self) -> String {
        "mail".into()
    }

    /// Fails with a ToolFailure.
    #[tool]
    async fn fail(&self) -> Result<Json<Out>, ToolFailure> {
        Err(ToolFailure::new("conflict", "Already exists").status(409))
    }

    /// Checks a role in the handler.
    #[tool]
    async fn handler_check(&self, me: Principal) -> Result<String, ToolFailure> {
        me.require_role("Admin")?;
        Ok("ok".into())
    }
}

#[prompt_router(vis = "pub")]
impl Probe {
    /// A greeting.
    #[prompt]
    async fn greet(&self) -> Vec<PromptMessage> {
        vec![PromptMessage::new_text(Role::User, "hello")]
    }

    /// Admin prompt.
    #[prompt]
    async fn admin_prompt(&self) -> GetPromptResult {
        GetPromptResult::new(vec![PromptMessage::new_text(Role::User, "admin")])
    }
}

#[tool_handler(router = self.tool_router)]
#[prompt_handler(router = self.prompt_router)]
impl ServerHandler for Probe {
    fn get_info(&self) -> ServerConfig {
        let mut info = mcpward::server_info("probe", "0.0.0", "Probe server");
        info.capabilities.prompts = Some(Default::default());
        info.capabilities.resources = Some(Default::default());
        info
    }

    async fn list_resources(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        Ok(self.docs.list())
    }

    async fn read_resource(
        &self,
        req: ReadResourceRequestParams,
        _: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        self.docs.read(&req.uri)
    }
}

pub fn policies() -> Policies {
    Policies::new()
        .tools(["probe", "whoami", "fail"], Require::authenticated())
        .tool("write", Require::role("Writer"))
        .tool("handler_check", Require::authenticated())
        .tool("mail", Require::scope("Mail.Read"))
        .prompt("greet", Require::authenticated())
        .prompt("admin_prompt", Require::role("Admin"))
        .resource_prefix("docs://", Require::authenticated())
        .resource_prefix("docs://admin/", Require::role("Admin"))
}

pub fn builder() -> McpServerBuilder<Probe> {
    McpServer::builder(Probe::new()).tools(&Probe::tool_router()).prompts(&Probe::prompt_router()).policies(policies())
}

pub async fn server(issuer: &mcpward_testing::TestIssuer) -> McpServer {
    builder().resource_url(URL).unwrap().auth(issuer.auth_for(URL)).build().await.unwrap()
}
