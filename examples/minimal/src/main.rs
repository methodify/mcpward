//! Two tools; `add_note` needs the `Notes.Writer` role. Configure with `MCPWARD_*` variables.
use mcpward::prelude::*;
use rmcp::{
    ServerHandler, handler::server::router::tool::ToolRouter, model::ServerConfig, tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
struct Notes {
    tool_router: ToolRouter<Self>,
}

#[derive(Deserialize, JsonSchema)]
struct AddNote {
    text: String,
}

#[derive(Serialize, JsonSchema)]
struct Me {
    id: String,
    name: Option<String>,
}

#[tool_router]
impl Notes {
    fn new() -> Self {
        Self { tool_router: Self::tool_router() }
    }

    /// Show who is calling.
    #[tool(annotations(read_only_hint = true, open_world_hint = false))]
    async fn whoami(&self, me: Principal) -> Json<Me> {
        Json(Me { id: me.subject.key().to_owned(), name: me.name.clone() })
    }

    /// Add a note. Requires the Notes.Writer role.
    #[tool(annotations(read_only_hint = false, destructive_hint = false))]
    async fn add_note(&self, me: Principal, Parameters(a): Parameters<AddNote>) -> String {
        format!("{} added: {}", me.subject.key(), a.text)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Notes {
    fn get_info(&self) -> ServerConfig {
        mcpward::server_info(
            "notes",
            env!("CARGO_PKG_VERSION"),
            "Use whoami to check identity. add_note needs the Notes.Writer role.",
        )
    }
}

fn server() -> McpServerBuilder<Notes> {
    McpServer::builder(Notes::new()).tools(&Notes::tool_router()).policies(
        Policies::new().tool("whoami", Require::authenticated()).tool("add_note", Require::role("Notes.Writer")),
    )
}

#[tokio::main]
async fn main() -> Result<(), mcpward::Error> {
    tracing_subscriber::fmt().json().init();
    server().from_env()?.build().await?.serve().await?;
    Ok(())
}

#[cfg(test)]
mod tests;
