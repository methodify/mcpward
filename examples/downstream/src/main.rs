//! Calls a downstream REST API as the signed-in user with Entra On-Behalf-Of.
//!
//! Environment: `TENANT_ID`, `API_CLIENT_ID`, `UAMI_CLIENT_ID` (a user-assigned managed
//! identity federated with the API registration), `ORDERS_API_URL`, `ORDERS_API_SCOPE`,
//! `RESOURCE_URL`, and `ALLOWED_CLIENTS` (comma-separated).
use std::sync::Arc;

use mcpward::prelude::*;
use rmcp::{
    ServerHandler, handler::server::router::tool::ToolRouter, model::ServerConfig, tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone)]
struct Orders {
    tool_router: ToolRouter<Self>,
    api: Arc<Downstream>,
}

#[derive(Deserialize, JsonSchema)]
struct FindOrders {
    /// Customer email.
    email: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
struct OrderPage {
    orders: Vec<Value>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
struct DraftOrder {
    sku: String,
    quantity: u32,
}

#[derive(Serialize, Deserialize, JsonSchema)]
struct Created {
    id: String,
}

#[derive(Serialize, JsonSchema)]
struct Me {
    id: String,
    roles: Vec<String>,
}

#[tool_router]
impl Orders {
    /// Show who is calling and their roles.
    #[tool(annotations(read_only_hint = true, open_world_hint = false))]
    async fn whoami(&self, me: Principal) -> Json<Me> {
        Json(Me { id: me.subject.key().to_owned(), roles: me.roles.iter().cloned().collect() })
    }

    /// Find orders by customer email.
    #[tool(annotations(read_only_hint = true))]
    async fn find_orders(
        &self,
        caller: Caller,
        Parameters(q): Parameters<FindOrders>,
    ) -> Result<Json<OrderPage>, ToolFailure> {
        let api = caller.client(&self.api).await?; // OBO, cached per user, single-flight
        let page = api.json(api.get("/v1/orders").query(&[("email", &q.email)])).await?;
        Ok(Json(page))
    }

    /// Create a draft order. Requires Orders.Writer.
    #[tool(annotations(read_only_hint = false, destructive_hint = false, idempotent_hint = false))]
    async fn draft_order(
        &self,
        caller: Caller,
        Parameters(d): Parameters<DraftOrder>,
    ) -> Result<Json<Created>, ToolFailure> {
        let api = caller.client(&self.api).await?;
        Ok(Json(api.json(api.post("/v1/orders/drafts").json(&d)).await?))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Orders {
    fn get_info(&self) -> ServerConfig {
        mcpward::server_info(
            "orders",
            env!("CARGO_PKG_VERSION"),
            "find_orders searches by email; draft_order needs Orders.Writer.",
        )
    }
}

fn server(api: Arc<Downstream>) -> McpServerBuilder<Orders> {
    McpServer::builder(Orders { tool_router: Orders::tool_router(), api: api.clone() })
        .tools(&Orders::tool_router())
        .downstream(api)
        .policies(
            Policies::new()
                .tools(["whoami", "find_orders"], Require::any_role(["Orders.Reader", "Orders.Writer"]))
                .tool("draft_order", Require::role("Orders.Writer")),
        )
}

fn env(name: &str) -> Result<String, mcpward::Error> {
    std::env::var(name).map_err(|_| mcpward::Error::Other(format!("{name} is required")))
}

#[tokio::main]
async fn main() -> Result<(), mcpward::Error> {
    tracing_subscriber::fmt().json().init();
    let entra = Entra::new(env("TENANT_ID")?, env("API_CLIENT_ID")?);
    let obo = EntraObo::builder(
        &entra.tenant_id,
        &entra.api_client_id,
        ClientCredential::ManagedIdentity { client_id: env("UAMI_CLIENT_ID")? },
    )
    .build()?;
    let api = Arc::new(
        Downstream::builder("orders-api", env("ORDERS_API_URL")?.parse()?)
            .exchanger(Arc::new(obo))
            .scopes([env("ORDERS_API_SCOPE")?])
            .propagate_request_id(true)
            .build()?,
    );
    let clients: Vec<String> = env("ALLOWED_CLIENTS")?.split(',').map(str::to_owned).collect();
    server(api)
        .resource_url(&env("RESOURCE_URL")?)?
        .auth(Auth::entra(entra).required_scopes(["access_as_user"]).allowed_clients(clients))
        .build()
        .await?
        .serve()
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests;
