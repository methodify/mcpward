//! The conformance suite against the probe server, with a scope-gated tool.

mod common;

use common::*;
use mcpward_testing::{TestIssuer, conformance::Conformance};

mcpward_testing::conformance! {
    issuer = TestIssuer::entra(TENANT, API).start(),
    server = server,
    config = Conformance::new(URL, "whoami").role_tool("write", "Writer").scope_tool("mail", "Mail.Read"),
}
