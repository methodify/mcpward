use rmcp::model::{Implementation, ServerCapabilities, ServerConfig};

/// A `ServerConfig` (rmcp's `ServerInfo`) with the server's own name and version (rmcp would otherwise report its
/// own), tools enabled, and instructions when non-empty.
///
/// Enable more capabilities by editing the result's `capabilities` field.
pub fn server_info(name: &str, version: &str, instructions: &str) -> ServerConfig {
    let mut info = ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
        .with_server_info(Implementation::new(name, version));
    if !instructions.is_empty() {
        info = info.with_instructions(instructions);
    }
    info
}
