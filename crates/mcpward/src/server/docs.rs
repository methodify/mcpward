//! [`DocsResources`]: a small in-memory resource list for documentation.
//!
//! rmcp has no resource router. Load the content however you like, then delegate
//! `list_resources` and `read_resource` in your `ServerHandler`:
//!
//! ```ignore
//! async fn list_resources(&self, _: Option<PaginatedRequestParams>, _: RequestContext<RoleServer>)
//!     -> Result<ListResourcesResult, ErrorData> { Ok(self.docs.list()) }
//! async fn read_resource(&self, req: ReadResourceRequestParams, _: RequestContext<RoleServer>)
//!     -> Result<ReadResourceResponse, ErrorData> { self.docs.read(&req.uri) }
//! ```

use std::sync::Arc;

use rmcp::{
    ErrorData,
    model::{ListResourcesResult, ReadResourceResponse, ReadResourceResult, Resource, ResourceContents},
};
use serde_json::json;

/// One document.
#[derive(Clone, Debug)]
pub struct DocEntry {
    /// The resource URI, for example `docs://guide`.
    pub uri: String,
    /// Programmatic name.
    pub name: String,
    /// Display title.
    pub title: Option<String>,
    /// Description shown in lists.
    pub description: Option<String>,
    /// MIME type, for example `text/markdown`.
    pub mime: String,
    /// The content.
    pub text: String,
}

/// An in-memory set of text resources.
#[derive(Clone, Debug, Default)]
pub struct DocsResources {
    entries: Arc<Vec<DocEntry>>,
}

impl DocsResources {
    /// Wraps a list of entries.
    pub fn from_entries(entries: Vec<DocEntry>) -> Self {
        DocsResources { entries: Arc::new(entries) }
    }

    /// The entries.
    pub fn entries(&self) -> &[DocEntry] {
        &self.entries
    }

    /// The `resources/list` result.
    pub fn list(&self) -> ListResourcesResult {
        let items = self
            .entries
            .iter()
            .map(|e| {
                let mut r = Resource::new(e.uri.clone(), e.name.clone())
                    .with_mime_type(e.mime.clone())
                    .with_size(e.text.len() as u64);
                if let Some(t) = &e.title {
                    r = r.with_title(t.clone());
                }
                if let Some(d) = &e.description {
                    r = r.with_description(d.clone());
                }
                r
            })
            .collect();
        ListResourcesResult::with_all_items(items)
    }

    /// The `resources/read` result, or `resource_not_found`.
    pub fn read(&self, uri: &str) -> Result<ReadResourceResponse, ErrorData> {
        let e = self
            .entries
            .iter()
            .find(|e| e.uri == uri)
            .ok_or_else(|| ErrorData::resource_not_found("resource not found", Some(json!({"uri": uri}))))?;
        let contents = ResourceContents::text(e.text.clone(), e.uri.clone()).with_mime_type(e.mime.clone());
        Ok(ReadResourceResult::new(vec![contents]).into())
    }
}
