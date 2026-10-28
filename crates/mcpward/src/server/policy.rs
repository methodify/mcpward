//! Declarative authorization: [`Require`], [`Policies`], and the policy layer that enforces
//! them on every `tools/call`, `resources/read`, `resources/subscribe`, `prompts/get`, and
//! `completion/complete`, and filters list results.

use std::{
    collections::{BTreeSet, HashMap},
    fmt,
    sync::Arc,
};

use axum::{
    body::{Body, to_bytes},
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use http::{HeaderValue, StatusCode, header};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Value, json};

use super::{ServerState, obs::Obs};
use crate::auth::{Challenge, Principal, Scope};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Rule {
    All(Vec<String>),
    Any(Vec<String>),
}

impl Rule {
    fn ok(&self, have: &BTreeSet<String>) -> bool {
        match self {
            Rule::All(v) => v.iter().all(|x| have.contains(x)),
            Rule::Any(v) => v.iter().any(|x| have.contains(x)),
        }
    }

    fn items(&self) -> &[String] {
        match self {
            Rule::All(v) | Rule::Any(v) => v,
        }
    }
}

/// What a tool, prompt, or resource requires beyond a valid token with the base scopes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Require {
    scopes: Vec<Rule>,
    roles: Vec<Rule>,
}

fn owned<'a, I: IntoIterator<Item = &'a str>>(i: I) -> Vec<String> {
    i.into_iter().map(str::to_owned).collect()
}

impl Require {
    /// A valid token with the base scopes. No extra requirement.
    pub fn authenticated() -> Self {
        Require::default()
    }

    /// A delegated scope, in claim form.
    pub fn scope(s: &str) -> Self {
        Require { scopes: vec![Rule::All(vec![s.to_owned()])], roles: vec![] }
    }

    /// Every one of these scopes.
    pub fn all_scopes<'a, I: IntoIterator<Item = &'a str>>(i: I) -> Self {
        Require { scopes: vec![Rule::All(owned(i))], roles: vec![] }
    }

    /// At least one of these scopes.
    pub fn any_scope<'a, I: IntoIterator<Item = &'a str>>(i: I) -> Self {
        Require { scopes: vec![Rule::Any(owned(i))], roles: vec![] }
    }

    /// An app role.
    pub fn role(r: &str) -> Self {
        Require { scopes: vec![], roles: vec![Rule::All(vec![r.to_owned()])] }
    }

    /// At least one of these roles.
    pub fn any_role<'a, I: IntoIterator<Item = &'a str>>(i: I) -> Self {
        Require { scopes: vec![], roles: vec![Rule::Any(owned(i))] }
    }

    /// Every one of these roles.
    pub fn all_roles<'a, I: IntoIterator<Item = &'a str>>(i: I) -> Self {
        Require { scopes: vec![], roles: vec![Rule::All(owned(i))] }
    }

    /// Both requirements.
    pub fn and(mut self, other: Require) -> Self {
        self.scopes.extend(other.scopes);
        self.roles.extend(other.roles);
        self
    }

    /// Whether any role rule is present.
    pub fn has_role_rule(&self) -> bool {
        !self.roles.is_empty()
    }

    /// Whether any scope rule is present.
    pub fn has_scope_rule(&self) -> bool {
        !self.scopes.is_empty()
    }

    /// Every role this requirement names.
    pub fn role_names(&self) -> Vec<&str> {
        self.roles.iter().flat_map(|r| r.items()).map(String::as_str).collect()
    }

    /// Every scope this requirement names (claim form).
    pub fn scope_names(&self) -> Vec<&str> {
        self.scopes.iter().flat_map(|r| r.items()).map(String::as_str).collect()
    }

    fn roles_ok(&self, have: &BTreeSet<String>) -> bool {
        self.roles.iter().all(|r| r.ok(have))
    }

    fn scopes_ok(&self, have: &BTreeSet<String>) -> bool {
        self.scopes.iter().all(|r| r.ok(have))
    }

    fn describe_roles(&self) -> String {
        let parts: Vec<String> = self
            .roles
            .iter()
            .map(|r| match r {
                Rule::All(v) if v.len() == 1 => format!("the `{}` role", v[0]),
                Rule::All(v) => format!("all of the {} roles", quoted(v, "and")),
                Rule::Any(v) if v.len() == 1 => format!("the `{}` role", v[0]),
                Rule::Any(v) => format!("one of the {} roles", quoted(v, "or")),
            })
            .collect();
        parts.join(" and ")
    }
}

fn quoted(v: &[String], conj: &str) -> String {
    let q: Vec<String> = v.iter().map(|s| format!("`{s}`")).collect();
    match q.len() {
        0 => String::new(),
        1 => q[0].clone(),
        2 => format!("{} {conj} {}", q[0], q[1]),
        n => format!("{}, {conj} {}", q[..n - 1].join(", "), q[n - 1]),
    }
}

/// What a role failure returns.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum RoleDenial {
    /// HTTP `200` with an in-band tool error (`isError: true`). App roles come from
    /// assignment, not consent, so a new sign-in can't fix a missing role and an HTTP
    /// challenge could loop.
    #[default]
    InBand,
    /// HTTP `403` with `error="insufficient_scope"` and the base scopes, for organizations
    /// whose auth standard requires it.
    HttpInsufficientScope,
}

type DeniedMessage = Arc<dyn Fn(&str, &Require) -> String + Send + Sync>;

/// The policy table: one [`Require`] per tool, prompt, and resource prefix.
///
/// Deny by default: a tool with no policy fails `build()` (when its router is declared with
/// `.tools()`), and any call to a name with no policy is denied, unless
/// [`Policies::default`] is set.
#[derive(Clone, Default)]
pub struct Policies {
    pub(crate) tools: HashMap<String, Require>,
    pub(crate) prompts: HashMap<String, Require>,
    pub(crate) resources: Vec<(String, Require)>,
    pub(crate) default: Option<Require>,
    pub(crate) role_denial: RoleDenial,
    scope_implies: HashMap<String, Vec<String>>,
    role_implies: HashMap<String, Vec<String>>,
    hide_on_missing_scope: bool,
    allow_tasks: bool,
    reveal_requirements: Option<bool>,
    denied_message: Option<DeniedMessage>,
}

impl fmt::Debug for Policies {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Policies")
            .field("tools", &self.tools)
            .field("prompts", &self.prompts)
            .field("resources", &self.resources)
            .field("default", &self.default)
            .field("role_denial", &self.role_denial)
            .finish_non_exhaustive()
    }
}

impl Policies {
    /// An empty table.
    pub fn new() -> Self {
        <Policies as Default>::default()
    }

    /// The requirement for one tool.
    pub fn tool(mut self, name: &str, req: Require) -> Self {
        self.tools.insert(name.to_owned(), req);
        self
    }

    /// The same requirement for several tools.
    pub fn tools<'a, I: IntoIterator<Item = &'a str>>(mut self, names: I, req: Require) -> Self {
        for n in names {
            self.tools.insert(n.to_owned(), req.clone());
        }
        self
    }

    /// The requirement for resources whose URI starts with `uri_prefix`. The longest
    /// matching prefix wins.
    ///
    /// The match is on the raw URI the client sent, byte for byte: no case folding, percent
    /// decoding, or dot-segment removal. The handler must serve only URIs it matches exactly
    /// (as written), or `DOCS://admin/x`, `docs://guide/../admin/x`, and `docs://%61dmin/x`
    /// could reach a handler that normalizes them under a broader prefix's policy.
    pub fn resource_prefix(mut self, uri_prefix: &str, req: Require) -> Self {
        self.resources.push((uri_prefix.to_owned(), req));
        self.resources.sort_by_key(|(p, _)| std::cmp::Reverse(p.len()));
        self
    }

    /// The requirement for one prompt.
    pub fn prompt(mut self, name: &str, req: Require) -> Self {
        self.prompts.insert(name.to_owned(), req);
        self
    }

    /// The requirement for anything not listed. Without one, unlisted names are denied.
    pub fn default(mut self, req: Require) -> Self {
        self.default = Some(req);
        self
    }

    /// What a role failure returns. Default [`RoleDenial::InBand`].
    pub fn role_denial(mut self, mode: RoleDenial) -> Self {
        self.role_denial = mode;
        self
    }

    /// A broader scope that satisfies narrower ones: `scope_implies("Mail.ReadWrite", ["Mail.Read"])`.
    pub fn scope_implies<'a, I: IntoIterator<Item = &'a str>>(mut self, scope: &str, implied: I) -> Self {
        self.scope_implies.entry(scope.to_owned()).or_default().extend(owned(implied));
        self
    }

    /// A role that satisfies others: `role_implies("Writer", ["Reader"])`.
    pub fn role_implies<'a, I: IntoIterator<Item = &'a str>>(mut self, role: &str, implied: I) -> Self {
        self.role_implies.entry(role.to_owned()).or_default().extend(owned(implied));
        self
    }

    /// Also hide list entries whose scope requirement isn't met. Default false: they stay
    /// listed, and calling them returns the `403` step-up challenge.
    pub fn hide_on_missing_scope(mut self, hide: bool) -> Self {
        self.hide_on_missing_scope = hide;
        self
    }

    /// Let `tasks/get`, `tasks/result`, `tasks/cancel`, and `tasks/list` through to the
    /// server. Default false: they are refused, because the policy layer can't tell whose task
    /// an ID belongs to. Turn this on only if the server binds each task to the
    /// [`Principal`]'s subject and refuses other subjects' task IDs.
    pub fn allow_tasks(mut self, allow: bool) -> Self {
        self.allow_tasks = allow;
        self
    }

    /// Whether denial text names the missing role. Default true.
    pub fn reveal_requirements(mut self, reveal: bool) -> Self {
        self.reveal_requirements = Some(reveal);
        self
    }

    /// Custom denial text: `(name, requirement) -> message`.
    pub fn denied_message(mut self, f: impl Fn(&str, &Require) -> String + Send + Sync + 'static) -> Self {
        self.denied_message = Some(Arc::new(f));
        self
    }

    /// The number of explicit entries.
    pub fn len(&self) -> usize {
        self.tools.len() + self.prompts.len() + self.resources.len()
    }

    /// Whether there are no explicit entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn all_rules(&self) -> impl Iterator<Item = &Require> {
        self.tools
            .values()
            .chain(self.prompts.values())
            .chain(self.resources.iter().map(|(_, r)| r))
            .chain(self.default.iter())
    }

    pub(crate) fn any_role_rules(&self) -> bool {
        self.all_rules().any(Require::has_role_rule)
    }

    /// Whether list results can differ between users, so clients mustn't share them.
    pub(crate) fn lists_vary_per_user(&self) -> bool {
        self.any_role_rules() || (self.hide_on_missing_scope && self.all_rules().any(Require::has_scope_rule))
    }

    pub(crate) fn for_tool(&self, name: &str) -> Option<&Require> {
        self.tools.get(name).or(self.default.as_ref())
    }

    pub(crate) fn for_prompt(&self, name: &str) -> Option<&Require> {
        self.prompts.get(name).or(self.default.as_ref())
    }

    pub(crate) fn for_resource(&self, uri: &str) -> Option<&Require> {
        self.resources.iter().find(|(p, _)| uri.starts_with(p.as_str())).map(|(_, r)| r).or(self.default.as_ref())
    }

    fn closure(base: &BTreeSet<String>, implies: &HashMap<String, Vec<String>>) -> BTreeSet<String> {
        let mut out = base.clone();
        let mut stack: Vec<String> = base.iter().cloned().collect();
        while let Some(x) = stack.pop() {
            if let Some(more) = implies.get(&x) {
                for m in more {
                    if out.insert(m.clone()) {
                        stack.push(m.clone());
                    }
                }
            }
        }
        out
    }

    pub(crate) fn effective(&self, p: &Principal) -> Effective {
        Effective {
            scopes: Self::closure(&p.scopes, &self.scope_implies),
            roles: Self::closure(&p.roles, &self.role_implies),
        }
    }

    pub(crate) fn message(&self, name: &str, req: Option<&Require>) -> String {
        if let (Some(f), Some(r)) = (&self.denied_message, req) {
            return f(name, r);
        }
        match req {
            Some(r) if r.has_role_rule() && self.reveal_requirements.unwrap_or(true) => format!(
                "You don't have permission to use `{name}`. It requires {}. Ask an administrator to assign it to you, then reconnect.",
                r.describe_roles()
            ),
            Some(_) => {
                format!("You don't have permission to use `{name}`. Ask an administrator for access, then reconnect.")
            }
            None => format!("`{name}` isn't available on this server."),
        }
    }
}

pub(crate) struct Effective {
    scopes: BTreeSet<String>,
    roles: BTreeSet<String>,
}

enum Decision {
    Allow,
    MissingScopes(Vec<String>),
    MissingRole,
    Unpoliced,
}

fn decide(req: Option<&Require>, eff: &Effective) -> Decision {
    let Some(req) = req else { return Decision::Unpoliced };
    if !req.scopes_ok(&eff.scopes) {
        return Decision::MissingScopes(req.scope_names().into_iter().map(str::to_owned).collect());
    }
    if !req.roles_ok(&eff.roles) {
        return Decision::MissingRole;
    }
    Decision::Allow
}

fn visible(req: Option<&Require>, eff: &Effective, hide_on_scope: bool) -> bool {
    match req {
        None => false,
        Some(r) => r.roles_ok(&eff.roles) && (!hide_on_scope || r.scopes_ok(&eff.scopes)),
    }
}

/// A bounded buffer for the response, which is always one JSON document (mcpward forces
/// `json_response`).
const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

fn json_response(status: StatusCode, v: &Value) -> Response {
    let mut r = (status, v.to_string()).into_response();
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    r
}

fn jsonrpc_error(id: Value, code: i64, message: &str, data: Option<Value>) -> Value {
    let mut err = json!({"code": code, "message": message});
    if let Some(d) = data {
        err["data"] = d;
    }
    json!({"jsonrpc": "2.0", "id": id, "error": err})
}

fn is_2026(protocol: Option<&str>) -> bool {
    protocol.is_some_and(|v| v >= "2026-07-28")
}

fn in_band_tool_error(id: Value, text: &str, protocol: Option<&str>) -> Value {
    let mut result = json!({"content": [{"type": "text", "text": text}], "isError": true});
    if is_2026(protocol) {
        result["resultType"] = json!("complete");
    }
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

/// The policy layer. Runs after the auth layer, before rmcp.
pub(crate) async fn policy_mw(State(st): State<Arc<ServerState>>, req: Request, next: Next) -> Response {
    if req.method() != http::Method::POST {
        return next.run(req).await;
    }
    let obs = req.extensions().get::<Obs>().cloned().unwrap_or_default();
    let Some(principal) = req.extensions().get::<Arc<Principal>>().cloned() else {
        obs.outcome("error");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let protocol = req.headers().get("mcp-protocol-version").and_then(|v| v.to_str().ok()).map(str::to_owned);
    let (parts, body) = req.into_parts();
    let bytes = match to_bytes(body, st.max_body_bytes).await {
        Ok(b) => b,
        Err(_) => {
            obs.outcome("bad_request");
            return (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response();
        }
    };
    // Fail closed: anything this layer can't read exactly one way never reaches rmcp, so a
    // difference between the two parsers can't turn into a policy bypass.
    let bad = |code: i64, message: &str| {
        obs.outcome("bad_request");
        json_response(StatusCode::BAD_REQUEST, &jsonrpc_error(Value::Null, code, message, None))
    };
    let msg = match serde_json::from_slice::<Value>(&bytes) {
        Ok(Value::Object(m)) => m,
        Ok(Value::Array(_)) => return bad(-32600, "JSON-RPC batches are not supported"),
        Ok(_) => return bad(-32600, "the request must be a JSON-RPC object"),
        Err(_) => return bad(-32700, "the request body isn't valid JSON"),
    };
    if !no_duplicate_keys(&bytes) {
        return bad(-32600, "the request has duplicate object keys");
    }
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("").to_owned();
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    let params = msg.get("params");
    let target = |k: &str| params.and_then(|p| p.get(k)).and_then(Value::as_str).map(str::to_owned);
    obs.method(&method);

    let pol = &st.policies;
    if method.starts_with("tasks/") && !pol.allow_tasks {
        obs.outcome("denied_role");
        return json_response(StatusCode::OK, &jsonrpc_error(id, -32601, "method not found", None));
    }
    let eff = pol.effective(&principal);
    let check = match method.as_str() {
        "tools/call" => target("name").map(|n| (n.clone(), pol.for_tool(&n), Kind::Tool)),
        "prompts/get" => target("name").map(|n| (n.clone(), pol.for_prompt(&n), Kind::Other)),
        "resources/read" | "resources/subscribe" | "resources/unsubscribe" => {
            target("uri").map(|u| (u.clone(), pol.for_resource(&u), Kind::Other))
        }
        // Completion names a prompt or a resource template; it gets that entry's policy.
        "completion/complete" => {
            let r = params.and_then(|p| p.get("ref"));
            let field = |k: &str| r.and_then(|r| r.get(k)).and_then(Value::as_str).map(str::to_owned);
            match field("type").as_deref() {
                Some("ref/prompt") => field("name").map(|n| (n.clone(), pol.for_prompt(&n), Kind::Other)),
                Some("ref/resource") => field("uri").map(|u| (u.clone(), pol.for_resource(&u), Kind::Other)),
                // An unknown reference type has no policy to apply.
                _ => Some((String::new(), None, Kind::Other)),
            }
        }
        _ => None,
    };
    if let Some((name, req_for, kind)) = check {
        obs.tool(&name);
        match decide(req_for, &eff) {
            Decision::Allow => {}
            Decision::MissingScopes(needed) => {
                obs.outcome("insufficient_scope");
                let mut scopes: Vec<Scope> = st.base_scopes.clone();
                scopes.extend(needed.iter().map(|s| st.scope_form(s)));
                return st.challenge(&Challenge::InsufficientScope { scopes });
            }
            Decision::MissingRole if pol.role_denial == RoleDenial::HttpInsufficientScope => {
                obs.outcome("denied_role");
                return st.challenge(&Challenge::InsufficientScope { scopes: st.base_scopes.clone() });
            }
            d @ (Decision::MissingRole | Decision::Unpoliced) => {
                obs.outcome("denied_role");
                if matches!(d, Decision::Unpoliced) {
                    tracing::warn!(target: "mcpward::policy", name = %crate::auth::truncate_for_log(&name), "call to a name with no policy denied");
                }
                let text = pol.message(&name, req_for);
                let body = match kind {
                    Kind::Tool => in_band_tool_error(id, &text, protocol.as_deref()),
                    Kind::Other => jsonrpc_error(id, -32002, "forbidden", Some(json!({"message": text}))),
                };
                return json_response(StatusCode::OK, &body);
            }
        }
    }

    let list_key = match method.as_str() {
        "tools/list" => Some("tools"),
        "prompts/list" => Some("prompts"),
        "resources/list" => Some("resources"),
        "resources/templates/list" => Some("resourceTemplates"),
        _ => None,
    };
    let resp = next.run(Request::from_parts(parts, Body::from(bytes))).await;
    if list_key.is_none() && method != "tools/call" {
        return resp;
    }
    let is_json = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"));
    if !is_json {
        if list_key.is_some() && resp.status().is_success() {
            // A streamed list can't be filtered, so it isn't sent at all.
            obs.outcome("error");
            tracing::error!(target: "mcpward::policy", method = %method, "list response was not JSON; refusing to send it unfiltered");
            return json_response(StatusCode::OK, &jsonrpc_error(id, -32603, "internal error", None));
        }
        return resp;
    }
    let (mut rparts, rbody) = resp.into_parts();
    let Ok(rbytes) = to_bytes(rbody, MAX_RESPONSE_BYTES).await else {
        obs.outcome("error");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Ok(mut doc) = serde_json::from_slice::<Value>(&rbytes) else {
        return Response::from_parts(rparts, Body::from(rbytes));
    };
    if method == "tools/call" {
        if doc.pointer("/result/isError") == Some(&Value::Bool(true)) {
            obs.outcome("tool_error");
        }
        return Response::from_parts(rparts, Body::from(rbytes));
    }
    let key = list_key.unwrap_or_default();
    if let Some(result) = doc.get_mut("result").and_then(Value::as_object_mut) {
        if let Some(Value::Array(items)) = result.get_mut(key) {
            items.retain(|item| {
                let req = match key {
                    "tools" => item.get("name").and_then(Value::as_str).and_then(|n| pol.for_tool(n)),
                    "prompts" => item.get("name").and_then(Value::as_str).and_then(|n| pol.for_prompt(n)),
                    "resources" => item.get("uri").and_then(Value::as_str).and_then(|u| pol.for_resource(u)),
                    _ => item.get("uriTemplate").and_then(Value::as_str).and_then(|u| pol.for_resource(u)),
                };
                visible(req, &eff, pol.hide_on_missing_scope)
            });
        }
        if pol.lists_vary_per_user() {
            result.insert("cacheScope".into(), json!("private"));
        }
    }
    let out = doc.to_string();
    rparts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(rparts, Body::from(out))
}

enum Kind {
    Tool,
    Other,
}

/// Whether a JSON document has no object with a repeated key, at any depth. `serde_json::Value`
/// keeps the last of duplicate keys while other parsers keep the first, so a duplicate
/// `method`, `params`, or `name` could be read one way here and another way by rmcp.
fn no_duplicate_keys(bytes: &[u8]) -> bool {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    NoDupes::deserialize(&mut de).is_ok() && de.end().is_ok()
}

struct NoDupes;

impl<'de> Deserialize<'de> for NoDupes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(NoDupesVisitor)
    }
}

struct NoDupesVisitor;

impl<'de> Visitor<'de> for NoDupesVisitor {
    type Value = NoDupes;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }
    fn visit_bool<E>(self, _: bool) -> Result<NoDupes, E> {
        Ok(NoDupes)
    }
    fn visit_i64<E>(self, _: i64) -> Result<NoDupes, E> {
        Ok(NoDupes)
    }
    fn visit_u64<E>(self, _: u64) -> Result<NoDupes, E> {
        Ok(NoDupes)
    }
    fn visit_f64<E>(self, _: f64) -> Result<NoDupes, E> {
        Ok(NoDupes)
    }
    fn visit_str<E>(self, _: &str) -> Result<NoDupes, E> {
        Ok(NoDupes)
    }
    fn visit_unit<E>(self) -> Result<NoDupes, E> {
        Ok(NoDupes)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<NoDupes, A::Error> {
        while seq.next_element::<NoDupes>()?.is_some() {}
        Ok(NoDupes)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<NoDupes, A::Error> {
        let mut seen = std::collections::HashSet::new();
        while let Some(k) = map.next_key::<String>()? {
            if !seen.insert(k) {
                return Err(de::Error::custom("duplicate key"));
            }
            map.next_value::<NoDupes>()?;
        }
        Ok(NoDupes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{PrincipalKind, Subject};
    use std::time::SystemTime;

    fn principal(roles: &[&str], scopes: &[&str]) -> Principal {
        let mut p = Principal::new(Subject::new("i", None, "s"), PrincipalKind::User, SystemTime::now());
        p.roles = roles.iter().map(|s| s.to_string()).collect();
        p.scopes = scopes.iter().map(|s| s.to_string()).collect();
        p
    }

    #[test]
    fn rules() {
        let pol = Policies::new().role_implies("Writer", ["Reader"]);
        let w = pol.effective(&principal(&["Writer"], &[]));
        assert!(matches!(decide(Some(&Require::role("Reader")), &w), Decision::Allow));
        assert!(matches!(decide(Some(&Require::any_role(["X", "Writer"])), &w), Decision::Allow));
        assert!(matches!(decide(Some(&Require::all_roles(["X", "Writer"])), &w), Decision::MissingRole));
        assert!(matches!(decide(None, &w), Decision::Unpoliced));
        assert!(matches!(
            decide(Some(&Require::scope("s").and(Require::role("Writer"))), &w),
            Decision::MissingScopes(_)
        ));
    }

    #[test]
    fn messages() {
        let pol = Policies::new();
        let m = pol.message("draft", Some(&Require::role("Orders.Writer")));
        assert!(m.contains("`Orders.Writer` role"));
        let m = pol.message("x", Some(&Require::any_role(["A", "B"])));
        assert!(m.contains("one of the `A` or `B` roles"), "{m}");
        let pol = Policies::new().reveal_requirements(false);
        assert!(!pol.message("draft", Some(&Require::role("Orders.Writer"))).contains("Orders.Writer"));
    }

    #[test]
    fn duplicate_keys_are_found_at_any_depth() {
        assert!(no_duplicate_keys(br#"{"a":1,"b":{"c":[{"d":1,"e":"\u0041"}]}}"#));
        assert!(!no_duplicate_keys(br#"{"a":1,"a":2}"#));
        assert!(!no_duplicate_keys(br#"{"p":{"name":"x","name":"y"}}"#));
        assert!(!no_duplicate_keys(br#"{"p":[{"k":1,"k":1}]}"#));
        // An escaped key that decodes to the same name is a duplicate too.
        assert!(!no_duplicate_keys(br#"{"name":1,"n\u0061me":2}"#));
    }

    #[test]
    fn lists_vary_with_hidden_scopes() {
        assert!(!Policies::new().tool("a", Require::scope("s")).lists_vary_per_user());
        assert!(Policies::new().tool("a", Require::scope("s")).hide_on_missing_scope(true).lists_vary_per_user());
        assert!(Policies::new().tool("a", Require::role("R")).lists_vary_per_user());
    }

    #[test]
    fn resource_prefix_longest_wins() {
        let pol = Policies::new()
            .resource_prefix("docs://", Require::authenticated())
            .resource_prefix("docs://admin/", Require::role("Admin"));
        assert!(pol.for_resource("docs://admin/x").unwrap().has_role_rule());
        assert!(!pol.for_resource("docs://guide").unwrap().has_role_rule());
        assert!(pol.for_resource("other://x").is_none());
    }
}
