//! Portable tool schemas: rewrites the JSON Schemas rmcp and schemars generate into a spelling
//! that MCP clients with narrower schema dialects accept, and that passes the MCP Inspector's
//! schema portability checks (`--strict`).
//!
//! schemars emits valid JSON Schema 2020-12, but some of what it emits trips clients that map
//! tool schemas onto a smaller dialect (for example the OpenAPI subset some model providers use
//! for function declarations):
//!
//! | schemars emits | Inspector rule | [`Portable`] writes |
//! |---|---|---|
//! | `true` or `{}` for `serde_json::Value` | `boolean-schema` (error), `untyped-schema` | an `anyOf` of one branch per JSON type (without `null` on an optional property), or a free-form object ([`AnyValue`]) |
//! | `false` | `boolean-schema` (error) | `{"not": {}}` |
//! | `"type": ["string", "null"]` on an optional property | `type-union` | `"type": "string"` |
//! | `"type": ["string", "null"]` on a required property, an array item, or a map value | `type-union` | `"anyOf": [{"type": "string"}, {"type": "null"}]` |
//! | `"anyOf": [{"$ref": …}, {"type": "null"}]` on an optional property | none, but noisy | `"$ref": …` |
//! | `"format": "uint32"` (and `uint`, `int8`, `uint64`, …) on integers | none, but not a JSON Schema format | no `format` (`minimum: 0` stays) |
//!
//! Dropping `null` from an optional property changes only what the schema advertises: a client
//! that wants "no value" leaves the property out. Your server must still accept an explicit
//! `null`, which serde does for `Option<T>` fields. Booleans under `additionalProperties`,
//! `unevaluatedProperties`, `additionalItems`, and `unevaluatedItems` are portable and are kept.
//! Remote `$ref`s (outside the document) are left alone; schemars doesn't emit them.
//!
//! The transform is opt-in, idempotent, and never changes which arguments your handlers accept:
//! rmcp deserializes arguments with serde, not by validating them against the advertised schema.
//!
//! # Turning it on
//!
//! rmcp's `#[tool]` macros generate schemas with fixed schemars settings, so mcpward rewrites the
//! tools after the fact. Pass the router through [`portable`] where you build it, and point
//! `#[tool_handler]` at the field that holds it:
//!
//! ```
//! use mcpward::server::schema::portable;
//! use rmcp::{
//!     ServerHandler, handler::server::{router::tool::ToolRouter, wrapper::Parameters}, tool, tool_handler,
//!     tool_router,
//! };
//! use schemars::JsonSchema;
//! use serde::Deserialize;
//!
//! #[derive(Deserialize, JsonSchema)]
//! struct Search {
//!     /// Words to match.
//!     query: String,
//!     /// Results per page.
//!     limit: Option<u32>,
//!     /// Free-form filters.
//!     filters: Option<serde_json::Value>,
//! }
//!
//! #[derive(Clone)]
//! struct Notes {
//!     tool_router: ToolRouter<Self>,
//! }
//!
//! #[tool_router]
//! impl Notes {
//!     fn new() -> Self {
//!         Self { tool_router: portable(Self::tool_router()) }
//!     }
//!
//!     /// Search notes.
//!     #[tool]
//!     async fn search(&self, Parameters(s): Parameters<Search>) -> String {
//!         s.query
//!     }
//! }
//!
//! #[tool_handler(router = self.tool_router)]
//! impl ServerHandler for Notes {}
//!
//! let notes = Notes::new();
//! let schema = &notes.tool_router.get("search").unwrap().input_schema;
//! assert_eq!(schema["properties"]["limit"]["type"], "integer"); // was ["integer", "null"]
//! assert!(schema["properties"]["filters"]["anyOf"].is_array()); // was `true`
//! ```
//!
//! Keep `.tools(&Notes::tool_router())` on the [`McpServerBuilder`](super::McpServerBuilder) as
//! it is; the policy check reads only tool names. With the default `#[tool_handler]` (which
//! rebuilds the router on every call), use `#[tool_handler(router = portable(Self::tool_router()))]`
//! instead, or store the router in a field as above.
//!
//! For options, build a [`Portable`]:
//!
//! ```
//! # use rmcp::handler::server::router::tool::ToolRouter;
//! # fn tool_router() -> ToolRouter<()> { ToolRouter::new() }
//! use mcpward::server::schema::{AnyValue, Portable};
//!
//! let router = Portable::new()
//!     .any_value(AnyValue::Object) // `serde_json::Value` fields advertise a free-form object
//!     .output_schemas(true) // rewrite outputSchema too (input schemas only by default)
//!     .router(tool_router());
//! # let _ = router;
//! ```
//!
//! [`Portable`] also implements schemars' [`Transform`], for schemas you generate yourself:
//! `SchemaSettings::draft2020_12().with_transform(Portable::new())`.
//!
//! # Choosing what a free-form value advertises
//!
//! `serde_json::Value` accepts any JSON, and its schemars schema is `true`. The default,
//! [`AnyValue::AnyOf`], keeps that contract with one branch per JSON type. When a field is
//! really a JSON object (a payload, metadata, a map of variables), say so in the type instead:
//! `serde_json::Map<String, Value>` (or `#[schemars(with = "serde_json::Map<String, serde_json::Value>")]`)
//! generates `{"type": "object", "additionalProperties": true}`, which is what the Inspector
//! suggests. [`AnyValue::Object`] applies that to every untyped value at once.

use std::collections::BTreeSet;

use rmcp::{handler::server::router::tool::ToolRouter, model::Tool, service::MaybeSend};
use schemars::{Schema, transform::Transform};
use serde_json::{Map, Value, json};

type JsonObject = Map<String, Value>;

/// What an untyped value schema (`true`, `{}`, or a schema with only annotations) becomes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnyValue {
    /// `{"anyOf": [{"type": "object", "additionalProperties": true}, {"type": "array"},
    /// {"type": "string"}, {"type": "number"}, {"type": "boolean"}, {"type": "null"}]}`.
    /// Still accepts any JSON value.
    #[default]
    AnyOf,
    /// `{"type": "object", "additionalProperties": true}`. Advertises a free-form object; a
    /// deliberate narrowing of the contract.
    Object,
}

/// The schema rewriter. See the [module documentation](self).
#[derive(Clone, Debug, Default)]
pub struct Portable {
    any_value: AnyValue,
    output_schemas: bool,
}

/// Rewrites every tool's input schema in `router` with the default [`Portable`] settings.
pub fn portable<S: MaybeSend + 'static>(router: ToolRouter<S>) -> ToolRouter<S> {
    Portable::new().router(router)
}

/// Where a subschema sits, which decides how an untyped schema and `null` are rewritten.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pos {
    /// A value: the root, a property, an item, a map value, a definition.
    Value { optional: bool },
    /// Under a keyword where only an exact equivalent of "anything" is safe (`anyOf` branches,
    /// `if`, `contains`, `propertyNames`, ...).
    Exact,
    /// Under `not`, where `{}` is the right spelling of `true`.
    Not,
    /// Under a keyword where a boolean is portable (`additionalProperties`, ...).
    BoolOk,
}

/// Keywords that annotate rather than constrain, plus document structure. These stay on the
/// outer schema when a nullable type is split into `anyOf` branches.
const OUTER_KEYS: &[&str] = &[
    "title",
    "description",
    "default",
    "examples",
    "deprecated",
    "readOnly",
    "writeOnly",
    "$comment",
    "$schema",
    "$id",
    "$anchor",
    "$dynamicAnchor",
    "$defs",
    "definitions",
];

/// Keywords that constrain an instance. A schema object with none of them accepts anything.
/// Mirrors the Inspector's list.
const CONSTRAINING: &[&str] = &[
    "type",
    "enum",
    "const",
    "multipleOf",
    "maximum",
    "exclusiveMaximum",
    "minimum",
    "exclusiveMinimum",
    "maxLength",
    "minLength",
    "pattern",
    "format",
    "contentMediaType",
    "contentEncoding",
    "contentSchema",
    "maxItems",
    "minItems",
    "uniqueItems",
    "maxContains",
    "minContains",
    "maxProperties",
    "minProperties",
    "required",
    "dependentRequired",
    "allOf",
    "anyOf",
    "oneOf",
    "not",
    "items",
    "prefixItems",
    "contains",
    "additionalItems",
    "unevaluatedItems",
    "properties",
    "patternProperties",
    "additionalProperties",
    "unevaluatedProperties",
    "propertyNames",
    "dependentSchemas",
    "dependencies",
    "$ref",
    "$dynamicRef",
    "$recursiveRef",
];

impl Portable {
    /// Default settings: input schemas only, untyped values as [`AnyValue::AnyOf`].
    pub fn new() -> Self {
        Self::default()
    }

    /// What untyped value schemas become. Default [`AnyValue::AnyOf`].
    pub fn any_value(mut self, any: AnyValue) -> Self {
        self.any_value = any;
        self
    }

    /// Also rewrite each tool's `outputSchema`. Off by default.
    pub fn output_schemas(mut self, on: bool) -> Self {
        self.output_schemas = on;
        self
    }

    /// Rewrites every tool in `router` (disabled tools included).
    pub fn router<S: MaybeSend + 'static>(&self, mut router: ToolRouter<S>) -> ToolRouter<S> {
        for route in router.map.values_mut() {
            self.tool(&mut route.attr);
        }
        router
    }

    /// Rewrites one tool's input schema, and its output schema when
    /// [`output_schemas`](Self::output_schemas) is on. Use it on the tools you return from a
    /// hand-written `list_tools`.
    pub fn tool(&self, tool: &mut Tool) {
        self.schema(std::sync::Arc::make_mut(&mut tool.input_schema));
        if self.output_schemas
            && let Some(out) = tool.output_schema.as_mut()
        {
            self.schema(std::sync::Arc::make_mut(out));
        }
    }

    /// Rewrites a root schema object in place.
    pub fn schema(&self, schema: &mut JsonObject) {
        self.object(schema, Pos::Value { optional: false });
    }

    /// Rewrites a root schema in place. A boolean root becomes an object schema.
    pub fn value(&self, schema: &mut Value) {
        self.node(schema, Pos::Value { optional: false });
    }

    fn any_value_schema(&self, pos: Pos) -> JsonObject {
        let v = match (pos, self.any_value) {
            (Pos::Not, _) => json!({}),
            (Pos::Value { .. }, AnyValue::Object) => json!({"type": "object", "additionalProperties": true}),
            // An optional property advertises no `null`, as with `Option<T>` fields.
            (Pos::Value { optional: true }, AnyValue::AnyOf) => json!({"anyOf": [
                {"type": "object", "additionalProperties": true},
                {"type": "array"},
                {"type": "string"},
                {"type": "number"},
                {"type": "boolean"},
            ]}),
            _ => json!({"anyOf": [
                {"type": "object", "additionalProperties": true},
                {"type": "array"},
                {"type": "string"},
                {"type": "number"},
                {"type": "boolean"},
                {"type": "null"},
            ]}),
        };
        let Value::Object(m) = v else { unreachable!() };
        m
    }

    fn node(&self, v: &mut Value, pos: Pos) {
        match v {
            Value::Bool(_) if pos == Pos::BoolOk => {}
            Value::Bool(true) => *v = Value::Object(self.any_value_schema(pos)),
            Value::Bool(false) => *v = json!({"not": {}}),
            Value::Object(m) => self.object(m, pos),
            _ => {}
        }
    }

    fn object(&self, m: &mut JsonObject, pos: Pos) {
        let optional = matches!(pos, Pos::Value { optional: true });
        drop_nonstandard_format(m);
        fix_type(m, optional);
        if optional {
            drop_null_branches(m);
        }
        if pos != Pos::Not && !CONSTRAINING.iter().any(|k| m.contains_key(*k)) {
            m.extend(self.any_value_schema(pos));
        }
        self.children(m);
    }

    fn children(&self, m: &mut JsonObject) {
        let value = Pos::Value { optional: false };
        let required: BTreeSet<String> = match m.get("required") {
            Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(str::to_owned).collect(),
            _ => BTreeSet::new(),
        };
        if let Some(Value::Object(props)) = m.get_mut("properties") {
            for (name, sub) in props.iter_mut() {
                self.node(sub, Pos::Value { optional: !required.contains(name) });
            }
        }
        for key in ["patternProperties", "$defs", "definitions"] {
            if let Some(Value::Object(map)) = m.get_mut(key) {
                map.values_mut().for_each(|s| self.node(s, value));
            }
        }
        for key in ["dependentSchemas", "dependencies"] {
            if let Some(Value::Object(map)) = m.get_mut(key) {
                // `dependencies` also has an array form (required property names); `node` skips it.
                map.values_mut().for_each(|s| self.node(s, Pos::Exact));
            }
        }
        for key in ["additionalProperties", "unevaluatedProperties", "additionalItems", "unevaluatedItems"] {
            if let Some(s) = m.get_mut(key) {
                self.node(s, if s.is_boolean() { Pos::BoolOk } else { value });
            }
        }
        match m.get_mut("items") {
            Some(Value::Array(items)) => items.iter_mut().for_each(|s| self.node(s, value)),
            Some(s) => self.node(s, value),
            None => {}
        }
        if let Some(Value::Array(items)) = m.get_mut("prefixItems") {
            items.iter_mut().for_each(|s| self.node(s, value));
        }
        for key in ["allOf", "anyOf", "oneOf"] {
            if let Some(Value::Array(branches)) = m.get_mut(key) {
                branches.iter_mut().for_each(|s| self.node(s, Pos::Exact));
            }
        }
        for key in ["if", "then", "else", "contains", "propertyNames", "contentSchema"] {
            if let Some(s) = m.get_mut(key) {
                self.node(s, Pos::Exact);
            }
        }
        if let Some(s) = m.get_mut("not") {
            self.node(s, Pos::Not);
        }
    }
}

impl Transform for Portable {
    fn transform(&mut self, schema: &mut Schema) {
        let mut v: Value = std::mem::take(schema).into();
        self.value(&mut v);
        // `value` leaves an object or a boolean, both valid schemas.
        *schema = Schema::try_from(v).unwrap_or_default();
    }
}

/// The `format` values clients can rely on: JSON Schema 2020-12's formats, plus the numeric
/// formats OpenAPI defines.
const KNOWN_FORMATS: &[&str] = &[
    "date-time",
    "date",
    "time",
    "duration",
    "email",
    "idn-email",
    "hostname",
    "idn-hostname",
    "ipv4",
    "ipv6",
    "uri",
    "uri-reference",
    "iri",
    "iri-reference",
    "uuid",
    "uri-template",
    "json-pointer",
    "relative-json-pointer",
    "regex",
    "int32",
    "int64",
    "float",
    "double",
];

/// Removes the integer formats schemars writes for Rust integer types (`uint32`, `uint`,
/// `int8`, ...), which aren't JSON Schema formats. Any other `format` is kept: it may be one a
/// client knows, and unknown formats are annotations, not constraints.
fn drop_nonstandard_format(m: &mut JsonObject) {
    let rust_int = |f: &str| {
        let digits = f.strip_prefix("uint").or_else(|| f.strip_prefix("int"));
        digits.is_some_and(|d| d.is_empty() || d.chars().all(|c| c.is_ascii_digit()))
    };
    if let Some(Value::String(f)) = m.get("format")
        && !KNOWN_FORMATS.contains(&f.as_str())
        && rust_int(f)
    {
        m.remove("format");
    }
}

/// Removes `null` from an optional property's `enum` and `default`, after its type lost `null`.
fn forget_null(m: &mut JsonObject) {
    if let Some(Value::Array(e)) = m.get_mut("enum") {
        e.retain(|v| !v.is_null());
    }
    if m.get("default").is_some_and(Value::is_null) {
        m.remove("default");
    }
}

/// Rewrites an array-valued `type` into a single type or `anyOf` branches.
fn fix_type(m: &mut JsonObject, optional: bool) {
    let Some(Value::Array(raw)) = m.get("type") else { return };
    let mut types: Vec<String> = Vec::new();
    for t in raw {
        let Some(t) = t.as_str() else { return }; // not a type union we understand; leave it
        if !types.iter().any(|x| x == t) {
            types.push(t.to_owned());
        }
    }
    if optional && types.len() > 1 && types.iter().any(|t| t == "null") {
        types.retain(|t| t != "null");
        forget_null(m);
    }
    let has_null = types.iter().any(|t| t == "null");
    match types.len() {
        0 => {}
        1 => {
            m.insert("type".into(), Value::String(types.remove(0)));
        }
        2 if has_null => {
            // Required nullable: [T, "null"] -> anyOf [{type: T, ...constraints}, {type: "null"}].
            m.remove("type");
            let t = types.into_iter().find(|t| t != "null").unwrap_or_default();
            let mut branch = JsonObject::new();
            branch.insert("type".into(), Value::String(t));
            let moved: Vec<String> = m.keys().filter(|k| !OUTER_KEYS.contains(&k.as_str())).cloned().collect();
            for k in moved {
                if let Some(v) = m.remove(&k) {
                    branch.insert(k, v);
                }
            }
            if let Some(Value::Array(e)) = branch.get_mut("enum") {
                e.retain(|v| !v.is_null());
            }
            m.insert("anyOf".into(), json!([Value::Object(branch), {"type": "null"}]));
        }
        _ => {
            // A general union: one branch per type; type-specific keywords stay on the outer
            // schema, where they already apply only to values of their type.
            m.remove("type");
            let branches: Vec<Value> = types.into_iter().map(|t| json!({"type": t})).collect();
            if m.contains_key("anyOf") {
                let all = m.entry("allOf").or_insert_with(|| Value::Array(Vec::new()));
                if let Value::Array(all) = all {
                    all.push(json!({"anyOf": branches}));
                }
            } else {
                m.insert("anyOf".into(), Value::Array(branches));
            }
        }
    }
}

fn is_null_branch(v: &Value) -> bool {
    let Some(b) = v.as_object() else { return false };
    b.get("type").is_some_and(|t| t == "null")
        || b.get("const").is_some_and(Value::is_null)
        || b.get("enum").is_some_and(|e| e.as_array().is_some_and(|a| a.len() == 1 && a[0].is_null()))
}

/// On an optional property, drops `null` branches from `anyOf`/`oneOf`, and folds a single
/// remaining branch into the schema when no keyword clashes.
fn drop_null_branches(m: &mut JsonObject) {
    for key in ["anyOf", "oneOf"] {
        let Some(Value::Array(branches)) = m.get_mut(key) else { continue };
        if !branches.iter().any(is_null_branch) || branches.iter().all(is_null_branch) {
            continue;
        }
        branches.retain(|b| !is_null_branch(b));
        forget_null(m);
        let Some(Value::Array(branches)) = m.get(key) else { continue };
        if let [Value::Object(only)] = branches.as_slice()
            && only.keys().all(|k| !m.contains_key(k))
        {
            let only = only.clone();
            m.remove(key);
            m.extend(only);
        }
    }
}

#[cfg(test)]
mod tests {
    use rmcp::handler::server::common::schema_for_type;
    use schemars::JsonSchema;
    use serde::Deserialize;
    use serde_json::{Value, json};

    use super::*;

    fn run(p: &Portable, v: Value) -> Value {
        let mut v = v;
        p.value(&mut v);
        v
    }

    fn fix(v: Value) -> Value {
        run(&Portable::new(), v)
    }

    fn any() -> Value {
        json!({"anyOf": [
            {"type": "object", "additionalProperties": true},
            {"type": "array"},
            {"type": "string"},
            {"type": "number"},
            {"type": "boolean"},
            {"type": "null"},
        ]})
    }

    fn any_optional() -> Value {
        let mut v = any();
        v["anyOf"].as_array_mut().unwrap().pop();
        v
    }

    /// A Rust port of the MCP Inspector's schema lint (`core/json/schemaLint.ts`), returning
    /// `(rule, path)` for every finding.
    fn lint(schema: &Value) -> Vec<(String, String)> {
        const BOOL_OK: &[&str] =
            &["additionalProperties", "unevaluatedProperties", "additionalItems", "unevaluatedItems"];
        const SUB: &[&str] = &[
            "items",
            "contains",
            "not",
            "propertyNames",
            "if",
            "then",
            "else",
            "additionalProperties",
            "unevaluatedProperties",
            "additionalItems",
            "unevaluatedItems",
            "contentSchema",
        ];
        const ARR: &[&str] = &["allOf", "anyOf", "oneOf", "prefixItems"];
        const MAPS: &[&str] =
            &["properties", "patternProperties", "dependentSchemas", "dependencies", "$defs", "definitions"];
        const TYPES: &[&str] = &["null", "boolean", "object", "array", "number", "string", "integer"];
        fn walk(n: &Value, path: String, kw: Option<&str>, out: &mut Vec<(String, String)>) {
            if n.is_boolean() {
                if kw.is_some_and(|k| BOOL_OK.contains(&k)) {
                    return;
                }
                out.push(("boolean-schema".into(), path));
                return;
            }
            let Some(m) = n.as_object() else { return };
            if let Some(Value::Array(t)) = m.get("type") {
                let names: Vec<&str> = t.iter().filter_map(Value::as_str).collect();
                let distinct: BTreeSet<&str> = names.iter().copied().collect();
                if !t.is_empty()
                    && names.len() == t.len()
                    && names.iter().all(|x| TYPES.contains(x))
                    && distinct.len() == names.len()
                {
                    out.push(("type-union".into(), path.clone()));
                }
            }
            if m.get("$ref").and_then(Value::as_str).is_some_and(|r| !r.is_empty() && !r.starts_with('#')) {
                out.push(("remote-ref".into(), path.clone()));
            }
            let constrains = m.keys().any(|k| CONSTRAINING.contains(&k.as_str()))
                || (m.contains_key("if") && (m.contains_key("then") || m.contains_key("else")));
            if !constrains && kw != Some("not") {
                out.push(("untyped-schema".into(), path.clone()));
            }
            for k in MAPS {
                if let Some(Value::Object(map)) = m.get(*k) {
                    for (name, sub) in map {
                        walk(sub, format!("{path}.{k}.{name}"), Some(k), out);
                    }
                }
            }
            for k in ARR {
                if let Some(Value::Array(a)) = m.get(*k) {
                    for (i, sub) in a.iter().enumerate() {
                        walk(sub, format!("{path}.{k}[{i}]"), Some(k), out);
                    }
                }
            }
            for k in SUB {
                match m.get(*k) {
                    Some(Value::Array(a)) if *k == "items" => {
                        for (i, sub) in a.iter().enumerate() {
                            walk(sub, format!("{path}.{k}[{i}]"), Some(k), out);
                        }
                    }
                    Some(sub) => walk(sub, format!("{path}.{k}"), Some(k), out),
                    None => {}
                }
            }
        }
        let mut out = Vec::new();
        walk(schema, String::new(), None, &mut out);
        out
    }

    fn assert_portable(v: &Value) {
        let findings = lint(v);
        assert!(findings.is_empty(), "{findings:?} in {v:#}");
    }

    #[test]
    fn bare_true_and_empty_value_schemas() {
        let input = json!({
            "type": "object",
            "properties": {
                "a": true,
                "b": {},
                "c": {"description": "Anything."},
                "d": false,
            },
            "required": ["a", "b", "c"],
        });
        assert!(!lint(&input).is_empty());
        let out = fix(input);
        assert_eq!(out["properties"]["a"], any());
        assert_eq!(out["properties"]["b"], any());
        let mut c = any();
        c["description"] = json!("Anything.");
        assert_eq!(out["properties"]["c"], c);
        assert_eq!(out["properties"]["d"], json!({"not": {}}));
        assert_portable(&out);
    }

    #[test]
    fn any_value_object_mode() {
        let p = Portable::new().any_value(AnyValue::Object);
        let out = run(&p, json!({"type": "object", "properties": {"payload": true, "meta": {"title": "M"}}}));
        assert_eq!(out["properties"]["payload"], json!({"type": "object", "additionalProperties": true}));
        assert_eq!(out["properties"]["meta"], json!({"title": "M", "type": "object", "additionalProperties": true}));
        assert_portable(&out);
    }

    #[test]
    fn exact_positions_keep_meaning() {
        // `true` in an anyOf branch or under `not` must keep its meaning even in Object mode.
        let p = Portable::new().any_value(AnyValue::Object);
        let out = run(&p, json!({"type": "object", "anyOf": [true, {"type": "string"}], "not": {"not": true}}));
        assert_eq!(out["anyOf"][0], any());
        assert_eq!(out["not"]["not"], json!({}));
        assert_portable(&out);
    }

    #[test]
    fn bool_valued_keywords_are_kept() {
        let input = json!({"type": "object", "additionalProperties": false, "properties": {
            "m": {"type": "object", "additionalProperties": true},
        }});
        assert_eq!(fix(input.clone()), input);
        assert_portable(&input);
    }

    #[test]
    fn optional_type_arrays_lose_null() {
        let out = fix(json!({
            "type": "object",
            "properties": {
                "limit": {"type": ["integer", "null"], "format": "uint32", "minimum": 0, "default": null},
                "mode": {"type": ["string", "null"], "enum": ["a", "b", null]},
                "single": {"type": ["string"]},
                "multi": {"type": ["string", "number", "null"]},
            },
        }));
        assert_eq!(out["properties"]["limit"], json!({"type": "integer", "minimum": 0}));
        assert_eq!(out["properties"]["mode"], json!({"type": "string", "enum": ["a", "b"]}));
        assert_eq!(out["properties"]["single"], json!({"type": "string"}));
        assert_eq!(out["properties"]["multi"], json!({"anyOf": [{"type": "string"}, {"type": "number"}]}));
        assert_portable(&out);
    }

    #[test]
    fn rust_integer_formats_are_dropped() {
        let out = fix(json!({
            "type": "object",
            "properties": {
                "a": {"type": "integer", "format": "uint", "minimum": 0},
                "b": {"type": "integer", "format": "uint64"},
                "c": {"type": "integer", "format": "int8"},
                "d": {"type": "integer", "format": "int32"},
                "e": {"type": "string", "format": "date-time"},
                "f": {"type": "string", "format": "internal"},
            },
            "required": ["a", "b", "c", "d", "e", "f"],
        }));
        assert_eq!(out["properties"]["a"], json!({"type": "integer", "minimum": 0}));
        assert_eq!(out["properties"]["b"], json!({"type": "integer"}));
        assert_eq!(out["properties"]["c"], json!({"type": "integer"}));
        assert_eq!(out["properties"]["d"]["format"], "int32");
        assert_eq!(out["properties"]["e"]["format"], "date-time");
        assert_eq!(out["properties"]["f"]["format"], "internal");
        assert_portable(&out);
    }

    #[test]
    fn required_nullable_becomes_any_of() {
        let out = fix(json!({
            "type": "object",
            "properties": {
                "note": {"type": ["string", "null"], "description": "A note.", "maxLength": 10},
                "mode": {"type": ["string", "null"], "enum": ["a", null]},
            },
            "required": ["note", "mode"],
        }));
        assert_eq!(
            out["properties"]["note"],
            json!({"description": "A note.", "anyOf": [{"type": "string", "maxLength": 10}, {"type": "null"}]})
        );
        assert_eq!(out["properties"]["mode"], json!({"anyOf": [{"type": "string", "enum": ["a"]}, {"type": "null"}]}));
        assert_portable(&out);
    }

    #[test]
    fn any_of_with_null() {
        let out = fix(json!({
            "type": "object",
            "properties": {
                "opt": {"anyOf": [{"$ref": "#/$defs/Mode"}, {"type": "null"}], "description": "Optional."},
                "opt_many": {"oneOf": [{"type": "string"}, {"type": "integer"}, {"const": null}]},
                "req": {"anyOf": [{"$ref": "#/$defs/Mode"}, {"type": "null"}]},
            },
            "required": ["req"],
            "$defs": {"Mode": {"type": "string", "enum": ["a", "b"]}},
        }));
        assert_eq!(out["properties"]["opt"], json!({"$ref": "#/$defs/Mode", "description": "Optional."}));
        assert_eq!(out["properties"]["opt_many"], json!({"oneOf": [{"type": "string"}, {"type": "integer"}]}));
        assert_eq!(out["properties"]["req"], json!({"anyOf": [{"$ref": "#/$defs/Mode"}, {"type": "null"}]}));
        assert_portable(&out);
    }

    #[test]
    fn nested_defs_and_arrays() {
        let out = fix(json!({
            "type": "object",
            "properties": {
                "rules": {"type": "array", "items": {"$ref": "#/$defs/Rule"}},
                "tags": {"type": ["array", "null"], "items": {"type": ["string", "null"]}},
                "tuple": {"type": "array", "prefixItems": [true, {"type": ["integer", "null"]}]},
                "vars": {"type": "object", "additionalProperties": {"type": ["string", "null"]}},
            },
            "required": ["rules"],
            "$defs": {
                "Rule": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "vars": {"type": ["object", "null"], "additionalProperties": true},
                        "data": true,
                        "policy": {"anyOf": [{"$ref": "#/$defs/Policy"}, {"type": "null"}]},
                    },
                    "required": ["name", "data"],
                    "additionalProperties": false,
                },
                "Policy": {"type": "object", "properties": {"delay": {"type": ["string", "null"]}}},
                "Nullable": {"type": ["integer", "null"]},
            },
        }));
        assert_eq!(out["properties"]["tags"]["type"], "array");
        assert_eq!(out["properties"]["tags"]["items"], json!({"anyOf": [{"type": "string"}, {"type": "null"}]}));
        assert_eq!(out["properties"]["tuple"]["prefixItems"][0], any());
        assert_eq!(
            out["properties"]["vars"]["additionalProperties"],
            json!({"anyOf": [{"type": "string"}, {"type": "null"}]})
        );
        let rule = &out["$defs"]["Rule"];
        assert_eq!(rule["properties"]["vars"], json!({"type": "object", "additionalProperties": true}));
        assert_eq!(rule["properties"]["data"], any());
        assert_eq!(rule["properties"]["policy"], json!({"$ref": "#/$defs/Policy"}));
        assert_eq!(rule["additionalProperties"], false);
        assert_eq!(out["$defs"]["Policy"]["properties"]["delay"], json!({"type": "string"}));
        assert_eq!(out["$defs"]["Nullable"], json!({"anyOf": [{"type": "integer"}, {"type": "null"}]}));
        assert_portable(&out);
    }

    #[test]
    fn idempotent() {
        let input = json!({
            "type": "object",
            "properties": {"a": true, "b": {"type": ["string", "null"]}, "c": {"type": ["string", "null"]}},
            "required": ["c"],
        });
        let once = fix(input);
        assert_eq!(fix(once.clone()), once);
        let p = Portable::new().any_value(AnyValue::Object);
        let once = run(&p, json!({"properties": {"a": true}}));
        assert_eq!(run(&p, once.clone()), once);
    }

    #[derive(Deserialize, JsonSchema)]
    #[allow(dead_code)]
    enum Timing {
        Immediate,
        Hold { delay: String },
    }

    #[derive(Deserialize, JsonSchema)]
    #[allow(dead_code)]
    struct Policy {
        key: Option<String>,
        timing: Option<Timing>,
        cancel_on: Vec<String>,
    }

    #[derive(Deserialize, JsonSchema)]
    #[allow(dead_code)]
    struct Rule {
        /// The rule name.
        name: String,
        enabled: Option<bool>,
        vars: Option<std::collections::BTreeMap<String, Option<String>>>,
        policy: Option<Policy>,
        tags: Vec<Option<String>>,
        payload: serde_json::Value,
        metadata: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default)]
        note: Option<String>,
        must_be_present: Option<u32>,
    }

    #[derive(Deserialize, JsonSchema)]
    #[allow(dead_code)]
    struct Args {
        rules: Vec<Rule>,
        sample: Option<serde_json::Value>,
    }

    #[test]
    fn schemars_output_becomes_portable() {
        let raw = Value::Object(schema_for_type::<Args>().as_ref().clone());
        assert!(lint(&raw).iter().any(|(r, _)| r == "boolean-schema"), "{raw:#}");
        assert!(lint(&raw).iter().any(|(r, _)| r == "type-union"), "{raw:#}");
        let out = fix(raw);
        assert_portable(&out);
        assert_eq!(out["properties"]["sample"], any_optional());
        let rule = &out["$defs"]["Rule"]["properties"];
        assert_eq!(rule["enabled"]["type"], "boolean");
        assert_eq!(rule["note"]["type"], "string");
        assert_eq!(rule["metadata"]["type"], "object");
        assert_eq!(rule["policy"]["$ref"], "#/$defs/Policy");
        assert_eq!(rule["tags"]["items"]["anyOf"], json!([{"type": "string"}, {"type": "null"}]));
    }

    #[test]
    fn schemars_transform() {
        let settings = schemars::generate::SchemaSettings::draft2020_12().with_transform(Portable::new());
        let schema = settings.into_generator().into_root_schema_for::<Args>();
        let v = serde_json::to_value(schema).unwrap();
        assert_portable(&v);
        assert_eq!(v["properties"]["sample"], any_optional());
    }

    #[test]
    fn router_and_output_schemas() {
        use rmcp::{
            handler::server::router::tool::ToolRoute,
            model::{CallToolResponse, CallToolResult},
        };

        let mut tool = Tool::new("t", "test", schema_for_type::<Args>());
        tool.output_schema = Some(schema_for_type::<Args>());
        let route: ToolRoute<()> = ToolRoute::new_dyn(tool, |_| {
            Box::pin(async { Ok::<_, rmcp::ErrorData>(CallToolResponse::from(CallToolResult::success(vec![]))) })
        });
        let router = ToolRouter::<()>::new().with_route(route);

        let only_input = portable(router.clone());
        let t = only_input.get("t").unwrap();
        assert_portable(&Value::Object(t.input_schema.as_ref().clone()));
        assert!(!lint(&Value::Object(t.output_schema.clone().unwrap().as_ref().clone())).is_empty());

        let both = Portable::new().output_schemas(true).router(router);
        let t = both.get("t").unwrap();
        assert_portable(&Value::Object(t.output_schema.clone().unwrap().as_ref().clone()));
    }
}
