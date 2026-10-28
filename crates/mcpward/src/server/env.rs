//! Configuration from environment variables. Every problem is collected and reported at once.

use std::{net::SocketAddr, time::Duration};

use rmcp::ServerHandler;

use super::{Auth, AuthBuilder, McpServerBuilder};
use crate::{
    ConfigError, EnvErrors,
    auth::{Entra, Oidc, ResourceUrl, ScopeClaim},
};

struct Env<'a> {
    prefix: &'a str,
    lookup: &'a dyn Fn(&str) -> Option<String>,
    problems: Vec<(String, String)>,
}

impl Env<'_> {
    fn name(&self, k: &str) -> String {
        format!("{}{k}", self.prefix)
    }
    fn get(&self, k: &str) -> Option<String> {
        (self.lookup)(&self.name(k)).map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
    }
    fn problem(&mut self, k: &str, msg: impl Into<String>) {
        let n = self.name(k);
        self.problems.push((n, msg.into()));
    }
    fn required(&mut self, k: &str, why: &str) -> Option<String> {
        let v = self.get(k);
        if v.is_none() {
            self.problem(k, format!("required {why}"));
        }
        v
    }
    fn list(&self, k: &str) -> Option<Vec<String>> {
        self.get(k).map(|v| v.split(',').map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()).collect())
    }
    fn num<T>(&mut self, k: &str, range: std::ops::RangeInclusive<T>) -> Option<T>
    where
        T: std::str::FromStr + PartialOrd + std::fmt::Display + Copy,
    {
        let raw = self.get(k)?;
        match raw.parse::<T>() {
            Ok(n) if range.contains(&n) => Some(n),
            Ok(_) => {
                self.problem(k, format!("{raw:?} is out of range {}..={}", range.start(), range.end()));
                None
            }
            Err(_) => {
                self.problem(k, format!("{raw:?} is not a number"));
                None
            }
        }
    }
    fn bool(&mut self, k: &str) -> Option<bool> {
        let raw = self.get(k)?;
        match raw.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => {
                self.problem(k, format!("{raw:?} is not true or false"));
                None
            }
        }
    }
}

pub(super) fn apply<H>(
    mut b: McpServerBuilder<H>,
    prefix: &str,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<McpServerBuilder<H>, ConfigError>
where
    H: ServerHandler + Clone + Send + Sync + 'static,
{
    let mut e = Env { prefix, lookup, problems: Vec::new() };

    let mode = e.required("AUTH", "(entra, oidc, or dev)");
    let is_dev = mode.as_deref() == Some("dev");
    if let Some(url) = e.required("RESOURCE_URL", "") {
        match ResourceUrl::parse(&url, is_dev) {
            Ok(_) => b.resource_url = Some(url),
            Err(ConfigError::ResourceUrl(m)) => e.problem("RESOURCE_URL", m),
            Err(other) => e.problem("RESOURCE_URL", other.to_string()),
        }
    }
    if let Some(bind) = e.get("BIND") {
        match bind.parse::<SocketAddr>() {
            Ok(a) => b.bind = a,
            Err(_) => e.problem("BIND", format!("{bind:?} is not an address like 0.0.0.0:8080")),
        }
    }

    let mut auth: Option<AuthBuilder> = match mode.as_deref() {
        Some("entra") => {
            let t = e.required("ENTRA_TENANT_ID", "when AUTH=entra");
            let a = e.required("ENTRA_API_CLIENT_ID", "when AUTH=entra");
            for (k, v) in [("ENTRA_TENANT_ID", &t), ("ENTRA_API_CLIENT_ID", &a)] {
                if let Some(v) = v
                    && !crate::auth::providers_is_guid(v)
                {
                    e.problem(k, format!("{v:?} is not a GUID"));
                }
            }
            match (t, a) {
                (Some(t), Some(a)) => {
                    let mut en = Entra::new(t, a);
                    for uri in e.list("ENTRA_APP_ID_URIS").unwrap_or_default() {
                        en = en.app_id_uri(uri);
                    }
                    Some(Auth::entra(en))
                }
                _ => None,
            }
        }
        Some("oidc") => {
            let iss = e.required("OIDC_ISSUER", "when AUTH=oidc");
            let auds = e.list("OIDC_AUDIENCES");
            if auds.as_ref().is_none_or(Vec::is_empty) {
                e.problem("OIDC_AUDIENCES", "required when AUTH=oidc");
            }
            iss.map(|iss| {
                let mut o = Oidc::new(iss);
                for a in auds.unwrap_or_default() {
                    o = o.audience(a);
                }
                if let Some(j) = e.get("OIDC_JWKS_URI") {
                    match j.parse() {
                        Ok(u) => o = o.jwks_uri(u),
                        Err(_) => e.problem("OIDC_JWKS_URI", format!("{j:?} is not a URL")),
                    }
                }
                if let Some(r) = e.get("OIDC_ROLES_CLAIM") {
                    o = o.roles_claim(r.as_str());
                }
                if let Some(s) = e.get("OIDC_SCOPES_CLAIM") {
                    o = o.scopes_claim(match s.as_str() {
                        "auto" => ScopeClaim::Auto,
                        other => ScopeClaim::SpaceSeparated(other.to_owned()),
                    });
                }
                Auth::oidc(o)
            })
        }
        Some("dev") => dev_auth(&mut e),
        Some(other) => {
            e.problem("AUTH", format!("{other:?} is not entra, oidc, or dev"));
            None
        }
        None => None,
    };

    // Parsed even when the provider settings are incomplete, so every problem is reported.
    enum Scopes {
        None,
        List(Vec<String>),
    }
    let scopes = match e.list("REQUIRED_SCOPES") {
        Some(v) if v == ["none"] => Some(Scopes::None),
        Some(v) if !v.is_empty() => Some(Scopes::List(v)),
        _ if is_dev => None,
        _ => {
            e.problem("REQUIRED_SCOPES", "required (comma-separated claim-form scopes, or `none`)");
            None
        }
    };
    let clients = match e.list("ALLOWED_CLIENTS") {
        Some(v) if v == ["any"] => Some(Scopes::None),
        Some(v) if !v.is_empty() => {
            if mode.as_deref() == Some("entra") {
                for c in &v {
                    if !crate::auth::providers_is_guid(c) {
                        e.problem("ALLOWED_CLIENTS", format!("{c:?} is not a GUID"));
                    }
                }
            }
            Some(Scopes::List(v))
        }
        _ if is_dev => None,
        _ => {
            e.problem("ALLOWED_CLIENTS", "required (comma-separated client IDs, or `any`)");
            None
        }
    };
    let skew = e.num::<u64>("CLOCK_SKEW_SECS", 0..=300);
    let refresh = e.num::<u64>("JWKS_REFRESH_SECS", 60..=7 * 24 * 3600);
    let min = e.num::<u64>("JWKS_MIN_REFETCH_SECS", 10..=600);

    if let Some(mut a) = auth.take() {
        match scopes {
            Some(Scopes::None) => a = a.no_required_scopes(),
            Some(Scopes::List(v)) => a = a.required_scopes(v),
            None => {}
        }
        match clients {
            Some(Scopes::None) => a = a.allow_any_client(),
            Some(Scopes::List(v)) => a = a.allowed_clients(v),
            None => {}
        }
        if let Some(s) = skew {
            a = a.leeway(Duration::from_secs(s));
        }
        if refresh.is_some() || min.is_some() {
            a = a.jwks(move |mut j| {
                if let Some(r) = refresh {
                    j.refresh_interval = Duration::from_secs(r);
                }
                if let Some(m) = min {
                    j.min_refetch_interval = Duration::from_secs(m);
                }
                j
            });
        }
        b.auth = Some(a);
    }

    if let Some(h) = e.list("EXTRA_ALLOWED_HOSTS") {
        b.extra_allowed_hosts = h;
    }
    if let Some(o) = e.list("ALLOWED_ORIGINS") {
        b.allowed_origins = o;
    }
    if let Some(s) = e.num::<u64>("SHUTDOWN_TIMEOUT_SECS", 0..=3600) {
        b.shutdown_timeout = Duration::from_secs(s);
    }
    if let Some(n) = e.num::<usize>("TRUST_FORWARDED_FOR", 0..=16) {
        b.trust_forwarded_for = n;
    }
    if let Some(r) = e.bool("SERVE_ROOT_PRM") {
        b.serve_root_prm = r;
    }

    if e.problems.is_empty() { Ok(b) } else { Err(ConfigError::Env(EnvErrors { problems: e.problems })) }
}

#[cfg(feature = "dev-auth")]
fn dev_auth(e: &mut Env<'_>) -> Option<AuthBuilder> {
    let mut id = super::DevIdentity::default();
    if let Some(s) = e.get("DEV_SUBJECT") {
        id.subject = s;
    }
    if let Some(n) = e.get("DEV_NAME") {
        id.name = Some(n);
    }
    if let Some(s) = e.list("DEV_SCOPES") {
        id.scopes = s;
    }
    if let Some(r) = e.list("DEV_ROLES") {
        id.roles = r;
    }
    let mut a = Auth::dev(id);
    if let Some(ack) = e.get("DEV_ALLOW_NON_LOOPBACK") {
        if ack == super::DEV_NON_LOOPBACK_ACK {
            a = a.dev_allow_non_loopback(&ack);
        } else {
            e.problem("DEV_ALLOW_NON_LOOPBACK", format!("must equal {:?}", super::DEV_NON_LOOPBACK_ACK));
        }
    }
    Some(a)
}

#[cfg(not(feature = "dev-auth"))]
fn dev_auth(e: &mut Env<'_>) -> Option<AuthBuilder> {
    e.problem("AUTH", "dev requires the `dev-auth` feature, which this build doesn't have");
    None
}
