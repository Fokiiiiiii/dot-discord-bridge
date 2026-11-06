//! Single-owner OAuth authorization server. No dynamic client registration.
use anyhow::{bail, Context, Result};
use axum::{
    extract::{DefaultBodyLimit, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Form, Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    env,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use url::Url;
use uuid::Uuid;
const SCOPE: &str = "discord:dm";
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
fn hash(s: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(s.as_bytes()))
}
fn random() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}
fn equal(a: &str, b: &str) -> bool {
    let ha = Sha256::digest(a.as_bytes());
    let hb = Sha256::digest(b.as_bytes());
    bool::from(ha.as_slice().ct_eq(hb.as_slice()))
}
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
#[derive(Clone)]
struct Config {
    issuer: String,
    client: String,
    secret: String,
    owner: String,
    redirects: Vec<String>,
}
impl Config {
    fn validate(&self) -> Result<()> {
        let u = Url::parse(&self.issuer)?;
        if u.scheme() != "https"
            || u.host_str().is_none()
            || u.username() != ""
            || u.password().is_some()
            || u.query().is_some()
            || u.fragment().is_some()
            || u.path() != "/"
            || self.issuer.ends_with('/')
        {
            bail!("OAUTH_ISSUER must be an HTTPS origin without trailing slash");
        }
        if self.client.is_empty()
            || self.client.len() > 200
            || !self
                .client
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            || self.secret.len() < 32
            || self.owner.len() < 32
            || equal(&self.secret, &self.owner)
        {
            bail!("OAuth client and distinct strong secrets required");
        }
        if self.redirects.is_empty() {
            bail!("Explicit OAuth redirect allowlist required");
        }
        for r in &self.redirects {
            let u = Url::parse(r)?;
            if u.scheme() != "https"
                || u.host_str().is_none()
                || !u.username().is_empty()
                || u.password().is_some()
                || u.fragment().is_some()
                || r.len() > 2048
            {
                bail!("Invalid OAuth redirect URI");
            }
        }
        Ok(())
    }
    fn resource(&self) -> String {
        format!("{}/mcp", self.issuer)
    }
    fn tag(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.issuer.as_bytes());
        h.update(b"\0");
        h.update(self.client.as_bytes());
        h.update(b"\0");
        h.update(self.secret.as_bytes());
        h.update(b"\0");
        h.update(self.owner.as_bytes());
        if self.redirects.is_empty() {
            h.update(b"\0");
        } else {
            for r in &self.redirects {
                h.update(b"\0");
                h.update(r.as_bytes());
            }
        }
        URL_SAFE_NO_PAD.encode(h.finalize())
    }
}
pub struct OAuth {
    config: Config,
    resource: String,
    authority: String,
    db: Mutex<Connection>,
    attempts: Mutex<VecDeque<i64>>,
}
#[derive(Clone, Deserialize, Serialize)]
struct Authorization {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    state: String,
    code_challenge: String,
    code_challenge_method: String,
    resource: String,
    scope: String,
}
#[derive(Deserialize)]
struct Consent {
    request: String,
    approval_secret: String,
}
#[derive(Default, Deserialize)]
struct TokenForm {
    grant_type: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    resource: Option<String>,
    refresh_token: Option<String>,
    token: Option<String>,
}
impl OAuth {
    #[cfg(test)]
    pub(crate) fn test_fixture() -> (Self, String, String) {
        let s = Self::new(
            Config {
                issuer: "https://discord.example.com".into(),
                client: "chatgpt-private".into(),
                secret: "s".repeat(40),
                owner: "o".repeat(40),
                redirects: vec!["https://chatgpt.com/connector_platform_oauth_redirect".into()],
            },
            Connection::open_in_memory().unwrap(),
        )
        .unwrap();
        let family = "test-family".to_owned();
        let v = Self::issue(&s.db.lock().unwrap(), &s.config.tag(), &family).unwrap();
        let access = v["access_token"].as_str().unwrap().to_owned();
        (s, access, family)
    }
    #[cfg(test)]
    pub(crate) fn test_revoke(&self, family: &str) {
        self.db
            .lock()
            .unwrap()
            .execute("INSERT OR IGNORE INTO oauth_revoked VALUES(?1)", [family])
            .unwrap();
    }
    #[cfg(test)]
    pub(crate) fn test_new_grant(&self) -> (String, String) {
        let family = random();
        let v = Self::issue(&self.db.lock().unwrap(), &self.config.tag(), &family).unwrap();
        (v["access_token"].as_str().unwrap().into(), family)
    }
    pub fn from_env(database_path: &str) -> Result<Self> {
        let c = Config {
            issuer: env::var("OAUTH_ISSUER")?,
            client: env::var("OAUTH_CLIENT_ID")?,
            secret: env::var("OAUTH_CLIENT_SECRET")?,
            owner: env::var("OAUTH_OWNER_APPROVAL_SECRET")?,
            redirects: env::var("OAUTH_REDIRECT_URIS")?
                .split(',')
                .map(str::trim)
                .map(str::to_owned)
                .collect(),
        };
        Self::new(c, Connection::open(database_path)?)
    }
    fn new(config: Config, db: Connection) -> Result<Self> {
        config.validate()?;
        let u = Url::parse(&config.issuer)?;
        let authority = match u.port() {
            Some(p) => format!("{}:{}", u.host_str().unwrap_or(""), p),
            None => u.host_str().unwrap_or("").to_owned(),
        };
        let resource = config.resource();
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS oauth_pending(id TEXT PRIMARY KEY,cookie TEXT NOT NULL,request TEXT NOT NULL,expires INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS oauth_codes(code TEXT PRIMARY KEY,request TEXT NOT NULL,tag TEXT NOT NULL,expires INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS oauth_tokens(token TEXT PRIMARY KEY,kind TEXT NOT NULL,family TEXT NOT NULL,tag TEXT NOT NULL,expires INTEGER NOT NULL,used INTEGER NOT NULL DEFAULT 0); CREATE TABLE IF NOT EXISTS oauth_revoked(family TEXT PRIMARY KEY); CREATE TABLE IF NOT EXISTS oauth_used_codes(code TEXT PRIMARY KEY,tag TEXT NOT NULL,family TEXT NOT NULL); CREATE INDEX IF NOT EXISTS idx_oauth_tokens_family_tag_expires ON oauth_tokens(family, tag, expires); CREATE INDEX IF NOT EXISTS idx_oauth_tokens_expires ON oauth_tokens(expires); CREATE INDEX IF NOT EXISTS idx_oauth_codes_expires ON oauth_codes(expires); CREATE INDEX IF NOT EXISTS idx_oauth_pending_expires ON oauth_pending(expires);")?;
        Ok(Self {
            config,
            resource,
            authority,
            db: Mutex::new(db),
            attempts: Mutex::new(VecDeque::new()),
        })
    }
    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route("/.well-known/oauth-authorization-server", get(metadata))
            .route(
                "/.well-known/oauth-protected-resource",
                get(resource_metadata),
            )
            .route(
                "/.well-known/oauth-protected-resource/mcp",
                get(resource_metadata),
            )
            .route("/oauth/authorize", get(authorize).post(consent))
            .route("/oauth/token", post(token))
            .route("/oauth/revoke", post(revoke))
            .layer(DefaultBodyLimit::max(16 * 1024))
            .with_state(self)
    }
    pub fn challenge(&self) -> String {
        format!("Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource/mcp\", scope=\"{}\"",self.config.issuer,SCOPE)
    }
    #[cfg(test)]
    pub fn authorize_bearer(&self, token: &str) -> bool {
        self.grant_for_bearer(token).is_some()
    }
    pub fn grant_for_bearer(&self, token: &str) -> Option<String> {
        if token.len() > 256 {
            return None;
        }
        let db = self.db.lock().ok()?;
        db.query_row("SELECT family FROM oauth_tokens t WHERE token=?1 AND kind='access' AND tag=?2 AND expires>?3 AND NOT EXISTS(SELECT 1 FROM oauth_revoked r WHERE r.family=t.family)",params![hash(token),self.config.tag(),now()],|r|r.get(0)).optional().ok().flatten()
    }
    pub fn grant_active(&self, family: &str) -> bool {
        let Ok(db) = self.db.lock() else { return false };
        db.query_row("SELECT EXISTS(SELECT 1 FROM oauth_tokens t WHERE family=?1 AND tag=?2 AND expires>?3 AND (kind='access' OR (kind='refresh' AND used=0)) AND NOT EXISTS(SELECT 1 FROM oauth_revoked r WHERE r.family=t.family))",params![family,self.config.tag(),now()],|r|r.get::<_,bool>(0)).unwrap_or(false)
    }
    fn good_host(&self, h: &HeaderMap) -> bool {
        h.get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == self.authority)
    }
    fn validate_request(&self, a: &Authorization) -> bool {
        a.response_type == "code"
            && a.client_id == self.config.client
            && self.config.redirects.contains(&a.redirect_uri)
            && (16..=1024).contains(&a.state.len())
            && a.code_challenge_method == "S256"
            && a.code_challenge.len() == 43
            && URL_SAFE_NO_PAD
                .decode(&a.code_challenge)
                .is_ok_and(|v| v.len() == 32)
            && a.resource == self.resource
            && a.scope == SCOPE
    }
    fn authenticate(&self, h: &HeaderMap, f: &TokenForm) -> bool {
        if let Some(auth) = h.get(header::AUTHORIZATION) {
            if f.client_secret.is_some() {
                return false;
            }
            let Some(s) = auth.to_str().ok().and_then(|s| s.strip_prefix("Basic ")) else {
                return false;
            };
            let Ok(bytes) = STANDARD.decode(s) else {
                return false;
            };
            let Ok(s) = String::from_utf8(bytes) else {
                return false;
            };
            let Some((id, secret)) = s.split_once(':') else {
                return false;
            };
            // OAuth Basic credentials are form-urlencoded before Base64.
            let decode = |v: &str| {
                url::form_urlencoded::parse(format!("x={v}").as_bytes())
                    .next()
                    .map(|(_, v)| v.into_owned())
                    .unwrap_or_default()
            };
            equal(&decode(id), &self.config.client)
                && equal(&decode(secret), &self.config.secret)
                && f.client_id
                    .as_ref()
                    .is_none_or(|v| v == &self.config.client)
        } else {
            f.client_id.as_ref() == Some(&self.config.client)
                && f.client_secret
                    .as_ref()
                    .is_some_and(|s| equal(s, &self.config.secret))
        }
    }
    fn issue(db: &Connection, tag: &str, family: &str) -> Result<serde_json::Value> {
        let access = random();
        let refresh = random();
        let t = now();
        db.execute("DELETE FROM oauth_tokens WHERE expires<=?1", [t])?;
        db.execute("DELETE FROM oauth_codes WHERE expires<=?1", [t])?;
        db.execute(
            "INSERT INTO oauth_tokens(token,kind,family,tag,expires) VALUES(?1,'access',?2,?3,?4)",
            params![hash(&access), family, tag, t + 900],
        )?;
        db.execute(
            "INSERT INTO oauth_tokens(token,kind,family,tag,expires) VALUES(?1,'refresh',?2,?3,?4)",
            params![hash(&refresh), family, tag, t + 30 * 86400],
        )?;
        Ok(
            json!({"access_token":access,"token_type":"Bearer","expires_in":900,"refresh_token":refresh,"scope":SCOPE}),
        )
    }
    fn exchange(&self, f: &TokenForm) -> Result<serde_json::Value> {
        if f.resource.as_deref() != Some(self.resource.as_str()) {
            bail!("invalid_target");
        }
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("server_error"))?;
        let tx = db.transaction()?;
        let tag = self.config.tag();
        let out = match f.grant_type.as_deref() {
            Some("authorization_code") => {
                let code = f.code.as_deref().context("invalid_grant")?;
                let reused: Option<String> = tx
                    .query_row(
                        "SELECT family FROM oauth_used_codes WHERE code=?1 AND tag=?2",
                        params![hash(code), tag],
                        |r| r.get(0),
                    )
                    .optional()?;
                if let Some(family) = reused {
                    tx.execute("INSERT OR IGNORE INTO oauth_revoked VALUES(?1)", [&family])?;
                    tx.commit()?;
                    bail!("invalid_grant");
                }

                let row: Option<(String, i64)> = tx
                    .query_row(
                        "SELECT request,expires FROM oauth_codes WHERE code=?1 AND tag=?2",
                        params![hash(code), tag],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                let (request, expires) = row.context("invalid_grant")?;
                let a: Authorization = serde_json::from_str(&request)?;
                let verifier = f.code_verifier.as_deref().context("invalid_grant")?;
                if expires <= now()
                    || f.redirect_uri.as_ref() != Some(&a.redirect_uri)
                    || !(43..=128).contains(&verifier.len())
                    || !verifier
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
                    || !equal(&hash(verifier), &a.code_challenge)
                {
                    bail!("invalid_grant");
                }
                tx.execute("DELETE FROM oauth_codes WHERE code=?1", params![hash(code)])?;
                let family = random();
                tx.execute(
                    "INSERT INTO oauth_used_codes VALUES(?1,?2,?3)",
                    params![hash(code), tag, family],
                )?;
                Self::issue(&tx, &tag, &family)?
            }
            Some("refresh_token") => {
                let value = f.refresh_token.as_deref().context("invalid_grant")?;
                let row:Option<(String,i64,i64)>=tx.query_row("SELECT family,expires,used FROM oauth_tokens WHERE token=?1 AND kind='refresh' AND tag=?2",params![hash(value),tag],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
                let (family, expires, used) = row.context("invalid_grant")?;
                if used != 0 {
                    tx.execute("INSERT OR IGNORE INTO oauth_revoked VALUES(?1)", [&family])?;
                    tx.commit()?;
                    bail!("invalid_grant");
                }
                let revoked: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM oauth_revoked WHERE family=?1)",
                    [&family],
                    |r| r.get(0),
                )?;
                if expires <= now() || revoked {
                    bail!("invalid_grant");
                }
                tx.execute(
                    "UPDATE oauth_tokens SET used=1 WHERE token=?1",
                    [hash(value)],
                )?;
                Self::issue(&tx, &tag, &family)?
            }
            _ => bail!("unsupported_grant_type"),
        };
        tx.commit()?;
        Ok(out)
    }
}
fn secure(mut r: Response) -> Response {
    let h = r.headers_mut();
    h.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    h.insert(header::PRAGMA, "no-cache".parse().unwrap());
    h.insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    h.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
            .parse()
            .unwrap(),
    );
    r
}
fn error(status: StatusCode, code: &str) -> Response {
    secure((status, Json(json!({"error":code}))).into_response())
}
fn invalid_client() -> Response {
    let mut r = error(StatusCode::UNAUTHORIZED, "invalid_client");
    r.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        "Basic realm=\"discord-oauth\"".parse().unwrap(),
    );
    r
}
fn consent_csp(s: &OAuth, r: &mut Response) {
    let origins = s
        .config
        .redirects
        .iter()
        .filter_map(|r| Url::parse(r).ok())
        .map(|u| u.origin().ascii_serialization())
        .collect::<Vec<_>>()
        .join(" ");
    let value = format!(
        "default-src 'none'; form-action 'self' {origins}; frame-ancestors 'none'; base-uri 'none'"
    );
    r.headers_mut()
        .insert(header::CONTENT_SECURITY_POLICY, value.parse().unwrap());
}
async fn metadata(State(s): State<Arc<OAuth>>, h: HeaderMap) -> Response {
    if !s.good_host(&h) {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let i = &s.config.issuer;
    secure(Json(json!({"issuer":i,"authorization_response_iss_parameter_supported":true,"authorization_endpoint":format!("{i}/oauth/authorize"),"token_endpoint":format!("{i}/oauth/token"),"revocation_endpoint":format!("{i}/oauth/revoke"),"response_types_supported":["code"],"grant_types_supported":["authorization_code","refresh_token"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post"],"revocation_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post"],"code_challenge_methods_supported":["S256"],"scopes_supported":[SCOPE]})).into_response())
}
async fn resource_metadata(State(s): State<Arc<OAuth>>, h: HeaderMap) -> Response {
    if !s.good_host(&h) {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    secure(Json(json!({"resource":&s.resource,"authorization_servers":[s.config.issuer],"scopes_supported":[SCOPE],"bearer_methods_supported":["header"]})).into_response())
}
fn extract_cookie(h: &HeaderMap) -> Option<String> {
    h.get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.split(';')
                .find_map(|x| x.trim().strip_prefix("__Host-discord-oauth="))
        })
        .map(str::to_owned)
}

async fn authorize(
    State(s): State<Arc<OAuth>>,
    h: HeaderMap,
    Query(a): Query<Authorization>,
) -> Response {
    if !s.good_host(&h) || !s.validate_request(&a) {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let existing_cookie = extract_cookie(&h);
    let request = random();
    let cookie = random();
    let result = (|| -> Result<()> {
        let db = s.db.lock().map_err(|_| anyhow::anyhow!("lock"))?;
        db.execute("DELETE FROM oauth_pending WHERE expires<=?1", [now()])?;
        if let Some(existing_cookie) = existing_cookie {
            let _ = db.execute(
                "DELETE FROM oauth_pending WHERE cookie=?1",
                [hash(&existing_cookie)],
            );
        }
        let count: i64 = db.query_row("SELECT COUNT(*) FROM oauth_pending", [], |r| r.get(0))?;
        if count >= 100 {
            let overflow = (count - 99).max(1);
            db.execute(
                "DELETE FROM oauth_pending WHERE id IN (SELECT id FROM oauth_pending ORDER BY expires ASC, rowid ASC LIMIT ?1)",
                [overflow],
            )?;
        }
        db.execute(
            "INSERT INTO oauth_pending VALUES(?1,?2,?3,?4)",
            params![
                hash(&request),
                hash(&cookie),
                serde_json::to_string(&a)?,
                now() + 300
            ],
        )?;
        Ok(())
    })();
    if result.is_err() {
        return error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    }
    let html=format!("<!doctype html><html><meta charset=utf-8><title>Authorize Discord DM bridge</title><h1>Authorize Discord DM bridge</h1><p>This client can receive your Discord DMs and reply as your bot. Approve only the ChatGPT connection you just initiated.</p><p>Client: {}<br>Redirect: {}</p><form method=post action=/oauth/authorize><input type=hidden name=request value=\"{}\"><label>Owner approval secret <input type=password name=approval_secret autocomplete=off required></label><button type=submit>Approve access</button></form><p>Close this page to deny.</p></html>",escape(&s.config.client),escape(&a.redirect_uri),request);
    let mut r = secure(Html(html).into_response());
    // Native non-CORS form POSTs under no-referrer can serialize Origin as null
    // (Fetch: append a request Origin header). Preserve origin without exposing
    // the authorization path/query. Other OAuth responses keep no-referrer.
    r.headers_mut()
        .insert(header::REFERRER_POLICY, "strict-origin".parse().unwrap());
    consent_csp(&s, &mut r);
    r.headers_mut().insert(
        header::SET_COOKIE,
        format!(
            "__Host-discord-oauth={cookie}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=300"
        )
        .parse()
        .unwrap(),
    );
    r
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConsentFailure {
    Host,
    Origin,
    PendingMissing,
    PendingExpired,
    CookieMismatch,
    Database,
    Validation,
}
impl ConsentFailure {
    fn diagnostic(self) -> &'static str {
        match self {
            Self::Host => "oauth_consent_denied category=host",
            Self::Origin => "oauth_consent_denied category=origin",
            Self::PendingMissing => "oauth_consent_denied category=pending_missing",
            Self::PendingExpired => "oauth_consent_denied category=pending_expired",
            Self::CookieMismatch => "oauth_consent_denied category=cookie_mismatch",
            Self::Database => "oauth_consent_denied category=db_error",
            Self::Validation => "oauth_consent_denied category=validation",
        }
    }
}
impl From<rusqlite::Error> for ConsentFailure {
    fn from(_: rusqlite::Error) -> Self {
        Self::Database
    }
}
fn consent_location(
    s: &OAuth,
    h: &HeaderMap,
    f: &Consent,
) -> std::result::Result<String, ConsentFailure> {
    if !s.good_host(h) {
        return Err(ConsentFailure::Host);
    }
    if h.get(header::ORIGIN).and_then(|v| v.to_str().ok()) != Some(s.config.issuer.as_str()) {
        return Err(ConsentFailure::Origin);
    }
    let cookie = h
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.split(';')
                .find_map(|x| x.trim().strip_prefix("__Host-discord-oauth="))
        })
        .unwrap_or("");

    let mut db = s.db.lock().map_err(|_| ConsentFailure::Database)?;
    let tx = db.transaction()?;
    let row: Option<(String, String, i64)> = tx
        .query_row(
            "SELECT cookie,request,expires FROM oauth_pending WHERE id=?1",
            [hash(&f.request)],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let (expected, request, expires) = row.ok_or(ConsentFailure::PendingMissing)?;
    if expires <= now() {
        return Err(ConsentFailure::PendingExpired);
    }
    if !equal(&expected, &hash(cookie)) {
        return Err(ConsentFailure::CookieMismatch);
    }
    // The high-entropy owner key is checked before the failed-attempt budget:
    // public clients must not be able to lock the legitimate owner out.
    let owner_authorized = equal(&f.approval_secret, &s.config.owner);
    if !owner_authorized {
        let mut attempts = s.attempts.lock().map_err(|_| ConsentFailure::Validation)?;
        while attempts.front().is_some_and(|t| *t <= now() - 3600) {
            attempts.pop_front();
        }
        if attempts.len() >= 10 {
            return Err(ConsentFailure::Validation);
        }
        attempts.push_back(now());
        drop(attempts);
    }
    tx.execute("DELETE FROM oauth_pending WHERE id=?1", [hash(&f.request)])?;
    let a: Authorization =
        serde_json::from_str(&request).map_err(|_| ConsentFailure::Validation)?;
    if !s.validate_request(&a) {
        return Err(ConsentFailure::Validation);
    }
    if !owner_authorized {
        tx.commit()?;
        let mut u = Url::parse(&a.redirect_uri).map_err(|_| ConsentFailure::Validation)?;
        u.query_pairs_mut()
            .append_pair("error", "access_denied")
            .append_pair("state", &a.state)
            .append_pair("iss", &s.config.issuer);
        return Ok(u.into());
    }
    let code = random();
    tx.execute(
        "INSERT INTO oauth_codes VALUES(?1,?2,?3,?4)",
        params![hash(&code), request, s.config.tag(), now() + 120],
    )?;
    tx.commit()?;
    let mut u = Url::parse(&a.redirect_uri).map_err(|_| ConsentFailure::Validation)?;
    u.query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &a.state)
        .append_pair("iss", &s.config.issuer);
    Ok(u.into())
}
async fn consent(State(s): State<Arc<OAuth>>, h: HeaderMap, Form(f): Form<Consent>) -> Response {
    match consent_location(&s, &h, &f) {
        Ok(location) => {
            let mut r = secure(StatusCode::SEE_OTHER.into_response());
            consent_csp(&s, &mut r);
            r.headers_mut()
                .insert(header::LOCATION, location.parse().unwrap());
            r.headers_mut().insert(
                header::SET_COOKIE,
                "__Host-discord-oauth=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"
                    .parse()
                    .unwrap(),
            );
            r
        }
        Err(category) => {
            // Static category only: never format errors, request values, or headers.
            eprintln!("{}", category.diagnostic());
            error(StatusCode::FORBIDDEN, "access_denied")
        }
    }
}
async fn token(State(s): State<Arc<OAuth>>, h: HeaderMap, Form(f): Form<TokenForm>) -> Response {
    if !s.good_host(&h) {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    if !s.authenticate(&h, &f) {
        return invalid_client();
    }
    match s.exchange(&f) {
        Ok(v) => secure(Json(v).into_response()),
        Err(e) => {
            let code = e.to_string();
            let code = match code.as_str() {
                "invalid_target" | "invalid_grant" | "unsupported_grant_type" => code.as_str(),
                _ => "server_error",
            };
            error(
                if code == "server_error" {
                    StatusCode::INTERNAL_SERVER_ERROR
                } else {
                    StatusCode::BAD_REQUEST
                },
                code,
            )
        }
    }
}
async fn revoke(State(s): State<Arc<OAuth>>, h: HeaderMap, Form(f): Form<TokenForm>) -> Response {
    if !s.good_host(&h) {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    if !s.authenticate(&h, &f) {
        return invalid_client();
    }
    let Some(token) = f.token else {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let result = (|| -> Result<()> {
        let db = s.db.lock().map_err(|_| anyhow::anyhow!("lock"))?;
        db.execute("INSERT OR IGNORE INTO oauth_revoked SELECT family FROM oauth_tokens WHERE token=?1 AND tag=?2",params![hash(&token),s.config.tag()])?;
        Ok(())
    })();
    if result.is_err() {
        error(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
    } else {
        secure(StatusCode::OK.into_response())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn server() -> OAuth {
        OAuth::new(
            Config {
                issuer: "https://discord.example.com".into(),
                client: "chatgpt-private".into(),
                secret: "s".repeat(40),
                owner: "o".repeat(40),
                redirects: vec!["https://chatgpt.com/connector_platform/oauth/callback".into()],
            },
            Connection::open_in_memory().unwrap(),
        )
        .unwrap()
    }
    fn auth(s: &OAuth) -> Authorization {
        Authorization {
            response_type: "code".into(),
            client_id: s.config.client.clone(),
            redirect_uri: s.config.redirects[0].clone(),
            state: "state-with-at-least-16-chars".into(),
            code_challenge: hash(&"v".repeat(43)),
            code_challenge_method: "S256".into(),
            resource: s.config.resource(),
            scope: SCOPE.into(),
        }
    }
    fn grant(s: &OAuth) -> TokenForm {
        let a = auth(s);
        s.db.lock()
            .unwrap()
            .execute(
                "INSERT INTO oauth_codes VALUES(?1,?2,?3,?4)",
                params![
                    hash("test-code"),
                    serde_json::to_string(&a).unwrap(),
                    s.config.tag(),
                    now() + 120
                ],
            )
            .unwrap();
        TokenForm {
            grant_type: Some("authorization_code".into()),
            code: Some("test-code".into()),
            redirect_uri: Some(a.redirect_uri),
            code_verifier: Some("v".repeat(43)),
            resource: Some(s.config.resource()),
            ..Default::default()
        }
    }
    fn pending_consent() -> (OAuth, HeaderMap, Consent) {
        let s = server();
        let f = Consent {
            request: "synthetic-request-not-for-logs".into(),
            approval_secret: s.config.owner.clone(),
        };
        let cookie = "synthetic-cookie-not-for-logs";
        s.db.lock()
            .unwrap()
            .execute(
                "INSERT INTO oauth_pending VALUES(?,?,?,?)",
                params![
                    hash(&f.request),
                    hash(cookie),
                    serde_json::to_string(&auth(&s)).unwrap(),
                    now() + 300
                ],
            )
            .unwrap();
        let mut h = headers();
        h.insert(header::ORIGIN, s.config.issuer.parse().unwrap());
        h.insert(
            header::COOKIE,
            format!("__Host-discord-oauth={cookie}").parse().unwrap(),
        );
        (s, h, f)
    }
    #[tokio::test]
    async fn consent_failures_are_classified_without_response_or_log_values() {
        let cases = [
            ConsentFailure::Host,
            ConsentFailure::Origin,
            ConsentFailure::PendingMissing,
            ConsentFailure::PendingExpired,
            ConsentFailure::CookieMismatch,
            ConsentFailure::Database,
            ConsentFailure::Validation,
        ];
        let logs = [
            "oauth_consent_denied category=host",
            "oauth_consent_denied category=origin",
            "oauth_consent_denied category=pending_missing",
            "oauth_consent_denied category=pending_expired",
            "oauth_consent_denied category=cookie_mismatch",
            "oauth_consent_denied category=db_error",
            "oauth_consent_denied category=validation",
        ];
        for (expected, line) in cases.into_iter().zip(logs) {
            let (s, mut h, f) = pending_consent();
            match expected {
                ConsentFailure::Host => {
                    h.insert(header::HOST, "wrong-private-host.example".parse().unwrap());
                }
                ConsentFailure::Origin => {
                    h.insert(
                        header::ORIGIN,
                        "https://wrong-private-origin.example".parse().unwrap(),
                    );
                }
                ConsentFailure::PendingMissing => {
                    s.db.lock()
                        .unwrap()
                        .execute("DELETE FROM oauth_pending", [])
                        .unwrap();
                }
                ConsentFailure::PendingExpired => {
                    s.db.lock()
                        .unwrap()
                        .execute("UPDATE oauth_pending SET expires=0", [])
                        .unwrap();
                }
                ConsentFailure::CookieMismatch => {
                    h.remove(header::COOKIE);
                }
                ConsentFailure::Database => {
                    s.db.lock()
                        .unwrap()
                        .execute("DROP TABLE oauth_pending", [])
                        .unwrap();
                }
                ConsentFailure::Validation => {
                    s.db.lock()
                        .unwrap()
                        .execute(
                            "UPDATE oauth_pending SET request=?",
                            ["private-malformed-authorization-not-for-logs"],
                        )
                        .unwrap();
                }
            }
            assert_eq!(consent_location(&s, &h, &f), Err(expected));
            assert_eq!(expected.diagnostic(), line);
            // Public failure remains generic, no diagnostic header or redirect.
            let response = consent(State(Arc::new(s)), h, Form(f)).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert!(!response.headers().contains_key(header::LOCATION));
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let bytes = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            assert_eq!(&bytes[..], br#"{"error":"access_denied"}"#);
        }
    }
    #[tokio::test]
    async fn consent_html_uses_origin_only_referrer_policy_and_other_responses_do_not() {
        let s = Arc::new(server());
        let page = authorize(State(s.clone()), headers(), Query(auth(&s))).await;
        assert_eq!(page.status(), StatusCode::OK);
        assert_eq!(page.headers()[header::REFERRER_POLICY], "strict-origin");
        assert_eq!(page.headers()[header::CACHE_CONTROL], "no-store");
        for response in [
            metadata(State(s.clone()), headers()).await,
            resource_metadata(State(s.clone()), headers()).await,
            error(StatusCode::FORBIDDEN, "access_denied"),
        ] {
            assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
        }
        let (server, h, f) = pending_consent();
        let response = consent(State(Arc::new(server)), h, Form(f)).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
    }
    #[test]
    fn consent_still_rejects_null_missing_and_hostile_origin() {
        for origin in [
            None,
            Some("null"),
            Some("https://attacker.example"),
            Some("https://discord.example.com.attacker.example"),
        ] {
            let (s, mut h, f) = pending_consent();
            h.remove(header::ORIGIN);
            if let Some(origin) = origin {
                h.insert(header::ORIGIN, origin.parse().unwrap());
            }
            assert_eq!(consent_location(&s, &h, &f), Err(ConsentFailure::Origin));
            assert_eq!(
                s.db.lock()
                    .unwrap()
                    .query_row("SELECT count(*) FROM oauth_codes", [], |r| r
                        .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
    }
    #[test]
    fn missing_origin_and_wrong_cookie_keep_distinct_safe_categories() {
        let (s, mut h, f) = pending_consent();
        h.remove(header::ORIGIN);
        assert_eq!(consent_location(&s, &h, &f), Err(ConsentFailure::Origin));
        h.insert(header::ORIGIN, s.config.issuer.parse().unwrap());
        h.insert(
            header::COOKIE,
            "__Host-discord-oauth=wrong-secret-cookie".parse().unwrap(),
        );
        assert_eq!(
            consent_location(&s, &h, &f),
            Err(ConsentFailure::CookieMismatch)
        );
        assert!(s.attempts.lock().unwrap().is_empty());
        assert_eq!(
            s.db.lock()
                .unwrap()
                .query_row("SELECT count(*) FROM oauth_pending", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
    #[test]
    fn consent_database_write_failure_is_generic_and_rolls_back() {
        let (s, h, f) = pending_consent();
        s.db.lock()
            .unwrap()
            .execute("DROP TABLE oauth_codes", [])
            .unwrap();
        assert_eq!(consent_location(&s, &h, &f), Err(ConsentFailure::Database));
        assert_eq!(
            s.db.lock()
                .unwrap()
                .query_row("SELECT count(*) FROM oauth_pending", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
    #[test]
    fn request_rejects_redirect_prefix_and_plain_pkce() {
        let s = server();
        let mut a = auth(&s);
        assert!(s.validate_request(&a));
        a.redirect_uri.push_str("/evil");
        assert!(!s.validate_request(&a));
        a = auth(&s);
        a.code_challenge_method = "plain".into();
        assert!(!s.validate_request(&a));
        a = auth(&s);
        a.resource = "https://other.example/mcp".into();
        assert!(!s.validate_request(&a));
    }
    #[test]
    fn authorization_code_is_bound_and_one_use() {
        let s = server();
        let mut f = grant(&s);
        f.code_verifier = Some("wrong".repeat(10));
        assert!(s.exchange(&f).is_err());
        f.code_verifier = Some("v".repeat(43));
        let v = s.exchange(&f).unwrap();
        assert!(s.authorize_bearer(v["access_token"].as_str().unwrap()));
        assert!(s.exchange(&f).is_err());
        assert!(!s.authorize_bearer(v["access_token"].as_str().unwrap()));
    }
    #[test]
    fn refresh_reuse_revokes_family() {
        let s = server();
        let v = s.exchange(&grant(&s)).unwrap();
        let f = TokenForm {
            grant_type: Some("refresh_token".into()),
            refresh_token: Some(v["refresh_token"].as_str().unwrap().into()),
            resource: Some(s.config.resource()),
            ..Default::default()
        };
        let v2 = s.exchange(&f).unwrap();
        assert!(s.authorize_bearer(v2["access_token"].as_str().unwrap()));
        assert!(s.exchange(&f).is_err());
        assert!(!s.authorize_bearer(v["access_token"].as_str().unwrap()));
        assert!(!s.authorize_bearer(v2["access_token"].as_str().unwrap()));
    }
    #[test]
    fn access_tokens_hash_only_and_expire() {
        let s = server();
        let v = s.exchange(&grant(&s)).unwrap();
        let a = v["access_token"].as_str().unwrap();
        let db = s.db.lock().unwrap();
        assert_eq!(
            db.query_row(
                "SELECT COUNT(*) FROM oauth_tokens WHERE token=?1",
                [a],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        db.execute("UPDATE oauth_tokens SET expires=0", []).unwrap();
        drop(db);
        assert!(!s.authorize_bearer(a));
    }
    #[test]
    fn client_auth_requires_secret_and_no_ambiguous_credentials() {
        let s = server();
        let mut f = TokenForm {
            client_id: Some(s.config.client.clone()),
            client_secret: Some(s.config.secret.clone()),
            ..Default::default()
        };
        assert!(s.authenticate(&HeaderMap::new(), &f));
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            format!(
                "Basic {}",
                STANDARD.encode(format!("{}:{}", s.config.client, s.config.secret))
            )
            .parse()
            .unwrap(),
        );
        assert!(!s.authenticate(&h, &f));
        f.client_secret = None;
        assert!(s.authenticate(&h, &f));
    }
    fn headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "discord.example.com".parse().unwrap());
        h
    }
    #[tokio::test]
    async fn consent_requires_cookie_origin_owner_and_is_one_use() {
        let s = Arc::new(server());
        let a = auth(&s);
        let r = authorize(State(s.clone()), headers(), Query(a)).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert!(r.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("form-action 'self' https://chatgpt.com"));
        let cookie = r.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let body = axum::body::to_bytes(r.into_body(), 16384).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        let request = html
            .split("name=request value=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
            .to_owned();
        let mut h = headers();
        h.insert(header::ORIGIN, "https://attacker.example".parse().unwrap());
        h.insert(header::COOKIE, cookie.parse().unwrap());
        let f = || Consent {
            request: request.clone(),
            approval_secret: s.config.owner.clone(),
        };
        assert_eq!(
            consent(State(s.clone()), h.clone(), Form(f()))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        h.insert(header::ORIGIN, s.config.issuer.parse().unwrap());
        let mut missing = h.clone();
        missing.remove(header::COOKIE);
        assert_eq!(
            consent(State(s.clone()), missing, Form(f())).await.status(),
            StatusCode::FORBIDDEN
        );
        assert!(s.attempts.lock().unwrap().is_empty());
        s.attempts
            .lock()
            .unwrap()
            .extend(std::iter::repeat_n(now(), 10));
        let r = consent(State(s.clone()), h.clone(), Form(f())).await;
        assert_eq!(r.status(), StatusCode::SEE_OTHER);
        let u = Url::parse(r.headers()[header::LOCATION].to_str().unwrap()).unwrap();
        assert!(u
            .query_pairs()
            .any(|(k, v)| k == "iss" && v == s.config.issuer));
        assert_eq!(
            consent(State(s.clone()), h, Form(f())).await.status(),
            StatusCode::FORBIDDEN
        );
    }
    #[tokio::test]
    async fn revocation_invalidates_access_refresh_and_event_grant() {
        let s = Arc::new(server());
        let v = s.exchange(&grant(&s)).unwrap();
        let access = v["access_token"].as_str().unwrap();
        let family = s.grant_for_bearer(access).unwrap();
        assert!(s.grant_active(&family));
        let f = TokenForm {
            client_id: Some(s.config.client.clone()),
            client_secret: Some(s.config.secret.clone()),
            token: Some(v["refresh_token"].as_str().unwrap().into()),
            ..Default::default()
        };
        assert_eq!(
            revoke(State(s.clone()), headers(), Form(f)).await.status(),
            StatusCode::OK
        );
        assert!(!s.authorize_bearer(access));
        assert!(!s.grant_active(&family));
    }
    #[test]
    fn owner_secret_rotation_invalidates_stored_grants() {
        let mut s = server();
        let v = s.exchange(&grant(&s)).unwrap();
        let access = v["access_token"].as_str().unwrap();
        let family = s.grant_for_bearer(access).unwrap();
        s.config.owner = "changed-secret".repeat(4);
        assert!(!s.authorize_bearer(access));
        assert!(!s.grant_active(&family));
    }
    #[test]
    fn token_state_survives_reopen_and_redirect_change_invalidates() {
        let path = std::env::temp_dir().join(format!("oauth-test-{}.sqlite", Uuid::new_v4()));
        let config = server().config.clone();
        let s = OAuth::new(config.clone(), Connection::open(&path).unwrap()).unwrap();
        let v = s.exchange(&grant(&s)).unwrap();
        let access = v["access_token"].as_str().unwrap().to_owned();
        drop(s);
        let s = OAuth::new(config.clone(), Connection::open(&path).unwrap()).unwrap();
        assert!(s.authorize_bearer(&access));
        drop(s);
        let mut config = config;
        config.redirects.push("https://chatgpt.com/other".into());
        let s = OAuth::new(config, Connection::open(&path).unwrap()).unwrap();
        assert!(!s.authorize_bearer(&access));
        drop(s);
        std::fs::remove_file(path).unwrap();
    }
    #[tokio::test]
    async fn metadata_advertises_exact_resource_pkce_and_issuer_response() {
        let s = Arc::new(server());
        let r = metadata(State(s.clone()), headers()).await;
        assert_eq!(r.status(), StatusCode::OK);
        let body = axum::body::to_bytes(r.into_body(), 16384).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["authorization_response_iss_parameter_supported"], true);
        assert_eq!(v["code_challenge_methods_supported"], json!(["S256"]));
        let r = resource_metadata(State(s.clone()), headers()).await;
        let body = axum::body::to_bytes(r.into_body(), 16384).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["resource"], s.config.resource());
        let mut h = headers();
        h.insert(header::HOST, "attacker.example".parse().unwrap());
        assert_eq!(
            metadata(State(s), h).await.status(),
            StatusCode::BAD_REQUEST
        );
    }
    #[tokio::test]
    async fn bound_denial_redirect_has_state_issuer_and_no_code() {
        let s = Arc::new(server());
        let a = auth(&s);
        s.db.lock()
            .unwrap()
            .execute(
                "INSERT INTO oauth_pending VALUES(?1,?2,?3,?4)",
                params![
                    hash("request"),
                    hash("cookie"),
                    serde_json::to_string(&a).unwrap(),
                    now() + 300
                ],
            )
            .unwrap();
        let mut h = headers();
        h.insert(header::ORIGIN, s.config.issuer.parse().unwrap());
        h.insert(
            header::COOKIE,
            "__Host-discord-oauth=cookie".parse().unwrap(),
        );
        let r = consent(
            State(s.clone()),
            h,
            Form(Consent {
                request: "request".into(),
                approval_secret: "wrong".into(),
            }),
        )
        .await;
        assert_eq!(r.status(), StatusCode::SEE_OTHER);
        let u = Url::parse(r.headers()[header::LOCATION].to_str().unwrap()).unwrap();
        assert!(u
            .query_pairs()
            .any(|(k, v)| k == "error" && v == "access_denied"));
        assert!(u.query_pairs().any(|(k, v)| k == "state" && v == a.state));
        assert!(u
            .query_pairs()
            .any(|(k, v)| k == "iss" && v == s.config.issuer));
        assert!(!u.query_pairs().any(|(k, _)| k == "code"));
        assert_eq!(
            s.db.lock()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM oauth_codes", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        let r = token(State(s), headers(), Form(TokenForm::default())).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        assert!(r.headers()[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap()
            .starts_with("Basic "));
    }
    #[test]
    fn issue_prunes_expired_tokens_and_codes_while_preserving_active_family() {
        let s = server();
        let v1 = s.exchange(&grant(&s)).unwrap();
        {
            let db = s.db.lock().unwrap();
            db.execute("UPDATE oauth_tokens SET expires=0 WHERE kind='access'", [])
                .unwrap();
            db.execute(
                "INSERT INTO oauth_codes(code,request,tag,expires) VALUES('expired_code','{}','tag',0)",
                [],
            )
            .unwrap();
        }
        let f = TokenForm {
            grant_type: Some("refresh_token".into()),
            refresh_token: Some(v1["refresh_token"].as_str().unwrap().into()),
            resource: Some(s.config.resource()),
            ..Default::default()
        };
        let v2 = s.exchange(&f).unwrap();
        assert!(s.authorize_bearer(v2["access_token"].as_str().unwrap()));
        let db = s.db.lock().unwrap();
        let expired_tokens: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM oauth_tokens WHERE expires<=?1",
                [now()],
                |r| r.get(0),
            )
            .unwrap();
        let expired_codes: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM oauth_codes WHERE expires<=?1",
                [now()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(expired_tokens, 0);
        assert_eq!(expired_codes, 0);
    }

    #[tokio::test]
    async fn oauth_evicts_oldest_pending_to_prevent_dos() {
        let s = Arc::new(server());
        // Insert 100 pending authorizations
        {
            let db = s.db.lock().unwrap();
            for i in 0..100 {
                db.execute(
                    "INSERT INTO oauth_pending VALUES(?,?,?,?)",
                    params![
                        format!("pending_{i:03}"),
                        format!("cookie_{i:03}"),
                        "{}",
                        now() + 300
                    ],
                )
                .unwrap();
            }
        }
        let a = auth(&s);
        let res = authorize(State(s.clone()), headers(), Query(a)).await;
        assert_eq!(res.status(), StatusCode::OK);
        let count: i64 =
            s.db.lock()
                .unwrap()
                .query_row("SELECT count(*) FROM oauth_pending", [], |r| r.get(0))
                .unwrap();
        assert_eq!(count, 100);
    }
}
