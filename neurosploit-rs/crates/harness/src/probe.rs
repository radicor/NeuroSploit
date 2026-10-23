//! Deterministic HTTP request/response analysis (v3.6.5).
//!
//! Before the LLM recon runs, the harness performs a **real** probe of the
//! target and captures observed facts — status, headers, security headers,
//! cookie flags, CORS reflection, redirect, tech hints, linked scripts, a small
//! set of interesting paths, and a 404 baseline for differentials. Those facts
//! are injected into recon so agent selection and exploitation decisions are
//! grounded in the actual request/response, not just the model's guess. This
//! makes the harness more robust (works even when the model's recon is weak) and
//! its decisions sharper. Best-effort: failures are noted, never fatal. Honors
//! NEUROSPLOIT_UA (identifying User-Agent) and NEUROSPLOIT_PROXY (Burp/ZAP).
use serde::Serialize;
use std::time::Duration;

#[derive(Serialize, Default)]
pub struct SecHeaders {
    pub hsts: bool,
    pub csp: bool,
    pub x_frame_options: bool,
    pub x_content_type_options: bool,
    pub referrer_policy: bool,
    pub permissions_policy: bool,
    /// Count present (of the 6 tracked).
    pub present: u8,
}

#[derive(Serialize, Default)]
pub struct CookieFlags {
    pub name: String,
    pub http_only: bool,
    pub secure: bool,
    pub same_site: String,
}

#[derive(Serialize, Default)]
pub struct Cors {
    /// Does the app reflect an arbitrary Origin into Access-Control-Allow-Origin?
    pub reflects_origin: bool,
    pub wildcard: bool,
    pub allow_credentials: bool,
}

#[derive(Serialize, Default)]
pub struct PathHit {
    pub path: String,
    pub status: u16,
    pub len: usize,
}

/// A parsed HTML `<form>` — enough for an agent to auto-submit it (e.g. register
/// an account) with curl or the browser, without re-parsing the page.
#[derive(Serialize, Default, Clone)]
pub struct FormInfo {
    pub action: String,
    pub method: String,
    /// input/select/textarea field names with their type (name → type).
    pub fields: Vec<(String, String)>,
    /// Best-effort role guess: "register" | "login" | "search" | "other".
    pub kind: String,
    /// True if a CSRF/anti-forgery hidden token was seen in the form.
    pub has_csrf: bool,
}

#[derive(Serialize, Default)]
pub struct Probe {
    pub url: String,
    pub final_url: String,
    pub redirected: bool,
    pub status: u16,
    pub server: String,
    pub powered_by: String,
    pub content_type: String,
    pub title: String,
    pub tech: Vec<String>,
    pub security_headers: SecHeaders,
    pub cookies: Vec<CookieFlags>,
    pub cors: Cors,
    pub scripts: Vec<String>,
    /// Business/brand hint extracted from the page (og:site_name, application-name,
    /// or a "© <Name>" copyright) so the report can name the org, not just the URL.
    pub brand: String,
    pub forms: usize,
    /// Parsed forms (action/method/fields) so an agent can auto-submit them —
    /// e.g. register a test account to reach the authenticated surface.
    pub form_details: Vec<FormInfo>,
    pub interesting_paths: Vec<PathHit>,
    /// Baseline for a random non-existent path (status + body length), so agents
    /// can tell a real hit from a soft-404 catch-all.
    pub baseline_404_status: u16,
    pub baseline_404_len: usize,
    pub notes: Vec<String>,
}

/// The harness's HTTP client: identifying User-Agent, proxy honoured, and
/// invalid certificates tolerated (test targets rarely have valid ones).
/// Shared with `crate::replay` so every request the harness itself makes is
/// shaped the same way and is attributable to NeuroSploit.
pub fn http_client() -> reqwest::Client {
    client()
}

fn client() -> reqwest::Client {
    client_for(None)
}

/// A client whose redirects are judged by `policy`. The in-scope probe uses
/// this, so a 302 off the authorized surface is returned as data rather than
/// followed — and a hostname pointing at loopback is stopped before it resolves.
fn client_for(policy: Option<std::sync::Arc<crate::scope::ScopePolicy>>) -> reqwest::Client {
    let mut b = base_builder_for(policy);
    if let Some(p) = proxy_url(&std::env::var("NEUROSPLOIT_PROXY").unwrap_or_default()) {
        if let Ok(px) = reqwest::Proxy::all(p) { b = b.proxy(px); }
    }
    b.build().unwrap_or_default()
}

/// Everything both clients share: UA, timeout, redirect guard, scan headers.
fn base_builder() -> reqwest::ClientBuilder {
    base_builder_for(None)
}

fn base_builder_for(
    policy: Option<std::sync::Arc<crate::scope::ScopePolicy>>,
) -> reqwest::ClientBuilder {
    let ua = std::env::var("NEUROSPLOIT_UA").ok().filter(|v| !v.trim().is_empty())
        .unwrap_or_else(crate::pipeline::default_user_agent);
    // A redirect is a request the server asks us to make, so it passes the same
    // boundary as any other: resolve the target (a hostname pointing at
    // loopback is the same pivot as a literal) and, when a policy is attached,
    // ask the scope layer. Without a policy the literal check still applies —
    // that is the recorder-only case.
    let redirect_policy = policy.clone();
    let redirect = reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= 5 {
            return attempt.stop();
        }
        let next = attempt.url().as_str();
        match &redirect_policy {
            Some(pol) => {
                // Resolve before following: a hostname pointing at loopback is
                // the same pivot as a literal, and only resolution can see it.
                let next_host = crate::scope::host_of(next);
                if crate::netguard::pin(&next_host).is_err() {
                    return attempt.stop();
                }
                let prev = attempt
                    .previous()
                    .last()
                    .map(|u| u.as_str().to_string())
                    .unwrap_or_default();
                match crate::netguard::redirect_allowed(&prev, next, |u| {
                    pol.check(u, crate::scope::Action::Probe).allowed()
                }) {
                    Ok(_) => attempt.follow(),
                    Err(_) => attempt.stop(),
                }
            }
            // No policy: keep the previous behaviour exactly — a literal
            // private target is refused, and no DNS lookup is introduced for
            // clients that never opted into scope enforcement.
            None => {
                let host = crate::netguard::normalize_host(
                    attempt.url().host_str().unwrap_or(""),
                );
                if let Some(ip) = crate::netguard::parse_ip_any(&host) {
                    if crate::netguard::is_private(&ip) {
                        return attempt.stop();
                    }
                }
                attempt.follow()
            }
        }
    });
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(true)
        .redirect(redirect)
        .default_headers(crate::pipeline::default_scan_headers())
        .user_agent(ua)
}

/// Pure form of the proxy flag, so a test can drive the seam without mutating the
/// process environment. `http_client()` honours it by design (Burp/ZAP).
pub fn proxy_url(raw: &str) -> Option<&str> {
    let t = raw.trim();
    if t.is_empty() { None } else { Some(t) }
}

/// A client that never proxies. Loopback tests must use this: a proxied client
/// cannot reach a local mock, and a stray `NEUROSPLOIT_PROXY` would silently
/// redirect the assertion at whatever the proxy returns.
pub fn http_client_direct() -> reqwest::Client {
    base_builder()
        .no_proxy()
        .build()
        .unwrap_or_default()
}

fn hget(h: &reqwest::header::HeaderMap, k: &str) -> String {
    h.get(k).and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
}

fn between<'a>(s: &'a str, a: &str, b: &str) -> Option<&'a str> {
    let i = s.find(a)? + a.len();
    let j = s[i..].find(b)? + i;
    Some(&s[i..j])
}

/// Read one HTML attribute value (double- or single-quoted) from a tag slice.
fn attr(tag: &str, name: &str) -> String {
    for q in ["\"", "'"] {
        if let Some(v) = between(tag, &format!("{name}={q}"), q) {
            return v.trim().to_string();
        }
    }
    String::new()
}

/// Best-effort business/brand name from the page: `og:site_name` or
/// `application-name` meta, else a "© <Name>" / "Copyright <Name>" notice. Helps
/// the report name the organisation/product instead of only the URL.
fn extract_brand(body: &str) -> String {
    brand_after(body)
}

/// Same as `extract_brand`, on a bounded head of the body.
///
/// The mirror used for case-insensitive search is `to_ascii_lowercase`, not
/// `to_lowercase`: ASCII lowercasing never changes byte length ('İ' stays two
/// bytes, 'ẞ' stays three), so every byte offset in the mirror addresses the
/// same byte in the original and hits can be sliced back out of `head` with
/// their original casing intact.
fn brand_after(body: &str) -> String {
    let head = &body[..first_boundary_at_or_before(body, 4 * 1024 * 1024)];
    let head_low = head.to_ascii_lowercase();
    // <meta property="og:site_name" content="X"> / name="application-name"
    for key in ["og:site_name", "application-name", "author", "twitter:site"] {
        let Some(i) = head_low.find(key) else { continue };
        let rest = &head[i..];
        let tail = &rest[..first_boundary_at_or_before(rest, 220)];
        if let Some(c) = between(tail, "content=\"", "\"").or_else(|| between(tail, "content='", "'")) {
            let c = c.trim();
            if c.len() >= 2 && c.len() <= 60 { return c.to_string(); }
        }
    }
    // Copyright notice: "© Company" or "Copyright 2024 Company". `copyright` is
    // matched case-insensitively through the offset-safe mirror; `©` and
    // `&copy;` are ASCII-lowercase-stable so they match either way.
    for marker in ["©", "&copy;", "copyright"] {
        let Some(i) = head_low.find(marker) else { continue };
        let seg: String = head[i..].chars().take(80).collect();
        // strip the marker + a year, take the first capitalised words.
        let cleaned = seg.replace('©', " ").replace("&copy;", " ");
        let cleaned = cleaned.trim_start_matches(|c: char| !c.is_alphabetic());
        let name: String = cleaned.split(['<', '.', '|', '\n'])
            .next().unwrap_or("").chars().filter(|c| c.is_alphanumeric() || c.is_whitespace() || *c == '&' || *c == '-')
            .collect::<String>().trim().to_string();
        // drop a leading year like "2024 "
        let name = name.split_whitespace().filter(|w| !w.chars().all(|c| c.is_ascii_digit()))
            .collect::<Vec<_>>().join(" ");
        if name.len() >= 2 && name.len() <= 50 && name.to_lowercase() != "copyright" { return name; }
    }
    String::new()
}

/// Largest index `<= cap` that is a char boundary, so slicing never panics on
/// attacker-supplied multi-byte text.
fn first_boundary_at_or_before(s: &str, cap: usize) -> usize {
    if cap >= s.len() {
        return s.len();
    }
    let mut end = cap;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    end
}

/// Best-effort parse of the HTML `<form>`s on a page so agents can auto-submit
/// them (e.g. register a test account) without re-parsing. Non-destructive: this
/// only READS the markup. Bounded to the first few forms.
fn parse_forms(body: &str) -> Vec<FormInfo> {
    let mut out = Vec::new();
    for chunk in body.split("<form").skip(1).take(8) {
        // The form's own attributes live before the first '>'.
        let head = chunk.split('>').next().unwrap_or("");
        let inner = chunk.split("</form").next().unwrap_or(chunk);
        let mut f = FormInfo {
            action: attr(head, "action"),
            method: {
                let m = attr(head, "method");
                if m.is_empty() { "get".into() } else { m.to_lowercase() }
            },
            ..Default::default()
        };
        // Fields: <input>, <select>, <textarea> — capture name + type.
        for tag in ["<input", "<select", "<textarea"] {
            for seg in inner.split(tag).skip(1) {
                let t = seg.split('>').next().unwrap_or("");
                let name = attr(t, "name");
                if name.is_empty() { continue; }
                let ty = if tag == "<input" {
                    let ty = attr(t, "type");
                    if ty.is_empty() { "text".into() } else { ty.to_lowercase() }
                } else { tag.trim_start_matches('<').into() };
                if ty == "hidden" && (t.to_lowercase().contains("csrf") || t.to_lowercase().contains("token") || name.to_lowercase().contains("csrf") || name.to_lowercase().contains("_token")) {
                    f.has_csrf = true;
                }
                if f.fields.len() < 25 && !f.fields.iter().any(|(n, _)| *n == name) {
                    f.fields.push((name, ty));
                }
            }
        }
        // Guess the form's role from action + field names.
        let hay = format!("{} {}", f.action, f.fields.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(" ")).to_lowercase();
        let has_pw = f.fields.iter().any(|(_, t)| t == "password");
        f.kind = if hay.contains("regist") || hay.contains("signup") || hay.contains("sign-up") || hay.contains("create") || (has_pw && (hay.contains("confirm") || hay.contains("repeat"))) {
            "register".into()
        } else if hay.contains("login") || hay.contains("signin") || hay.contains("sign-in") || hay.contains("auth") || has_pw {
            "login".into()
        } else if hay.contains("search") || hay.contains("query") || f.fields.iter().any(|(n, _)| n == "q") {
            "search".into()
        } else { "other".into() };
        out.push(f);
    }
    out
}

/// Run the probe. Never panics; on total failure returns a Probe with a note.
/// Probe a target after checking it against the engagement's boundary.
///
/// This is the harness's own network chokepoint: it is the one place the
/// harness itself sends requests, so the guard runs here rather than trusting
/// the caller. An out-of-scope target yields an empty probe with a note, not a
/// request.
/// Apply a resolved credential to a probe request. Probe baselines are anonymous
/// by default; when the operator's auth is a vault slot the caller resolves it
/// once and every request here carries it, so the baseline reflects the
/// authenticated surface rather than the login page.
fn with_auth(rb: reqwest::RequestBuilder, auth: Option<(&str, &str)>) -> reqwest::RequestBuilder {
    match auth {
        Some((k, v)) => rb.header(k, v),
        None => rb,
    }
}

pub async fn probe_in_scope(target: &str, policy: &crate::scope::ScopePolicy) -> Probe {
    probe_in_scope_auth(target, policy, None).await
}

/// As `probe_in_scope`, with a resolved credential attached to every request.
pub async fn probe_in_scope_auth(
    target: &str,
    policy: &crate::scope::ScopePolicy,
    auth: Option<(&str, &str)>,
) -> Probe {
    let d = policy.check(target, crate::scope::Action::Probe);
    if !d.allowed() {
        let mut p = Probe::default();
        p.notes.push(format!("scope guard blocked the probe: {}", d.reason()));
        return p;
    }
    let policy = std::sync::Arc::new(policy.clone());
    if let crate::scope::Decision::Warn(w) = d {
        let mut p = probe_auth_with_policy(target, auth, Some(policy)).await;
        p.notes.push(format!("scope guard: {w}"));
        return p;
    }
    probe_auth_with_policy(target, auth, Some(policy)).await
}

pub async fn probe(target: &str) -> Probe {
    probe_auth(target, None).await
}

pub async fn probe_auth(target: &str, auth: Option<(&str, &str)>) -> Probe {
    probe_auth_with_policy(target, auth, None).await
}

/// As `probe_auth`, but redirects are judged by `policy`. `probe_in_scope_auth`
/// uses this: the scope check on the first request is not enough when the target
/// can hand back a 302 to somewhere else.
pub async fn probe_auth_with_policy(
    target: &str,
    auth: Option<(&str, &str)>,
    policy: Option<std::sync::Arc<crate::scope::ScopePolicy>>,
) -> Probe {
    let mut p = Probe { url: target.to_string(), ..Default::default() };
    let c = client_for(policy);

    let resp = match with_auth(c.get(target), auth).send().await {
        Ok(r) => r,
        Err(e) => { p.notes.push(format!("initial GET failed: {e}")); return p; }
    };
    p.final_url = resp.url().to_string();
    p.redirected = p.final_url.trim_end_matches('/') != target.trim_end_matches('/');
    p.status = resp.status().as_u16();
    let h = resp.headers().clone();
    p.server = hget(&h, "server");
    p.powered_by = hget(&h, "x-powered-by");
    p.content_type = hget(&h, "content-type");

    // Security headers.
    let mut sec = SecHeaders::default();
    sec.hsts = h.contains_key("strict-transport-security");
    sec.csp = h.contains_key("content-security-policy");
    sec.x_frame_options = h.contains_key("x-frame-options");
    sec.x_content_type_options = h.contains_key("x-content-type-options");
    sec.referrer_policy = h.contains_key("referrer-policy");
    sec.permissions_policy = h.contains_key("permissions-policy");
    sec.present = [sec.hsts, sec.csp, sec.x_frame_options, sec.x_content_type_options, sec.referrer_policy, sec.permissions_policy]
        .iter().filter(|x| **x).count() as u8;
    p.security_headers = sec;

    // Cookie flags.
    for hv in h.get_all("set-cookie") {
        if let Ok(s) = hv.to_str() {
            let name = s.split('=').next().unwrap_or("").trim().to_string();
            let low = s.to_lowercase();
            let same = if low.contains("samesite=strict") { "Strict" }
                else if low.contains("samesite=lax") { "Lax" }
                else if low.contains("samesite=none") { "None" } else { "(none)" };
            p.cookies.push(CookieFlags {
                name, http_only: low.contains("httponly"), secure: low.contains("secure"),
                same_site: same.to_string(),
            });
        }
    }

    // Body-derived facts (bounded).
    let body = resp.text().await.unwrap_or_default();
    let body = crate::replay::truncate_str(&body, 400_000).to_string();
    if let Some(t) = between(&body, "<title>", "</title>") {
        p.title = t.trim().chars().take(120).collect();
    }
    p.forms = body.matches("<form").count();
    p.form_details = parse_forms(&body);
    p.brand = extract_brand(&body);
    // linked scripts (src="...")
    for cap in body.split("<script").skip(1) {
        if let Some(src) = between(cap, "src=\"", "\"").or_else(|| between(cap, "src='", "'")) {
            if !src.is_empty() && p.scripts.len() < 40 && !p.scripts.iter().any(|x| x == src) {
                p.scripts.push(src.to_string());
            }
        }
    }
    // Tech hints (headers + body keywords).
    let hay = format!("{} {} {} {}", p.server, p.powered_by, p.content_type, body.chars().take(30_000).collect::<String>()).to_lowercase();
    for (needle, tech) in [
        ("wp-content", "WordPress"), ("/wp-json", "WordPress"), ("drupal", "Drupal"), ("joomla", "Joomla"),
        ("x-drupal", "Drupal"), ("laravel_session", "Laravel"), ("csrftoken", "Django"), ("__next", "Next.js"),
        ("react", "React"), ("vue", "Vue"), ("nginx", "nginx"), ("apache", "Apache"),
        ("microsoft-iis", "IIS"), ("express", "Express"), ("phpsessid", "PHP"), ("jsessionid", "Java"),
        ("cloudflare", "Cloudflare"), ("swagger", "Swagger/OpenAPI"), ("graphql", "GraphQL"),
        // SPA / framework markers (Juice Shop = Angular <app-root>).
        ("<app-root", "Angular"), ("ng-version", "Angular"), ("angular", "Angular"),
        ("data-reactroot", "React"), ("id=\"root\"", "SPA"), ("id=\"app\"", "SPA"),
        ("polyfills", "SPA"), ("runtime.", "SPA"),
    ] {
        if hay.contains(needle) && !p.tech.iter().any(|t| t == tech) { p.tech.push(tech.to_string()); }
    }
    // Heuristic: a nearly-empty body with several linked scripts is a JS SPA
    // (curl sees the shell only — the browser is required to render it).
    let text_len = body.chars().filter(|c| !c.is_whitespace()).count();
    if p.scripts.len() >= 2 && text_len < 3000 && !p.tech.iter().any(|t| t == "SPA") {
        p.tech.push("SPA".to_string());
    }
    if p.tech.iter().any(|t| t == "SPA" || t == "Angular" || t == "React" || t == "Vue") {
        p.notes.push("JS-rendered SPA — curl sees the shell only; use the browser (MCP/Playwright) to render, enumerate routes, and discover the API.".to_string());
    }

    // CORS reflection probe.
    if let Ok(r2) = with_auth(c.get(target).header("Origin", "https://evil.neurosploit.test"), auth).send().await {
        let acao = hget(r2.headers(), "access-control-allow-origin");
        let acac = hget(r2.headers(), "access-control-allow-credentials");
        p.cors.wildcard = acao.trim() == "*";
        p.cors.reflects_origin = acao.contains("evil.neurosploit.test");
        p.cors.allow_credentials = acac.trim().eq_ignore_ascii_case("true");
    }

    // 404 baseline (soft-404 detection).
    let base = format!("{}/nrsplt_baseline_404_check_9x7", target.trim_end_matches('/'));
    if let Ok(rb) = with_auth(c.get(&base), auth).send().await {
        p.baseline_404_status = rb.status().as_u16();
        p.baseline_404_len = rb.text().await.unwrap_or_default().len();
    }

    // A few high-signal paths (kept small to stay fast).
    for path in ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/.git/config", "/.env"] {
        let u = format!("{}{}", target.trim_end_matches('/'), path);
        if let Ok(rp) = with_auth(c.get(&u), auth).send().await {
            let st = rp.status().as_u16();
            let len = rp.text().await.unwrap_or_default().len();
            // only report if it looks like a real hit (200 and unlike the 404 baseline)
            if st == 200 && !(st == p.baseline_404_status && len == p.baseline_404_len) {
                p.interesting_paths.push(PathHit { path: path.to_string(), status: st, len });
            }
        }
    }
    p
}

/// Pretty-JSON of the probe for injection into recon context.
pub fn probe_json(p: &Probe) -> String {
    serde_json::to_string_pretty(p).unwrap_or_default()
}

/// One-line human summary for the live feed.
pub fn probe_summary(p: &Probe) -> String {
    format!(
        "probe: HTTP {} {}{} · {}{} · sec-headers {}/6 · {} cookie(s) · {} script(s){}{}{}",
        p.status,
        if p.server.is_empty() { "".into() } else { format!("{} ", p.server) },
        if p.tech.is_empty() { "".to_string() } else { format!("[{}]", p.tech.join(",")) },
        if p.redirected { "→ " } else { "" },
        if p.redirected { p.final_url.clone() } else { String::new() },
        p.security_headers.present,
        p.cookies.len(),
        p.scripts.len(),
        {
            let kinds: Vec<&str> = p.form_details.iter().map(|f| f.kind.as_str()).filter(|k| *k == "register" || *k == "login").collect();
            if kinds.is_empty() { String::new() } else { format!(" · forms: {}", kinds.join(",")) }
        },
        if p.cors.reflects_origin { " · CORS reflects origin!" } else { "" },
        if p.interesting_paths.is_empty() { String::new() } else { format!(" · hits: {}", p.interesting_paths.iter().map(|h| h.path.clone()).collect::<Vec<_>>().join(",")) },
    )
}

#[cfg(test)]
mod tests {
    use super::{parse_forms, brand_after};

    #[test]
    fn parses_register_form_fields_and_kind() {
        let html = r#"<html><body>
          <form action="/api/register" method="post">
            <input type="text" name="username">
            <input type="email" name="email">
            <input type="password" name="password">
            <input type="password" name="confirmPassword">
            <input type="hidden" name="csrf_token" value="abc">
            <button>Sign up</button>
          </form>
          <form action="/search" method="get"><input name="q"></form>
        </body></html>"#;
        let forms = parse_forms(html);
        assert_eq!(forms.len(), 2);
        let reg = &forms[0];
        assert_eq!(reg.action, "/api/register");
        assert_eq!(reg.method, "post");
        assert_eq!(reg.kind, "register");
        assert!(reg.has_csrf, "hidden csrf_token should be detected");
        assert!(reg.fields.iter().any(|(n, t)| n == "password" && t == "password"));
        assert_eq!(forms[1].kind, "search");
    }

    #[test]
    fn login_form_detected_by_password() {
        let html = r#"<form action="/login"><input name="user"><input type="password" name="pw"></form>"#;
        let f = parse_forms(html);
        assert_eq!(f[0].kind, "login");
    }

    /// `to_lowercase` can change a string's byte length ('İ' → 2 bytes, 'ẞ' → 3),
    /// so an offset found in the lowercased copy does not address the same
    /// position in the original. A target that ships such a page used to panic
    /// the probe on `&body[i..]`.
    #[test]
    fn brand_survives_a_lowercase_length_change() {
        // 400 'İ' (2 bytes lowercased each) before the marker: the lowercased
        // index is ~400 bytes past the same position in the original.
        let body = format!("{}<meta property=\"og:site_name\" content=\"Acme\">", "İ".repeat(400));
        assert_eq!(brand_after(&body), "Acme");
    }

    #[test]
    fn brand_reads_ordinary_markup() {
        let body = r#"<meta property="og:site_name" content="Example Corp">"#;
        assert_eq!(brand_after(body), "Example Corp");
    }

    #[test]
    fn brand_returns_empty_when_nothing_matches() {
        assert_eq!(brand_after("<html><body>nothing here</body></html>"), "");
    }

    #[test]
    fn brand_reads_a_capitalised_copyright_notice() {
        // HEAD matched "copyright" against the lowercased body, so these were
        // detected before the offset fix. A case-sensitive search silently
        // regressed them. The marker word itself is NOT stripped by the
        // pre-existing cleanup (HEAD yields "Copyright Acme Corp"), so these
        // assert detection + year removal, not a prettier name.
        assert_eq!(brand_after("<p>Copyright 2026 Acme Corp</p>"), "Copyright Acme Corp");
        assert_eq!(brand_after("<footer>COPYRIGHT 2026 Acme Corp</footer>"), "COPYRIGHT Acme Corp");
        assert_eq!(brand_after("<p>copyright 2026 Acme Corp</p>"), "copyright Acme Corp");
    }

    /// Uppercase `CONTENT=` was never supported — HEAD returns "" for it too,
    /// because the delimiter search is case-sensitive. Recorded so the limit is
    /// visible and the behaviour cannot drift silently in either direction.
    #[test]
    fn brand_uppercase_content_attribute_is_unsupported() {
        let body = r#"<META PROPERTY="OG:SITE_NAME" CONTENT="Acme Corp">"#;
        assert_eq!(brand_after(body), "");
        // Mixed case: key uppercase, delimiter lowercase — the mirror finds the
        // key and the value keeps its original casing.
        let mixed = r#"<META PROPERTY="OG:SITE_NAME" content="Acme Corp">"#;
        assert_eq!(brand_after(mixed), "Acme Corp");
    }

    #[test]
    fn brand_reads_a_capitalised_copyright_after_a_length_changing_prefix() {
        // Both defects at once: expanding-lowercase prefix AND capitalised marker.
        let body = format!("{}<p>Copyright 2026 Acme Corp</p>", "İ".repeat(200));
        assert_eq!(brand_after(&body), "Copyright Acme Corp");
    }

    #[test]
    fn brand_reads_a_copyright_notice_past_a_length_changing_prefix() {
        let body = format!("{}<p>&copy; 2026 Acme Widgets</p>", "ẞ".repeat(300));
        assert_eq!(brand_after(&body), "Acme Widgets");
    }
}
#[cfg(test)]
mod redirect_scope_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Criterion 5. The redirect target is IN SCOPE by name (`localhost`), so the
    /// scope check alone would follow it; only resolution shows that the name is
    /// loopback.
    ///
    /// The canary counts only requests for the redirect's own path: a bare accept
    /// count is not evidence, because this environment has a scanner that
    /// connects to fresh loopback listeners (the SEC-008 accept-race lesson).
    #[tokio::test]
    async fn a_302_to_an_in_scope_hostname_that_resolves_to_loopback_is_not_followed() {
        let redirected = Arc::new(AtomicUsize::new(0));
        let other = Arc::new(AtomicUsize::new(0));

        let canary = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let canary_port = canary.local_addr().unwrap().port();
        let (rd, ot) = (redirected.clone(), other.clone());
        tokio::spawn(async move {
            for _ in 0..8 {
                match tokio::time::timeout(std::time::Duration::from_secs(3), canary.accept()).await {
                    Ok(Ok((mut s, _))) => {
                        let mut b = [0u8; 2048];
                        let n = s.read(&mut b).await.unwrap_or(0);
                        let head = String::from_utf8_lossy(&b[..n]).to_lowercase();
                        if head.contains("/moved") {
                            rd.fetch_add(1, Ordering::SeqCst);
                        } else {
                            ot.fetch_add(1, Ordering::SeqCst);
                        }
                        let _ = s
                            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: close\r\n\r\nHIT!!")
                            .await;
                    }
                    _ => break,
                }
            }
        });

        let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_port = origin.local_addr().unwrap().port();
        tokio::spawn(async move {
            // Answer every request on the origin: the probe makes more than one
            // (Origin-header check, 404 baseline), and a single accept would make
            // this test depend on which request won.
            for _ in 0..8 {
                match tokio::time::timeout(std::time::Duration::from_secs(3), origin.accept()).await {
                    Ok(Ok((mut s, _))) => {
                        let mut b = [0u8; 2048];
                        let _ = s.read(&mut b).await;
                        let resp = format!(
                            "HTTP/1.1 302 Found\r\nlocation: http://localhost:{canary_port}/moved\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                        );
                        let _ = s.write_all(resp.as_bytes()).await;
                    }
                    _ => break,
                }
            }
        });

        let mut policy = crate::scope::ScopePolicy::for_target(&format!("http://127.0.0.1:{origin_port}/"));
        // Authorized by name, which is the trap: scope alone says yes.
        policy
            .hard
            .push(crate::scope::Pattern::parse("localhost").expect("pattern"));

        let p = probe_in_scope_auth(&format!("http://127.0.0.1:{origin_port}/"), &policy, None).await;
        assert_eq!(p.status, 302, "the redirect must come back as data, notes: {:?}", p.notes);

        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        assert_eq!(
            redirected.load(Ordering::SeqCst),
            0,
            "the client followed the redirect: {} request(s) for /moved reached the canary ({} unrelated connection(s) also seen)",
            redirected.load(Ordering::SeqCst),
            other.load(Ordering::SeqCst)
        );
    }
}
