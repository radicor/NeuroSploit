//! Intercepting proxy — owning the request stream, and plugging into the tools
//! that already do.
//!
//! Two capabilities the harness lacked, and one reason they belong together.
//!
//! An operator's toolchain has a proxy in it — Burp, Caido, ZAP, mitmproxy —
//! and the engagement should flow through it, so the human can watch, replay,
//! and pick up where the agent left off. That is the *tool* side: point the
//! harness at `127.0.0.1:8080` and everything it does appears in Burp.
//!
//! But even with no tool running, the harness benefits from seeing its own
//! traffic as a stream rather than as isolated requests: passive discovery
//! (every host, cookie and header that went by), and a faithful record for
//! replay. That is the *own interceptor*: a recording forward proxy the harness
//! runs itself.
//!
//! They compose. The own interceptor records, then forwards upstream to the
//! tool — so the operator gets Burp *and* the harness gets its passive log,
//! from one configuration:
//!
//! ```text
//!   harness + agent curls ──→ own interceptor ──→ [Burp/Caido/mitmproxy] ──→ target
//!                                   │
//!                                   └── records every flow (passive discovery, replay)
//! ```
//!
//! ## Honest about TLS
//!
//! The own interceptor records plaintext HTTP in full. For HTTPS it tunnels
//! (CONNECT) and records the metadata it can see without breaking TLS — host,
//! timing, byte counts — but not the decrypted body. Decrypting HTTPS needs a
//! CA the client trusts, which Burp/Caido/mitmproxy already solved; so for full
//! HTTPS interception you **chain to one of them**, and this module makes that
//! one flag rather than a re-implementation of their certificate machinery.
//! Claiming to MITM TLS without a trusted CA would be a lie the operator finds
//! out about mid-engagement.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A known interception tool, with where it listens by default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tool {
    /// Burp Suite — default proxy 127.0.0.1:8080.
    Burp,
    /// Caido — default 127.0.0.1:8080 (shares the convention).
    Caido,
    /// OWASP ZAP — default 127.0.0.1:8080, sometimes :8081.
    Zap,
    /// mitmproxy / mitmdump — default 127.0.0.1:8080.
    Mitmproxy,
    /// Any HTTP proxy at an explicit address.
    Custom(String),
}

impl Tool {
    /// The proxy URL to forward to.
    pub fn proxy_url(&self) -> String {
        match self {
            Tool::Burp | Tool::Caido | Tool::Zap | Tool::Mitmproxy => "http://127.0.0.1:8080".into(),
            Tool::Custom(url) => {
                if url.contains("://") {
                    url.clone()
                } else {
                    format!("http://{url}")
                }
            }
        }
    }
    pub fn name(&self) -> String {
        match self {
            Tool::Burp => "Burp Suite".into(),
            Tool::Caido => "Caido".into(),
            Tool::Zap => "OWASP ZAP".into(),
            Tool::Mitmproxy => "mitmproxy".into(),
            Tool::Custom(u) => format!("proxy {u}"),
        }
    }
    pub fn parse(s: &str) -> Option<Tool> {
        Some(match s.trim().to_lowercase().as_str() {
            "burp" | "burpsuite" => Tool::Burp,
            "caido" => Tool::Caido,
            "zap" | "owasp-zap" => Tool::Zap,
            "mitm" | "mitmproxy" | "mitmdump" => Tool::Mitmproxy,
            "" | "none" | "off" => return None,
            other => Tool::Custom(other.to_string()),
        })
    }
    /// Is a proxy actually listening where this tool expects to be?
    ///
    /// Checked before a run commits to routing through it: an operator who
    /// typed `--intercept burp` but forgot to start Burp should be told, not
    /// have every request fail with a connection error three minutes in.
    pub async fn is_listening(&self) -> bool {
        let url = self.proxy_url();
        let hostport = url.split("://").nth(1).unwrap_or(&url).trim_end_matches('/');
        let addr: Option<SocketAddr> = hostport.to_socket_addrs_first();
        match addr {
            Some(a) => tokio::time::timeout(Duration::from_millis(600), tokio::net::TcpStream::connect(a)).await.map(|r| r.is_ok()).unwrap_or(false),
            None => false,
        }
    }
}

trait ToSocketAddrFirst {
    fn to_socket_addrs_first(&self) -> Option<SocketAddr>;
}
impl ToSocketAddrFirst for str {
    fn to_socket_addrs_first(&self) -> Option<SocketAddr> {
        use std::net::ToSocketAddrs;
        self.to_socket_addrs().ok().and_then(|mut it| it.next())
    }
}

/// One request/response the interceptor saw.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Flow {
    pub at: u64,
    pub method: String,
    pub url: String,
    pub status: u16,
    /// Bytes client→server (request) and server→client (response). For a
    /// tunnelled HTTPS connection this is all we can honestly report.
    pub req_bytes: usize,
    pub resp_bytes: usize,
    /// True when this was a CONNECT tunnel (TLS body not visible to us).
    #[serde(default)]
    pub tunnelled: bool,
    /// Response content-type, when seen in cleartext.
    #[serde(default)]
    pub content_type: String,
    /// True when the choke refused this destination instead of dialling it.
    /// A refused flow is evidence, so it is recorded like any other.
    #[serde(default)]
    pub denied: bool,
}

/// How the harness should route its traffic.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Run the harness's own recording interceptor.
    pub own_interceptor: bool,
    /// Where the own interceptor binds.
    pub bind: SocketAddr,
    /// Forward upstream to this tool after recording (full HTTPS interception).
    pub upstream: Option<Tool>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            own_interceptor: false,
            bind: "127.0.0.1:8899".parse().unwrap(),
            upstream: None,
        }
    }
}

impl ProxyConfig {
    /// Parse an operator spec.
    ///
    /// ```text
    ///   burp | caido | zap | mitmproxy      → route straight through the tool
    ///   own                                 → own interceptor only, no upstream
    ///   own@127.0.0.1:9000                  → own interceptor on a chosen bind
    ///   own+burp | own+caido | own+…        → own interceptor, recording, then the tool
    ///   http://127.0.0.1:8080               → an explicit upstream proxy
    /// ```
    pub fn parse(spec: &str) -> Result<ProxyConfig, String> {
        let s = spec.trim().to_lowercase();
        if s.is_empty() || s == "off" || s == "none" {
            return Ok(ProxyConfig::default());
        }
        if let Some(rest) = s.strip_prefix("own+") {
            let tool = Tool::parse(rest).ok_or_else(|| format!("unknown upstream tool `{rest}`"))?;
            return Ok(ProxyConfig { own_interceptor: true, upstream: Some(tool), ..Default::default() });
        }
        if let Some(rest) = s.strip_prefix("own@") {
            let bind: SocketAddr = rest
                .parse()
                .map_err(|_| format!("own@ needs host:port, got `{rest}`"))?;
            return Ok(ProxyConfig { own_interceptor: true, bind, upstream: None, ..Default::default() });
        }
        if s == "own" {
            return Ok(ProxyConfig { own_interceptor: true, upstream: None, ..Default::default() });
        }
        let tool = Tool::parse(&s).ok_or_else(|| format!("unrecognised intercept spec `{spec}`"))?;
        // A bare tool routes straight through it — no own interceptor, because
        // the tool already records. The own interceptor is for adding recording
        // where there is none, or a passive log alongside the tool (own+tool).
        Ok(ProxyConfig { own_interceptor: false, upstream: Some(tool), ..Default::default() })
    }

    /// The proxy URL the HTTP client and child processes should use.
    ///
    /// When the own interceptor is on, that is its address (it forwards upstream
    /// itself). Otherwise it is the tool's address directly. `None` means no
    /// proxying at all.
    pub fn client_proxy_url(&self) -> Option<String> {
        if self.own_interceptor {
            Some(format!("http://{}", self.bind))
        } else {
            self.upstream.as_ref().map(|t| t.proxy_url())
        }
    }

    /// Environment for child processes (curl, tool commands) so they route the
    /// same way the harness does.
    pub fn env(&self) -> Vec<(String, String)> {
        match self.client_proxy_url() {
            Some(p) => ProxyConfig::env_for(&p),
            None => Vec::new(),
        }
    }

    /// The proxy environment for a concrete URL. Separate from `env()` because a
    /// choke bound to port 0 learns its address only after `listen`.
    pub fn env_for(url: &str) -> Vec<(String, String)> {
        vec![
            ("HTTP_PROXY".into(), url.to_string()),
            ("HTTPS_PROXY".into(), url.to_string()),
            ("ALL_PROXY".into(), url.to_string()),
            ("http_proxy".into(), url.to_string()),
            ("https_proxy".into(), url.to_string()),
            ("all_proxy".into(), url.to_string()),
        ]
    }

    /// `NO_PROXY` value: loopback always, plus whatever the run must reach
    /// directly (provider APIs). Never a wildcard — that would disable the
    /// choke for every host while looking like a configuration.
    pub fn no_proxy_value(extra: &[String]) -> String {
        let mut hosts: Vec<String> = vec![
            "127.0.0.1".into(),
            "localhost".into(),
            "::1".into(),
        ];
        for h in extra {
            let h = h.trim().to_lowercase();
            if !h.is_empty() && h != "*" && !hosts.contains(&h) {
                hosts.push(h);
            }
        }
        hosts.join(",")
    }

    /// The full child environment: proxy vars plus a `NO_PROXY` that keeps
    /// loopback and the named providers off the choke.
    pub fn env_with_no_proxy(url: &str, extra: &[String]) -> Vec<(String, String)> {
        let mut v = ProxyConfig::env_for(url);
        let np = ProxyConfig::no_proxy_value(extra);
        v.push(("NO_PROXY".into(), np.clone()));
        v.push(("no_proxy".into(), np));
        v
    }

    pub fn summary(&self) -> String {
        match (self.own_interceptor, &self.upstream) {
            (true, Some(t)) => format!("own interceptor on {} → {}", self.bind, t.name()),
            (true, None) => format!("own interceptor on {} (HTTP recorded, HTTPS tunnelled)", self.bind),
            (false, Some(t)) => format!("routing through {}", t.name()),
            (false, None) => "direct (no interception)".into(),
        }
    }
}

/// Why the choke refused a destination. Each variant maps to one code, so a
/// refusal is machine-readable and a test can name the branch that refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    OutOfScope,
    PrivateAddress,
    RebindDetected,
}

impl DenyReason {
    pub fn code(self) -> &'static str {
        match self {
            DenyReason::OutOfScope => "OUT_OF_SCOPE",
            DenyReason::PrivateAddress => "PRIVATE_ADDRESS",
            DenyReason::RebindDetected => "REBIND_DETECTED",
        }
    }
}

/// Hosts the scope policy does not govern: the run's own out-of-band listener
/// (which is internal by design) and provider APIs the harness itself calls.
#[derive(Debug, Clone, Default)]
pub struct ExtraAllow {
    /// Suffixes such as ".oob.example.com" or the bare apex.
    pub oob_suffixes: Vec<String>,
    pub passthrough_hosts: Vec<String>,
}

impl ExtraAllow {
    pub fn allows(&self, host: &str) -> bool {
        self.passthrough_hosts
            .iter()
            .any(|h| h.eq_ignore_ascii_case(host))
            || self.oob_suffixes.iter().any(|s| {
                let suffix = s.trim_start_matches('*');
                host.ends_with(suffix) || host == suffix.trim_start_matches('.')
            })
    }
}

/// Split `host:port` (CONNECT authority), tolerating `[v6]:port`.
fn split_host_port(s: &str) -> (String, u16) {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((h, p)) = rest.split_once("]:") {
            return (h.to_string(), p.parse().unwrap_or(443));
        }
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (h.to_string(), p.parse().unwrap_or(443))
        }
        _ => (s.to_string(), 443),
    }
}

/// Host and port from an absolute-form URL (`http://host:port/path`).
fn host_port_from_url(url: &str) -> (String, u16) {
    let after = url.split("://").nth(1).unwrap_or(url);
    let authority = after.split(['/', '?', '#']).next().unwrap_or(after);
    let (host, port) = split_host_port(authority);
    (host, if port == 443 { 80 } else { port })
}

/// The running own interceptor: a recording forward proxy.
#[derive(Clone)]
pub struct Interceptor {
    upstream: Option<String>,
    flows: Arc<Mutex<Vec<Flow>>>,
    jsonl: Option<String>,
    /// The run's effective policy. `None` means no policy was attached (yolo, or
    /// a caller using the interceptor purely as a recorder).
    policy: Option<Arc<crate::scope::ScopePolicy>>,
    rebind: Option<Arc<Mutex<crate::netguard::RebindGuard>>>,
    extras: ExtraAllow,
    /// Seam so a test can drive admission without DNS; production uses
    /// `netguard::resolve`.
    resolver: Arc<dyn Fn(&str) -> Vec<std::net::IpAddr> + Send + Sync>,
}

impl Interceptor {
    pub fn new(upstream: Option<String>) -> Self {
        Interceptor {
            upstream,
            flows: Arc::new(Mutex::new(Vec::new())),
            jsonl: None,
            policy: None,
            rebind: None,
            extras: ExtraAllow::default(),
            resolver: Arc::new(crate::netguard::resolve),
        }
    }

    /// Attach the run's effective scope. Without this the interceptor records
    /// but admits anything, which is only correct for `yolo`.
    pub fn with_policy(mut self, policy: Arc<crate::scope::ScopePolicy>) -> Self {
        self.policy = Some(policy);
        self
    }

    pub fn with_rebind_guard(mut self, guard: Arc<Mutex<crate::netguard::RebindGuard>>) -> Self {
        self.rebind = Some(guard);
        self
    }

    pub fn with_extras(mut self, extras: ExtraAllow) -> Self {
        self.extras = extras;
        self
    }

    pub fn with_resolver(
        mut self,
        resolver: Arc<dyn Fn(&str) -> Vec<std::net::IpAddr> + Send + Sync>,
    ) -> Self {
        self.resolver = resolver;
        self
    }

    /// Decide whether this CONNECT/absolute-form target may be dialled, and
    /// which addresses may be dialled. Every address returned is one this
    /// function vetted, so the dial must use them rather than re-resolving.
    pub fn admit(&self, host: &str, port: u16) -> Result<Vec<std::net::IpAddr>, DenyReason> {
        use crate::netguard::{is_private, normalize_host, parse_ip_any};
        let host = normalize_host(host);
        let extra = self.extras.allows(&host);
        let hard = self.hard_allows(&host);

        // No policy and no guard means this interceptor is a recorder (yolo, or
        // a caller using it to watch traffic). The policy is what makes it a
        // choke; pretending otherwise would refuse the recorder's own harness.
        if self.policy.is_none() && self.rebind.is_none() {
            if let Some(ip) = parse_ip_any(&host) {
                return Ok(vec![ip]);
            }
            let resolved = (self.resolver)(&host);
            return if resolved.is_empty() {
                Err(DenyReason::OutOfScope)
            } else {
                Ok(resolved)
            };
        }

        // A literal (or obfuscated) address needs no resolution, and the reason
        // it is refused should say "private", not "out of scope" — the operator
        // needs to know an internal pivot was attempted.
        if let Some(ip) = parse_ip_any(&host) {
            if is_private(&ip) && !hard && !extra {
                return Err(DenyReason::PrivateAddress);
            }
            if !extra && !self.in_scope(&host, port) {
                return Err(DenyReason::OutOfScope);
            }
            return Ok(vec![ip]);
        }

        if !extra && !self.in_scope(&host, port) {
            return Err(DenyReason::OutOfScope);
        }
        let resolved = (self.resolver)(&host);
        if resolved.is_empty() {
            return Err(DenyReason::OutOfScope);
        }
        // The guard knows whether it has seen this name before, so it decides
        // first: a new private address on a re-resolution is a rebind, not an
        // ordinary private target, and the two codes must not collapse.
        if let Some(g) = &self.rebind {
            let seen = g.lock().map(|g| g.seen(&host)).unwrap_or(false);
            let mut g = g.lock().map_err(|_| DenyReason::RebindDetected)?;
            return match g.check_with(&host, resolved.clone()) {
                Ok(pinned) => Ok(pinned),
                // A name that has resolved before and now gains a private
                // address is a rebind whatever the scope says about it.
                Err(_) if seen => Err(DenyReason::RebindDetected),
                // First sight of an internal name the operator explicitly
                // authorized (hard scope or extras) is an intended target.
                Err(_) if hard || extra => Ok(resolved),
                Err(_) => Err(DenyReason::PrivateAddress),
            };
        }
        if resolved.iter().any(is_private) && !hard && !extra {
            return Err(DenyReason::PrivateAddress);
        }
        Ok(resolved)
    }

    fn in_scope(&self, host: &str, port: u16) -> bool {
        match &self.policy {
            Some(p) => p.check_connect(host, port).allowed(),
            None => true,
        }
    }

    /// A hard entry is an explicit authorization of that host, which is what
    /// lets an internal literal through when the operator named it.
    fn hard_allows(&self, host: &str) -> bool {
        match &self.policy {
            Some(p) => p
                .hard
                .iter()
                .any(|pat| pat.matches(&format!("https://{host}/"))),
            None => false,
        }
    }

    /// Also append every flow to a JSONL file, so a run's traffic survives it.
    pub fn logging_to(mut self, path: impl Into<String>) -> Self {
        self.jsonl = Some(path.into());
        self
    }

    pub fn flows(&self) -> Vec<Flow> {
        self.flows.lock().map(|f| f.clone()).unwrap_or_default()
    }

    /// Distinct hosts seen — the passive-discovery product.
    pub fn hosts(&self) -> Vec<String> {
        let mut hs: Vec<String> = self
            .flows()
            .iter()
            .filter_map(|f| f.url.split("://").nth(1).map(|r| r.split('/').next().unwrap_or("").to_string()))
            .filter(|h| !h.is_empty())
            .collect();
        hs.sort();
        hs.dedup();
        hs
    }

    fn record(&self, flow: Flow) {
        if let Some(path) = &self.jsonl {
            if let Ok(line) = serde_json::to_string(&flow) {
                use std::io::Write;
                if let Ok(mut fh) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
                    let _ = writeln!(fh, "{line}");
                }
            }
        }
        if let Ok(mut f) = self.flows.lock() {
            if f.len() >= 20_000 {
                f.remove(0);
            }
            f.push(flow);
        }
    }

    /// Start listening. Returns the address actually bound — a caller that asked
    /// for port 0 needs it to export the right proxy URL — and serving continues
    /// in the background.
    pub async fn listen(&self, bind: SocketAddr) -> std::io::Result<SocketAddr> {
        let listener = tokio::net::TcpListener::bind(bind).await?;
        let addr = listener.local_addr()?;
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else { continue };
                let me = me.clone();
                tokio::spawn(async move {
                    let _ = me.serve(sock).await;
                });
            }
        });
        Ok(addr)
    }

    /// Refuse an admitted-against destination. The 403 is for the client; the
    /// recorded flow is for the operator, so a refusal is evidence rather than
    /// a silent drop.
    async fn refuse(&self, mut client: tokio::net::TcpStream, target: &str, method: &str, reason: DenyReason) -> std::io::Result<()> {
        let body = format!("{} refused: {target}", reason.code());
        let _ = client
            .write_all(
                format!(
                    "HTTP/1.1 403 Forbidden\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            )
            .await;
        self.record(Flow {
            at: now(),
            method: method.to_uppercase(),
            url: target.to_string(),
            status: 403,
            req_bytes: 0,
            resp_bytes: body.len(),
            tunnelled: false,
            content_type: "text/plain".into(),
            denied: true,
        });
        Ok(())
    }

    async fn serve(&self, mut client: tokio::net::TcpStream) -> std::io::Result<()> {
        // Read the request head (up to the blank line). Proxies see the head
        // before the body, and the first line tells us CONNECT vs absolute-URI.
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while head.len() < 32 * 1024 {
            let n = client.read(&mut byte).await?;
            if n == 0 {
                break;
            }
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let head_str = String::from_utf8_lossy(&head).to_string();
        let first = head_str.lines().next().unwrap_or("").to_string();
        let mut parts = first.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let target = parts.next().unwrap_or("").to_string();

        if method.eq_ignore_ascii_case("CONNECT") {
            let (host, port) = split_host_port(&target);
            match self.admit(&host, port) {
                Ok(pinned) => self.tunnel(client, &target, &pinned).await,
                Err(reason) => self.refuse(client, &target, &method, reason).await,
            }
        } else if target.starts_with("http://") {
            let (host, port) = host_port_from_url(&target);
            match self.admit(&host, port) {
                Ok(pinned) => self.forward_http(client, &method, &target, &head_str, &pinned).await,
                Err(reason) => self.refuse(client, &target, &method, reason).await,
            }
        } else {
            let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\nconnection: close\r\n\r\nthis proxy handles absolute-form HTTP and CONNECT").await;
            Ok(())
        }
    }

    /// Plain HTTP: forward via reqwest (honouring an upstream proxy), record
    /// the full flow, and write the response back to the client.
    async fn forward_http(&self, mut client: tokio::net::TcpStream, method: &str, url: &str, head: &str, pinned: &[std::net::IpAddr]) -> std::io::Result<()> {
        let (host, port) = host_port_from_url(url);
        let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(30)).redirect(reqwest::redirect::Policy::none());
        // Dial the address `admit` vetted, not a fresh resolution: a second
        // lookup is exactly the rebinding window the guard just closed.
        if let Some(ip) = pinned.first() {
            builder = builder.resolve(&host, std::net::SocketAddr::new(*ip, port));
        }
        if let Some(up) = &self.upstream {
            if let Ok(px) = reqwest::Proxy::all(up) {
                builder = builder.proxy(px);
            }
        }
        let client_http = builder.build().unwrap_or_default();
        let m = reqwest::Method::from_bytes(method.to_uppercase().as_bytes()).unwrap_or(reqwest::Method::GET);
        let mut rb = client_http.request(m, url);
        let mut req_bytes = head.len();
        for line in head.lines().skip(1) {
            if let Some((k, v)) = line.split_once(':') {
                let k = k.trim();
                // Hop-by-hop headers a proxy must not forward.
                if !matches!(k.to_lowercase().as_str(), "proxy-connection" | "connection" | "host") {
                    rb = rb.header(k, v.trim());
                }
            }
        }

        let now = now();
        match rb.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let ct = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                let mut out = format!("HTTP/1.1 {status} {}\r\n", resp.status().canonical_reason().unwrap_or(""));
                for (k, v) in resp.headers().iter() {
                    if !matches!(k.as_str(), "transfer-encoding" | "connection") {
                        out.push_str(&format!("{}: {}\r\n", k, v.to_str().unwrap_or("")));
                    }
                }
                let body = resp.bytes().await.unwrap_or_default();
                out.push_str(&format!("content-length: {}\r\nconnection: close\r\n\r\n", body.len()));
                client.write_all(out.as_bytes()).await?;
                client.write_all(&body).await?;
                self.record(Flow {
                    at: now,
                    method: method.to_uppercase(),
                    url: url.to_string(),
                    status,
                    req_bytes,
                    resp_bytes: body.len(),
                    tunnelled: false,
                    content_type: ct,
                    denied: false,
                });
            }
            Err(e) => {
                req_bytes += 0;
                let _ = client.write_all(format!("HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\n\r\n{e}").as_bytes()).await;
                self.record(Flow { at: now, method: method.to_uppercase(), url: url.to_string(), status: 502, req_bytes, resp_bytes: 0, tunnelled: false, content_type: String::new(), denied: false });
            }
        }
        Ok(())
    }

    /// HTTPS: open a tunnel, record what we can see without breaking TLS.
    ///
    /// With an upstream tool, the CONNECT is handed to it so the tool does the
    /// full interception; without one, we connect straight to the target and
    /// relay bytes, recording host, timing and byte counts. We do NOT pretend
    /// to see the plaintext.
    async fn tunnel(&self, mut client: tokio::net::TcpStream, target: &str, pinned: &[std::net::IpAddr]) -> std::io::Result<()> {
        let now = now();
        // Connect to the upstream tool if configured, else to the target.
        let (mut server, via_upstream) = match &self.upstream {
            Some(up) => {
                let hostport = up.split("://").nth(1).unwrap_or(up).trim_end_matches('/').to_string();
                match tokio::net::TcpStream::connect(&hostport).await {
                    Ok(mut s) => {
                        // Replay the CONNECT to the upstream proxy verbatim.
                        let _ = s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes()).await;
                        // Swallow the upstream's "200 Connection Established".
                        let mut buf = [0u8; 1024];
                        let _ = s.read(&mut buf).await;
                        (s, true)
                    }
                    Err(e) => {
                        let _ = client.write_all(format!("HTTP/1.1 502 Bad Gateway\r\n\r\nupstream proxy: {e}").as_bytes()).await;
                        return Ok(());
                    }
                }
            }
            None => {
                let (_, port) = split_host_port(target);
                let sa = match pinned.first() {
                    Some(ip) => std::net::SocketAddr::new(*ip, port),
                    None => return self.refuse(client, target, "CONNECT", DenyReason::OutOfScope).await,
                };
                match tokio::net::TcpStream::connect(sa).await {
                    Ok(s) => (s, false),
                    Err(e) => {
                        let _ = client.write_all(format!("HTTP/1.1 502 Bad Gateway\r\n\r\n{e}").as_bytes()).await;
                        return Ok(());
                    }
                }
            }
        };
        // Tell the client the tunnel is open (unless the upstream already did,
        // in which case we still must, since the client spoke to us).
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

        // Relay both directions, counting bytes. The bodies are TLS ciphertext;
        // we record the shape, not the content — honestly.
        let (mut cr, mut cw) = client.split();
        let (mut sr, mut sw) = server.split();
        let c2s = tokio::io::copy(&mut cr, &mut sw);
        let s2c = tokio::io::copy(&mut sr, &mut cw);
        let (up, down) = tokio::join!(c2s, s2c);
        let req_bytes = up.unwrap_or(0) as usize;
        let resp_bytes = down.unwrap_or(0) as usize;
        let _ = via_upstream;
        self.record(Flow {
            at: now,
            method: "CONNECT".into(),
            url: format!("https://{target}"),
            status: 200,
            req_bytes,
            resp_bytes,
            tunnelled: true,
            content_type: String::new(),
            denied: false,
        });
        Ok(())
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_specs_map_to_the_right_upstream() {
        assert_eq!(Tool::parse("burp"), Some(Tool::Burp));
        assert_eq!(Tool::parse("caido"), Some(Tool::Caido));
        assert_eq!(Tool::parse("mitmproxy"), Some(Tool::Mitmproxy));
        assert_eq!(Tool::parse("off"), None);
        assert_eq!(Tool::Burp.proxy_url(), "http://127.0.0.1:8080");
        assert_eq!(Tool::Custom("127.0.0.1:9000".into()).proxy_url(), "http://127.0.0.1:9000");
    }

    #[test]
    fn a_bare_tool_routes_through_it_without_the_own_interceptor() {
        let c = ProxyConfig::parse("burp").unwrap();
        assert!(!c.own_interceptor, "the tool already records — no need to double up");
        assert_eq!(c.upstream, Some(Tool::Burp));
        assert_eq!(c.client_proxy_url().as_deref(), Some("http://127.0.0.1:8080"));
    }

    #[test]
    fn own_plus_tool_records_then_forwards() {
        let c = ProxyConfig::parse("own+caido").unwrap();
        assert!(c.own_interceptor);
        assert_eq!(c.upstream, Some(Tool::Caido));
        // Clients point at the own interceptor, which forwards to the tool.
        assert_eq!(c.client_proxy_url(), Some(format!("http://{}", c.bind)));
    }

    #[test]
    fn own_alone_records_with_no_upstream() {
        let c = ProxyConfig::parse("own").unwrap();
        assert!(c.own_interceptor && c.upstream.is_none());
        assert!(c.summary().contains("HTTPS tunnelled"), "the summary is honest about not decrypting TLS");
    }

    #[test]
    fn off_means_direct() {
        let c = ProxyConfig::parse("").unwrap();
        assert!(c.client_proxy_url().is_none());
        assert!(c.env().is_empty());
    }

    #[test]
    fn child_env_covers_both_cases_of_the_variable() {
        let c = ProxyConfig::parse("burp").unwrap();
        let env = c.env();
        assert!(env.iter().any(|(k, _)| k == "HTTPS_PROXY"));
        assert!(env.iter().any(|(k, _)| k == "https_proxy"), "curl reads the lowercase one");
    }

    #[tokio::test]
    async fn the_own_interceptor_records_a_plain_http_flow() {
        // A tiny origin server the interceptor will forward to.
        let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = origin.accept().await {
                let mut b = [0u8; 1024];
                let _ = s.read(&mut b).await;
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 2\r\n\r\nhi").await;
            }
        });

        let interceptor = Interceptor::new(None);
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = tokio::net::TcpListener::bind(bind).await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let me = interceptor.clone();
        tokio::spawn(async move {
            if let Ok((sock, _)) = listener.accept().await {
                let _ = me.serve(sock).await;
            }
        });

        // Speak proxy protocol: absolute-form request line.
        let mut c = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let req = format!("GET http://{origin_addr}/x HTTP/1.1\r\nHost: {origin_addr}\r\n\r\n");
        c.write_all(req.as_bytes()).await.unwrap();
        let mut resp = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), c.read_to_end(&mut resp)).await;
        assert!(String::from_utf8_lossy(&resp).contains("hi"), "the interceptor relayed the origin's body");

        // Give the record a beat, then check the flow was captured.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let flows = interceptor.flows();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].status, 200);
        assert!(!flows[0].tunnelled);
        assert!(interceptor.hosts().iter().any(|h| h == &origin_addr.to_string()));
    }
}
#[cfg(test)]
mod admit_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn ip(s: &str) -> std::net::IpAddr {
        s.parse().unwrap()
    }

    fn scoped() -> Interceptor {
        Interceptor::new(None)
            .with_policy(Arc::new(crate::scope::ScopePolicy::for_target(
                "https://app.example.com",
            )))
            .with_resolver(Arc::new(|h: &str| match h {
                "app.example.com" => vec![ip("93.184.216.34")],
                _ => vec![ip("203.0.113.10")],
            }))
    }

    #[test]
    fn the_proxy_environment_names_every_variable_and_a_non_wildcard_no_proxy() {
        let env = ProxyConfig::env_for("http://127.0.0.1:9000");
        let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        for k in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            assert!(keys.contains(&k), "missing {k} in {keys:?}");
        }
        let np = ProxyConfig::no_proxy_value(&["api.anthropic.com".into(), "*".into()]);
        assert!(np.contains("127.0.0.1"), "{np}");
        assert!(np.contains("api.anthropic.com"), "{np}");
        assert!(!np.contains('*'), "no wildcard allowed: {np}");
        let full = ProxyConfig::env_with_no_proxy(
            "http://127.0.0.1:9000",
            &["api.anthropic.com".into()],
        );
        assert!(full
            .iter()
            .any(|(k, v)| k == "NO_PROXY" && v.contains("api.anthropic.com")));
    }

    #[test]
    fn the_admission_table() {
        let i = scoped();
        assert_eq!(
            i.admit("evil.test", 443).unwrap_err(),
            DenyReason::OutOfScope,
            "a host the scope never named must be refused"
        );
        assert_eq!(
            i.admit("127.0.0.1", 80).unwrap_err(),
            DenyReason::PrivateAddress,
            "loopback is refused even though the policy is silent about it"
        );
        assert_eq!(
            i.admit("2130706433", 80).unwrap_err(),
            DenyReason::PrivateAddress,
            "the decimal encoding is the same address and must not slip through"
        );
        assert_eq!(
            i.admit("app.example.com", 443).unwrap(),
            vec![ip("93.184.216.34")],
            "an in-scope name returns the pinned address"
        );
    }

    #[test]
    fn a_rebind_to_a_private_address_is_refused_with_its_own_code() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let i = Interceptor::new(None)
            .with_policy(Arc::new(crate::scope::ScopePolicy::for_target(
                "https://app.example.com",
            )))
            .with_rebind_guard(Arc::new(Mutex::new(crate::netguard::RebindGuard::new())))
            .with_resolver(Arc::new(move |_h: &str| {
                if c.fetch_add(1, Ordering::SeqCst) == 0 {
                    vec![ip("93.184.216.34")]
                } else {
                    vec![ip("93.184.216.34"), ip("127.0.0.1")]
                }
            }));
        assert_eq!(i.admit("app.example.com", 443).unwrap(), vec![ip("93.184.216.34")]);
        assert_eq!(
            i.admit("app.example.com", 443).unwrap_err(),
            DenyReason::RebindDetected,
            "a name that gains a private address on re-resolution is a rebind"
        );
    }

    #[test]
    fn out_of_band_and_passthrough_hosts_are_admitted_despite_being_internal() {
        let i = Interceptor::new(None)
            .with_policy(Arc::new(crate::scope::ScopePolicy::for_target(
                "https://app.example.com",
            )))
            .with_extras(ExtraAllow {
                oob_suffixes: vec![".oob.test".into()],
                passthrough_hosts: vec!["api.anthropic.com".into()],
            })
            .with_resolver(Arc::new(|_h: &str| vec![ip("127.0.0.1")]));
        assert_eq!(i.admit("abc.oob.test", 80).unwrap(), vec![ip("127.0.0.1")]);
        assert_eq!(i.admit("api.anthropic.com", 443).unwrap(), vec![ip("127.0.0.1")]);
        assert_eq!(
            i.admit("other.test", 443).unwrap_err(),
            DenyReason::OutOfScope,
            "the extras must not become a general allow"
        );
    }

    /// Criterion 7: drive the real listener with a raw request. `admit` is the
    /// table; this is the proof that the table is consulted on the wire, and
    /// that a refusal is recorded rather than silently dropped.
    #[tokio::test]
    async fn the_wire_refuses_an_out_of_scope_destination_and_records_it() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let i = Arc::new(scoped());
        let addr = i.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();

        let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        sock.write_all(b"GET http://evil.test/ HTTP/1.1\r\nHost: evil.test\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let _ = sock.read_to_end(&mut buf).await;
        let text = String::from_utf8_lossy(&buf).to_string();

        assert!(
            text.starts_with("HTTP/1.1 403"),
            "an out-of-scope request must be refused at the wire, got: {text}"
        );
        assert!(
            text.contains("OUT_OF_SCOPE"),
            "the body must name the branch that refused: {text}"
        );
        let denied = i.flows().into_iter().filter(|f| f.denied).count();
        assert_eq!(denied, 1, "the refusal must be recorded as evidence");
    }

    #[tokio::test]
    async fn the_wire_refuses_a_connect_to_loopback() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let i = Arc::new(scoped());
        let addr = i.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        sock.write_all(b"CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: 127.0.0.1:80\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let _ = sock.read_to_end(&mut buf).await;
        let text = String::from_utf8_lossy(&buf).to_string();
        assert!(text.starts_with("HTTP/1.1 403"), "got: {text}");
        assert!(
            text.contains("PRIVATE_ADDRESS"),
            "a loopback CONNECT must say why: {text}"
        );
    }
}
