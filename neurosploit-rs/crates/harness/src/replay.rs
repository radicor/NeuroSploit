//! Replay engine — the harness re-runs an interaction itself.
//!
//! The validators in [`crate::validation`] decide from recorded artifacts, and
//! the weakest link in that chain is who recorded them. An agent reporting "the
//! payload returned a 500" is still an agent's account of what happened. Replay
//! closes that gap for the part that matters most in practice: **reproducibility**.
//! SQL injection is confirmed by a difference that repeats, and a difference
//! observed once on a dynamic page is the single most common false positive in
//! the class.
//!
//! So the harness sends the request again — itself, through its own client,
//! with its own scope guard in front of it — and keeps what came back. What it
//! produces is evidence about the target, not a description of evidence.
//!
//! Three properties this module is built around:
//!
//! - **Every request passes the guard.** [`crate::scope::ScopePolicy::check_request`]
//!   runs before the socket is opened, so replay cannot be the thing that
//!   wanders off-scope while trying to verify a finding.
//! - **Replay never mutates.** A finding proven with DELETE is not re-proven by
//!   deleting the record again. Non-idempotent verbs are refused unless the
//!   operator explicitly allowed destructive actions, and even then repeats are
//!   capped at one.
//! - **Bodies are truncated.** Evidence is stored with the run and shipped in
//!   the report; a 40MB response is not evidence, it is a liability.

use crate::scope::ScopePolicy;
use serde::{Deserialize, Serialize};
use crate::validation::{Evidence, Exchange};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// A request the engine can perform.
#[derive(Debug, Clone, Default)]
pub struct ReqSpec {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: String,
    /// Label for the identity these credentials belong to ("userA", "anonymous").
    pub identity: String,
}

impl ReqSpec {
    pub fn get(url: &str) -> ReqSpec {
        ReqSpec { method: "GET".into(), url: url.to_string(), ..Default::default() }
    }
    pub fn with_header(mut self, k: &str, v: &str) -> Self {
        self.headers.insert(k.to_string(), v.to_string());
        self
    }
    pub fn as_identity(mut self, who: &str) -> Self {
        self.identity = who.to_string();
        self
    }
    /// Set the request body, if the finding recorded a payload separately from
    /// the recorded exchange (which stores only the response body).
    pub fn with_body(mut self, body: &str) -> Self {
        if !body.trim().is_empty() {
            self.body = body.to_string();
        }
        self
    }
    /// Verbs that change state. Replay refuses these by default: re-running a
    /// destructive request to "confirm" it means doing the damage twice.
    pub fn is_mutating(&self) -> bool {
        !matches!(self.method.to_uppercase().as_str(), "GET" | "HEAD" | "OPTIONS")
    }
}

/// Response bodies above this are truncated. Big enough for a page or an API
/// payload, small enough that a run's evidence stays readable and shippable.
pub const BODY_CAP: usize = 96 * 1024;

/// Why a replay could not happen. Kept as data rather than logged and dropped,
/// because "we could not verify this" belongs in the finding's review reason.
#[derive(Debug, Clone)]
pub enum ReplayError {
    OutOfScope(String),
    Mutating(String),
    Transport(String),
    NoRequest,
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplayError::OutOfScope(r) => write!(f, "scope guard refused the replay: {r}"),
            ReplayError::Mutating(m) => write!(f, "{m} is state-changing — not replayed"),
            ReplayError::Transport(e) => write!(f, "replay failed: {e}"),
            ReplayError::NoRequest => write!(f, "nothing recorded to replay"),
        }
    }
}

pub struct ReplayEngine {
    client: reqwest::Client,
    policy: ScopePolicy,
    /// Pause between repeats so verification does not look like a flood.
    pace: Duration,
    /// Operator secrets. A header value of `$VAULT:<id>` is resolved here, at
    /// send time — injected, never a global, so a test can drive the real path.
    vault: crate::vault::Vault,
}

impl ReplayEngine {
    pub fn new(policy: ScopePolicy) -> Self {
        // The engine's client must know the policy: checking only the initial
        // URL leaves every redirect unguarded.
        let client = crate::probe::client_for(
            Some(std::sync::Arc::new(policy.clone())),
            false,
        );
        ReplayEngine {
            client,
            policy,
            pace: Duration::from_millis(350),
            vault: crate::vault::Vault::default(),
        }
    }

    /// Attach the run's vault so `$VAULT:<id>` header values resolve.
    pub fn with_vault(mut self, vault: crate::vault::Vault) -> Self {
        self.vault = vault;
        self
    }

    /// Use a client that never proxies. Loopback tests must call this: a stray
    /// `NEUROSPLOIT_PROXY` would send the request at the proxy instead of the mock.
    pub fn no_proxy(mut self) -> Self {
        // Keep the policy: the loopback seam must not drop the guard it tests.
        self.client = crate::probe::client_for_direct(
            Some(std::sync::Arc::new(self.policy.clone())),
            false,
        );
        self
    }

    /// A header value is either literal or `$VAULT:<id>`. An unknown slot stays
    /// literal so the request fails loudly instead of sending an empty header.
    fn resolve_header_value(&self, v: &str) -> String {
        match v.strip_prefix(crate::vault::SLOT_PREFIX) {
            Some(id) => self.vault.get(id.trim()).map(|s| s.to_string()).unwrap_or_else(|| v.to_string()),
            None => v.to_string(),
        }
    }

    pub fn with_pace(mut self, pace: Duration) -> Self {
        self.pace = pace;
        self
    }

    /// Perform one request and record it.
    pub async fn send(&self, req: &ReqSpec) -> Result<Exchange, ReplayError> {
        if req.url.trim().is_empty() {
            return Err(ReplayError::NoRequest);
        }
        let decision = self.policy.check_request(&req.url, &req.method, &req.body);
        if !decision.allowed() {
            return Err(ReplayError::OutOfScope(decision.reason().to_string()));
        }
        if req.is_mutating() && !self.policy.soft.allow_destructive_methods {
            return Err(ReplayError::Mutating(req.method.to_uppercase()));
        }

        let method = reqwest::Method::from_bytes(req.method.to_uppercase().as_bytes())
            .unwrap_or(reqwest::Method::GET);
        let mut rb = self.client.request(method, &req.url);
        for (k, v) in &req.headers {
            rb = rb.header(k.as_str(), self.resolve_header_value(v).as_str());
        }
        if !req.body.is_empty() {
            rb = rb.body(req.body.clone());
        }

        let started = Instant::now();
        let resp = rb.send().await.map_err(|e| ReplayError::Transport(e.to_string()))?;
        let status = resp.status().as_u16();
        let mut headers = BTreeMap::new();
        for (k, v) in resp.headers().iter() {
            // Multi-value headers (notably Set-Cookie) are joined rather than
            // dropped: the cookie validators read flags out of the whole string.
            let key = k.as_str().to_lowercase();
            let val = v.to_str().unwrap_or("").to_string();
            headers
                .entry(key)
                .and_modify(|prev: &mut String| {
                    prev.push_str("; ");
                    prev.push_str(&val);
                })
                .or_insert(val);
        }
        let content_type = headers.get("content-type").cloned().unwrap_or_default();
        let body = resp.text().await.unwrap_or_default();
        let elapsed_ms = started.elapsed().as_millis() as u64;

        Ok(Exchange {
            method: req.method.to_uppercase(),
            url: req.url.clone(),
            status,
            body: truncate(&body, BODY_CAP),
            content_type,
            elapsed_ms,
            identity: req.identity.clone(),
            headers,
            request_headers: req.headers.clone(),
            provenance: "wire:replay".into(),
        })
    }

    /// Send the same request `n` extra times, pacing between them.
    ///
    /// This is what a reproducibility rule actually needs: the SQLi validator
    /// asks for the difference to hold across repeats, and only the harness can
    /// honestly produce them.
    pub async fn repeat(&self, req: &ReqSpec, n: usize) -> (Vec<Exchange>, Vec<String>) {
        let mut out = Vec::new();
        let mut notes = Vec::new();
        if req.is_mutating() {
            notes.push(format!("{} not repeated — replaying a state-changing request would act twice", req.method.to_uppercase()));
            return (out, notes);
        }
        for i in 0..n {
            if i > 0 {
                tokio::time::sleep(self.pace).await;
            }
            match self.send(req).await {
                Ok(x) => out.push(x),
                Err(e) => {
                    notes.push(e.to_string());
                    break;
                }
            }
        }
        (out, notes)
    }

    /// Fill in what a finding's evidence is missing, without inventing any of it.
    ///
    /// Only the repeats are produced here. A baseline cannot be derived from an
    /// attack request in general — removing "the payload" from an arbitrary URL
    /// is guesswork, and a guessed baseline would silently decide the verdict.
    /// When the agent recorded one, it is re-sent so both sides of the
    /// comparison come from the same moment in the target's life.
    pub async fn enrich(&self, ev: &mut Evidence, want_repeats: usize) -> Vec<String> {
        let mut notes = Vec::new();
        let Some(attack) = ev.attack.clone() else {
            notes.push("no attack request recorded — nothing to replay".into());
            return notes;
        };
        let req = spec_of(&attack);
        if ev.repeats.len() < want_repeats {
            let need = want_repeats - ev.repeats.len();
            let (mut got, mut n) = self.repeat(&req, need).await;
            ev.repeats.append(&mut got);
            notes.append(&mut n);
        }
        if let Some(base) = ev.baseline.clone() {
            // Re-measure the baseline too: comparing a fresh attack against a
            // baseline captured an hour ago attributes ordinary drift (a new
            // banner, a rotated token) to the payload.
            match self.send(&spec_of(&base)).await {
                Ok(fresh) => ev.baseline = Some(fresh),
                Err(e) => notes.push(format!("baseline not re-measured: {e}")),
            }
        }
        ev.notes.extend(notes.iter().cloned());
        notes
    }

    /// Request the same resource as two identities — the evidence an access
    /// control rule needs, produced by the harness rather than described.
    pub async fn identity_pair(&self, url: &str, a: (&str, &str), b: (&str, &str)) -> (Option<Exchange>, Option<Exchange>, Vec<String>) {
        let mut notes = Vec::new();
        let mk = |(who, auth): (&str, &str)| {
            let mut r = ReqSpec::get(url).as_identity(who);
            if !auth.is_empty() {
                let (k, v) = auth.split_once(':').unwrap_or(("Authorization", auth));
                r = r.with_header(k.trim(), v.trim());
            }
            r
        };
        let ra = match self.send(&mk(a)).await {
            Ok(x) => Some(x),
            Err(e) => {
                notes.push(format!("identity '{}' request failed: {e}", a.0));
                None
            }
        };
        tokio::time::sleep(self.pace).await;
        let rb = match self.send(&mk(b)).await {
            Ok(x) => Some(x),
            Err(e) => {
                notes.push(format!("identity '{}' request failed: {e}", b.0));
                None
            }
        };
        (ra, rb, notes)
    }
}

// ---------------------------------------------------------------------------
// Effect layers
//
// The engagement that motivated this recorded 25 accepted POSTs and concluded
// "reset email flooding". Those are different facts at different layers, and
// the pipeline had no way to say so: a request being accepted is not a state
// change, and a state change is not a message leaving the building.
//
//   request_effect      the response: status, headers, latency, body delta
//   application_effect  something changed inside: a record, a token, a queued job
//   external_effect     something left: an email delivered, a webhook fired
//
// Each layer needs its own observation. The harness can measure the first
// directly, the second with a read-back, and the third only through a channel
// it controls (a mailbox it owns, an OOB callback). Anything it cannot observe
// is recorded as NOT OBSERVED rather than inferred — which is exactly the line
// the agent crossed.
// ---------------------------------------------------------------------------

/// Which layer an observation belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectLayer {
    Request,
    Application,
    External,
}

impl EffectLayer {
    pub fn as_str(self) -> &'static str {
        match self {
            EffectLayer::Request => "request_effect",
            EffectLayer::Application => "application_effect",
            EffectLayer::External => "external_effect",
        }
    }
}

/// What was seen at one layer — or that nothing was looked at.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EffectObservation {
    pub layer: EffectLayer,
    /// True only when the harness itself observed it.
    pub observed: bool,
    pub detail: String,
    /// Evidence ledger ids, when the caller is building a claim set.
    #[serde(default)]
    pub evidence: Vec<String>,
}

impl EffectObservation {
    pub fn seen(layer: EffectLayer, detail: impl Into<String>) -> Self {
        EffectObservation { layer, observed: true, detail: detail.into(), evidence: Vec::new() }
    }
    /// Not observed, with the reason. "We did not look" and "we looked and saw
    /// nothing" are both recorded here, and neither is evidence of absence of
    /// the effect — only of its demonstration.
    pub fn not_seen(layer: EffectLayer, why: impl Into<String>) -> Self {
        EffectObservation { layer, observed: false, detail: why.into(), evidence: Vec::new() }
    }
}

/// Everything observed about one interaction, layer by layer.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct EffectReport {
    #[serde(default)]
    pub observations: Vec<EffectObservation>,
}

impl EffectReport {
    pub fn push(&mut self, o: EffectObservation) {
        self.observations.push(o);
    }
    pub fn observed(&self, layer: EffectLayer) -> bool {
        self.observations.iter().any(|o| o.layer == layer && o.observed)
    }
    /// The deepest layer actually demonstrated. This is what a severity or an
    /// impact claim may be built on — and nothing deeper.
    pub fn deepest_observed(&self) -> Option<EffectLayer> {
        [EffectLayer::External, EffectLayer::Application, EffectLayer::Request]
            .into_iter()
            .find(|l| self.observed(*l))
    }
    /// One line per layer, for the evidence section of a report.
    pub fn summary(&self) -> String {
        let mut out = String::new();
        for layer in [EffectLayer::Request, EffectLayer::Application, EffectLayer::External] {
            let line = self
                .observations
                .iter()
                .find(|o| o.layer == layer)
                .map(|o| format!("{} {}", if o.observed { "observed:" } else { "NOT observed:" }, o.detail))
                .unwrap_or_else(|| "not examined".to_string());
            out.push_str(&format!("  {:<20} {line}\n", layer.as_str()));
        }
        out
    }
}

impl ReplayEngine {
    /// Re-run an interaction and record what it did at every layer the harness
    /// can reach.
    ///
    /// `verify` is a read-back request that reveals an application effect (the
    /// record as it now stands, the account's state, the audit endpoint).
    /// `marker` is a value expected to appear there if the write took. Without
    /// a verification request the application layer is honestly reported as
    /// unexamined — the alternative, inferring it from a 200, is the mistake
    /// this whole layering exists to prevent.
    pub async fn observe_effects(
        &self,
        action: &ReqSpec,
        verify: Option<&ReqSpec>,
        marker: Option<&str>,
    ) -> (EffectReport, Option<Exchange>) {
        let mut report = EffectReport::default();

        let before = match verify {
            Some(v) => self.send(v).await.ok(),
            None => None,
        };

        let acted = match self.send(action).await {
            Ok(x) => x,
            Err(e) => {
                report.push(EffectObservation::not_seen(EffectLayer::Request, format!("the request could not be sent: {e}")));
                report.push(EffectObservation::not_seen(EffectLayer::Application, "no request, so no application effect to look for"));
                report.push(EffectObservation::not_seen(EffectLayer::External, "no request, so no external effect to look for"));
                return (report, None);
            }
        };
        report.push(EffectObservation::seen(
            EffectLayer::Request,
            format!("{} {} → {} · {} bytes · {} ms", acted.method, acted.url, acted.status, acted.len(), acted.elapsed_ms),
        ));

        match verify {
            None => report.push(EffectObservation::not_seen(
                EffectLayer::Application,
                "no read-back was performed — a response status does not show whether state changed",
            )),
            Some(v) => match self.send(v).await {
                Err(e) => report.push(EffectObservation::not_seen(EffectLayer::Application, format!("the read-back failed: {e}"))),
                Ok(after) => {
                    let marker_hit = marker.map(|m| after.body.contains(m) && !before.as_ref().map(|b| b.body.contains(m)).unwrap_or(false));
                    match marker_hit {
                        Some(true) => report.push(EffectObservation::seen(
                            EffectLayer::Application,
                            format!("the read-back now contains the injected value ({})", marker.unwrap_or("")),
                        )),
                        Some(false) => report.push(EffectObservation::not_seen(
                            EffectLayer::Application,
                            "the read-back does not contain the injected value — the request was accepted and the change was not persisted",
                        )),
                        None => {
                            // No marker to look for: fall back to whether the
                            // resource changed at all, which is weaker and says so.
                            let changed = before
                                .as_ref()
                                .map(|b| b.status != after.status || b.body != after.body)
                                .unwrap_or(false);
                            if changed {
                                report.push(EffectObservation::seen(
                                    EffectLayer::Application,
                                    format!("the resource differs after the request ({} → {}, {} → {} bytes)", before.as_ref().map(|b| b.status).unwrap_or(0), after.status, before.as_ref().map(|b| b.len()).unwrap_or(0), after.len()),
                                ));
                            } else {
                                report.push(EffectObservation::not_seen(
                                    EffectLayer::Application,
                                    "the resource is unchanged after the request",
                                ));
                            }
                        }
                    }
                }
            },
        }

        // The harness has no mailbox and no callback listener of its own yet, so
        // it cannot see this layer. Saying that plainly is the point: an
        // unobserved external effect must never be inferred from an accepted
        // request.
        report.push(EffectObservation::not_seen(
            EffectLayer::External,
            "no channel the harness controls (mailbox, OOB callback) was watching — delivery of mail, notifications or downstream jobs was not observed",
        ));

        (report, Some(acted))
    }
}

/// Rebuild a request spec from a recorded exchange.
pub fn spec_of(x: &Exchange) -> ReqSpec {
    ReqSpec {
        method: if x.method.is_empty() { "GET".into() } else { x.method.clone() },
        url: x.url.clone(),
        headers: x.request_headers.clone(),
        body: String::new(),
        identity: x.identity.clone(),
    }
}

/// Cut `s` to at most `cap` bytes without splitting a character. Targets send
/// arbitrary bytes, and a byte slice panics when the cut lands mid-character.
pub fn truncate_str(s: &str, cap: usize) -> &str {
    if s.len() <= cap {
        return s;
    }
    let mut end = cap;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn truncate(s: &str, cap: usize) -> String {
    if s.len() <= cap {
        return s.to_string();
    }
    // Cut on a character boundary, then say so — a silently clipped body would
    // make a length differential meaningless.
    format!("{}\n…[truncated at {cap} bytes by the replay engine]", truncate_str(s, cap))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ScopePolicy {
        let mut p = ScopePolicy::for_target("https://app.example.com/");
        p.soft.max_requests_per_minute = 0;
        p
    }

    #[tokio::test]
    async fn a_replay_outside_scope_never_opens_a_socket() {
        let engine = ReplayEngine::new(policy());
        // other.test resolves nowhere; if the guard let it through this would
        // fail with a transport error instead, which is the distinction.
        let err = engine.send(&ReqSpec::get("https://other.test/secret")).await.unwrap_err();
        match err {
            ReplayError::OutOfScope(r) => assert!(r.contains("outside the authorized scope"), "{r}"),
            e => panic!("expected a scope refusal, got {e}"),
        }
    }

    #[tokio::test]
    async fn a_destructive_verb_is_not_replayed_by_default() {
        let engine = ReplayEngine::new(policy());
        let req = ReqSpec { method: "DELETE".into(), url: "https://app.example.com/orders/1".into(), ..Default::default() };
        match engine.send(&req).await.unwrap_err() {
            // The scope guard gets there first, which is the stronger refusal.
            ReplayError::OutOfScope(r) => assert!(r.contains("destructive"), "{r}"),
            ReplayError::Mutating(m) => assert_eq!(m, "DELETE"),
            e => panic!("a DELETE must not be replayed: {e}"),
        }
    }

    #[tokio::test]
    async fn repeats_are_refused_for_state_changing_requests() {
        let engine = ReplayEngine::new(policy());
        let req = ReqSpec { method: "POST".into(), url: "https://app.example.com/x".into(), ..Default::default() };
        let (got, notes) = engine.repeat(&req, 3).await;
        assert!(got.is_empty());
        assert!(notes[0].contains("would act twice"), "{:?}", notes);
    }

    #[tokio::test]
    async fn enrich_reports_when_there_is_nothing_to_replay() {
        let engine = ReplayEngine::new(policy());
        let mut ev = Evidence::default();
        let notes = engine.enrich(&mut ev, 2).await;
        assert!(notes[0].contains("nothing to replay"), "{:?}", notes);
        assert!(ev.repeats.is_empty(), "the engine must not fabricate repeats");
    }

    #[test]
    fn a_truncated_body_says_that_it_was_truncated() {
        let big = "a".repeat(BODY_CAP + 500);
        let t = truncate(&big, BODY_CAP);
        assert!(t.len() < big.len());
        assert!(t.contains("truncated"), "a silently clipped body makes a length diff meaningless");
        // Multi-byte safety: cutting mid-character would panic on slicing.
        let multi = "é".repeat(BODY_CAP);
        assert!(!truncate(&multi, BODY_CAP - 1).is_empty());
    }

    #[test]
    fn truncate_str_stops_on_a_boundary_and_never_grows() {
        // 3-byte characters: every cap that is not a multiple of 3 must back off.
        let cjk = "日本語abc";
        for cap in 0..cjk.len() {
            let got = truncate_str(cjk, cap);
            assert!(got.len() <= cap);
            assert!(cjk.starts_with(got), "cap {cap} produced a non-prefix");
        }
        assert_eq!(truncate_str(cjk, cjk.len()), cjk);
        assert_eq!(truncate_str(cjk, 999), cjk, "cap above length is a no-op");
    }

    /// Criterion 9: this is the exact function `send` calls for every header, so
    /// the resolution path is driven rather than described. The wire-level case is
    /// declared as environment-limited in the completion report: this sandbox
    /// rewrites loopback requests (a foreign UA and stripped headers arrived at
    /// the mock), so a mock-server assertion there would test the interceptor.
    /// Criterion 9 at the wire, restored: a `$VAULT:<id>` header resolves to the
    /// real bearer on a loopback request. The mock accepts in a **bounded loop**
    /// because an environment scanner can win a single-accept race, and it fails
    /// loudly — counting non-matching connections — rather than hanging or
    /// passing vacuously.
    #[tokio::test]
    async fn replay_resolves_slot_header_over_loopback() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::time::Instant;

        // The seam that could redirect this test: http_client() honours a proxy by
        // design, the direct client this test uses does not.
        assert!(crate::probe::proxy_url("http://127.0.0.1:1").is_some(), "the proxy seam must be live");

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();

        let mut vault = crate::vault::Vault::default();
        assert!(vault.put("auth", "Bearer sk-live-123"));
        // Host only: the policy matches the request host, not the port.
        let policy = ScopePolicy::from_yaml("hard:\n  - 127.0.0.1\n");
        let engine = ReplayEngine::new(policy)
            .no_proxy()
            .with_vault(vault)
            .with_pace(Duration::from_millis(0));

        let mock = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut probes = 0usize;
            let mut attempts = 0usize;
            while Instant::now() < deadline && attempts < 64 {
                attempts += 1;
                match listener.accept() {
                    Ok((mut sock, _)) => {
                        let mut buf = [0u8; 4096];
                        let n = sock.read(&mut buf).unwrap_or(0);
                        let req = String::from_utf8_lossy(&buf[..n]).to_string();
                        let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                        // Header names are lowercased on the wire by reqwest.
                        if req.to_ascii_lowercase().contains("authorization:") {
                            return (Some(req), probes);
                        }
                        probes += 1;
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
            (None, probes)
        });

        let mut req = ReqSpec::get(&format!("http://127.0.0.1:{port}/x"));
        req.headers.insert("Authorization".into(), "$VAULT:auth".into());
        // Surface a refusal: discarding this hid whether the request was ever sent.
        let sent = engine.send(&req).await;
        assert!(sent.is_ok(), "send refused before the socket: {:?}", sent.err());

        let (captured, probes) = mock.join().unwrap_or((None, 0));
        let seen = captured.unwrap_or_else(|| {
            panic!("no request carrying Authorization reached the mock; {probes} non-matching connection(s) seen")
        });
        assert!(seen.contains("Bearer sk-live-123"), "the slot must resolve on the wire: {seen}");
        assert!(!seen.contains("$VAULT:"), "the reference must not be sent literally: {seen}");
    }

    #[test]
    fn slot_header_values_resolve_on_the_engine() {
        let mut v = crate::vault::Vault::default();
        assert!(v.put("auth", "Bearer sk-live-123"));
        let engine = ReplayEngine::new(ScopePolicy::for_target("https://app.example.com/")).with_vault(v);

        assert_eq!(engine.resolve_header_value("$VAULT:auth"), "Bearer sk-live-123");
        assert_eq!(engine.resolve_header_value("Bearer literal"), "Bearer literal");
        // an unknown slot stays literal, so the failure is loud rather than an
        // empty header on the wire
        assert_eq!(engine.resolve_header_value("$VAULT:missing"), "$VAULT:missing");

        // without a vault the reference is not silently dropped either
        let bare = ReplayEngine::new(ScopePolicy::for_target("https://app.example.com/"));
        assert_eq!(bare.resolve_header_value("$VAULT:auth"), "$VAULT:auth");
    }

    #[test]
    fn a_spec_rebuilt_from_an_exchange_keeps_identity_and_request_headers() {
        let mut x = Exchange { method: "GET".into(), url: "https://app.example.com/a".into(), identity: "userB".into(), ..Default::default() };
        x.request_headers.insert("Authorization".into(), "Bearer t".into());
        let spec = spec_of(&x);
        assert_eq!(spec.identity, "userB");
        assert_eq!(spec.headers.get("Authorization").map(String::as_str), Some("Bearer t"));
    }

    #[test]
    fn mutating_verbs_are_classified_correctly() {
        for m in ["POST", "PUT", "PATCH", "DELETE"] {
            assert!(ReqSpec { method: m.into(), ..Default::default() }.is_mutating(), "{m}");
        }
        for m in ["GET", "HEAD", "OPTIONS", "get"] {
            assert!(!ReqSpec { method: m.into(), ..Default::default() }.is_mutating(), "{m}");
        }
    }
}

#[cfg(test)]
mod effect_tests {
    use super::*;

    #[test]
    fn an_accepted_request_is_not_an_application_effect() {
        let mut r = EffectReport::default();
        r.push(EffectObservation::seen(EffectLayer::Request, "POST /reset → 302"));
        r.push(EffectObservation::not_seen(EffectLayer::Application, "no read-back was performed"));
        r.push(EffectObservation::not_seen(EffectLayer::External, "no mailbox watched"));
        assert!(r.observed(EffectLayer::Request));
        assert!(!r.observed(EffectLayer::Application));
        // The deepest thing demonstrated is the request — an impact claim may
        // be built on that and nothing further.
        assert_eq!(r.deepest_observed(), Some(EffectLayer::Request));
    }

    #[test]
    fn the_summary_says_not_observed_rather_than_staying_silent() {
        let mut r = EffectReport::default();
        r.push(EffectObservation::seen(EffectLayer::Request, "25 requests accepted"));
        r.push(EffectObservation::not_seen(EffectLayer::External, "no mailbox watched"));
        let s = r.summary();
        assert!(s.contains("request_effect") && s.contains("observed:"));
        assert!(s.contains("external_effect") && s.contains("NOT observed:"));
        // A layer nobody looked at must not read as a clean result.
        assert!(s.contains("application_effect") && s.contains("not examined"));
    }

    #[test]
    fn the_deepest_observed_layer_is_the_ceiling_for_a_claim() {
        let mut r = EffectReport::default();
        r.push(EffectObservation::seen(EffectLayer::Request, "POST accepted"));
        r.push(EffectObservation::seen(EffectLayer::Application, "read-back shows the new value"));
        r.push(EffectObservation::not_seen(EffectLayer::External, "no delivery channel"));
        assert_eq!(r.deepest_observed(), Some(EffectLayer::Application));
        let empty = EffectReport::default();
        assert_eq!(empty.deepest_observed(), None);
    }

    #[tokio::test]
    async fn a_refused_request_reports_every_layer_as_unobserved() {
        let mut p = ScopePolicy::for_target("https://app.example.com/");
        p.soft.max_requests_per_minute = 0;
        let engine = ReplayEngine::new(p);
        let (report, exchange) = engine.observe_effects(&ReqSpec::get("https://other.test/x"), None, None).await;
        assert!(exchange.is_none());
        for l in [EffectLayer::Request, EffectLayer::Application, EffectLayer::External] {
            assert!(!report.observed(l), "{l:?} must not be reported as observed when nothing was sent");
        }
    }
}
#[cfg(test)]
mod redirect_scope_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn canary() -> (u16, Arc<AtomicUsize>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        tokio::spawn(async move {
            for _ in 0..4 {
                match tokio::time::timeout(std::time::Duration::from_secs(5), l.accept()).await {
                    Ok(Ok((mut sock, _))) => {
                        let mut b = [0u8; 1024];
                        let n = sock.read(&mut b).await.unwrap_or(0);
                        let head = String::from_utf8_lossy(&b[..n]).to_lowercase();
                        // Count only the redirect's own request: a bare accept
                        // count picks up environment scanners (SEC-008 lesson).
                        if head.contains("/moved") {
                            h.fetch_add(1, Ordering::SeqCst);
                        }
                        let _ = sock
                            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\nconnection: close\r\n\r\nHIT")
                            .await;
                    }
                    _ => break,
                }
            }
        });
        (port, hits)
    }

    async fn origin_redirecting_to(location: String) -> u16 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok(Ok((mut sock, _))) =
                tokio::time::timeout(std::time::Duration::from_secs(5), l.accept()).await
            {
                let mut b = [0u8; 2048];
                let _ = sock.read(&mut b).await;
                let resp = format!(
                    "HTTP/1.1 302 Found\r\nlocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });
        port
    }

    /// C1 — a redirect to a hostname that resolves to loopback is not followed.
    /// The target is a NAME, so the old literal-only guard could not have
    /// stopped it; only resolution can.
    #[tokio::test]
    async fn a_redirect_to_a_private_hostname_is_not_followed() {
        let (canary_port, hits) = canary().await;
        let origin_port =
            origin_redirecting_to(format!("http://localhost:{canary_port}/moved")).await;

        let policy = crate::scope::ScopePolicy::for_target(&format!("http://127.0.0.1:{origin_port}/"));
        let eng = ReplayEngine::new(policy)
            .no_proxy()
            .with_pace(std::time::Duration::ZERO);
        let ex = eng
            .send(&ReqSpec::get(&format!("http://127.0.0.1:{origin_port}/")))
            .await
            .expect("the in-scope initial request must succeed");

        assert_eq!(ex.status, 302, "the redirect must come back as data");
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "the engine followed a redirect whose hostname resolves to loopback"
        );
    }

    /// The pin-only discriminator: the target is IN SCOPE (`hard` holds
    /// 127.0.0.1 from `for_target`) but nobody named it, so only the private
    /// resolution stops the follow. Removing the scope check leaves this green;
    /// removing `pin_with` reddens it — each layer gets a test where it alone
    /// is load-bearing.
    #[tokio::test]
    async fn an_in_scope_private_redirect_is_refused_unless_explicitly_named() {
        let (canary_port, hits) = canary().await;
        let origin_port =
            origin_redirecting_to(format!("http://127.0.0.1:{canary_port}/moved")).await;

        let policy =
            crate::scope::ScopePolicy::for_target(&format!("http://127.0.0.1:{origin_port}/"));
        let eng = ReplayEngine::new(policy)
            .no_proxy()
            .with_pace(std::time::Duration::ZERO);
        let ex = eng
            .send(&ReqSpec::get(&format!("http://127.0.0.1:{origin_port}/")))
            .await
            .expect("initial request");

        assert_eq!(ex.status, 302);
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "in scope is reachability; only an explicit grant may allow a private redirect"
        );
    }

    /// C2 — the allow direction: a redirect to a host the policy explicitly
    /// authorizes is followed, so the guard is not refusing everything.
    #[tokio::test]
    async fn a_redirect_to_a_hard_scoped_host_is_followed() {
        let (canary_port, hits) = canary().await;
        let origin_port =
            origin_redirecting_to(format!("http://127.0.0.1:{canary_port}/moved")).await;

        let mut policy =
            crate::scope::ScopePolicy::for_target(&format!("http://127.0.0.1:{origin_port}/"));
        // A human named the canary host; that — not `hard` — is what may exempt
        // it from the private-address refusal.
        policy.authorize_explicitly(&format!("127.0.0.1"));
        let eng = ReplayEngine::new(policy)
            .no_proxy()
            .with_pace(std::time::Duration::ZERO);
        let _ = eng
            .send(&ReqSpec::get(&format!("http://127.0.0.1:{origin_port}/")))
            .await
            .expect("initial request");

        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "a redirect to an explicitly authorized host must be followed"
        );
    }
}
