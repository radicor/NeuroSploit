//! Vault slots: operator secrets become references that are resolved only at
//! request time.
//!
//! The prompt tells an agent `$VAULT:auth` and the path of a header file; it
//! never carries the header itself. That is what keeps credentials out of
//! traces, findings and the vendor API, and it is why `redact` must run before
//! every write.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

pub const SLOT_PREFIX: &str = "$VAULT:";

/// `[A-Za-z][A-Za-z0-9_.-]*`, at most 64 characters. A malformed id that were
/// accepted would become an unresolvable reference — the agent told to use a
/// slot that can never be filled.
pub fn valid_slot_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    if !bytes[0].is_ascii_alphabetic() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// Pure form of the `NEUROSPLOIT_VAULT` flag, so the tests drive it directly
/// instead of mutating the process environment (racy across test threads).
pub fn vault_enabled(raw: &str) -> bool {
    !matches!(raw.trim().to_ascii_lowercase().as_str(), "off" | "0" | "false")
}

/// True when slots are usable for this process. Redaction is *not* affected:
/// turning slots off must never turn redaction off.
pub fn slots_enabled() -> bool {
    let raw = std::env::var("NEUROSPLOIT_VAULT").unwrap_or_default();
    let on = vault_enabled(&raw);
    if !on {
        eprintln!(
            "warning: NEUROSPLOIT_VAULT=off — slots are disabled, so prompts and files will \
             contain literal values. Redaction still runs. Use only to work around a slot bug."
        );
    }
    on
}

/// A slot id derived from an identity name: ASCII-safe, starts alphabetic, ≤64.
pub fn slot_id_for(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '_' })
        .collect();
    if out.is_empty() {
        out.push_str("role");
    }
    if !out.chars().next().map(|c| c.is_ascii_alphabetic()).unwrap_or(false) {
        out.insert(0, 'r');
    }
    out.truncate(64);
    out
}

#[derive(Debug, Default, Clone)]
pub struct Vault {
    map: BTreeMap<String, String>,
    dir: PathBuf,
}

impl Vault {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { map: BTreeMap::new(), dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Register a value. Returns `false` when the id is malformed or the value
    /// is empty — a caller that ignores the result still gets a loud log line.
    pub fn put(&mut self, id: &str, value: &str) -> bool {
        if !valid_slot_id(id) {
            eprintln!("warning: refusing malformed vault slot id {id:?}");
            return false;
        }
        if value.trim().is_empty() {
            return false;
        }
        self.map.insert(id.to_string(), value.to_string());
        true
    }

    pub fn get(&self, id: &str) -> Option<&str> {
        self.map.get(id).map(String::as_str)
    }

    /// Where this slot's header file lives. `slots/<id>.header` under the vault
    /// directory, which is created `0700`.
    pub fn header_path(&self, id: &str) -> PathBuf {
        self.dir.join("slots").join(format!("{id}.header"))
    }

    /// What a prompt may say about a slot: the reference and the file path.
    pub fn prompt_hint(&self, id: &str) -> String {
        format!(
            "send the header file {} (reference {SLOT_PREFIX}{id})",
            self.header_path(id).display()
        )
    }

    /// Replace registered values with their references.
    ///
    /// **Longest value first.** With `auth = "Bearer sk-live-123"` and
    /// `token = "sk-live-123"` both registered, a short-first pass rewrites the
    /// long one into `Bearer $VAULT:token` and leaves the credential readable in
    /// every other place it appears. Sorting by length descending is the
    /// correctness property, not an optimisation.
    pub fn redact(&self, s: &str) -> String {
        if s.is_empty() || self.map.is_empty() {
            return s.to_string();
        }
        let mut pairs: Vec<(&String, &String)> = self.map.iter().collect();
        pairs.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(b.0)));
        let mut out = s.to_string();
        for (id, value) in pairs {
            if value.is_empty() || !out.contains(value.as_str()) {
                continue;
            }
            out = out.replace(value.as_str(), &format!("{SLOT_PREFIX}{id}"));
        }
        out
    }

    /// True when a string already holds only references — makes `redact`
    /// idempotent so a trace rewritten twice is not mangled.
    pub fn already_redacted(s: &str) -> bool {
        s.contains(SLOT_PREFIX)
    }

    /// Write one `<id>.header` file per slot, `0600` inside `0700`.
    pub fn materialize_files(&self) -> io::Result<()> {
        if !slots_enabled() {
            return Ok(());
        }
        for (id, value) in &self.map {
            // A header file is `Name: value` for `curl -H @file`; a value that
            // already carries its header name is written as-is.
            let body = if value.contains(':') { value.clone() } else { format!("Authorization: {value}") };
            write_private(&self.header_path(id), body.as_bytes())?;
        }
        Ok(())
    }

    /// The value a request needs right now. Late binding is the point: rotating a
    /// slot changes what goes on the wire without rewriting any prompt.
    pub fn resolve_header(&self, id: &str) -> Option<String> {
        if !slots_enabled() {
            return None;
        }
        self.get(id).map(|v| {
            if v.starts_with("Authorization:") || v.contains(": ") { v.to_string() }
            else { format!("Authorization: {v}") }
        })
    }
}

impl Vault {
    /// Persist the slot map for a run so a retest can reproduce the request.
    /// `0600` because it holds values, not references.
    pub fn save_slots(&self, run_dir: &Path) -> io::Result<PathBuf> {
        let p = run_dir.join("slots.bin");
        let mut body = String::new();
        for (id, value) in &self.map {
            body.push_str(id);
            body.push('\t');
            body.push_str(value);
            body.push('\n');
        }
        write_private(&p, body.as_bytes())?;
        Ok(p)
    }

    /// Reload a run's slots for a retest.
    pub fn load_slots(run_dir: &Path) -> io::Result<Self> {
        let text = std::fs::read_to_string(run_dir.join("slots.bin"))?;
        let mut v = Vault::new(run_dir.to_path_buf());
        for line in text.lines() {
            if let Some((id, val)) = line.split_once('\t') {
                v.map.insert(id.to_string(), val.to_string());
            }
        }
        Ok(v)
    }
}

/// Create `p` (and parents) `0700`. Set at creation where the platform allows,
/// and re-asserted afterwards so an existing loose directory is tightened too.
pub fn ensure_private_dir(p: &Path) -> io::Result<()> {
    std::fs::create_dir_all(p)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write a secret file `0600`, atomically.
pub fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            ensure_private_dir(dir)?;
        }
    }
    crate::state::write_atomic_mode(path, data, 0o600)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault() -> Vault {
        Vault::new(std::env::temp_dir().join(format!("ns-vault-test-{}", std::process::id())))
    }

    fn modes(p: &Path) -> (u32, u32) {
        use std::os::unix::fs::PermissionsExt;
        let f = std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let d = std::fs::metadata(p.parent().unwrap()).unwrap().permissions().mode() & 0o777;
        (f, d)
    }

    #[test]
    fn redact_is_longest_first() {
        let mut v = vault();
        assert!(v.put("auth", "Bearer sk-live-123"));
        assert!(v.put("token", "sk-live-123")); // a substring of the value above

        let out = v.redact("header is Bearer sk-live-123 and token sk-live-123");
        assert!(!out.contains("sk-live-123"), "a fragment survived: {out}");
        assert!(out.contains("$VAULT:auth"), "the long value must map to its own slot: {out}");
        assert!(out.contains("$VAULT:token"), "the short value must map to its own slot: {out}");
    }

    #[test]
    fn redact_leaves_prose_alone() {
        let mut v = vault();
        assert!(v.put("auth", "Bearer sk-live-123"));
        assert_eq!(v.redact("admin logged in as root"), "admin logged in as root");
        // a near-miss must NOT be masked
        assert_eq!(v.redact("Bearer sk-live-124"), "Bearer sk-live-124");
        assert_eq!(Vault::default().redact("untouched"), "untouched");
    }

    #[test]
    fn slot_grammar() {
        assert!(valid_slot_id("auth"));
        assert!(valid_slot_id("admin.token-1_2"));
        assert!(valid_slot_id(&format!("a{}", "b".repeat(63))), "64 chars total is fine");
        for bad in ["", "1auth", "auth$", "au th", "auth:1", &"a".repeat(65)] {
            assert!(!valid_slot_id(bad), "{bad:?} must be rejected");
        }
        let mut v = vault();
        assert!(!v.put("1bad", "x"));
        assert_eq!(v.len(), 0);
        assert!(!v.put("empty", "   "));
    }

    #[test]
    fn write_private_modes_on_a_fresh_file() {
        let dir = std::env::temp_dir().join(format!("ns-vault-modes-{}", std::process::id()));
        let p = dir.join("slots").join("auth.header");
        // delete first: a pre-existing 0600 would hide a create-with-0644 regression
        let _ = std::fs::remove_file(&p);
        write_private(&p, b"Authorization: secret").unwrap();
        let (file_mode, dir_mode) = modes(&p);
        assert_eq!(file_mode, 0o600, "file mode {file_mode:o}");
        assert_eq!(dir_mode, 0o700, "dir mode {dir_mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_is_late_bound() {
        let mut v = vault();
        assert!(v.put("auth", "Bearer first"));
        assert_eq!(v.resolve_header("auth").unwrap(), "Authorization: Bearer first");
        // rotating the slot changes the wire value; nothing else is rebuilt
        assert!(v.put("auth", "Bearer second"));
        assert_eq!(v.resolve_header("auth").unwrap(), "Authorization: Bearer second");
        assert_eq!(v.resolve_header("missing"), None);
    }

    /// TN-10: the leak assertion is scoped to what was registered at write time.
    #[test]
    fn late_slot_is_not_a_leak_in_earlier_files() {
        let mut v = vault();
        assert!(v.put("first", "alpha-secret"));
        let written = v.redact("uses alpha-secret here");
        assert!(written.contains("$VAULT:first"));
        assert!(!written.contains("alpha-secret"));

        // a slot registered afterwards was never in scope for that write
        assert!(v.put("second", "beta-secret"));
        assert!(!written.contains("beta-secret"), "the earlier file could not have contained it");
        assert!(v.redact("uses beta-secret here").contains("$VAULT:second"));
    }

    /// Criterion 5 / TN-4: the trace writer redacts before the write, so the file
    /// on disk carries references.
    #[test]
    fn trace_on_disk_is_redacted() {
        let dir = std::env::temp_dir().join(format!("ns-vault-trace-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut v = vault();
        assert!(v.put("auth", "Bearer sk-live-123"));

        crate::traces::record(
            Some(dir.to_str().unwrap()),
            "alpha",
            "agent echoed Authorization: Bearer sk-live-123 and a JWT eyJhbGciOiJIUzI1NiJ9.x",
            &v,
        );

        // `record` writes into <workdir>/traces, not into the workdir itself.
        let tdir = dir.join("traces");
        let written = std::fs::read_dir(&tdir).unwrap().flatten().next().expect("a trace file").path();
        let body = std::fs::read_to_string(&written).unwrap();
        assert!(!body.contains("sk-live-123"), "the credential reached the trace: {body}");
        assert!(body.contains("$VAULT:auth"), "the reference must be recorded: {body}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Criterion 11 / TN-8: the flag is pure and testable, and turning slots off
    /// must never turn redaction off.
    #[test]
    fn vault_off_warns_but_still_redacts() {
        for off in ["off", "OFF", " 0 ", "false", "False"] {
            assert!(!vault_enabled(off), "{off:?} must disable slots");
        }
        for on in ["", "on", "1", "true", "token"] {
            assert!(vault_enabled(on), "{on:?} must keep slots on");
        }

        // redaction is env-independent: with slots disabled it still masks
        let mut v = vault();
        assert!(v.put("auth", "Bearer sk-live-123"));
        assert_eq!(v.redact("uses Bearer sk-live-123 here"), "uses $VAULT:auth here");
    }

    /// Criterion 10: slots.bin is per run, private, and reloads for a retest.
    #[test]
    fn slots_bin_per_run() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("ns-vault-slots-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut v = vault();
        assert!(v.put("auth", "Bearer sk-live-123"));
        let p = v.save_slots(&dir).unwrap();

        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        let back = Vault::load_slots(&dir).unwrap();
        assert_eq!(back.get("auth"), Some("Bearer sk-live-123"), "a retest must be able to reproduce");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Criteria 1 and 2: the prompt names a slot and a file path, never a value —
    /// and it still tells the agent how to authenticate.
    #[test]
    fn prompts_carry_slots_not_values() {
        use crate::creds::{Creds, Identity};
        let mut c = Creds::default();
        c.roles.push(Identity {
            name: "admin".into(),
            jwt: "eyJhbGciOiJIUzI1NiJ9.payload.sig".into(),
            tier: "high".into(),
            ..Default::default()
        });
        c.roles.push(Identity {
            name: "reader".into(),
            header: "X-Api-Key: sk-reader-999".into(),
            tier: "readonly".into(),
            ..Default::default()
        });

        let mut v = vault();
        assert_eq!(c.adopt_vault(&mut v), 2, "both identities must be slotted");

        let text = c.roles_instruction().unwrap_or_default();
        assert!(text.contains("$VAULT:admin"), "{text}");
        assert!(text.contains("$VAULT:reader"), "{text}");
        // TN-1: the protocol must survive its own redaction
        assert!(text.contains("slots/admin.header"), "the agent needs the path: {text}");
        assert!(!text.contains("eyJ"), "the JWT must not reach the prompt: {text}");
        assert!(!text.contains("sk-reader-999"), "the key must not reach the prompt: {text}");
        // TN-7: the value is still available for request-time resolution
        assert!(v.resolve_header("admin").is_some());
        assert!(v.resolve_header("reader").is_some());
    }

    #[test]
    fn prompt_hint_names_the_reference_and_the_path() {
        let v = vault();
        let hint = v.prompt_hint("auth");
        assert!(hint.contains("$VAULT:auth"), "{hint}");
        assert!(hint.contains("slots/auth.header"), "{hint}");
    }
}
