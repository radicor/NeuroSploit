//! Atomic state writes and tolerant loads.
//!
//! Engagement state (`runs.json`, the checkpoint, `session.json`) used to be
//! saved with a bare truncating write, so a crash part-way through left a
//! truncated file — and because every reader treats a parse failure as "no
//! data", the next save destroyed the evidence. These two primitives make a
//! torn write cost at most the last save, and keep a corrupt file instead of
//! overwriting it.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// What a state file yielded. `Fresh` is a first run, not an error.
pub enum Load<T> {
    /// The file does not exist (or could not be read at all).
    Fresh,
    /// Parsed successfully, from the main file or its `.bak`.
    Value(T),
    /// Unreadable and unrecoverable; a copy was preserved.
    Corrupt { quarantined: PathBuf },
}

fn bak_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".bak");
    PathBuf::from(s)
}

fn tmp_sibling(path: &Path) -> PathBuf {
    // Beside the target, never in the system temp dir: `rename` is only atomic
    // within one filesystem.
    let mut s = path.as_os_str().to_os_string();
    s.push(format!(".tmp-{}", std::process::id()));
    PathBuf::from(s)
}

fn quarantine_path(path: &Path) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut candidate = {
        let mut s = path.as_os_str().to_os_string();
        s.push(format!(".corrupt-{nanos}"));
        PathBuf::from(s)
    };
    // Never overwrite an earlier quarantine: two corruptions in the same
    // nanosecond would otherwise destroy the first copy.
    let mut n = 0u32;
    while candidate.exists() {
        n += 1;
        let mut s = path.as_os_str().to_os_string();
        s.push(format!(".corrupt-{nanos}-{n}"));
        candidate = PathBuf::from(s);
    }
    candidate
}

/// Write `data` to `path` atomically: temp file, fsync, rotate the old file to
/// `<path>.bak`, then rename the temp into place. On failure `path` is left as
/// it was and no temp file survives.
pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    write_atomic_impl(path, data, None)
}

/// Same as `write_atomic`, but the file is created with an explicit mode so a
/// secret is never briefly world-readable. Unix only; elsewhere the mode is
/// ignored (the Windows DACL work is a separate item).
pub fn write_atomic_mode(path: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    write_atomic_impl(path, data, Some(mode))
}

fn write_atomic_impl(path: &Path, data: &[u8], mode: Option<u32>) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            fs::create_dir_all(dir)?;
        }
    }
    let tmp = tmp_sibling(path);
    {
        #[cfg(unix)]
        let mut f = match mode {
            Some(m) => {
                use std::os::unix::fs::OpenOptionsExt;
                fs::OpenOptions::new().write(true).create(true).truncate(true).mode(m).open(&tmp)?
            }
            None => fs::File::create(&tmp)?,
        };
        #[cfg(not(unix))]
        let mut f = {
            let _ = mode;
            fs::File::create(&tmp)?
        };
        // fsync before the rename, or the name can land without the bytes.
        if let Err(e) = f.write_all(data).and_then(|_| f.sync_all()) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
    }
    if path.exists() {
        let bak = bak_path(path);
        let _ = fs::remove_file(&bak);
        if let Err(e) = fs::rename(path, &bak) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
    }
    match fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Load a JSON state file. Missing → `Fresh`; valid → `Value`; truncated with a
/// good `.bak` → the `.bak` value (nothing is quarantined); both invalid →
/// preserve a copy and report `Corrupt`. Never deletes data.
pub fn load_json<T: serde::de::DeserializeOwned>(path: &Path) -> Load<T> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Load::Fresh,
        Err(_) => return Load::Fresh,
    };
    if let Ok(v) = serde_json::from_slice::<T>(&bytes) {
        return Load::Value(v);
    }
    if let Ok(bak) = fs::read(bak_path(path)) {
        if let Ok(v) = serde_json::from_slice::<T>(&bak) {
            // Keep the bad main: a human may want to see what was lost.
            eprintln!("warning: {} was unreadable; recovered from .bak", path.display());
            return Load::Value(v);
        }
    }
    let q = quarantine_path(path);
    if fs::copy(path, &q).is_err() {
        return Load::Corrupt { quarantined: PathBuf::new() };
    }
    eprintln!(
        "warning: {} is corrupt and its backup is unusable; preserved as {}",
        path.display(),
        q.display()
    );
    Load::Corrupt { quarantined: q }
}

/// Remove orphan `*.tmp-*` files left by a hard kill mid-write. Returns how many
/// were removed.
pub fn sweep_tmp(dir: &Path) -> usize {
    let Ok(entries) = fs::read_dir(dir) else { return 0 };
    let mut removed = 0;
    for e in entries.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name.contains(".tmp-") {
            if fs::remove_file(e.path()).is_ok() {
                removed += 1;
            }
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "ns-state-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn leftovers(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains(".tmp-"))
            .collect()
    }

    #[test]
    fn write_atomic_rotates_bak_and_leaves_no_tmp() {
        let d = tmpdir("rotate");
        let p = d.join("runs.json");
        fs::write(&p, "old").unwrap();

        write_atomic(&p, b"new").unwrap();

        assert_eq!(fs::read_to_string(&p).unwrap(), "new");
        assert_eq!(fs::read_to_string(bak_path(&p)).unwrap(), "old");
        assert!(leftovers(&d).is_empty(), "temp files left: {:?}", leftovers(&d));
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn missing_file_is_fresh() {
        let d = tmpdir("fresh");
        let p = d.join("none.json");
        match load_json::<Vec<String>>(&p) {
            Load::Fresh => {}
            _ => panic!("a missing file must be Fresh, not an error"),
        }
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn valid_file_loads() {
        let d = tmpdir("valid");
        let p = d.join("runs.json");
        fs::write(&p, r#"["a","b"]"#).unwrap();
        match load_json::<Vec<String>>(&p) {
            Load::Value(v) => assert_eq!(v, vec!["a".to_string(), "b".to_string()]),
            _ => panic!("a valid file must load"),
        }
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn truncated_main_recovers_from_bak() {
        let d = tmpdir("recover");
        let p = d.join("runs.json");
        fs::write(&p, "[").unwrap();                       // truncated
        fs::write(bak_path(&p), r#"["a"]"#).unwrap();      // good backup

        match load_json::<Vec<String>>(&p) {
            Load::Value(v) => assert_eq!(v, vec!["a".to_string()]),
            Load::Corrupt { .. } => panic!("a good .bak must be preferred over quarantine"),
            Load::Fresh => panic!("the main file exists"),
        }
        // recovery must not quarantine anything
        assert!(!fs::read_dir(&d).unwrap().flatten()
            .any(|e| e.file_name().to_string_lossy().contains(".corrupt-")));
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn both_corrupt_quarantines_and_keeps_main() {
        let d = tmpdir("corrupt");
        let p = d.join("runs.json");
        fs::write(&p, "{\"trunc").unwrap();
        fs::write(bak_path(&p), "also not json").unwrap();

        let q = match load_json::<Vec<String>>(&p) {
            Load::Corrupt { quarantined } => quarantined,
            _ => panic!("both files are unreadable"),
        };
        assert!(q.exists(), "the quarantine copy must exist");
        assert_eq!(fs::read_to_string(&q).unwrap(), "{\"trunc", "bytes preserved");
        assert!(p.exists(), "the main file must not be deleted");
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn torn_write_does_not_empty_history() {
        let d = tmpdir("torn");
        let p = d.join("runs.json");
        // Two saves: the second rotates the first into .bak. A single save has
        // nothing to back up, so a torn *first* write is recoverable only by
        // quarantine — the guarantee is "at most the last save is lost".
        write_atomic(&p, br#"["run-1"]"#).unwrap();
        write_atomic(&p, br#"["run-1","run-2"]"#).unwrap();
        // simulate a crash mid-save: the current file is truncated on disk
        fs::write(&p, r#"["run-"#).unwrap();

        match load_json::<Vec<String>>(&p) {
            Load::Value(v) => assert_eq!(v, vec!["run-1".to_string()],
                "the previous save must survive a torn write"),
            _ => panic!("a torn write must not lose the history entirely"),
        }
        fs::remove_dir_all(&d).ok();
    }
}
