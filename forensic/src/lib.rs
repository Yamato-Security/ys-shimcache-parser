//! Windows **AppCompatCache** (ShimCache) forensic analyzer.
//!
//! ShimCache records, for each executable the OS shimmed, the file's path and last-modification
//! `FILETIME` — and, on Windows 7 to 11, whether it was *executed*. [`analyze_blob`] decodes an
//! AppCompatCache value blob (with [`shimcache_core`]) and [`audit`] adds a small set of
//! *high-precision* graded findings: a Windows system-binary name recorded at a non-`System32`
//! path (masquerading) and an entry in a known-suspicious directory.
//!
//! [`read_system`] reads every control set's cache from a `SYSTEM` hive (see [`hive`]: its
//! transaction logs replayed when it is dirty), with the entries left in the slack of each value's
//! cell; [`analyze_blob`] takes a value's bytes.
//!
//! Findings are observations, never verdicts: ShimCache establishes that a binary at a given path
//! was shimmed (and, from Windows 7, executed) — whether that is malicious is a
//! correlation/tribunal question. Note the well-known caveat that ShimCache *presence* alone is
//! not proof of execution (the file may only have been browsed to); the execution flag (Windows 7
//! and 8: insertion flag 0x2; Windows 10 and 11: data tag 0x100) is the execution witness.
//!
//! Built on [`shimcache_core`]; findings use [`forensicnomicon::report`].

#![forbid(unsafe_code)]

pub mod hive;

use forensicnomicon::report::{Category, Finding, Observation, Severity, Source, SubjectRef};
use std::collections::HashSet;
use std::path::Path;

// Re-export the core types that appear in this crate's public API so consumers need only depend
// on `shimcache-forensic`.
pub use hive::{Hive, HiveError, LogFile, Recovery};
pub use shimcache_core::{
    Cache, PackageRecord, ShimcacheEntry, ShimcacheError, ShimcacheFormat, decode, recover_slack,
};

/// Where a control set keeps its cache: `AppCompatCache`, and `AppCompatibility` on Windows XP.
const CACHE_KEYS: [&str; 2] = [
    r"Control\Session Manager\AppCompatCache",
    r"Control\Session Manager\AppCompatibility",
];

/// A `SYSTEM` hive's AppCompatCaches.
#[derive(Debug, Clone)]
pub struct SystemCaches {
    /// What was done with the hive's transaction logs.
    pub recovery: Recovery,
    /// The control set in use (`Select\Current`).
    pub current_control_set: Option<u32>,
    /// The system's architecture (`PROCESSOR_ARCHITECTURE` of the current control set is `x86`),
    /// when the hive records it.
    pub is_32bit: Option<bool>,
    /// The control sets with a cache key, in order.
    pub control_sets: Vec<ControlSetCache>,
}

/// One control set's cache.
#[derive(Debug, Clone)]
pub struct ControlSetCache {
    /// Its number (`ControlSet001` is 1).
    pub control_set: u32,
    /// The cache key's path in the hive.
    pub key_path: String,
    /// When the cache key was last written (FILETIME): when Windows last saved the cache.
    pub key_last_written: u64,
    /// The decoded cache; `None` when the value is missing or not a cache (see `error`).
    pub cache: Option<Cache>,
    /// Why there is no cache.
    pub error: Option<String>,
    /// Entries recovered from the slack of the value's cell that are not in the cache.
    pub slack: Vec<ShimcacheEntry>,
}

/// One row of output: a control set's entry, and whether the same entry (time and path) was in
/// an earlier control set or earlier in this one (AppCompatCacheParser's `Duplicate`).
#[derive(Debug, Clone, Copy)]
pub struct Row<'a> {
    /// The control set.
    pub control_set: u32,
    /// The entry.
    pub entry: &'a ShimcacheEntry,
    /// Seen before.
    pub duplicate: bool,
}

impl SystemCaches {
    /// Every entry in AppCompatCacheParser's order: each control set's cache, then its slack.
    #[must_use]
    pub fn rows(&self) -> Vec<Row<'_>> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for cs in &self.control_sets {
            let entries = cs
                .cache
                .iter()
                .flat_map(|c| c.entries.iter())
                .chain(cs.slack.iter());
            for e in entries {
                out.push(Row {
                    control_set: cs.control_set,
                    entry: e,
                    duplicate: !seen.insert(e.key()),
                });
            }
        }
        out
    }
}

/// The transaction logs next to `hive_path`: its name with `.LOG`, `.LOG1` or `.LOG2`, in any
/// case, that are not empty.
#[must_use]
pub fn find_logs(hive_path: &Path) -> Vec<LogFile> {
    let Some(name) = hive_path
        .file_name()
        .map(|n| n.to_string_lossy().to_uppercase())
    else {
        return Vec::new();
    };
    let dir = hive_path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let wanted: Vec<String> = [".LOG", ".LOG1", ".LOG2"]
        .iter()
        .map(|x| format!("{name}{x}"))
        .collect();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut logs: Vec<LogFile> = entries
        .flatten()
        .filter(|e| wanted.contains(&e.file_name().to_string_lossy().to_uppercase()))
        .filter_map(|e| {
            let data = std::fs::read(e.path()).ok().filter(|d| !d.is_empty())?;
            Some(LogFile {
                name: e.file_name().to_string_lossy().to_string(),
                data,
            })
        })
        .collect();
    logs.sort_by_key(|l| l.name.to_uppercase());
    logs
}

/// Read a `SYSTEM` hive file's caches, with its transaction logs (next to it) when it is dirty.
///
/// # Errors
/// When the file can't be read or is not a hive.
pub fn read_system_file(path: &Path) -> Result<SystemCaches, HiveError> {
    let data = std::fs::read(path).map_err(|e| HiveError(e.to_string()))?;
    read_system(data, &find_logs(path))
}

/// Read a `SYSTEM` hive's caches: every `ControlSetNNN` with a cache key, the value decoded with
/// the system's architecture, and the entries in the slack of its cell.
///
/// # Errors
/// When `hive` is not a hive.
pub fn read_system(hive: Vec<u8>, logs: &[LogFile]) -> Result<SystemCaches, HiveError> {
    let (hive, recovery) = Hive::open(hive, logs)?;
    let current_control_set = hive
        .key("Select")
        .and_then(|k| k.value("Current"))
        .and_then(|v| v.text().parse::<u32>().ok());
    let is_32bit = current_control_set.and_then(|cs| {
        hive.key(&format!(
            r"ControlSet{cs:03}\Control\Session Manager\Environment"
        ))
        .and_then(|k| k.value("PROCESSOR_ARCHITECTURE"))
        .map(|v| v.text() == "x86")
    });
    let mut sets: Vec<(u32, hive::Key<'_>)> = hive
        .root()
        .map(|r| r.subkeys())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|k| {
            let name = k.name();
            name.get(..10)
                .filter(|p| p.eq_ignore_ascii_case("ControlSet"))?;
            let digits = name
                .get(10..)
                .filter(|d| d.len() == 3 && d.bytes().all(|b| b.is_ascii_digit()))?;
            Some((digits.parse().ok()?, k))
        })
        .collect();
    sets.sort_by_key(|(n, _)| *n);
    let mut control_sets = Vec::new();
    for (n, set) in sets {
        let Some((key, sub)) = CACHE_KEYS.iter().find_map(|p| {
            let mut k = set;
            for part in p.split('\\') {
                k = k.subkey(part)?;
            }
            Some((k, p))
        }) else {
            continue;
        };
        let mut cs = ControlSetCache {
            control_set: n,
            key_path: format!(r"{}\{sub}", set.name()),
            key_last_written: key.last_written(),
            cache: None,
            error: None,
            slack: Vec::new(),
        };
        match key.value("AppCompatCache") {
            None => cs.error = Some("no AppCompatCache value".to_owned()),
            Some(v) => {
                let (data, slack) = v.data_and_slack();
                match decode(&data, is_32bit) {
                    Ok(cache) => {
                        cs.slack = recover_slack(&slack, &cache);
                        cs.cache = Some(cache);
                    }
                    Err(e) => cs.error = Some(e.to_string()),
                }
            }
        }
        control_sets.push(cs);
    }
    Ok(SystemCaches {
        recovery,
        current_control_set,
        is_32bit,
        control_sets,
    })
}

/// The result of analyzing an AppCompatCache value.
#[derive(Debug, Clone)]
pub struct ShimcacheReport {
    /// The control set the value was read from (e.g. `ControlSet001`), for provenance.
    pub control_set: String,
    /// The detected AppCompatCache format.
    pub format: ShimcacheFormat,
    /// The decoded cache entries, in cache order (most-recent first).
    pub entries: Vec<ShimcacheEntry>,
    /// Graded anomalies (may be empty).
    pub anomalies: Vec<ShimcacheAnomaly>,
}

/// A graded ShimCache finding. Each variant is a *high-precision* triage signal — it stays quiet
/// on benign entries (a normal `System32` binary) and fires only on a genuinely anomalous pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShimcacheAnomaly {
    /// A Windows system-binary *name* recorded at a path that is not under `System32`/`SysWOW64`
    /// — consistent with masquerading (`T1036.005`).
    SystemBinaryRelocated {
        /// The system-binary base name (e.g. `SVCHOST.EXE`).
        name: String,
        /// The full path ShimCache recorded.
        path: String,
    },
    /// An entry whose path is a directory commonly used to stage malware (Temp, Downloads,
    /// `$Recycle.Bin`, …) — `T1204`. `executed` carries the execution flag when known.
    SuspiciousPath {
        /// The executable base name.
        executable: String,
        /// The suspicious path.
        path: String,
        /// Whether the entry's execution flag was set (`None` where the format has none).
        executed: Option<bool>,
    },
}

/// Decode an AppCompatCache value blob and audit it. `control_set` is recorded on the report for
/// provenance (pass e.g. `"ControlSet001"`, or `""` if unknown).
///
/// # Errors
/// [`ShimcacheError`] if the blob is not a recognized AppCompatCache format.
pub fn analyze_blob(
    blob: &[u8],
    control_set: impl Into<String>,
) -> Result<ShimcacheReport, ShimcacheError> {
    let cache = decode(blob, None)?;
    let anomalies = audit(&cache.entries);
    Ok(ShimcacheReport {
        control_set: control_set.into(),
        format: cache.format,
        entries: cache.entries,
        anomalies,
    })
}

/// Audit decoded ShimCache entries for graded anomalies (may be empty).
#[must_use]
pub fn audit(entries: &[ShimcacheEntry]) -> Vec<ShimcacheAnomaly> {
    let mut out = Vec::new();
    for e in entries {
        let name = base_name(&e.path);
        // System-binary baseline + suspicious-location list are shared DFIR knowledge — they
        // live in forensicnomicon, not baked in here.
        if forensicnomicon::processes::is_system32_binary(&name)
            && !in_windows_system_directory(&e.path)
        {
            out.push(ShimcacheAnomaly::SystemBinaryRelocated {
                name: name.to_uppercase(),
                path: e.path.clone(),
            });
        }
        if forensicnomicon::heuristics::paths::is_suspicious_exec_path(&e.path) {
            out.push(ShimcacheAnomaly::SuspiciousPath {
                executable: name,
                path: e.path.clone(),
                executed: e.executed,
            });
        }
    }
    out
}

/// Whether `path` is in Windows' own `System32` or `SysWOW64` (or a folder in them): under the
/// Windows directory of a drive (`C:\Windows`, `C:\WINNT`, also as `\\?\C:\Windows`), of the
/// system volume as Windows 8 records it (`SYSVOL\Windows`), or of `%SystemRoot%`, `%windir%` or
/// `\SystemRoot`. A `System32` folder anywhere else (`C:\Program Files\Vendor\System32`) is
/// not Windows'.
fn in_windows_system_directory(path: &str) -> bool {
    let upper = path.replace('/', "\\").to_uppercase();
    let p = [r"\\?\", r"\\.\", r"\??\"]
        .iter()
        .find_map(|prefix| upper.strip_prefix(prefix))
        .unwrap_or(&upper);
    let system = |rest: &str| rest.starts_with("SYSTEM32\\") || rest.starts_with("SYSWOW64\\");
    if let Some(rest) = ["%SYSTEMROOT%\\", "%WINDIR%\\", "\\SYSTEMROOT\\"]
        .iter()
        .find_map(|root| p.strip_prefix(root))
    {
        return system(rest);
    }
    let b = p.as_bytes();
    let volume = if let Some(rest) = p.strip_prefix("SYSVOL\\") {
        rest
    } else if b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\' {
        &p[3..]
    } else {
        return false;
    };
    ["WINDOWS\\", "WINNT\\"]
        .iter()
        .find_map(|windows| volume.strip_prefix(windows))
        .is_some_and(system)
}

/// The base name (last `\`/`/`-component) of a Windows path.
fn base_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

impl Observation for ShimcacheAnomaly {
    fn severity(&self) -> Option<Severity> {
        Some(match self {
            ShimcacheAnomaly::SystemBinaryRelocated { .. } => Severity::High,
            ShimcacheAnomaly::SuspiciousPath { .. } => Severity::Medium,
        })
    }

    fn category(&self) -> Category {
        match self {
            ShimcacheAnomaly::SystemBinaryRelocated { .. } => Category::Concealment,
            ShimcacheAnomaly::SuspiciousPath { .. } => Category::Threat,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            ShimcacheAnomaly::SystemBinaryRelocated { .. } => "SHIMCACHE-SYSTEM-BINARY-RELOCATED",
            ShimcacheAnomaly::SuspiciousPath { .. } => "SHIMCACHE-SUSPICIOUS-PATH",
        }
    }

    fn note(&self) -> String {
        match self {
            ShimcacheAnomaly::SystemBinaryRelocated { name, path } => format!(
                "{name} is a Windows system binary, but AppCompatCache recorded it at {path} \
                 — consistent with masquerading."
            ),
            ShimcacheAnomaly::SuspiciousPath {
                executable,
                path,
                executed,
            } => {
                let ran = match executed {
                    Some(true) => " (execution flag set)",
                    Some(false) => " (no execution flag)",
                    None => "",
                };
                format!(
                    "{executable} at {path} sits in a directory commonly used to stage malware\
                     {ran} — consistent with suspicious execution."
                )
            }
        }
    }

    fn mitre(&self) -> &'static [&'static str] {
        match self {
            ShimcacheAnomaly::SystemBinaryRelocated { .. } => &["T1036.005"],
            ShimcacheAnomaly::SuspiciousPath { .. } => &["T1204"],
        }
    }

    fn subjects(&self) -> Vec<SubjectRef> {
        let (name, path) = match self {
            ShimcacheAnomaly::SystemBinaryRelocated { name, path } => (name, path),
            ShimcacheAnomaly::SuspiciousPath {
                executable, path, ..
            } => (executable, path),
        };
        vec![SubjectRef {
            scheme: "filesystem".to_string(),
            kind: "executable".to_string(),
            id: path.clone(),
            label: Some(name.clone()),
        }]
    }
}

/// Convenience: produce a [`Finding`] for an anomaly under the given scope.
#[must_use]
pub fn to_finding(anomaly: &ShimcacheAnomaly, scope: impl Into<String>) -> Finding {
    anomaly.to_finding(Source {
        analyzer: "shimcache-forensic".to_string(),
        scope: scope.into(),
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    })
}

#[cfg(test)]
mod tests;
