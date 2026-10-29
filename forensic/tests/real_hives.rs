//! Real `SYSTEM` hives against a second, independent parser (its library's output and its CSV
//! for each, `data/oracle/`), through the library and the `ys-shimcache-parser` binary:
//!
//! - the DFIR Artifact Museum's dirty Windows 11 hive (MIT) with its two transaction logs, and
//!   without them;
//! - python-registry's dirty Windows 8.1 hives (Apache-2.0) with new-format logs: as they are,
//!   with the logs' names swapped, and with an invalid base block (whose logs then give the base
//!   block);
//! - regipy's Windows 7 32-bit hive (MIT) with two control sets.
#![allow(clippy::unwrap_used)]

use serde_json::Value;
use shimcache_forensic::{SystemCaches, read_system_file};
use std::io::Read;
use std::path::{Path, PathBuf};

fn data() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data")
}

/// `files` (gzipped fixtures, renamed) in a directory of their own.
fn scenario(name: &str, files: &[(&str, &str)]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("shimcache-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for (from, to) in files {
        let mut gz = flate2::read::GzDecoder::new(std::fs::File::open(data().join(from)).unwrap());
        let mut bytes = Vec::new();
        gz.read_to_end(&mut bytes).unwrap();
        std::fs::write(dir.join(to), bytes).unwrap();
    }
    dir
}

const W11: &str = "museum/Win11/RathbunVM";
const LOG1: &str = "python-registry/new_log_1";

fn check(name: &str, dir: &Path) -> SystemCaches {
    let caches = read_system_file(&dir.join("SYSTEM")).unwrap();
    let oracle: Value = serde_json::from_str(
        &std::fs::read_to_string(data().join(format!("oracle/{name}.json"))).unwrap(),
    )
    .unwrap();
    let want = oracle["caches"].as_array().unwrap();
    assert_eq!(caches.control_sets.len(), want.len(), "{name}");
    for (cs, x) in caches.control_sets.iter().zip(want) {
        assert_eq!(
            u64::from(cs.control_set),
            x["control_set"].as_u64().unwrap(),
            "{name}"
        );
        let cache = cs.cache.as_ref().unwrap();
        assert_eq!(cache.format.name(), oracle["os"], "{name}");
        assert_eq!(
            cache.problems.len(),
            x["errors"].as_array().unwrap().len(),
            "{name}"
        );
        for (list, xs) in [(&cache.entries, &x["entries"]), (&cs.slack, &x["slack"])] {
            let xs = xs.as_array().unwrap();
            assert_eq!(list.len(), xs.len(), "{name}");
            for (e, x) in list.iter().zip(xs) {
                let at = format!(
                    "{name} ControlSet{:03} entry {}",
                    cs.control_set, e.position
                );
                assert_eq!(e.position as u64, x["pos"].as_u64().unwrap(), "{at}");
                assert_eq!(e.path, x["path"].as_str().unwrap(), "{at}");
                assert_eq!(e.last_modified(), x["ft"].as_u64(), "{at}");
                assert_eq!(
                    e.insert_flags.unwrap_or(0),
                    x["flags"].as_u64().unwrap() as u32,
                    "{at}"
                );
                assert_eq!(
                    e.data.len() as u64,
                    x["data_size"].as_u64().unwrap(),
                    "{at}"
                );
            }
        }
    }
    // the CSV, as the oracle writes it (SourceFile aside)
    let out = dir.join("out.csv");
    let run = std::process::Command::new(env!("CARGO_BIN_EXE_ys-shimcache-parser"))
        .arg(dir.join("SYSTEM"))
        .args(["--csv", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{name}: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let source = dir.join("SYSTEM").to_string_lossy().to_string();
    let ours = std::fs::read_to_string(&out)
        .unwrap()
        .replace(&source, "SYSTEM");
    let theirs = std::fs::read_to_string(data().join(format!("oracle/{name}.csv")))
        .unwrap()
        .replace("\r\n", "\n");
    assert_eq!(ours.trim_end(), theirs.trim_end(), "{name}");
    caches
}

#[test]
fn a_dirty_windows11_hive_with_its_logs() {
    let dir = scenario(
        "w11",
        &[
            (&format!("{W11}/SYSTEM.gz"), "SYSTEM"),
            (&format!("{W11}/SYSTEM.LOG1.gz"), "SYSTEM.LOG1"),
            (&format!("{W11}/SYSTEM.LOG2.gz"), "SYSTEM.LOG2"),
        ],
    );
    let c = check("museum-win11", &dir);
    assert!(c.recovery.dirty && c.recovery.recovered);
    assert_eq!(c.recovery.logs_applied, ["SYSTEM.LOG1", "SYSTEM.LOG2"]);
    assert_eq!(c.recovery.last_sequence, Some(635));
    assert_eq!((c.current_control_set, c.is_32bit), (Some(1), Some(false)));
    assert_eq!(c.select.last_known_good, Some(1));
    assert_eq!(c.control_sets[0].value_size, Some(80_260));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_dirty_hive_without_its_logs_is_read_as_it_is() {
    let dir = scenario("w11-nologs", &[(&format!("{W11}/SYSTEM.gz"), "SYSTEM")]);
    let c = check("museum-win11-no-logs", &dir);
    assert!(c.recovery.dirty && !c.recovery.recovered);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn new_format_logs_in_either_order() {
    for (name, l1, l2) in [
        ("pr-new-log-1", "SYSTEM.LOG1", "SYSTEM.LOG2"),
        ("pr-new-log-1-reversed", "SYSTEM.LOG2", "SYSTEM.LOG1"),
    ] {
        let dir = scenario(
            name,
            &[
                (&format!("{LOG1}/SYSTEM.gz"), "SYSTEM"),
                (&format!("{LOG1}/SYSTEM.LOG1.gz"), l1),
                (&format!("{LOG1}/SYSTEM.LOG2.gz"), l2),
            ],
        );
        let c = check(name, &dir);
        assert!(c.recovery.recovered, "{name}: {:?}", c.recovery.messages);
        let _ = std::fs::remove_dir_all(dir);
    }
    let dir = scenario(
        "pr2",
        &[
            ("python-registry/new_log_2/SYSTEM.gz", "SYSTEM"),
            ("python-registry/new_log_2/SYSTEM.LOG1.gz", "SYSTEM.LOG1"),
            ("python-registry/new_log_2/SYSTEM.LOG2.gz", "SYSTEM.LOG2"),
        ],
    );
    assert!(check("pr-new-log-2", &dir).recovery.recovered);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_hive_whose_base_block_is_invalid_takes_the_latest_log() {
    let dir = scenario(
        "pr-invalid",
        &[
            (&format!("{LOG1}/SYSTEM.gz"), "SYSTEM"),
            (&format!("{LOG1}/SYSTEM.LOG1.gz"), "SYSTEM.LOG2"),
            (&format!("{LOG1}/SYSTEM.LOG2.gz"), "SYSTEM.LOG1"),
        ],
    );
    let path = dir.join("SYSTEM");
    let mut b = std::fs::read(&path).unwrap();
    for x in &mut b[0x1fc..0x200] {
        *x ^= 0xff;
    }
    std::fs::write(&path, b).unwrap();
    let c = check("pr-new-log-1-invalid-checksum", &dir);
    assert!(c.recovery.recovered);
    assert_eq!(
        c.recovery.logs_applied.len(),
        1,
        "{:?}",
        c.recovery.messages
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_32bit_windows7_hive_with_two_control_sets() {
    let dir = scenario("w7", &[("regipy/SYSTEM.gz", "SYSTEM")]);
    let c = check("regipy-system", &dir);
    assert!(!c.recovery.dirty);
    assert_eq!(c.is_32bit, Some(true));
    // it uses ControlSet001 and last started from ControlSet002
    assert_eq!(
        (
            c.select.current,
            c.select.default,
            c.select.last_known_good,
            c.select.failed
        ),
        (Some(1), Some(1), Some(2), Some(0))
    );
    let sizes: Vec<Option<usize>> = c.control_sets.iter().map(|cs| cs.value_size).collect();
    assert_eq!(sizes, [Some(56_256), Some(56_256)]);
    let rows = c.rows();
    assert_eq!(rows.len(), 660);
    // the second control set's entries are the first's
    assert!(rows.iter().all(|r| r.duplicate == (r.control_set == 2)));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_log_whose_entries_are_damaged_is_not_applied() {
    let dir = scenario(
        "w11-damaged-log",
        &[
            (&format!("{W11}/SYSTEM.gz"), "SYSTEM"),
            (&format!("{W11}/SYSTEM.LOG1.gz"), "SYSTEM.LOG1"),
            (&format!("{W11}/SYSTEM.LOG2.gz"), "SYSTEM.LOG2"),
        ],
    );
    // one byte of the first entry's pages: its hash no longer matches
    let damage = |name: &str| {
        let path = dir.join(name);
        let mut b = std::fs::read(&path).unwrap();
        b[512 + 100] ^= 0xff;
        std::fs::write(&path, b).unwrap();
    };
    damage("SYSTEM.LOG1");
    // LOG1 (entries 620 and 621) gives nothing, so LOG2 (622 to 635) is used
    let c = read_system_file(&dir.join("SYSTEM")).unwrap();
    assert!(c.recovery.recovered, "{:?}", c.recovery.messages);
    assert_eq!(c.recovery.logs_applied, ["SYSTEM.LOG2"]);
    assert_eq!(c.recovery.last_sequence, Some(635));
    damage("SYSTEM.LOG2");
    let c = read_system_file(&dir.join("SYSTEM")).unwrap();
    assert!(c.recovery.dirty && !c.recovery.recovered);
    assert_eq!(c.recovery.logs_applied, Vec::<String>::new());
    assert_eq!(c.recovery.last_sequence, None);
    // the hive is read as it is
    assert_eq!(c.control_sets[0].cache.as_ref().unwrap().entries.len(), 359);
    let _ = std::fs::remove_dir_all(dir);
}
