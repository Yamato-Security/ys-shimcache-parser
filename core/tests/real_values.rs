//! Real AppCompatCache values against a second, independent parser (its library's output for
//! each, `data/oracle.jsonl`): every entry's position, path, time, executed flag,
//! insertion flags and data size, the header's entry count and the problems. The values: the
//! DFIR Artifact Museum's (MIT, `data/museum/`; one taken from its Windows Server 2012 R2 SYSTEM
//! hive, whose first dword is 0), artemis's (MIT, `data/artemis/`, one of them damaged) and the
//! NIST CFReDS Data Leakage case's (public domain).
#![allow(clippy::unwrap_used)]

use serde_json::Value;
use shimcache_core::decode;

fn data(rel: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/data/{rel}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

#[test]
fn every_value_reads_as_the_oracle_reads_it() {
    let jsonl = String::from_utf8(data("oracle.jsonl")).unwrap();
    let mut values = 0;
    let mut entries = 0;
    for line in jsonl.lines() {
        let oracle: Value = serde_json::from_str(line).unwrap();
        let file = oracle["file"].as_str().unwrap();
        let cache = decode(&data(file), None).unwrap();
        assert_eq!(cache.format.name(), oracle["os"], "{file}");
        let want = &oracle["caches"][0];
        let expected = want["expected"].as_i64().unwrap();
        if expected >= 0 {
            assert_eq!(cache.expected_entries, Some(expected as u32), "{file}");
        }
        // the oracle's problems, and where a signed cache ends before its header's
        // count (two of artemis's values are its first entries only), the note it doesn't make
        let (notes, problems): (Vec<_>, Vec<_>) = cache
            .problems
            .iter()
            .partition(|p| p.starts_with("The header gives"));
        assert_eq!(
            problems.len(),
            want["errors"].as_array().unwrap().len(),
            "{file}: {problems:?}"
        );
        let cut = matches!(
            file,
            "artemis/win10Creatorsshim.raw" | "artemis/win11shim.raw"
        );
        assert_eq!(notes.len(), usize::from(cut), "{file}: {notes:?}");
        let ee = want["entries"].as_array().unwrap();
        assert_eq!(cache.entries.len(), ee.len(), "{file}");
        for (e, x) in cache.entries.iter().zip(ee) {
            let at = format!("{file} entry {}", e.position);
            assert_eq!(e.position as u64, x["pos"].as_u64().unwrap(), "{at}");
            assert_eq!(e.path, x["path"].as_str().unwrap(), "{at}");
            assert_eq!(e.last_modified(), x["ft"].as_u64(), "{at}");
            let executed = match e.executed {
                Some(true) => "Yes",
                Some(false) => "No",
                None => "NA",
            };
            assert_eq!(executed, x["executed"], "{at}");
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
            entries += 1;
        }
        values += 1;
    }
    assert_eq!((values, entries), (14, 3709));
}
