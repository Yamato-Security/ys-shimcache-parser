//! Real AppCompatCache values against Eric Zimmerman's AppCompatCacheParser (its library's
//! output for each, `data/oracle.jsonl`): every entry's position, path, time, executed flag,
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
fn every_value_reads_as_appcompatcacheparser_reads_it() {
    let oracle = String::from_utf8(data("oracle.jsonl")).unwrap();
    let mut values = 0;
    let mut entries = 0;
    for line in oracle.lines() {
        let ez: Value = serde_json::from_str(line).unwrap();
        let file = ez["file"].as_str().unwrap();
        let cache = decode(&data(file), None).unwrap();
        assert_eq!(cache.format.name(), ez["os"], "{file}");
        let ec = &ez["caches"][0];
        let expected = ec["expected"].as_i64().unwrap();
        if expected >= 0 {
            assert_eq!(cache.expected_entries, Some(expected as u32), "{file}");
        }
        assert_eq!(
            cache.problems.len(),
            ec["errors"].as_array().unwrap().len(),
            "{file}: {:?}",
            cache.problems
        );
        let ee = ec["entries"].as_array().unwrap();
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
