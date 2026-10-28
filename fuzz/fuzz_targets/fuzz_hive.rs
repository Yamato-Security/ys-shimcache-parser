//! Fuzz target: arbitrary bytes as a SYSTEM hive (and as its transaction log).
//! Invariant: opening it, replaying the log and reading every control set never panic or hang.
#![no_main]
use libfuzzer_sys::fuzz_target;
use shimcache_forensic::{read_system, LogFile};

fuzz_target!(|data: &[u8]| {
    let _ = read_system(data.to_vec(), &[]).map(|c| c.rows().len());
    // the second half as a log of the first
    let (hive, log) = data.split_at(data.len() / 2);
    let logs = [LogFile { name: "SYSTEM.LOG1".to_owned(), data: log.to_vec() }];
    let _ = read_system(hive.to_vec(), &logs).map(|c| c.rows().len());
});
