//! Fuzz target: arbitrary bytes as an AppCompatCache value, and as the slack after one.
//! Invariant: `decode`, `recover_slack` and the entries' accessors never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for hint in [None, Some(true), Some(false)] {
        let _ = shimcache_core::detect_format(data, hint);
        if let Ok(cache) = shimcache_core::decode(data, hint) {
            let _ = shimcache_core::recover_slack(data, &cache);
            for e in &cache.entries {
                let _ = (e.data_tags(), e.machine(), e.package_record(), e.last_modified());
            }
        }
    }
});
