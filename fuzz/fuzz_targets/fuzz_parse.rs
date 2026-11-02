// Copyright (C) 2026 Shirofune Security Co., Ltd.
// Copyright (c) 2026 Albert Hui
//
// This file is changed from SecurityRonin/shimcache-forensic
// (https://github.com/SecurityRonin/shimcache-forensic), whose code is under the Apache License 2.0
// (LICENSE-APACHE).
//
// Unless explicitly acquired and licensed from Licensor under another license, the contents of this
// file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
// allowed by the RPL, and You may not copy or use this file in either source code or executable
// form, except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
// and limitations under the RPL.

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
