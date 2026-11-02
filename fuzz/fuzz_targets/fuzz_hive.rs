// Copyright (C) 2026 Shirofune Security Co., Ltd.
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
