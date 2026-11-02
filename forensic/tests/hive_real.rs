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

//! Tier-1 end-to-end validation of the `ys-shimcache-parser` binary against a real `SYSTEM`
//! hive — exercises the hive reader's control-set navigation + `AppCompatCache` value extraction
//! that the library's `analyze_blob` does not. Env-gated on `SHIMCACHE_TEST_SYSTEM_HIVE`.
//!
//! Point it at the NIST CFReDS "Data Leakage" `SYSTEM` hive (public domain) — the same blob that
//! `core/tests/data/win7_appcompatcache.bin` was extracted from, so the whole-hive path must yield
//! the identical 292 entries plus the Recycle-Bin suspicious-execution lead.
#![allow(clippy::unwrap_used)]

#[test]
fn ys_shimcache_parser_analyzes_a_real_system_hive_end_to_end() {
    let Ok(path) = std::env::var("SHIMCACHE_TEST_SYSTEM_HIVE") else {
        eprintln!("SKIP: set SHIMCACHE_TEST_SYSTEM_HIVE to a real SYSTEM hive (e.g. CFReDS)");
        return;
    };
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_ys-shimcache-parser"))
        .arg(&path)
        .output()
        .expect("run ys-shimcache-parser");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "ys-shimcache-parser failed: {:?}",
        out.status
    );
    // The whole-hive path reads Win7-64 AppCompatCache from ControlSet001 → 292 entries.
    assert!(
        stdout.contains("Windows7x64_Windows2008R2, ControlSet001, 292 entries"),
        "unexpected summary; got: {stdout}"
    );
    // …and surfaces the Recycle-Bin execution lead (high-value in a data-leakage case).
    assert!(
        stdout.contains(r"$Recycle.Bin") && stdout.contains("SHIMCACHE-SUSPICIOUS-PATH"),
        "expected the Recycle-Bin suspicious-path finding; got: {stdout}"
    );
}
