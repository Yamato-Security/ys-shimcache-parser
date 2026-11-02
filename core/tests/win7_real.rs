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

//! Tier-1 validation against a **real** Windows 7 64-bit AppCompatCache value blob extracted
//! from the NIST CFReDS "Data Leakage" case `SYSTEM` hive (public domain).
//!
//! Ground truth is cross-confirmed by two independent implementations: Mandiant's
//! `ShimCacheParser` (which parsed 291 entries and identifies the blob as "64bit Windows
//! 7/2k8-R2") and a from-spec read against libyal's dtfabric `appcompatcache.yaml`. The header
//! records `number_of_cached_entries = 292`; both spec-faithful reads yield 292 entries (Mandiant
//! excludes one trailing record). We assert the header-authoritative count of 292 and the exact
//! path + `FILETIME` + execution flag of specific entries both oracles agree on.
//!
//! Provenance: `core/tests/data/README.md`.
#![allow(clippy::unwrap_used)]

use shimcache_core::{ShimcacheFormat, detect_format, parse};

const BLOB: &[u8] = include_bytes!("data/win7_appcompatcache.bin");

#[test]
fn cfreds_win7_blob_is_detected_as_win7_64bit() {
    assert_eq!(detect_format(BLOB, None), Some(ShimcacheFormat::Win7_64));
}

#[test]
fn cfreds_win7_blob_decodes_all_292_entries_with_known_values() {
    let entries = parse(BLOB).unwrap();
    assert_eq!(entries.len(), 292, "header records 292 cached entries");

    // First entry — LogonUI.exe, executed, last-modified FILETIME 129347834495725262
    // (2010-11-21 03:24:09 UTC), agreed by Mandiant + the from-spec read.
    assert_eq!(entries[0].path, r"C:\Windows\system32\LogonUI.exe");
    assert_eq!(entries[0].last_modified_filetime, 129_347_834_495_725_262);
    assert_eq!(entries[0].executed, Some(true));

    // Second entry — SearchFilterHost.exe.
    assert_eq!(entries[1].path, r"C:\Windows\system32\SearchFilterHost.exe");
    assert_eq!(entries[1].last_modified_filetime, 128_920_091_770_490_000);

    // Last entry — bfsvc.exe.
    let last = entries.last().unwrap();
    assert_eq!(last.path, r"C:\Windows\bfsvc.exe");
    assert_eq!(last.last_modified_filetime, 129_347_834_628_481_495);
    assert_eq!(last.executed, Some(true));

    // The '\??\' device prefix must be stripped on every entry.
    assert!(entries.iter().all(|e| !e.path.starts_with(r"\??\")));
}
