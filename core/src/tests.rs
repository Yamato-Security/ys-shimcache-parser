//! Values built here in each format (as Eric Zimmerman's AppCompatCacheParser tests build
//! them): the executed flags, layouts, Windows XP's LRU order, damage, slack. The real values are
//! in `tests/`.

use super::*;

const WHEN: u64 = 133_000_000_000_000_000; // 2022-06-14
const DAY: u64 = 864_000_000_000;

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn u32b(n: u32) -> Vec<u8> {
    n.to_le_bytes().to_vec()
}

/// Windows 10 / 11 data: (tag, size, value) records, 4-byte aligned.
fn tags(records: &[(u32, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (tag, value) in records {
        out.extend(u32b(*tag));
        out.extend(u32b(value.len() as u32));
        out.extend_from_slice(value);
        while out.len() % 4 != 0 {
            out.push(0);
        }
    }
    out
}

fn win10_entry(path: &str, ft: u64, data: &[u8]) -> Vec<u8> {
    let p = utf16(path);
    let mut body = Vec::new();
    body.extend((p.len() as u16).to_le_bytes());
    body.extend(&p);
    body.extend(ft.to_le_bytes());
    body.extend(u32b(data.len() as u32));
    body.extend(data);
    let mut e = b"10ts".to_vec();
    e.extend(u32b(0x1234));
    e.extend(u32b(body.len() as u32));
    e.extend(body);
    e
}

fn win10(creators: bool, entries: &[Vec<u8>]) -> Vec<u8> {
    let header = if creators { 0x34 } else { 0x30 };
    let mut v = vec![0u8; header];
    v[..4].copy_from_slice(&(header as u32).to_le_bytes());
    let count_at = if creators { 0x28 } else { 0x24 };
    v[count_at..count_at + 4].copy_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        v.extend(e);
    }
    v
}

/// Windows 8.1 (`10ts`) or 8.0 (`00ts`): (path, time, insertion flags, package, data).
fn win8(v81: bool, entries: &[(&str, u64, u32, &str, &[u8])]) -> Vec<u8> {
    let mut v = vec![0u8; 128];
    v[..4].copy_from_slice(&0x80u32.to_le_bytes());
    for (path, ft, flags, package, data) in entries {
        let p = utf16(path);
        let pk = utf16(package);
        let mut body = Vec::new();
        body.extend((p.len() as u16).to_le_bytes());
        body.extend(&p);
        body.extend((pk.len() as u16).to_le_bytes());
        body.extend(&pk);
        body.extend(u32b(*flags));
        body.extend(u32b(0x55));
        body.extend(ft.to_le_bytes());
        body.extend(u32b(data.len() as u32));
        body.extend(*data);
        v.extend(if v81 { b"10ts" } else { b"00ts" });
        v.extend(u32b(7));
        v.extend(u32b(body.len() as u32));
        v.extend(body);
    }
    v
}

/// Windows 7 (`win7`) or 2003 / Vista table, 32 or 64 bit: (path, time, flags).
fn table(win7: bool, is32: bool, entries: &[(&str, u64, u32)]) -> Vec<u8> {
    let start = if win7 { 128 } else { 8 };
    let size = match (win7, is32) {
        (true, true) | (false, false) => 32,
        (true, false) => 48,
        (false, true) => 24,
    };
    let mut v = vec![0u8; start + entries.len() * size];
    v[..4].copy_from_slice(&(if win7 { 0xbadc_0fee_u32 } else { 0xbadc_0ffe }).to_le_bytes());
    v[4..8].copy_from_slice(&(entries.len() as u32).to_le_bytes());
    for (i, (path, ft, flags)) in entries.iter().enumerate() {
        let p = utf16(path);
        let offset = v.len() as u64;
        v.extend(&p);
        let at = start + i * size;
        v[at..at + 2].copy_from_slice(&(p.len() as u16).to_le_bytes());
        v[at + 2..at + 4].copy_from_slice(&(p.len() as u16 + 2).to_le_bytes());
        let (po, t, f) = if is32 { (4, 8, 16) } else { (8, 16, 24) };
        if is32 {
            v[at + po..at + po + 4].copy_from_slice(&(offset as u32).to_le_bytes());
        } else {
            v[at + po..at + po + 8].copy_from_slice(&offset.to_le_bytes());
        }
        v[at + t..at + t + 8].copy_from_slice(&ft.to_le_bytes());
        v[at + f..at + f + 4].copy_from_slice(&flags.to_le_bytes());
    }
    v
}

/// Windows XP: the LRU array, and slots (path, last modified, last update).
fn xp(lru: &[u32], slots: &[(&str, u64, u64)]) -> Vec<u8> {
    let mut v = vec![0u8; XP_HEADER + 96 * XP_SLOT];
    v[..4].copy_from_slice(&0xdead_beef_u32.to_le_bytes());
    v[4..8].copy_from_slice(&96u32.to_le_bytes());
    v[8..12].copy_from_slice(&(lru.len() as u32).to_le_bytes());
    for (i, s) in lru.iter().enumerate() {
        v[16 + i * 4..20 + i * 4].copy_from_slice(&s.to_le_bytes());
    }
    for (i, (path, ft, updated)) in slots.iter().enumerate() {
        let at = XP_HEADER + i * XP_SLOT;
        let p = utf16(path);
        v[at..at + p.len()].copy_from_slice(&p);
        v[at + 528..at + 536].copy_from_slice(&ft.to_le_bytes());
        v[at + 536..at + 544].copy_from_slice(&1234u64.to_le_bytes());
        v[at + 544..at + 552].copy_from_slice(&updated.to_le_bytes());
    }
    v
}

fn paths(c: &Cache) -> Vec<&str> {
    c.entries.iter().map(|e| e.path.as_str()).collect()
}

#[test]
fn windows10_executed_is_tag_0x100() {
    // "the last 4 bytes are 1" only works when tag 0x100 is the last record
    let one = u32b(1);
    let zero = u32b(0);
    let x64: &[u8] = &[0x64, 0x86];
    let v = win10(
        true,
        &[
            win10_entry(
                r"C:\a.exe",
                WHEN,
                &tags(&[(0x200, &zero), (0x800, x64), (0x100, &one), (0x20, &zero)]),
            ),
            win10_entry(
                r"C:\b.exe",
                WHEN,
                &tags(&[(0x200, &zero), (0x800, x64), (0x40, &one)]),
            ),
            win10_entry(r"C:\c.exe", WHEN, &tags(&[(0x200, &one), (0x100, &one)])),
            win10_entry(r"C:\d.exe", WHEN, &tags(&[(0x200, &zero), (0x800, x64)])),
        ],
    );
    let c = decode(&v, None).unwrap();
    assert_eq!(c.format, ShimcacheFormat::Win10Creators);
    assert_eq!(c.format.name(), "Windows10C_11");
    assert_eq!(
        paths(&c),
        [r"C:\a.exe", r"C:\b.exe", r"C:\c.exe", r"C:\d.exe"]
    );
    let executed: Vec<_> = c.entries.iter().map(|e| e.executed).collect();
    assert_eq!(executed, [Some(true), Some(false), Some(true), Some(false)]);
    assert_eq!(c.entries[0].last_modified(), Some(WHEN));
    let t: Vec<u32> = c.entries[0].data_tags().iter().map(|(t, _)| *t).collect();
    assert_eq!(t, [0x200, 0x800, 0x100, 0x20]);
    assert_eq!(c.entries[0].machine(), Some(0x8664));
    assert_eq!(c.entries[2].machine(), None);
    assert_eq!(c.expected_entries, Some(4));
}

#[test]
fn windows10_entries_with_little_or_no_data_are_read() {
    let v = win10(
        false,
        &[
            win10_entry(r"C:\a.exe", WHEN, &[]),
            win10_entry(r"C:\b.exe", 0, &[1, 2]),
            win10_entry(r"C:\c.exe", WHEN, &tags(&[(0x100, &u32b(1))])),
        ],
    );
    let c = decode(&v, None).unwrap();
    assert_eq!(c.format, ShimcacheFormat::Win10);
    assert_eq!(paths(&c), [r"C:\a.exe", r"C:\b.exe", r"C:\c.exe"]);
    assert_eq!(c.entries[1].last_modified(), None);
    assert_eq!(c.entries[2].executed, Some(true));
    assert_eq!(c.expected_entries, Some(3));
    assert_eq!(c.problems, Vec::<String>::new());
}

#[test]
fn a_truncated_windows10_value_keeps_the_entries_before() {
    let one = u32b(1);
    let v = win10(
        true,
        &[
            win10_entry(r"C:\a.exe", WHEN, &tags(&[(0x100, &one)])),
            win10_entry(r"C:\b.exe", WHEN, &tags(&[(0x100, &one)])),
        ],
    );
    let c = decode(&v[..v.len() - 6], None).unwrap();
    assert_eq!(paths(&c), [r"C:\a.exe"]);
    assert_eq!(c.problems.len(), 1);
    assert!(
        c.problems[0].starts_with("Entry 1 at offset 0x"),
        "{:?}",
        c.problems
    );
}

#[test]
fn windows8_flags_package_and_data() {
    let v = win8(
        true,
        &[
            (r"\??\C:\a.exe", WHEN, 0x2, "", &[9, 9, 9]),
            (
                r"C:\b.exe",
                WHEN,
                0x4,
                "Microsoft.App_8wekyb3d8bbwe",
                &u32b(0xAABB_CCDD),
            ),
        ],
    );
    let c = decode(&v, None).unwrap();
    assert_eq!(c.format, ShimcacheFormat::Win8_1);
    assert_eq!(paths(&c), [r"C:\a.exe", r"C:\b.exe"]);
    let executed: Vec<_> = c.entries.iter().map(|e| e.executed).collect();
    assert_eq!(executed, [Some(true), Some(false)]);
    assert_eq!(c.entries[1].insert_flags, Some(4));
    assert_eq!(c.entries[1].shim_flags, Some(0x55));
    assert_eq!(c.entries[1].package, "Microsoft.App_8wekyb3d8bbwe");
    assert_eq!(c.entries[1].data, u32b(0xAABB_CCDD));
    assert_eq!(c.entries[1].last_modified(), Some(WHEN));
    assert_eq!(
        decode(&win8(false, &[(r"C:\a.exe", WHEN, 0, "", &[])]), None)
            .unwrap()
            .format,
        ShimcacheFormat::Win8_0
    );
    // the first dword is not always 0x80: the entries' signature at 128 says what it is
    let mut zero = v.clone();
    zero[..4].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(decode(&zero, None).unwrap().entries.len(), 2);
}

#[test]
fn the_windows7_layout_is_checked_against_the_data() {
    for is32 in [true, false] {
        let v = table(
            true,
            is32,
            &[(r"\??\C:\a.exe", WHEN, 0x2), (r"C:\b.exe", WHEN, 0)],
        );
        // the architecture can be wrong, or unknown
        for hint in [Some(true), Some(false), None] {
            let c = decode(&v, hint).unwrap();
            assert_eq!(
                c.format,
                if is32 {
                    ShimcacheFormat::Win7_32
                } else {
                    ShimcacheFormat::Win7_64
                },
                "{is32} {hint:?}"
            );
            assert_eq!(c.expected_entries, Some(2));
            assert_eq!(paths(&c), [r"C:\a.exe", r"C:\b.exe"]);
            let executed: Vec<_> = c.entries.iter().map(|e| e.executed).collect();
            assert_eq!(executed, [Some(true), Some(false)]);
        }
    }
}

#[test]
fn vista_and_2003() {
    for is32 in [true, false] {
        let v = table(
            false,
            is32,
            &[(r"C:\a.exe", WHEN, 0x2), (r"C:\b.exe", WHEN, 0)],
        );
        let c = decode(&v, Some(!is32)).unwrap();
        assert_eq!(
            c.format,
            if is32 {
                ShimcacheFormat::Win2003_32
            } else {
                ShimcacheFormat::Win2003_64
            }
        );
        assert_eq!(c.format.name(), "WindowsVistaWin2k3Win2k8");
        assert_eq!(paths(&c), [r"C:\a.exe", r"C:\b.exe"]);
        // Windows 2003 has the file size where 32-bit Vista has the flags
        let executed: Vec<_> = c.entries.iter().map(|e| e.executed).collect();
        assert_eq!(
            executed,
            if is32 {
                [None, None]
            } else {
                [Some(true), Some(false)]
            }
        );
        assert_eq!(c.entries[0].insert_flags, Some(2));
    }
}

#[test]
fn windows_xp_entries_are_the_lru_array_in_order() {
    // 3 of 96 slots used; the LRU array lists them most recently updated first
    let v = xp(
        &[2, 0, 1],
        &[
            (r"C:\old.exe", WHEN - 1000 * DAY, WHEN - 2 * DAY),
            (r"C:\older.exe", WHEN - 1400 * DAY, WHEN - 3 * DAY),
            (r"C:\new.exe", WHEN - 300 * DAY, WHEN),
        ],
    );
    for hint in [Some(true), Some(false), None] {
        let c = decode(&v, hint).unwrap();
        assert_eq!(c.format, ShimcacheFormat::WinXp);
        assert_eq!(c.expected_entries, Some(3));
        assert_eq!(paths(&c), [r"C:\new.exe", r"C:\old.exe", r"C:\older.exe"]);
        assert_eq!(
            c.entries.iter().map(|e| e.position).collect::<Vec<_>>(),
            [0, 1, 2]
        );
        assert_eq!(c.entries[0].last_update(), Some(WHEN));
        assert_eq!(c.entries[0].last_modified(), Some(WHEN - 300 * DAY));
        assert_eq!(c.entries[0].file_size, Some(1234));
        assert!(c.entries.iter().all(|e| e.executed.is_none()));
    }
    // a slot listed twice, and an LRU array that claims more than its room
    let mut bad = xp(&[0, 0], &[(r"C:\a.exe", WHEN, WHEN)]);
    let c = decode(&bad, None).unwrap();
    assert_eq!(paths(&c), [r"C:\a.exe"]);
    assert!(c.problems[0].contains("more than once"), "{:?}", c.problems);
    bad[8..12].copy_from_slice(&500u32.to_le_bytes());
    let c = decode(&bad, None).unwrap();
    assert_eq!(c.expected_entries, Some(96));
    assert!(c.problems[0].contains("room for 96"), "{:?}", c.problems);
}

#[test]
fn a_damaged_windows7_entry_is_reported_and_the_rest_read() {
    let mut v = table(
        true,
        false,
        &[
            (r"C:\a.exe", WHEN, 0x2),
            (r"C:\b.exe", WHEN, 0),
            (r"C:\c.exe", WHEN, 0),
        ],
    );
    // entry 1's path offset past the end
    v[128 + 48 + 8..128 + 48 + 16].copy_from_slice(&0x7FFF_FFFFu64.to_le_bytes());
    let c = decode(&v, None).unwrap();
    assert_eq!(paths(&c), [r"C:\a.exe", r"C:\c.exe"]);
    assert_eq!(c.problems.len(), 1);
    assert!(c.problems[0].starts_with("Entry 1"), "{:?}", c.problems);
}

#[test]
fn values_that_are_not_caches() {
    for short in [&[][..], &[1, 2, 3]] {
        assert_eq!(
            decode(short, None),
            Err(ShimcacheError::TooShort { len: short.len() })
        );
    }
    let e = decode(&[0x11; 200], None).unwrap_err();
    assert!(matches!(
        e,
        ShimcacheError::UnknownSignature {
            signature: 0x1111_1111,
            ..
        }
    ));
    assert!(e.to_string().contains("11-11-11-11"), "{e}");
    assert_eq!(detect_format(&[0x11; 200], None), None);
}

#[test]
fn times_that_are_not_times() {
    let mut e = decode(&win10(true, &[win10_entry(r"C:\a.exe", WHEN, &[])]), None)
        .unwrap()
        .entries[0]
        .clone();
    for (ft, shown) in [
        (0, None),
        (1, None),
        (YEAR_1602 - 1, None),
        (YEAR_1602, Some(YEAR_1602)),
        (MAX_FILETIME, Some(MAX_FILETIME)),
        (MAX_FILETIME + 1, None),
        (u64::MAX, None),
    ] {
        e.last_modified_filetime = ft;
        assert_eq!(e.last_modified(), shown, "{ft}");
    }
}

#[test]
fn packaged_app_records() {
    let record = "00000009\t0001000763bb0000\t000a000027410000\t8664\tMicrosoft.NET.Native.Framework.1.7\t8wekyb3d8bbwe\t";
    let c = decode(
        &win10(
            true,
            &[
                win10_entry(record, 0, &[]),
                win10_entry(r"C:\a\b c.exe", WHEN, &[]),
            ],
        ),
        None,
    )
    .unwrap();
    let p = c.entries[0].package_record().unwrap();
    assert_eq!(p.name, "Microsoft.NET.Native.Framework.1.7");
    assert_eq!(p.publisher_id, "8wekyb3d8bbwe");
    assert_eq!(p.architecture, "8664");
    assert!(!p.neutral);
    assert_eq!(
        PackageRecord::dotted(p.version).as_deref(),
        Some("1.7.25531.0")
    );
    assert_eq!(
        PackageRecord::dotted(p.sdk_version).as_deref(),
        Some("10.0.10049.0")
    );
    assert!(c.entries[1].package_record().is_none());
    assert!(PackageRecord::dotted("123").is_none());
}

#[test]
fn slack_entries_are_recovered() {
    let one = u32b(1);
    let evicted = win10_entry(r"C:\evicted.exe", WHEN, &tags(&[(0x100, &one)]));
    let also = win10_entry(r"C:\also.exe", WHEN - DAY, &tags(&[(0x200, &u32b(0))]));
    let live = win10_entry(r"C:\live.exe", WHEN, &[]);
    let cache = decode(&win10(true, std::slice::from_ref(&live)), None).unwrap();
    // the slack starts in the middle of an entry, has a stray signature, an older copy of the
    // live entry, and ends with a cut off entry
    let mut slack = evicted[20..].to_vec();
    slack.extend([0x31, 0x30, 0x74, 0x73, 9, 9]);
    slack.extend(&evicted);
    slack.extend(&live);
    slack.extend(&also);
    slack.extend(&evicted[..evicted.len() - 3]);
    let found = recover_slack(&slack, &cache);
    let p: Vec<_> = found.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(p, [r"C:\evicted.exe", r"C:\also.exe"]);
    assert!(found.iter().all(|e| e.from_slack));
    assert_eq!(found.iter().map(|e| e.position).collect::<Vec<_>>(), [1, 2]);
    assert_eq!(found[0].executed, Some(true));
    // not in the table formats
    let win7 = decode(&table(true, false, &[(r"C:\a.exe", WHEN, 0)]), None).unwrap();
    assert_eq!(recover_slack(&slack, &win7), Vec::<ShimcacheEntry>::new());
    // Windows 8 entries
    let v = win8(true, &[(r"C:\a.exe", WHEN, 0, "", &[])]);
    let c8 = decode(&v, None).unwrap();
    let gone = win8(true, &[(r"C:\gone.exe", WHEN, 2, "", &[])]);
    let found = recover_slack(&gone[128..], &c8);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].path, r"C:\gone.exe");
}

#[test]
fn data_tags_stop_at_a_record_that_does_not_fit() {
    let mut d = tags(&[(0x100, &u32b(1))]);
    d.extend(u32b(0x200));
    d.extend(u32b(100));
    d.extend([1, 2]);
    assert_eq!(data_tags(&d).len(), 1);
    assert_eq!(data_tags(&[1, 2, 3]), Vec::<(u32, &[u8])>::new());
}

#[test]
fn random_damage_never_panics() {
    // every format, bytes changed and cut, 20,000 times
    let one = u32b(1);
    let samples = [
        win10(
            true,
            &[
                win10_entry(r"C:\a.exe", WHEN, &tags(&[(0x100, &one)])),
                win10_entry(r"C:\b.exe", WHEN, &[]),
            ],
        ),
        win10(false, &[win10_entry(r"C:\a.exe", WHEN, &[])]),
        win8(true, &[(r"C:\a.exe", WHEN, 2, "p", &[1])]),
        win8(false, &[(r"C:\a.exe", WHEN, 2, "", &[])]),
        table(
            true,
            true,
            &[(r"C:\a.exe", WHEN, 2), (r"C:\b.exe", WHEN, 0)],
        ),
        table(true, false, &[(r"C:\a.exe", WHEN, 2)]),
        table(false, true, &[(r"C:\a.exe", WHEN, 2)]),
        table(false, false, &[(r"C:\a.exe", WHEN, 2)]),
        xp(
            &[1, 0],
            &[(r"C:\a.exe", WHEN, WHEN), (r"C:\b.exe", WHEN, WHEN)],
        ),
    ];
    let mut seed = 0x9E37_79B9_7F4A_7C15_u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for n in 0..20_000 {
        let mut v = samples[n % samples.len()].clone();
        for _ in 0..=next() % 16 {
            let at = (next() as usize) % v.len();
            v[at] = next() as u8;
        }
        if next() % 3 == 0 {
            let cut = (next() as usize) % (v.len() + 1);
            v.truncate(cut);
        }
        if let Ok(c) = decode(&v, None) {
            let _ = recover_slack(&v, &c);
            for e in &c.entries {
                let _ = (
                    e.data_tags(),
                    e.machine(),
                    e.package_record(),
                    e.last_modified(),
                );
            }
        }
    }
}

#[test]
fn a_damaged_entry_signature_is_reported_not_skipped() {
    let entries = [
        win10_entry(r"C:\a.exe", 131_000_000_000_000_000, &[]),
        win10_entry(r"C:\b.exe", 131_000_000_000_000_001, &[]),
    ];
    let mut v = win10(true, &entries);
    let second = 0x34 + entries[0].len();
    v[second..second + 4].copy_from_slice(b"10tX");
    let c = decode(&v, None).unwrap();
    assert_eq!(c.entries.len(), 1);
    assert_eq!(c.expected_entries, Some(2));
    assert_eq!(c.problems.len(), 1, "{:?}", c.problems);
    assert!(
        c.problems[0].starts_with(&format!(
            "Entry 1 at offset 0x{second:X}: no entry signature"
        )),
        "{:?}",
        c.problems
    );
    // Windows 8: the same (it has no count)
    let mut v = win8(
        true,
        &[(r"C:\a.exe", 1, 2, "", &[]), (r"C:\b.exe", 2, 2, "", &[])],
    );
    let at = v.len() - (v.len() - 128) / 2;
    v[at..at + 4].copy_from_slice(b"XXXX");
    let c = decode(&v, None).unwrap();
    assert_eq!(c.entries.len(), 1);
    assert_eq!(c.problems.len(), 1, "{:?}", c.problems);
}

#[test]
fn a_cache_that_ends_before_its_header_count_says_so() {
    let entries = [
        win10_entry(r"C:\a.exe", 131_000_000_000_000_000, &[]),
        win10_entry(r"C:\b.exe", 131_000_000_000_000_001, &[]),
    ];
    // the first entry of a two-entry cache, then nothing (or zeros)
    for tail in [0, 64] {
        let mut v = win10(false, &entries);
        v.truncate(0x30 + entries[0].len());
        v.resize(v.len() + tail, 0);
        let c = decode(&v, None).unwrap();
        assert_eq!(c.entries.len(), 1);
        assert_eq!(
            c.problems,
            ["The header gives 2 entries, but the cache ends after 1: entries may be missing"]
        );
    }
    // a count lower than the entries (as Windows often writes it) is not a problem
    let mut v = win10(false, &entries);
    v[0x24..0x28].copy_from_slice(&0u32.to_le_bytes());
    let c = decode(&v, None).unwrap();
    assert_eq!((c.entries.len(), c.problems.len()), (2, 0));
    // nor are zeros after the last entry
    let mut v = win10(false, &entries);
    v.extend([0u8; 100]);
    assert_eq!(decode(&v, None).unwrap().problems.len(), 0);
}
