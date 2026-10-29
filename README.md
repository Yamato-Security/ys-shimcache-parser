# ys-shimcache-parser

Yamato Security's maintained fork of Security Ronin's
[shimcache-forensic](https://github.com/SecurityRonin/shimcache-forensic) (Albert Hui,
Apache-2.0): the Windows AppCompatCache (ShimCache) parser used by
[Juntei](https://github.com/Yamato-Security/juntei). Upstream's history is kept, with its licence.

| Crate | What it reads |
| --- | --- |
| [`ys-shimcache-parser-core`](core/) (library `shimcache_core`) | An AppCompatCache value, Windows XP to 11: every entry's path, last-modification time, execution flag, position, flags, data and packaged-app record; damaged entries reported; entries recovered from the slack after the value |
| [`ys-shimcache-parser`](forensic/) (library `shimcache_forensic`) | A `SYSTEM` hive: its own registry reader, the transaction logs replayed when the hive is dirty, every control set's cache and the slack of its cell; graded findings; the `ys-shimcache-parser` command |

## Why this crate

The reference is a second, independent AppCompatCache parser, built from source and its library
run directly. The parsers were compared with it on the public data found: 20 `SYSTEM` hives with
their logs (DFIR Artifact Museum, regipy, notatin, plaso, python-registry, dissect.target and
other projects' tests), 24 control sets with 7,290 cache entries.

| Parser | Hives it fails on | Control sets not read | Entries read | Paths or times not the reference's | Execution flag |
| --- | --- | --- | --- | --- | --- |
| **this fork** | **0** | **0** | **7,290** | **0** | **as the reference's on all** |
| postmortem 0.2.6 (AGPL-3.0) | 0 | 5 (reads the current one) | 5,836 | 0 | 50 wrong (Windows 10's old "last 4 bytes are 1" rule) |
| chainsaw 2.17.1 (GPL-3.0) | 0 | 5 | 5,836 | 1,440 (Windows 8.1 paths kept as stored, `SYSVOL\…`; times to the millisecond) | none for Windows 10 and 11 |
| artemis 0.21.0 (MIT) | 7 (Windows 8.1 values whose first dword is 0) | 0 | 6,427 | 535 paths, 519 times (a dirty hive read without its logs) | none |
| shimcache-forensic 0.1.0 (upstream) | 8 (Windows 8.1 values whose first dword is 0, a base block whose checksum is wrong, a damaged hive bin) | 4 | 5,190 | 0 | 842 wrong (Windows 8), none for Windows 10 and 11 |
| winreg-artifacts 0.4.1 (Apache-2.0) | 2 (a base block whose checksum is wrong, a damaged hive bin) | 5 | 5,116 | 2 | none |

Also surveyed, for what a value holds: libyal's
[winreg-kb](https://github.com/libyal/winreg-kb) documentation of the formats, Mandiant's
[ShimCacheParser](https://github.com/mandiant/ShimCacheParser), TeamT5's ShimcacheParser, RegRipper
3.0's `appcompatcache` plugin, regipy, plaso, dissect.target, Velociraptor's `AppCompatCache`
artifact, cairn and others (Windows 10 1607 and later only, or no hive reader). Upstream was the
best permissively licensed starting point: a bounds-checked decoder, a clean split between the
value and the hive, and findings. Its hive layer (winreg-core) panicked on damaged hives and
ignored the transaction logs, so it is replaced.

What the fork changes:

| Change | Reference |
| --- | --- |
| Windows 8.0 and 8.1 values whose first dword is 0 (Windows Server 2012 R2) read; Windows XP entries in the order of its LRU array; 32 or 64 bit Vista and 7 tables from `PROCESSOR_ARCHITECTURE`, checked against the data | fork |
| The execution flag: Windows 7 and 8 insertion flag 0x2 (it was wrong on Windows 8), 64-bit Vista and 2008 too, Windows 10 and 11 data tag 0x100 (it was not read); 32-bit Vista has none | fork |
| Every field of an entry: position, insertion and shim flags, data, the data's tags and machine type, a packaged app's record, Windows XP's file size and update time; `\??\` removed from paths; times outside 1602–9999 read as none | winreg-kb, fork |
| A damaged entry goes to `Cache::problems`: formats whose entries carry a signature stop there, table formats go on | fork |
| Entries in the slack of the value's cell (dropped from the cache) recovered, Windows 8 to 11, those not in the cache kept | fork |
| An own registry reader (`hive`): base block, `lf`/`lh`/`li`/`ri` lists, big data (`db`), each value's cell slack; bounds-checked, loops and depth limited | Maxim Suhanov's [regf specification](https://github.com/msuhanov/regf) (CC BY 4.0) |
| Transaction log replay: new-format logs (`HvLE`, Marvin32 hashes, sequence numbers, both logs in order, an invalid base block taken from the latest log) and old `DIRT` logs | the regf specification |
| Every `ControlSetNNN`, with `Duplicate` (an entry seen in an earlier control set or the slack) | fork |
| `ys-shimcache-parser SYSTEM [--list] [--csv FILE]`: the logs next to the hive applied, a summary per control set, the findings, and a CSV | fork |
| A log none of whose entries can be applied (or an old-format log with no dirty page) is not counted as applied, and the other log is tried; a dirty page must be inside its entry's hive bins (at most 2 GiB), and the hive grows only when the memory can be had. yarp counts such a log as applied, so a hive looked recovered with nothing applied | the regf specification; fork (found in review) |
| A signed cache (Windows 8 to 11) that stops where bytes other than zeros have no entry signature, or before the count its Windows 10 / 11 header gives, is reported in `Cache::problems` | fork (found in review) |
| Findings: a system binary is in place only in the Windows directory's `System32` or `SysWOW64` (not in any folder of that name, such as `C:\Program Files\Vendor\System32`); the entries recovered from the slack are audited too; `ys-shimcache-parser` rejects a missing `--csv` file name and unknown arguments | fork (found in review) |
| `SystemCaches::select` (`Current`, `Default`, `LastKnownGood`, `Failed`, problems when missing or malformed) and each value's size (`ControlSetCache::value_size`, the whole cache) | fork |
| One CI (Linux, macOS, Windows, MSRV, wasm32, cargo-deny), actions pinned by commit | fork |
| The crates named after the repository (`ys-shimcache-parser`, `ys-shimcache-parser-core`), version 1.0.0, edition 2024, Rust 1.99 | fork |

## How it's checked

- Values: on 41 values (the 24 above, read out of the hives, and 17 public value files: DFIR
  Artifact Museum, artemis, upstream's, Velociraptor's truncated ones) all 10,925 entries equal
  the reference's in position, path, time, executed flag, insertion flags and data size,
  with the same header count and problems.
- Hives: the bytes of every control set's value and of its slack equal those the reference
  reads, after log replay; so do all 7,290 entries. The 12 dirty hives with logs, replayed, are
  byte for byte what [yarp](https://github.com/msuhanov/yarp) recovers.
- 16,400 damaged copies of the values and 2,000 of the hives read without a panic, a hang or an
  allocation over 1 GiB (upstream's winreg-core panicked on them).
- In the tests: values built in each format; the 14 value files and 7 hive scenarios above (a
  dirty Windows 11 hive with and without its logs, Windows 8.1 hives with logs swapped or a broken
  base block, a 32-bit Windows 7 hive with two control sets) against the reference's output and
  its CSV, byte for byte; log replay on built logs; hives built with slack, big data
  and `ri` lists; random damage. Test data provenance: `core/tests/data/README.md`,
  `forensic/tests/data/README.md`.

## Use

The command is `ys-shimcache-parser` (upstream's was `shimcache4n6`):

```console
$ cargo install --git https://github.com/Yamato-Security/ys-shimcache-parser ys-shimcache-parser
$ ys-shimcache-parser SYSTEM --csv shimcache.csv
Transaction logs applied: SYSTEM.LOG1, SYSTEM.LOG2
  SYSTEM.LOG1: applied 2 log entries (sequence numbers 620 to 621)
  SYSTEM.LOG2: applied 14 log entries (sequence numbers 622 to 635)
AppCompatCache: Windows10C_11, ControlSet001, 359 entries
Findings (27):
  [MEDIUM] SHIMCACHE-SUSPICIOUS-PATH  C:\Users\ANDREW~1\AppData\Local\Temp\DA15D340-2806-4EF5-BB3C-C787E4CD384B\dismhost.exe
  …
```

`--list` prints every entry; `--csv` writes the columns `ControlSet`,
`CacheEntryPosition`, `Path`, `LastModifiedTimeUTC`, `Executed`, `Duplicate`, `SourceFile`,
`FromSlack`.

```rust
let caches = shimcache_forensic::read_system_file(std::path::Path::new("SYSTEM"))?;
if caches.recovery.dirty && !caches.recovery.recovered {
    eprintln!("dirty hive, no logs: entries may be missing");
}
for row in caches.rows() {
    let e = row.entry;
    println!("{} {} {:?} {:?} {}", row.control_set, e.path, e.last_modified(), e.executed, e.from_slack);
}
// or a value's bytes alone
let cache = shimcache_core::decode(&value, None)?;
```

From Cargo, by commit (the crates are named after the repository, `ys-shimcache-parser` and
`ys-shimcache-parser-core`, and keep upstream's library names, `shimcache_forensic` and
`shimcache_core`; they are not published, and need Rust 1.99):

```toml
shimcache-forensic = { package = "ys-shimcache-parser", git = "https://github.com/Yamato-Security/ys-shimcache-parser", rev = "<commit>" }
```

> **ShimCache is not proof of execution by itself.** An entry means the file was seen on a shimmed
> path; the execution flag is the witness, and the time is the file's last modification, not when
> it ran. Findings are observations ("consistent with …"), never verdicts.

## Findings

| Code | Severity | MITRE | Fires when |
|---|---|---|---|
| `SHIMCACHE-SYSTEM-BINARY-RELOCATED` | High | T1036.005 | A Windows system-binary name recorded at a non-`System32`/`SysWOW64` path (masquerading). |
| `SHIMCACHE-SUSPICIOUS-PATH` | Medium | T1204 | An entry whose path is a common staging directory (Temp, Downloads, `$Recycle.Bin`, …). |

## Credits

Joachim Metz's libyal (winreg-kb, libregf); Maxim Suhanov's regf specification and
yarp; Mandiant's ShimCacheParser and Andrew Davis's research that started it; Andrew Rathbun's DFIR
Artifact Museum; and the projects whose test data is used here: regipy, python-registry, artemis.
The data found for this work is also kept, with its licences, in
[juntei-sample-data](https://github.com/Yamato-Security/juntei-sample-data) (`Shimcache/`).

## Licence

Apache-2.0 (`LICENSE`), as upstream. The test data keeps its licences, each beside it: the DFIR
Artifact Museum's, regipy's and artemis's (MIT), python-registry's (Apache-2.0), and the NIST
CFReDS value (public domain). The reference parser was only run to write the expected values,
never included.
