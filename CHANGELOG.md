# Changelog

## 0.2.0 (ys-shimcache-parser)

First version of Yamato Security's fork, based on shimcache-forensic (SecurityRonin/shimcache-forensic
b22e571: shimcache-core 0.1.0, shimcache-forensic 0.1.0). Checked against Eric Zimmerman's
AppCompatCacheParser 2026.10.1 on every public value and hive found. (@YamatoSecurity)

### Added
- `shimcache_core::decode(value, is_32bit)` returns a `Cache`: the format, the header's entry
  count, the entries and the problems. A damaged entry no longer fails the value: it goes to
  `Cache::problems`, and the formats whose entries carry a signature stop there while the table
  formats go on, as AppCompatCacheParser does.
- Every field of an entry: its position (most recently used first), insertion and shim flags,
  data, the data's tags (`data_tags`) and machine type (`machine`), a packaged app's record
  (`package_record`: name, publisher id, version, architecture), Windows XP's file size and update
  time.
- `recover_slack`: entries left after the value in its cell (dropped from the cache), Windows 8 to
  11, those not in the cache kept, marked `from_slack`.
- `shimcache_forensic::hive`: an own `SYSTEM` hive reader (base block, `lf`/`lh`/`li`/`ri` subkey
  lists, big data, each value's cell slack), bounds-checked, with subkey loops and depth limited.
- Transaction log replay, after Eric Zimmerman's Registry `LogReplay` and Maxim Suhanov's regf
  specification: new-format logs (`HvLE` entries checked by their Marvin32 hashes and sequence
  numbers, both logs in order, an invalid base block taken from the latest log) and old `DIRT`
  logs; `Recovery` says what was applied and why a log was not.
- `read_system` / `read_system_file`: every `ControlSetNNN` with a cache key (`AppCompatibility`
  on Windows XP), its value decoded with the system's architecture (`PROCESSOR_ARCHITECTURE`) and
  its slack; `SystemCaches::rows` with AppCompatCacheParser's `Duplicate`.
- `shimcache4n6 SYSTEM [--list] [--csv FILE]`: the logs next to the hive applied, every control
  set, and AppCompatCacheParser's CSV columns.
- Tests against AppCompatCacheParser's output on 14 values and 7 hive scenarios (its CSV byte for
  byte), its own format tests rewritten, built hives and logs, random damage; a hive fuzz target.

### Changed
- `detect_format` takes the system's architecture (`Option<bool>`): Vista and 7 tables are 32 or 64
  bit by `PROCESSOR_ARCHITECTURE`, checked against the data.
- Format names are AppCompatCacheParser's (`Windows10C_11`, `Windows7x64_Windows2008R2`, …).
- The execution flag: Windows 7 and 8 insertion flag 0x2 (it was read wrong on Windows 8), 64-bit
  Vista and 2008 too, Windows 10 and 11 the data's 0x100 tag (it was not read); none for 32-bit
  Vista.
- Windows XP entries in the order of its LRU array, not the slots'.
- `\??\` is removed from paths; a time outside 1602–9999 is none.
- winreg-core is no longer used.

### Fixed
- Windows 8.0 and 8.1 values whose first dword is 0, not 0x80 (Windows Server 2012 R2 and
  others), were an unknown signature.
- Damaged hives panicked (winreg-core `cell_reader.rs`); dirty hives were read without their logs;
  only the current control set was read.
