# shimcache-core test data — provenance

| File | `win7_appcompatcache.bin` |
|---|---|
| **What** | The raw `AppCompatCache` registry value blob (Windows 7 64-bit AppCompatCache, signature `0xbadc0fee`, 60 816 bytes, 292 cached entries). |
| **Source** | Extracted from the `SYSTEM` hive of the **NIST CFReDS "Data Leakage" case** (`\ControlSet001\Control\Session Manager\AppCompatCache\AppCompatCache`). |
| **Origin** | NIST Computer Forensic Reference Data Sets — <https://cfreds.nist.gov/>. US Government work, **public domain**; freely redistributable. |
| **MD5** | `45e0bc963894a8bc8f4d52e2797c98d3` |
| **How extracted** | `regipy` read of the `AppCompatCache` REG_BINARY value from the case `SYSTEM` hive. |
| **Ground truth / oracle** | Cross-confirmed by two independent implementations: Mandiant `ShimCacheParser` (identifies "64bit Windows 7/2k8-R2", parses 291 entries) and a from-spec read against libyal dtfabric `winreg-kb/winregrc/appcompatcache.yaml` (292 entries; Mandiant excludes one trailing record). Both agree on entry content: e.g. `C:\Windows\system32\LogonUI.exe`, `FILETIME` `129347834495725262` (2010-11-21 03:24:09 UTC), executed. |
| **Used by** | `tests/win7_real.rs` (Tier-1 real-corpus validation of the Windows 7 64-bit path). |

The blob is small (≈ 59 KiB) and public-domain, so it is committed directly rather than gitignored.

## The other values

Every value is checked against Eric Zimmerman's
[AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser) 2026.10.1 (MIT),
built from source: `oracle.jsonl` holds, for each, what its library reads (the format, the
header's entry count, the problems, and every entry's position, path, time, executed flag,
insertion flags and data size), written with a small driver over the library. `tests/real_values.rs`
compares all of it.

| Files | Source | Licence |
|---|---|---|
| `museum/WinXPx86.bin`, `Win2k8Standard.bin`, `win7x86.bin`, `win7x64.bin`, `Win80.bin`, `Win81.bin`, `Win10.bin`, `Win10Creators.bin` | [DFIR Artifact Museum](https://github.com/AndrewRathbun/DFIRArtifactMuseum) `Windows/AppCompatCache/` (also AppCompatCacheParser's own test files) | MIT, `museum/LICENSE` |
| `museum/Win2012R2-StolenSzechuan-ControlSet001.bin` | `ControlSet001`'s value in the DFIR Artifact Museum's `Windows/Registry/Win2012R2/StolenSzechuan` `SYSTEM` hive, its transaction logs applied: a Windows 8.1 / 2012 R2 value whose first dword is 0, not 0x80 | MIT, `museum/LICENSE` |
| `artemis/win8shim.raw`, `win81shim.raw`, `win10Creatorsshim.raw`, `win11shim.raw` | [artemis](https://github.com/puffyCid/artemis) `forensics/tests/test_data/windows/shimcache/` | MIT, `artemis/LICENSE` |
