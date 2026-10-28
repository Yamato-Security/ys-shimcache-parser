# shimcache-forensic test data — provenance

`SYSTEM` hives and their transaction logs, gzipped (`tests/real_hives.rs` unpacks each scenario
into a directory of its own). Each scenario is checked against Eric Zimmerman's
[AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser) 2026.10.1 (MIT),
built from source: `oracle/<scenario>.json` is what its library reads from the hive (with the logs
next to it), every control set's entries and the entries it recovers from the value's slack;
`oracle/<scenario>.csv` is its `--csv` output (with `--nl` for the hive without its logs), the
`SourceFile` column set to `SYSTEM`.

| Files | Source | Licence | Scenarios |
|---|---|---|---|
| `museum/Win11/RathbunVM/SYSTEM`, `SYSTEM.LOG1`, `SYSTEM.LOG2` | [DFIR Artifact Museum](https://github.com/AndrewRathbun/DFIRArtifactMuseum) `Windows/Registry/Win11/RathbunVM/RathbunVM_W11RegistryHives.7z` (also in AppCompatCacheParser's tests): a dirty Windows 11 hive; its logs apply 16 entries | MIT, `museum/LICENSE` | `museum-win11` (with its logs), `museum-win11-no-logs` |
| `python-registry/new_log_1/*`, `new_log_2/*` | [python-registry](https://github.com/williballenthin/python-registry) `testing/reg_samples/`: dirty Windows 8.1 hives with new-format (`HvLE`) logs | Apache-2.0, `python-registry/LICENSE` | `pr-new-log-1`, `pr-new-log-1-reversed` (the logs' names swapped), `pr-new-log-1-invalid-checksum` (swapped, and the base block's checksum broken by the test), `pr-new-log-2` |
| `regipy/SYSTEM` | [regipy](https://github.com/mkorman90/regipy) `regipy_tests/data/SYSTEM.xz`: a 32-bit Windows 7 hive with two control sets | MIT, `regipy/LICENSE` | `regipy-system` |
