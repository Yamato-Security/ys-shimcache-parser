//! Hives built here, for what the real ones don't have: entries in the slack of the value's cell
//! (no real hive had any that were not still in the cache), big data values, `ri` lists, the
//! Windows XP key, a control set without the value, the architecture, and damage.
#![allow(clippy::unwrap_used)]

use shimcache_forensic::{read_system, Hive};

const WHEN: u64 = 133_000_000_000_000_000;

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// A Windows 10 / 11 entry, executed (tag 0x100) or not.
fn win10_entry(path: &str, executed: bool) -> Vec<u8> {
    let p = utf16(path);
    let data: Vec<u8> = if executed {
        [0x100u32, 4, 1]
            .iter()
            .flat_map(|n| n.to_le_bytes())
            .collect()
    } else {
        Vec::new()
    };
    let mut body = (p.len() as u16).to_le_bytes().to_vec();
    body.extend(&p);
    body.extend(WHEN.to_le_bytes());
    body.extend((data.len() as u32).to_le_bytes());
    body.extend(data);
    let mut e = b"10ts".to_vec();
    e.extend(0u32.to_le_bytes());
    e.extend((body.len() as u32).to_le_bytes());
    e.extend(body);
    e
}

fn win10(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut v = vec![0u8; 0x34];
    v[..4].copy_from_slice(&0x34u32.to_le_bytes());
    v[0x28..0x2c].copy_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        v.extend(e);
    }
    v
}

/// A Windows 7 table with one entry, 32 or 64 bit.
fn win7(is32: bool, path: &str) -> Vec<u8> {
    let size = if is32 { 32 } else { 48 };
    let p = utf16(path);
    let mut v = vec![0u8; 128 + size];
    v[..4].copy_from_slice(&0xbadc_0feeu32.to_le_bytes());
    v[4..8].copy_from_slice(&1u32.to_le_bytes());
    let offset = v.len();
    v[128..130].copy_from_slice(&(p.len() as u16).to_le_bytes());
    v[130..132].copy_from_slice(&(p.len() as u16).to_le_bytes());
    if is32 {
        v[132..136].copy_from_slice(&(offset as u32).to_le_bytes());
        v[136..144].copy_from_slice(&WHEN.to_le_bytes());
        v[144..148].copy_from_slice(&2u32.to_le_bytes());
    } else {
        v[136..144].copy_from_slice(&(offset as u64).to_le_bytes());
        v[144..152].copy_from_slice(&WHEN.to_le_bytes());
        v[152..156].copy_from_slice(&2u32.to_le_bytes());
    }
    v.extend(p);
    v
}

/// A key to build: its name, values (name, type, data, slack after the data) and subkeys.
struct K {
    name: &'static str,
    values: Vec<(&'static str, u32, Vec<u8>, Vec<u8>)>,
    subkeys: Vec<K>,
    /// List the subkeys through an `ri` index root.
    ri: bool,
}

fn k(name: &'static str, subkeys: Vec<K>) -> K {
    K {
        name,
        values: Vec::new(),
        subkeys,
        ri: false,
    }
}

/// A hive (minor version 5) with one bin holding every cell.
struct Builder {
    bin: Vec<u8>,
}

impl Builder {
    /// A cell of `data` with `extra` bytes after it; its offset.
    fn cell(&mut self, data: &[u8], extra: &[u8]) -> u32 {
        let offset = 32 + self.bin.len() as u32;
        let size = (4 + data.len() + extra.len()).div_ceil(8) * 8;
        self.bin.extend((-(size as i32)).to_le_bytes());
        self.bin.extend(data);
        self.bin.extend(extra);
        self.bin
            .resize(self.bin.len() + size - 4 - data.len() - extra.len(), 0);
        offset
    }

    fn value(&mut self, name: &str, kind: u32, data: &[u8], slack: &[u8]) -> u32 {
        let (len, offset) = if data.len() <= 4 && slack.is_empty() {
            let mut d = [0u8; 4];
            d[..data.len()].copy_from_slice(data);
            (0x8000_0000 | data.len() as u32, u32::from_le_bytes(d))
        } else if data.len() > 16344 {
            // big data: 16,344-byte segments listed by a db record
            let mut segments = Vec::new();
            let chunks: Vec<&[u8]> = data.chunks(16344).collect();
            for (i, c) in chunks.iter().enumerate() {
                let tail = if i + 1 == chunks.len() {
                    slack
                } else {
                    &[][..]
                };
                segments.push(self.cell(c, tail));
            }
            let list: Vec<u8> = segments.iter().flat_map(|o| o.to_le_bytes()).collect();
            let list = self.cell(&list, &[]);
            let mut db = b"db".to_vec();
            db.extend((segments.len() as u16).to_le_bytes());
            db.extend(list.to_le_bytes());
            (data.len() as u32, self.cell(&db, &[]))
        } else {
            (data.len() as u32, self.cell(data, slack))
        };
        let mut vk = b"vk".to_vec();
        vk.extend((name.len() as u16).to_le_bytes());
        vk.extend(len.to_le_bytes());
        vk.extend(offset.to_le_bytes());
        vk.extend(kind.to_le_bytes());
        vk.extend(1u16.to_le_bytes()); // ASCII name
        vk.extend(0u16.to_le_bytes());
        vk.extend(name.as_bytes());
        self.cell(&vk, &[])
    }

    fn key(&mut self, key: &K, root: bool) -> u32 {
        let subs: Vec<u32> = key.subkeys.iter().map(|s| self.key(s, false)).collect();
        let values: Vec<u32> = key
            .values
            .iter()
            .map(|(n, t, d, s)| self.value(n, *t, d, s))
            .collect();
        let list = if subs.is_empty() {
            u32::MAX
        } else {
            let mut lf = b"lf".to_vec();
            lf.extend((subs.len() as u16).to_le_bytes());
            for s in &subs {
                lf.extend(s.to_le_bytes());
                lf.extend(0u32.to_le_bytes());
            }
            let lf = self.cell(&lf, &[]);
            if key.ri {
                let mut ri = b"ri".to_vec();
                ri.extend(1u16.to_le_bytes());
                ri.extend(lf.to_le_bytes());
                self.cell(&ri, &[])
            } else {
                lf
            }
        };
        let vlist = if values.is_empty() {
            u32::MAX
        } else {
            let v: Vec<u8> = values.iter().flat_map(|o| o.to_le_bytes()).collect();
            self.cell(&v, &[])
        };
        let mut nk = vec![0u8; 0x4c];
        nk[..2].copy_from_slice(b"nk");
        nk[2..4].copy_from_slice(&(0x20u16 | if root { 0x4 } else { 0 }).to_le_bytes());
        nk[4..12].copy_from_slice(&WHEN.to_le_bytes());
        nk[0x14..0x18].copy_from_slice(&(subs.len() as u32).to_le_bytes());
        nk[0x1c..0x20].copy_from_slice(&list.to_le_bytes());
        nk[0x24..0x28].copy_from_slice(&(values.len() as u32).to_le_bytes());
        nk[0x28..0x2c].copy_from_slice(&vlist.to_le_bytes());
        nk[0x48..0x4a].copy_from_slice(&(key.name.len() as u16).to_le_bytes());
        nk.extend(key.name.as_bytes());
        self.cell(&nk, &[])
    }
}

fn hive(root: &K) -> Vec<u8> {
    let mut b = Builder { bin: Vec::new() };
    let root_offset = b.key(root, true);
    let size = (32 + b.bin.len()).div_ceil(4096) * 4096;
    let mut bin = vec![0u8; 32];
    bin[..4].copy_from_slice(b"hbin");
    bin[8..12].copy_from_slice(&(size as u32).to_le_bytes());
    bin.extend(&b.bin);
    bin.resize(size, 0);
    let mut base = vec![0u8; 4096];
    base[..4].copy_from_slice(b"regf");
    base[4..8].copy_from_slice(&7u32.to_le_bytes());
    base[8..12].copy_from_slice(&7u32.to_le_bytes());
    base[20..24].copy_from_slice(&1u32.to_le_bytes());
    base[24..28].copy_from_slice(&5u32.to_le_bytes());
    base[32..36].copy_from_slice(&1u32.to_le_bytes());
    base[36..40].copy_from_slice(&root_offset.to_le_bytes());
    base[40..44].copy_from_slice(&(size as u32).to_le_bytes());
    let x = (0..508).step_by(4).fold(0u32, |x, i| {
        x ^ u32::from_le_bytes(base[i..i + 4].try_into().unwrap())
    });
    base[508..512].copy_from_slice(&x.to_le_bytes());
    base.extend(bin);
    base
}

/// A control set: its number, its cache value and slack, its `PROCESSOR_ARCHITECTURE`.
type ControlSet = (&'static str, Option<(Vec<u8>, Vec<u8>)>, &'static str);

/// A SYSTEM hive: `Select\Current` = 1, and control sets.
fn system(sets: Vec<ControlSet>, ri: bool) -> Vec<u8> {
    let mut subkeys = vec![K {
        name: "Select",
        values: vec![("Current", 4, 1u32.to_le_bytes().to_vec(), Vec::new())],
        subkeys: Vec::new(),
        ri: false,
    }];
    for (name, cache, arch) in sets {
        let mut cache_key = k("AppCompatCache", Vec::new());
        if let Some((v, slack)) = cache {
            cache_key.values.push(("AppCompatCache", 3, v, slack));
        }
        let mut env = k("Environment", Vec::new());
        env.values.push((
            "PROCESSOR_ARCHITECTURE",
            1,
            utf16(&format!("{arch}\0")),
            Vec::new(),
        ));
        let mut session = k("Session Manager", vec![cache_key, env]);
        session.ri = ri;
        subkeys.push(k(name, vec![k("Control", vec![session])]));
    }
    subkeys.push(k("MountedDevices", Vec::new()));
    hive(&K {
        name: "ROOT",
        values: Vec::new(),
        subkeys,
        ri,
    })
}

#[test]
fn entries_in_the_slack_of_the_value_are_recovered() {
    let live = win10_entry(r"C:\live.exe", false);
    let gone = win10_entry(r"C:\evicted.exe", true);
    let mut slack = vec![0xAA, 0xBB];
    slack.extend(&gone);
    slack.extend(&live); // an older copy of a live entry: not recovered
    let h = system(
        vec![(
            "ControlSet001",
            Some((win10(std::slice::from_ref(&live)), slack)),
            "AMD64",
        )],
        false,
    );
    let c = read_system(h, &[]).unwrap();
    assert!(!c.recovery.dirty);
    assert_eq!(c.current_control_set, Some(1));
    assert_eq!(c.is_32bit, Some(false));
    let cs = &c.control_sets[0];
    assert_eq!(
        cs.key_path,
        r"ControlSet001\Control\Session Manager\AppCompatCache"
    );
    assert_eq!(cs.cache.as_ref().unwrap().entries.len(), 1);
    assert_eq!(cs.slack.len(), 1);
    assert_eq!(cs.slack[0].path, r"C:\evicted.exe");
    assert_eq!(
        (
            cs.slack[0].position,
            cs.slack[0].from_slack,
            cs.slack[0].executed
        ),
        (1, true, Some(true))
    );
    let rows = c.rows();
    assert_eq!(rows.len(), 2);
    assert!(rows[1].entry.from_slack && !rows[1].duplicate);
}

#[test]
fn big_data_values_and_index_roots() {
    // 600 entries: several 16,344-byte segments; the slack after the last segment's data
    let entries: Vec<Vec<u8>> = (0..600)
        .map(|i| win10_entry(&format!(r"C:\Program Files\app{i:03}\app.exe"), i % 2 == 0))
        .collect();
    let value = win10(&entries);
    assert!(value.len() > 3 * 16344);
    let gone = win10_entry(r"C:\gone.exe", false);
    let h = system(
        vec![("ControlSet001", Some((value.clone(), gone)), "AMD64")],
        true,
    );
    let c = read_system(h.clone(), &[]).unwrap();
    let cs = &c.control_sets[0];
    let cache = cs.cache.as_ref().unwrap();
    assert_eq!(cache.entries.len(), 600);
    assert_eq!(cache.entries[599].path, r"C:\Program Files\app599\app.exe");
    assert_eq!(cs.slack.len(), 1);
    // the value as stored
    let (hv, _) = Hive::open(h, &[]).unwrap();
    let data = hv
        .key(r"ControlSet001\Control\Session Manager\AppCompatCache")
        .unwrap()
        .value("appcompatcache")
        .unwrap()
        .data();
    assert_eq!(data, value);
}

#[test]
fn control_sets_the_xp_key_and_the_architecture() {
    let h = system(
        vec![
            (
                "ControlSet002",
                Some((win7(true, r"C:\b.exe"), Vec::new())),
                "x86",
            ),
            (
                "ControlSet001",
                Some((win7(true, r"C:\a.exe"), Vec::new())),
                "x86",
            ),
            ("ControlSet003", None, "x86"),
        ],
        false,
    );
    let c = read_system(h, &[]).unwrap();
    assert_eq!(c.is_32bit, Some(true));
    let numbers: Vec<u32> = c.control_sets.iter().map(|cs| cs.control_set).collect();
    assert_eq!(numbers, [1, 2, 3]);
    assert_eq!(
        c.control_sets[0].cache.as_ref().unwrap().format.name(),
        "Windows7x86"
    );
    assert_eq!(
        c.control_sets[0].cache.as_ref().unwrap().entries[0].path,
        r"C:\a.exe"
    );
    assert_eq!(
        c.control_sets[2].error.as_deref(),
        Some("no AppCompatCache value")
    );
    // Windows XP keeps it in AppCompatibility
    let mut xp_key = k("AppCompatibility", Vec::new());
    xp_key
        .values
        .push(("AppCompatCache", 3, win7(false, r"C:\xp.exe"), Vec::new()));
    let h = hive(&K {
        name: "ROOT",
        values: Vec::new(),
        subkeys: vec![k(
            "ControlSet001",
            vec![k("Control", vec![k("Session Manager", vec![xp_key])])],
        )],
        ri: false,
    });
    let c = read_system(h, &[]).unwrap();
    assert_eq!(
        c.control_sets[0].key_path,
        r"ControlSet001\Control\Session Manager\AppCompatibility"
    );
    assert_eq!(
        c.control_sets[0].cache.as_ref().unwrap().entries[0].path,
        r"C:\xp.exe"
    );
    assert_eq!((c.current_control_set, c.is_32bit), (None, None));
}

#[test]
fn not_a_hive() {
    assert!(read_system(b"not a hive".to_vec(), &[]).is_err());
    assert!(read_system(Vec::new(), &[]).is_err());
}

#[test]
fn damage_never_panics_or_hangs() {
    let entries: Vec<Vec<u8>> = (0..40)
        .map(|i| win10_entry(&format!(r"C:\a{i}.exe"), true))
        .collect();
    let sample = system(
        vec![
            (
                "ControlSet001",
                Some((win10(&entries), win10_entry(r"C:\s.exe", false))),
                "AMD64",
            ),
            (
                "ControlSet002",
                Some((win7(false, r"C:\b.exe"), Vec::new())),
                "x86",
            ),
        ],
        true,
    );
    let mut seed = 0x2545_F491_4F6C_DD1D_u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for _ in 0..5_000 {
        let mut h = sample.clone();
        for _ in 0..=next() % 12 {
            // mostly the cells, sometimes the base block
            let at = if next() % 8 == 0 {
                (next() as usize) % 4096
            } else {
                4096 + (next() as usize) % (h.len() - 4096)
            };
            h[at] = next() as u8;
        }
        if next() % 5 == 0 {
            let cut = (next() as usize) % (h.len() + 1);
            h.truncate(cut);
        }
        if let Ok(c) = read_system(h, &[]) {
            let _ = c.rows();
        }
    }
    // a subkey list that lists its own key, and one that points back at the root
    let mut looped = sample.clone();
    let root = u32::from_le_bytes(looped[36..40].try_into().unwrap());
    let nk = 4096 + root as usize + 4;
    let list = u32::from_le_bytes(looped[nk + 0x1c..nk + 0x20].try_into().unwrap()) as usize;
    let ri = 4096 + list + 4;
    looped[ri + 4..ri + 8].copy_from_slice(&list.to_le_bytes()[..4]);
    let _ = read_system(looped, &[]);
}

/// `shimcache4n6` in `dir` with these arguments: (exit status, stdout, stderr).
fn run_cli(dir: &std::path::Path, args: &[&str]) -> (i32, String, String) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_shimcache4n6"))
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn findings_include_the_entries_recovered_from_the_slack() {
    let live = win10_entry(r"C:\Windows\System32\notepad.exe", false);
    let gone = win10_entry(r"C:\Users\Public\Downloads\payload.exe", true);
    let mut slack = vec![0xAA, 0xBB];
    slack.extend(&gone);
    let h = system(
        vec![(
            "ControlSet001",
            Some((win10(std::slice::from_ref(&live)), slack)),
            "AMD64",
        )],
        false,
    );
    let dir = std::env::temp_dir().join(format!("shimcache-cli-slack-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("SYSTEM"), h).unwrap();
    let (code, out, err) = run_cli(&dir, &["SYSTEM"]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("1 entries (and 1 recovered from slack)"),
        "{out}"
    );
    assert!(
        out.contains(r"SHIMCACHE-SUSPICIOUS-PATH  C:\Users\Public\Downloads\payload.exe"),
        "{out}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn the_command_line_is_checked() {
    let dir = std::env::temp_dir().join(format!("shimcache-cli-args-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("SYSTEM"), system(vec![], false)).unwrap();
    for (args, problem) in [
        (&[][..], "no SYSTEM hive given"),
        (&["SYSTEM", "--csv"][..], "--csv needs a file name"),
        (
            &["SYSTEM", "--csv", "--list"][..],
            "--csv needs a file name",
        ),
        (&["SYSTEM", "--bogus"][..], "unknown option --bogus"),
        (&["SYSTEM", "OTHER"][..], "more than one hive given (OTHER)"),
    ] {
        let (code, out, err) = run_cli(&dir, args);
        assert_eq!(code, 2, "{args:?}: {out}");
        assert!(err.contains(problem), "{args:?}: {err}");
        assert!(err.contains("usage: shimcache4n6"), "{args:?}: {err}");
    }
    // nothing was written in place of the missing CSV name
    assert!(!dir.join("--list").exists());
    let (code, out, _) = run_cli(&dir, &["--help"]);
    assert_eq!((code, out.starts_with("usage:")), (0, true));
    let (code, _, err) = run_cli(&dir, &["SYSTEM", "--list", "--csv", "out.csv"]);
    assert_eq!(code, 0, "{err}");
    assert!(dir.join("out.csv").exists());
    let _ = std::fs::remove_dir_all(dir);
}
