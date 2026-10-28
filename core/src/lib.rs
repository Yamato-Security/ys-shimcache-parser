//! Pure-Rust read-only decoder for the Windows **AppCompatCache** (ShimCache) registry value
//! blob — the `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`
//! `AppCompatCache` value (`AppCompatibility` on Windows XP). Every format: Windows XP, Server
//! 2003 / Vista / 2008 (32 and 64 bit), 7 / 2008 R2 (32 and 64 bit), 8.0 / 2012, 8.1 / 2012 R2 and
//! 10 / 11 (both header sizes).
//!
//! Each [`ShimcacheEntry`] has the executable's **path**, the file's **last-modification
//! FILETIME** (not an execution time), the **execution flag** where the format has one (Windows
//! 7 and 8: insertion flag 0x2; 64-bit Vista and 2008 too; Windows 10 and 11: data tag 0x100),
//! its position in the cache (most recently used first) and the fields each format adds
//! (insertion flags, the entry's data, Windows XP's update time and file size). Entries left in
//! the slack of the value's registry cell, dropped from the cache, are found by
//! [`recover_slack`].
//!
//! The layouts are libyal's (`winreg-kb`, *Application compatibility cache key*); what is read
//! from them, and how, is what Eric Zimmerman's AppCompatCacheParser reads (the reference the
//! results are checked against): Windows XP entries in the order of its LRU array, the 32 or
//! 64 bit table layout checked against the data, the Windows 10 executed tag rather than "the
//! last 4 bytes are 1", `\??\` removed from paths, invalid times as none.
//!
//! This crate takes the raw value bytes and never touches the registry; `shimcache-forensic`
//! reads the value (and its slack) from a `SYSTEM` hive, with its transaction logs. It is
//! `#![forbid(unsafe_code)]` and panic-free: every read is bounds-checked, a damaged entry goes
//! to [`Cache::problems`].

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::collections::HashSet;
use std::fmt;

/// AppCompatCache header signatures (the value's first dword).
mod signature {
    pub const WINXP: u32 = 0xdead_beef;
    pub const WIN2003_VISTA: u32 = 0xbadc_0ffe;
    pub const WIN7: u32 = 0xbadc_0fee;
    pub const WIN10: u32 = 0x30;
    pub const WIN10_CREATORS: u32 = 0x34;
}

/// Windows 8.1, 10 and 11 entry signature; Windows 8.0's.
const ENTRY_10TS: &[u8; 4] = b"10ts";
const ENTRY_00TS: &[u8; 4] = b"00ts";

/// The Windows 10 / 11 data tag that is there when the file was executed (its value is 1).
pub const EXECUTED_TAG: u32 = 0x100;
/// The Windows 10 / 11 data tags holding the executable's PE machine type (`0x8664`, `0x14c`).
pub const MACHINE_TAGS: [u32; 2] = [0x800, 0x2000];

/// The detected AppCompatCache format variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShimcacheFormat {
    /// Windows XP 32-bit (`0xdeadbeef`): 96 slots of 552 bytes and an LRU array.
    WinXp,
    /// Windows Server 2003 / Vista / 2008 (`0xbadc0ffe`), 32-bit entries.
    Win2003_32,
    /// Windows Server 2003 / Vista / 2008 (`0xbadc0ffe`), 64-bit entries.
    Win2003_64,
    /// Windows 7 / Server 2008 R2 (`0xbadc0fee`), 32-bit entries.
    Win7_32,
    /// Windows 7 / Server 2008 R2 (`0xbadc0fee`), 64-bit entries.
    Win7_64,
    /// Windows 8.0 / Server 2012 (`00ts` entries after a 128-byte header).
    Win8_0,
    /// Windows 8.1 / Server 2012 R2 (`10ts` entries after a 128-byte header).
    Win8_1,
    /// Windows 10 before the Creators Update (`10ts` entries after a 0x30-byte header).
    Win10,
    /// Windows 10 from the Creators Update (1703), and Windows 11 (a 0x34-byte header).
    Win10Creators,
}

impl ShimcacheFormat {
    /// The Windows versions that write it, as Eric Zimmerman's AppCompatCacheParser names them.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::WinXp => "WindowsXP",
            Self::Win2003_32 | Self::Win2003_64 => "WindowsVistaWin2k3Win2k8",
            Self::Win7_32 => "Windows7x86",
            Self::Win7_64 => "Windows7x64_Windows2008R2",
            Self::Win8_0 => "Windows80_Windows2012",
            Self::Win8_1 => "Windows81_Windows2012R2",
            Self::Win10 => "Windows10",
            Self::Win10Creators => "Windows10C_11",
        }
    }

    /// Whether its entries have a signature and a size, so they can be found in slack.
    #[must_use]
    pub fn has_entry_signatures(self) -> bool {
        matches!(
            self,
            Self::Win8_0 | Self::Win8_1 | Self::Win10 | Self::Win10Creators
        )
    }
}

/// One decoded AppCompatCache entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShimcacheEntry {
    /// Its position in the cache, 0 being the most recently used (in slack: after the cache's).
    pub position: usize,
    /// The executable path, as the cache stores it without `\??\`. A packaged (UWP) app's entry
    /// has a tab-separated record here instead (see [`ShimcacheEntry::package`]).
    pub path: String,
    /// The file's last-modification time as stored: a Windows `FILETIME` (100 ns since
    /// 1601-01-01 UTC). See [`ShimcacheEntry::last_modified`] for the time it is.
    pub last_modified_filetime: u64,
    /// Whether the file was executed: insertion flag 0x2 (Windows 7, 8, and 64-bit Vista /
    /// 2008), data tag 0x100 (Windows 10 and 11). `None` where the format has no flag (Windows
    /// XP, 32-bit 2003 / Vista / 2008).
    pub executed: Option<bool>,
    /// The insertion flags (Windows 2003 to 8.1; on 32-bit Windows 2003 the same dword holds the
    /// file size instead, and the two can't be told apart).
    pub insert_flags: Option<u32>,
    /// The shim flags (Windows 8.0 and 8.1).
    pub shim_flags: Option<u32>,
    /// The file size (Windows XP).
    pub file_size: Option<u64>,
    /// When the entry was last updated (Windows XP; its LRU array is in this order), as stored.
    pub last_update_filetime: u64,
    /// The size of the path, in bytes, as stored.
    pub path_size: u16,
    /// The package data (Windows 8.0 and 8.1), decoded as UTF-16.
    pub package: String,
    /// The entry's data (Windows 7, 8 and 10 / 11; see [`ShimcacheEntry::data_tags`]).
    pub data: Vec<u8>,
    /// Recovered from the slack of the value's cell: dropped from the cache.
    pub from_slack: bool,
}

impl ShimcacheEntry {
    /// The last-modification time when the stored value is one: `None` for 0, values past
    /// 9999-12-31 and times in the year 1601 (as AppCompatCacheParser shows them).
    #[must_use]
    pub fn last_modified(&self) -> Option<u64> {
        filetime(self.last_modified_filetime)
    }

    /// Windows XP's last update time, when it is one (as [`ShimcacheEntry::last_modified`]).
    #[must_use]
    pub fn last_update(&self) -> Option<u64> {
        filetime(self.last_update_filetime)
    }

    /// The records of a Windows 10 / 11 entry's data: 4-byte-aligned (tag, size, value). Stops at
    /// the first record that does not fit.
    #[must_use]
    pub fn data_tags(&self) -> Vec<(u32, &[u8])> {
        data_tags(&self.data)
    }

    /// The PE machine type a Windows 10 / 11 entry records (tag 0x800 or 0x2000): `0x8664`
    /// (x64), `0x14c` (x86), `0xaa64` (ARM64).
    #[must_use]
    pub fn machine(&self) -> Option<u16> {
        self.data_tags()
            .into_iter()
            .find(|(t, v)| MACHINE_TAGS.contains(t) && v.len() >= 2)
            .map(|(_, v)| u16::from_le_bytes([v[0], v[1]]))
    }

    /// A packaged (UWP) app's entry: its tab-separated record (flags, version, SDK version,
    /// architecture, package name, publisher ID, `neutral`), when the path is one.
    #[must_use]
    pub fn package_record(&self) -> Option<PackageRecord<'_>> {
        PackageRecord::parse(&self.path)
    }

    /// The key AppCompatCacheParser marks duplicates by: the time and the path in upper case.
    #[must_use]
    pub fn key(&self) -> (u64, String) {
        (self.last_modified().unwrap_or(0), self.path.to_uppercase())
    }
}

/// A packaged (UWP) app's AppCompatCache record, kept in the path field on Windows 10 and 11.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRecord<'a> {
    /// The first field (hexadecimal flags).
    pub flags: &'a str,
    /// The package version: four 16-bit parts, packed (`0001000763bb0000` is 1.7.25531.0).
    pub version: &'a str,
    /// The SDK version, packed like `version`.
    pub sdk_version: &'a str,
    /// The architecture as a PE machine type in hexadecimal (`8664`).
    pub architecture: &'a str,
    /// The package name (`Microsoft.VCLibs.140.00`).
    pub name: &'a str,
    /// The publisher ID (`8wekyb3d8bbwe`).
    pub publisher_id: &'a str,
    /// Whether the package is architecture-neutral.
    pub neutral: bool,
}

impl<'a> PackageRecord<'a> {
    fn parse(path: &'a str) -> Option<Self> {
        let f: Vec<&str> = path.split('\t').collect();
        if f.len() != 7 || f[0].is_empty() || !f[0].bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        Some(Self {
            flags: f[0],
            version: f[1],
            sdk_version: f[2],
            architecture: f[3],
            name: f[4],
            publisher_id: f[5],
            neutral: f[6] == "neutral",
        })
    }

    /// A packed version (`0001000763bb0000`) as `1.7.25531.0`.
    #[must_use]
    pub fn dotted(packed: &str) -> Option<String> {
        let v = u64::from_str_radix(packed, 16)
            .ok()
            .filter(|_| packed.len() == 16)?;
        Some(format!(
            "{}.{}.{}.{}",
            v >> 48,
            (v >> 32) & 0xffff,
            (v >> 16) & 0xffff,
            v & 0xffff
        ))
    }
}

/// A decoded AppCompatCache value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cache {
    /// Its format.
    pub format: ShimcacheFormat,
    /// The number of entries its header gives, where it has one (the LRU array's on Windows XP).
    pub expected_entries: Option<u32>,
    /// The entries, most recently used first.
    pub entries: Vec<ShimcacheEntry>,
    /// Entries that could not be read, and why. The formats whose entries say how long they are
    /// (Windows 8 to 11) stop at the first; the table formats go on with the next entry.
    pub problems: Vec<String>,
}

/// A value that is not an AppCompatCache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShimcacheError {
    /// The value is shorter than any header (8 bytes).
    TooShort {
        /// Its length.
        len: usize,
    },
    /// The value has no format's signature.
    UnknownSignature {
        /// The first dword (little-endian).
        signature: u32,
        /// The first bytes, in hexadecimal.
        start: String,
    },
}

impl fmt::Display for ShimcacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { len } => {
                write!(f, "the AppCompatCache value is too small ({len} bytes)")
            }
            Self::UnknownSignature { start, .. } => {
                write!(
                    f,
                    "not a known AppCompatCache format (the value starts with {start})"
                )
            }
        }
    }
}

impl std::error::Error for ShimcacheError {}

/// Detect the format. `is_32bit` is the system's architecture when it is known (the hive's
/// `PROCESSOR_ARCHITECTURE`): it chooses the Windows 2003 to 7 table layout unless the data only
/// makes sense with the other one; without it, 64 bit is assumed first.
#[must_use]
pub fn detect_format(blob: &[u8], is_32bit: Option<bool>) -> Option<ShimcacheFormat> {
    let sig = read_u32(blob, 0)?;
    if blob.len() < 8 {
        return None;
    }
    let hint = is_32bit.unwrap_or(false);
    Some(match sig {
        signature::WINXP => ShimcacheFormat::WinXp,
        signature::WIN2003_VISTA => {
            let n = read_u32(blob, 4).unwrap_or(0) as usize;
            if table_is_32bit(blob, 8, n, hint, &VISTA32, &VISTA64) {
                ShimcacheFormat::Win2003_32
            } else {
                ShimcacheFormat::Win2003_64
            }
        }
        signature::WIN7 => {
            let n = read_u32(blob, 4).unwrap_or(0) as usize;
            if table_is_32bit(blob, 128, n, hint, &WIN7_32, &WIN7_64) {
                ShimcacheFormat::Win7_32
            } else {
                ShimcacheFormat::Win7_64
            }
        }
        // Windows 8.x: the entries' signature at 128 (the first dword is usually 0x80, not always)
        _ if blob.get(128..132) == Some(ENTRY_00TS) => ShimcacheFormat::Win8_0,
        _ if blob.get(128..132) == Some(ENTRY_10TS) => ShimcacheFormat::Win8_1,
        // Windows 10 / 11: the first dword is the header size, and the entries start there
        _ if sig >= signature::WIN10
            && (sig as usize) < blob.len()
            && blob.get(sig as usize..sig as usize + 4) == Some(ENTRY_10TS) =>
        {
            if sig == signature::WIN10_CREATORS {
                ShimcacheFormat::Win10Creators
            } else {
                ShimcacheFormat::Win10
            }
        }
        _ => return None,
    })
}

/// Decode an AppCompatCache value. `is_32bit` as for [`detect_format`].
///
/// # Errors
/// [`ShimcacheError`] when the value is too small or not a known format. Damaged entries are in
/// [`Cache::problems`].
pub fn decode(blob: &[u8], is_32bit: Option<bool>) -> Result<Cache, ShimcacheError> {
    if blob.len() < 8 {
        return Err(ShimcacheError::TooShort { len: blob.len() });
    }
    let Some(format) = detect_format(blob, is_32bit) else {
        let start = blob
            .iter()
            .take(16)
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join("-");
        return Err(ShimcacheError::UnknownSignature {
            signature: read_u32(blob, 0).unwrap_or(0),
            start,
        });
    };
    let mut cache = Cache {
        format,
        expected_entries: None,
        entries: Vec::new(),
        problems: Vec::new(),
    };
    match format {
        ShimcacheFormat::WinXp => decode_xp(blob, &mut cache),
        ShimcacheFormat::Win2003_32 => decode_table(blob, 8, &VISTA32, false, &mut cache),
        ShimcacheFormat::Win2003_64 => decode_table(blob, 8, &VISTA64, true, &mut cache),
        ShimcacheFormat::Win7_32 => decode_table(blob, 128, &WIN7_32, true, &mut cache),
        ShimcacheFormat::Win7_64 => decode_table(blob, 128, &WIN7_64, true, &mut cache),
        ShimcacheFormat::Win8_0 | ShimcacheFormat::Win8_1 => decode_signed(blob, 128, &mut cache),
        ShimcacheFormat::Win10 | ShimcacheFormat::Win10Creators => {
            let header = read_u32(blob, 0).unwrap_or(0) as usize;
            let count_at = if format == ShimcacheFormat::Win10Creators {
                0x28
            } else {
                0x24
            };
            cache.expected_entries = read_u32(blob, count_at);
            decode_signed(blob, header, &mut cache);
        }
    }
    Ok(cache)
}

/// Decode a value, its entries only (64 bit assumed for the table formats, then checked).
///
/// # Errors
/// As [`decode`].
pub fn parse(blob: &[u8]) -> Result<Vec<ShimcacheEntry>, ShimcacheError> {
    decode(blob, None).map(|c| c.entries)
}

/// Entries of `format` in `slack` (the bytes of the value's cell after its data): what was left
/// there when the cache shrank or the cell was reused, numbered from `first_position`. Only the
/// Windows 8 to 11 formats can be found (their entries have a signature and a size); entries
/// that are also in `cache` (same time and path) are left out, as they are older copies.
#[must_use]
pub fn recover_slack(slack: &[u8], cache: &Cache) -> Vec<ShimcacheEntry> {
    let sig: &[u8; 4] = match cache.format {
        ShimcacheFormat::Win8_0 => ENTRY_00TS,
        f if f.has_entry_signatures() => ENTRY_10TS,
        _ => return Vec::new(),
    };
    let live: HashSet<(u64, String)> = cache.entries.iter().map(ShimcacheEntry::key).collect();
    let first = cache.entries.len();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 12 <= slack.len() {
        if slack.get(i..i + 4) != Some(sig.as_slice()) {
            i += 1;
            continue;
        }
        let position = first + out.len();
        match read_signed_entry(slack, i, cache.format, position) {
            Ok((mut e, next)) if plausible(&e) => {
                if !live.contains(&e.key()) {
                    e.from_slack = true;
                    out.push(e);
                }
                i = next;
            }
            _ => i += 1,
        }
    }
    // renumber after the ones left out
    for (n, e) in out.iter_mut().enumerate() {
        e.position = first + n;
    }
    out
}

/// A slack entry that is one: a path without control characters (a tab is in packaged app
/// records), of a whole number of UTF-16 units.
fn plausible(e: &ShimcacheEntry) -> bool {
    !e.path.is_empty() && e.path_size % 2 == 0 && e.path.chars().all(|c| c >= ' ' || c == '\t')
}

// ── Windows XP ─────────────────────────────────────────────────────────────────────────────

const XP_HEADER: usize = 400;
const XP_SLOT: usize = 552;
const XP_PATH: usize = 528;

/// A 400-byte header (number of slots at 4, number of entries in the LRU array at 8, the LRU
/// array of slot numbers at 16, most recently used first), then 552-byte slots: a 528-byte UTF-16
/// path, last modified FILETIME, file size, last update FILETIME.
fn decode_xp(blob: &[u8], cache: &mut Cache) {
    let mut count = read_u32(blob, 8).unwrap_or(0);
    let room = ((XP_HEADER - 16) / 4) as u32;
    if count > room {
        cache.problems.push(format!(
            "The LRU array has {count} entries, but there is room for {room}"
        ));
        count = room;
    }
    cache.expected_entries = Some(count);
    let mut seen = HashSet::new();
    for position in 0..count as usize {
        let Some(slot) = read_u32(blob, 16 + position * 4) else {
            break;
        };
        if !seen.insert(slot) {
            cache.problems.push(format!(
                "Entry {position} (slot {slot}): slot {slot} is in the LRU array more than once"
            ));
            continue;
        }
        let at = XP_HEADER as u64 + u64::from(slot) * XP_SLOT as u64;
        let Some(s) = usize::try_from(at)
            .ok()
            .and_then(|at| blob.get(at..at + XP_SLOT))
        else {
            cache.problems.push(format!(
                "Entry {position} (slot {slot}): slot {slot} (0x{XP_SLOT:X} bytes at 0x{at:X}) is past the end of the data (0x{:X} bytes)",
                blob.len()
            ));
            continue;
        };
        let raw = utf16(&s[..XP_PATH]);
        let path = raw.split('\0').next().unwrap_or_default().trim();
        cache.entries.push(ShimcacheEntry {
            position,
            path: clean_path(path),
            last_modified_filetime: read_u64(s, XP_PATH).unwrap_or(0),
            executed: None,
            insert_flags: None,
            shim_flags: None,
            file_size: read_u64(s, XP_PATH + 8),
            last_update_filetime: read_u64(s, XP_PATH + 16).unwrap_or(0),
            path_size: XP_PATH as u16,
            package: String::new(),
            data: Vec::new(),
            from_slack: false,
        });
    }
}

// ── Windows 2003 / Vista / 2008 and 7 / 2008 R2: tables of fixed-size entries ───────────────

/// Where a table entry's fields are.
struct Layout {
    size: usize,
    path_offset_at: usize,
    path_offset_64: bool,
    time_at: usize,
    flags_at: usize,
    /// Data size, then offset (Windows 7)
    data_at: Option<usize>,
}

const VISTA32: Layout = Layout {
    size: 24,
    path_offset_at: 4,
    path_offset_64: false,
    time_at: 8,
    flags_at: 16,
    data_at: None,
};
const VISTA64: Layout = Layout {
    size: 32,
    path_offset_at: 8,
    path_offset_64: true,
    time_at: 16,
    flags_at: 24,
    data_at: None,
};
const WIN7_32: Layout = Layout {
    size: 32,
    path_offset_at: 4,
    path_offset_64: false,
    time_at: 8,
    flags_at: 16,
    data_at: Some(24),
};
const WIN7_64: Layout = Layout {
    size: 48,
    path_offset_at: 8,
    path_offset_64: true,
    time_at: 16,
    flags_at: 24,
    data_at: Some(32),
};

/// The layout for the system's architecture when the first entry makes sense with it, else the
/// other one when that one does (the architecture can be missing or wrong), else the hint.
fn table_is_32bit(
    blob: &[u8],
    start: usize,
    count: usize,
    hint_32: bool,
    l32: &Layout,
    l64: &Layout,
) -> bool {
    let (hinted, other) = if hint_32 { (l32, l64) } else { (l64, l32) };
    if table_plausible(blob, start, count, hinted) || !table_plausible(blob, start, count, other) {
        hint_32
    } else {
        !hint_32
    }
}

/// The first entry: an even path size, a maximum path size at least as big, and its path after
/// the table and inside the value.
fn table_plausible(blob: &[u8], start: usize, count: usize, l: &Layout) -> bool {
    if count == 0 || blob.get(start..start + l.size).is_none() {
        return false;
    }
    let (Some(size), Some(max)) = (read_u16(blob, start), read_u16(blob, start + 2)) else {
        return false;
    };
    let offset = if l.path_offset_64 {
        read_u64(blob, start + l.path_offset_at)
    } else {
        read_u32(blob, start + l.path_offset_at).map(u64::from)
    };
    let Some(offset) = offset else { return false };
    let end = start as u64 + count as u64 * l.size as u64;
    size % 2 == 0
        && max >= size
        && offset >= end
        && offset
            .checked_add(u64::from(size))
            .is_some_and(|e| e <= blob.len() as u64)
}

fn decode_table(
    blob: &[u8],
    start: usize,
    l: &Layout,
    flags_are_executed: bool,
    cache: &mut Cache,
) {
    let count = read_u32(blob, 4).unwrap_or(0);
    cache.expected_entries = Some(count);
    for n in 0..count as usize {
        let at = start as u64 + n as u64 * l.size as u64;
        let Some(e) = usize::try_from(at)
            .ok()
            .and_then(|at| blob.get(at..at + l.size))
        else {
            cache.problems.push(format!(
                "Entries {n} to {} are past the end of the data (0x{:X} bytes)",
                count - 1,
                blob.len()
            ));
            break;
        };
        match table_entry(blob, e, l, flags_are_executed, n) {
            Ok(entry) => cache.entries.push(entry),
            Err(problem) => cache
                .problems
                .push(format!("Entry {n} at offset 0x{at:X}: {problem}")),
        }
    }
}

fn table_entry(
    blob: &[u8],
    e: &[u8],
    l: &Layout,
    flags_are_executed: bool,
    position: usize,
) -> Result<ShimcacheEntry, String> {
    let path_size = read_u16(e, 0).unwrap_or(0);
    let offset = if l.path_offset_64 {
        read_u64(e, l.path_offset_at).unwrap_or(0)
    } else {
        u64::from(read_u32(e, l.path_offset_at).unwrap_or(0))
    };
    let path_bytes = slice(blob, offset, u64::from(path_size)).ok_or_else(|| {
        format!(
            "Path (0x{path_size:X} bytes at 0x{offset:X}) is past the end of the data (0x{:X} bytes)",
            blob.len()
        )
    })?;
    let flags = read_u32(e, l.flags_at).unwrap_or(0);
    let mut data = Vec::new();
    if let Some(d) = l.data_at {
        let (size, offset) = if l.path_offset_64 {
            (read_u64(e, d).unwrap_or(0), read_u64(e, d + 8).unwrap_or(0))
        } else {
            (
                u64::from(read_u32(e, d).unwrap_or(0)),
                u64::from(read_u32(e, d + 4).unwrap_or(0)),
            )
        };
        // data that isn't in the value is left out, not an error
        if size > 0 && (size as i64) > 0 {
            if let Some(b) = slice(blob, offset, size) {
                data = b.to_vec();
            }
        }
    }
    Ok(ShimcacheEntry {
        position,
        path: clean_path(&utf16(path_bytes)),
        last_modified_filetime: read_u64(e, l.time_at).unwrap_or(0),
        executed: flags_are_executed.then_some(flags & 0x2 != 0),
        // on 32-bit Windows 2003 this dword is the file size, on Vista the insertion flags:
        // kept as it is, executed unknown (as AppCompatCacheParser has it)
        insert_flags: Some(flags),
        shim_flags: None,
        file_size: None,
        last_update_filetime: 0,
        path_size,
        package: String::new(),
        data,
        from_slack: false,
    })
}

// ── Windows 8.0 / 8.1 and 10 / 11: entries with a signature and a size ──────────────────────

fn decode_signed(blob: &[u8], start: usize, cache: &mut Cache) {
    let sig: &[u8; 4] = if cache.format == ShimcacheFormat::Win8_0 {
        ENTRY_00TS
    } else {
        ENTRY_10TS
    };
    let mut i = start;
    while i + 12 <= blob.len() {
        if blob.get(i..i + 4) != Some(sig.as_slice()) {
            break;
        }
        let position = cache.entries.len();
        match read_signed_entry(blob, i, cache.format, position) {
            Ok((e, next)) => {
                cache.entries.push(e);
                i = next;
            }
            Err(problem) => {
                // the entries' sizes lead to the next one, so the rest can't be found
                cache
                    .problems
                    .push(format!("Entry {position} at offset 0x{i:X}: {problem}"));
                return;
            }
        }
    }
    // The cache ends at the first place without an entry signature: in a whole value, its end
    // (or zeros after it). AppCompatCacheParser stops there without a word; a damaged
    // signature would hide the entries after it, so it is reported.
    let n = cache.entries.len();
    let rest = blob.get(i..).unwrap_or_default();
    if rest.iter().any(|&b| b != 0) {
        cache.problems.push(format!(
            "Entry {n} at offset 0x{i:X}: no entry signature, so the 0x{:X} bytes from there are not read",
            rest.len()
        ));
    } else if let Some(expected) = cache.expected_entries.filter(|&e| e as usize > n) {
        // Windows 10 / 11: the header's count is not always the number of entries (it is often
        // fewer), but a whole cache has never been seen with more
        cache.problems.push(format!(
            "The header gives {expected} entries, but the cache ends after {n}: entries may be missing"
        ));
    }
}

/// The entry at `i` and where the next one starts. Windows 8: signature, unknown, entry size
/// (after these 12 bytes), path size, path, package data size and data, insertion flags, shim
/// flags, last modified FILETIME, data size, data. Windows 10 / 11: the same without the package
/// data and flags.
fn read_signed_entry(
    b: &[u8],
    i: usize,
    format: ShimcacheFormat,
    position: usize,
) -> Result<(ShimcacheEntry, usize), String> {
    let windows8 = matches!(format, ShimcacheFormat::Win8_0 | ShimcacheFormat::Win8_1);
    let len = b.len();
    let past = |field: &str, size: usize, at: usize| {
        format!(
            "{field} (0x{size:X} bytes at 0x{at:X}) is past the end of the data (0x{len:X} bytes)"
        )
    };
    let entry_size = read_u32(b, i + 8).ok_or_else(|| past("Entry size", 4, i + 8))? as usize;
    let next = (i + 12)
        .checked_add(entry_size)
        .filter(|&n| n <= len)
        .ok_or_else(|| past("Entry", entry_size, i + 12))?;
    let mut at = i + 12;
    let path_size = read_u16(b, at).ok_or_else(|| past("Path size", 2, at))?;
    at += 2;
    if at + path_size as usize > next {
        return Err(format!(
            "Path size 0x{path_size:X} is past the end of the entry"
        ));
    }
    let path = clean_path(&utf16(&b[at..at + path_size as usize]));
    at += path_size as usize;
    let mut e = ShimcacheEntry {
        position,
        path,
        last_modified_filetime: 0,
        executed: None,
        insert_flags: None,
        shim_flags: None,
        file_size: None,
        last_update_filetime: 0,
        path_size,
        package: String::new(),
        data: Vec::new(),
        from_slack: false,
    };
    if windows8 {
        let package_size =
            read_u16(b, at).ok_or_else(|| past("Package data size", 2, at))? as usize;
        let package = b
            .get(at + 2..at + 2 + package_size)
            .ok_or_else(|| past("Package data", package_size, at + 2))?;
        e.package = utf16(package).trim_end_matches('\0').to_string();
        at += 2 + package_size;
        let flags = read_u32(b, at).ok_or_else(|| past("Insertion flags", 4, at))?;
        e.insert_flags = Some(flags);
        e.executed = Some(flags & 0x2 != 0);
        at += 4;
        e.shim_flags = Some(read_u32(b, at).ok_or_else(|| past("Shim flags", 4, at))?);
        at += 4;
    }
    e.last_modified_filetime = read_u64(b, at).ok_or_else(|| past("Last modified time", 8, at))?;
    at += 8;
    let data_size = read_u32(b, at).ok_or_else(|| past("Data size", 4, at))?;
    at += 4;
    if data_size > i32::MAX as u32 || at + data_size as usize > next {
        return Err(format!(
            "Data size 0x{data_size:X} is past the end of the entry"
        ));
    }
    e.data = b[at..at + data_size as usize].to_vec();
    if !windows8 {
        e.executed = Some(data_tags(&e.data).iter().any(|(t, _)| *t == EXECUTED_TAG));
    }
    Ok((e, next))
}

/// 4-byte-aligned (tag, size, value) records, up to the first that does not fit.
fn data_tags(data: &[u8]) -> Vec<(u32, &[u8])> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 8 <= data.len() {
        let (Some(tag), Some(size)) = (read_u32(data, i), read_u32(data, i + 4)) else {
            break;
        };
        let size = size as usize;
        let Some(value) = data.get(i + 8..).and_then(|r| r.get(..size)) else {
            break;
        };
        out.push((tag, value));
        i += 8 + ((size + 3) & !3);
    }
    out
}

// ── helpers ──────────────────────────────────────────────────────────────────────────────

/// The largest FILETIME that is a time: 9999-12-31 23:59:59.9999999 UTC.
const MAX_FILETIME: u64 = 2_650_467_743_999_999_999;
/// The first FILETIME after the year 1601.
const YEAR_1602: u64 = 315_360_000_000_000;

fn filetime(ft: u64) -> Option<u64> {
    (YEAR_1602..=MAX_FILETIME).contains(&ft).then_some(ft)
}

/// UTF-16LE, lossily (an unpaired surrogate is U+FFFD).
fn utf16(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// A path as the cache stores it, without `\??\`.
fn clean_path(path: &str) -> String {
    path.replace(r"\??\", "")
}

fn slice(b: &[u8], offset: u64, len: u64) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let len = usize::try_from(len).ok()?;
    b.get(start..start.checked_add(len)?)
}

fn read_u16(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off.checked_add(2)?)?
        .try_into()
        .ok()
        .map(u16::from_le_bytes)
}
fn read_u32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off.checked_add(4)?)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}
fn read_u64(b: &[u8], off: usize) -> Option<u64> {
    b.get(off..off.checked_add(8)?)?
        .try_into()
        .ok()
        .map(u64::from_le_bytes)
}

#[cfg(test)]
mod tests;
