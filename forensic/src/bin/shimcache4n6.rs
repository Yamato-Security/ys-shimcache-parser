//! `shimcache4n6 SYSTEM [--list] [--csv FILE]`: a `SYSTEM` hive's AppCompatCaches (its
//! transaction logs, next to it, replayed when it is dirty): a summary per control set and the
//! findings; `--list` prints every entry, `--csv` writes them with Eric Zimmerman's
//! AppCompatCacheParser's columns (times UTC, `yyyy-MM-dd HH:mm:ss`, as its default).

use forensicnomicon::report::Observation;
use shimcache_forensic::{audit, read_system_file, ShimcacheAnomaly, SystemCaches};
use std::io::Write;
use std::process::ExitCode;

const USAGE: &str = "usage: shimcache4n6 <SYSTEM hive> [--list] [--csv FILE]";

/// A mistake in the arguments: said on stderr with the usage, exit status 2.
fn usage(problem: &str) -> ExitCode {
    eprintln!("shimcache4n6: {problem}\n{USAGE}");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let mut list = false;
    let mut csv = None;
    let mut hive_path = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--list" => list = true,
            // a file name that starts with "-" is given as ./-name
            "--csv" => match args.next() {
                Some(file) if !file.starts_with('-') => csv = Some(file),
                _ => return usage("--csv needs a file name"),
            },
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            _ if arg.starts_with('-') => return usage(&format!("unknown option {arg}")),
            _ if hive_path.is_none() => hive_path = Some(arg),
            _ => return usage(&format!("more than one hive given ({arg})")),
        }
    }
    let Some(hive_path) = hive_path else {
        return usage("no SYSTEM hive given");
    };
    let caches = match read_system_file(std::path::Path::new(&hive_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("shimcache4n6: {hive_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let stdout = std::io::stdout();
    match print_report(&mut stdout.lock(), &caches, list) {
        // `| head`: stop quietly
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => return ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("shimcache4n6: {e}");
            return ExitCode::FAILURE;
        }
        Ok(()) => {}
    }
    if let Some(out) = csv {
        if let Err(e) = write_csv(&caches, &hive_path, &out) {
            eprintln!("shimcache4n6: {out}: {e}");
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

fn print_report(w: &mut impl Write, caches: &SystemCaches, list: bool) -> std::io::Result<()> {
    let r = &caches.recovery;
    if r.recovered {
        writeln!(w, "Transaction logs applied: {}", r.logs_applied.join(", "))?;
    } else if r.dirty {
        writeln!(
            w,
            "The hive is dirty and its transaction logs were not applied: data may be missing"
        )?;
    }
    for m in &r.messages {
        writeln!(w, "  {m}")?;
    }
    let mut anomalies: Vec<ShimcacheAnomaly> = Vec::new();
    for cs in &caches.control_sets {
        match &cs.cache {
            Some(c) => {
                writeln!(
                    w,
                    "AppCompatCache: {}, ControlSet{:03}, {} entries{}",
                    c.format.name(),
                    cs.control_set,
                    c.entries.len(),
                    if cs.slack.is_empty() {
                        String::new()
                    } else {
                        format!(" (and {} recovered from slack)", cs.slack.len())
                    }
                )?;
                for p in &c.problems {
                    writeln!(w, "  {p}")?;
                }
                // the entries recovered from the slack too
                for a in audit(&c.entries).into_iter().chain(audit(&cs.slack)) {
                    if !anomalies.contains(&a) {
                        anomalies.push(a);
                    }
                }
            }
            None => writeln!(
                w,
                "AppCompatCache: ControlSet{:03}: {}",
                cs.control_set,
                cs.error.as_deref().unwrap_or("not read")
            )?,
        }
    }
    if anomalies.is_empty() {
        writeln!(w, "Findings: none")?;
    } else {
        writeln!(w, "Findings ({}):", anomalies.len())?;
        for a in &anomalies {
            let sev = a
                .severity()
                .map_or_else(|| "INFO".to_string(), |s| format!("{s:?}").to_uppercase());
            let (ShimcacheAnomaly::SystemBinaryRelocated { path, .. }
            | ShimcacheAnomaly::SuspiciousPath { path, .. }) = a;
            writeln!(w, "  [{sev}] {}  {path}", a.code())?;
            writeln!(w, "    {}", a.note())?;
        }
    }
    if list {
        writeln!(w, "\nEntries (most recently used first):")?;
        for row in caches.rows() {
            let e = row.entry;
            let exec = match e.executed {
                Some(true) => "executed",
                Some(false) => "present",
                None => "-",
            };
            writeln!(
                w,
                "  {:03} {:>4}  {:19}  {exec:<8}  {}{}",
                row.control_set,
                e.position,
                e.last_modified().map_or_else(|| "-".to_string(), when),
                e.path,
                if e.from_slack { "  (slack)" } else { "" }
            )?;
        }
    }
    Ok(())
}

fn write_csv(caches: &SystemCaches, hive: &str, out: &str) -> std::io::Result<()> {
    let mut w = std::io::BufWriter::new(std::fs::File::create(out)?);
    writeln!(w, "ControlSet,CacheEntryPosition,Path,LastModifiedTimeUTC,Executed,Duplicate,SourceFile,FromSlack")?;
    for row in caches.rows() {
        let e = row.entry;
        let executed = match e.executed {
            Some(true) => "Yes",
            Some(false) => "No",
            None => "NA",
        };
        writeln!(
            w,
            "{},{},{},{},{executed},{},{},{}",
            row.control_set,
            e.position,
            quote(&e.path),
            e.last_modified().map_or_else(String::new, when),
            if row.duplicate { "True" } else { "False" },
            quote(hive),
            if e.from_slack { "True" } else { "False" },
        )?;
    }
    w.flush()
}

/// A CSV field, quoted when it needs to be.
fn quote(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// A FILETIME as `yyyy-MM-dd HH:mm:ss` UTC.
fn when(ft: u64) -> String {
    let secs = (ft / 10_000_000) as i64 - 11_644_473_600;
    let (days, rest) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        rest / 3_600,
        rest % 3_600 / 60,
        rest % 60
    )
}
